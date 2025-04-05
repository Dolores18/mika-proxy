import socket
import struct
import random

def create_socks5_udp_request(data, dst_addr, dst_port):
    # SOCKS5 UDP 请求头
    header = bytearray()
    
    # RSV(2) + FRAG(1)
    header.extend(b'\x00\x00\x00')
    
    # ATYP: IPv4
    header.append(0x01)
    
    # DST.ADDR (IPv4)
    for part in dst_addr.split('.'):
        header.append(int(part))
    
    # DST.PORT (2 bytes, big-endian)
    header.extend(struct.pack('!H', dst_port))
    
    # 添加实际数据
    header.extend(data)
    return header

def build_dns_query(domain):
    # 构造 DNS 头
    ID = random.randint(0, 65535)  # 随机查询 ID
    FLAGS = 0x0100  # 标准查询
    QDCOUNT = 1  # 一个问题
    ANCOUNT = 0
    NSCOUNT = 0
    ARCOUNT = 0
    
    header = struct.pack('!HHHHHH', ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
    
    # 构造查询部分
    query = b''
    for part in domain.split('.'):
        query += struct.pack('B', len(part)) + part.encode()
    query += b'\x00'  # 域名结束符
    
    # 查询类型和类
    query += struct.pack('!HH', 1, 1)  # TYPE=A, CLASS=IN
    
    return header + query

def parse_dns_response(response_hex):
    # 将十六进制字符串转换为字节
    response = bytes.fromhex(response_hex)
    
    # 解析 DNS 头
    ID = struct.unpack('!H', response[0:2])[0]
    flags = struct.unpack('!H', response[2:4])[0]
    QR = (flags >> 15) & 1      # 查询/响应标志
    RCODE = flags & 0xF         # 响应码
    QDCOUNT = struct.unpack('!H', response[4:6])[0]
    ANCOUNT = struct.unpack('!H', response[6:8])[0]
    NSCOUNT = struct.unpack('!H', response[8:10])[0]
    ARCOUNT = struct.unpack('!H', response[10:12])[0]
    
    print("\n=== DNS 响应解析 ===")
    print(f"事务ID: 0x{ID:04x}")
    print(f"类型: {'响应' if QR else '查询'}")
    print(f"响应码: {RCODE} ({'成功' if RCODE == 0 else '错误'})")
    print(f"问题数量: {QDCOUNT}")
    print(f"回答数量: {ANCOUNT}")
    print(f"授权记录数: {NSCOUNT}")
    print(f"附加记录数: {ARCOUNT}")
    
    # 解析回答部分
    if ANCOUNT > 0:
        print("\n回答记录:")
        # 跳过问题部分（这里简化处理）
        pos = response.find(b'\x00', 12) + 5  # 跳过域名和类型/类
        
        for i in range(ANCOUNT):
            # 获取 IP 地址（假设是 A 记录）
            ip = response[pos+12:pos+16]  # A 记录的 IP 地址在偏移 12 字节处
            ip_str = '.'.join(str(b) for b in ip)
            ttl = struct.unpack('!I', response[pos+6:pos+10])[0]  # TTL 值
            print(f"IP地址: {ip_str} (TTL: {ttl}秒)")
            pos += 16  # 移动到下一条记录

try:
    # 创建 UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 绑定到一个具体的本地端口
    LOCAL_PORT = 3566  # 选择一个固定端口
    sock.bind(('0.0.0.0', LOCAL_PORT))
    local_addr = sock.getsockname()
    print(f"本地地址: {local_addr}")
        # 构造 DNS 查询包
    dns_query = build_dns_query('google.com')
    print(f"DNS查询数据: {dns_query.hex()}")

    # 包装成 SOCKS5 UDP 请求
    socks5_request = create_socks5_udp_request(
        dns_query,
        '1.1.1.1',  # 阿里云 DNS 服务器
        53            # DNS 端口
    )
    print(f"SOCKS5请求数据: {socks5_request.hex()}")

    # 发送到 SOCKS5 UDP 代理
    proxy_address = ('127.0.0.1', 1083)
    print(f"发送到代理: {proxy_address}")
    sock.sendto(socks5_request, proxy_address)

    # 设置超时
    sock.settimeout(5)

    # 接收响应
    print("等待响应...")
    data, addr = sock.recvfrom(1024)
    print(f"收到来自 {addr} 的响应")
    print(f"响应数据: {data.hex()}")

    # 解析响应
    if len(data) > 10:  # 确保有足够的数据
        # 跳过 SOCKS5 UDP 头
        dns_response = data[10:]  # 根据实际头部长度调整
        parse_dns_response(dns_response.hex())

except socket.timeout:
    print("接收超时")
except Exception as e:
    print(f"发生错误: {e}")
finally:
    sock.close()
