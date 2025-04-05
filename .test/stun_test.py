import socket
import struct
import time

def create_ntp_request():
    """创建 NTP 请求包"""
    # NTP v3 请求包
    return b'\x1b' + b'\0' * 47

def create_socks5_udp_request(data, dst_addr, dst_port):
    """创建 SOCKS5 UDP 请求"""
    header = bytearray()
    header.extend(b'\x00\x00\x00')  # RSV(2) + FRAG(1)
    header.append(0x01)  # ATYP: IPv4
    
    # DST.ADDR (IPv4)
    for part in dst_addr.split('.'):
        header.append(int(part))
    
    # DST.PORT
    header.extend(struct.pack('!H', dst_port))
    
    # 数据
    header.extend(data)
    return header

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 12345))
    print(f"本地地址: {sock.getsockname()}")
    
    # 创建 NTP 请求
    ntp_data = create_ntp_request()
    print(f"NTP请求数据: {ntp_data.hex()}")
    
    # 包装成 SOCKS5 UDP 请求
    # 使用阿里云 NTP 服务器的 IP 地址
    socks5_request = create_socks5_udp_request(
        ntp_data,
        '203.107.6.88',   # 阿里云 NTP 服务器 IP
        123               # NTP 端口
    )
    print(f"SOCKS5请求数据: {socks5_request.hex()}")
    
    # 发送请求
    proxy_address = ('127.0.0.1', 1082)
    print(f"发送到代理: {proxy_address}")
    sock.sendto(socks5_request, proxy_address)
    
    # 接收响应
    sock.settimeout(5)
    print("等待响应...")
    data, addr = sock.recvfrom(1024)
    print(f"收到来自 {addr} 的响应")
    print(f"响应数据: {data.hex()}")
    
    # 解析 NTP 响应
    if len(data) > 10:  # 跳过 SOCKS5 头
        ntp_response = data[10:]
        print(f"NTP响应数据: {ntp_response.hex()}")
        
        # 从响应中提取时间戳
        if len(ntp_response) >= 48:
            transmit_time = struct.unpack('!Q', ntp_response[40:48])[0]
            ntp_timestamp = transmit_time / 2**32
            print(f"\n=== NTP 响应解析 ===")
            print(f"NTP时间戳: {time.ctime(ntp_timestamp)}")

except socket.timeout:
    print("接收超时")
except Exception as e:
    print(f"发生错误: {e}")
finally:
    sock.close()
