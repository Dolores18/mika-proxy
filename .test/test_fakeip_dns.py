#!/usr/bin/env python3
import socket
import struct
import sys

def create_dns_query(domain, record_type=1):
    """创建DNS查询包"""
    # 随机ID
    transaction_id = 0x1234

    # 标志 - 标准查询
    flags = 0x0100
    
    # 1个查询
    qdcount = 1
    
    # 其它计数为0
    ancount = nscount = arcount = 0
    
    # 构建DNS头
    header = struct.pack('!HHHHHH', transaction_id, flags, qdcount, ancount, nscount, arcount)
    
    # 构建查询部分
    query = bytearray()
    
    # 分割域名并编码
    parts = domain.split('.')
    for part in parts:
        length = len(part)
        query.append(length)
        query.extend(part.encode('utf-8'))
    
    # 域名结束标志
    query.append(0)
    
    # 添加查询类型和类 (A记录, IN)
    query.extend(struct.pack('!HH', record_type, 1))
    
    # 打印详细的请求信息
    print("\nDNS请求详细信息:")
    print(f"交易ID: 0x{transaction_id:04x}")
    print(f"标志: 0x{flags:04x}")
    print(f"问题数: {qdcount}")
    print(f"回答数: {ancount}")
    print(f"授权服务器数: {nscount}")
    print(f"附加记录数: {arcount}")
    print(f"查询类型: {'A记录' if record_type == 1 else '其他'}")
    print(f"查询类: IN")
    print(f"查询域名: {domain}")
    
    return header + query

def parse_dns_response(data):
    """解析DNS响应包"""
    # 解析头部
    header = data[:12]
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', header)
    
    print("\nDNS响应详细信息:")
    print(f"交易ID: 0x{transaction_id:04x}")
    print(f"标志: 0x{flags:04x}")
    print(f"问题数: {qdcount}")
    print(f"回答数: {ancount}")
    print(f"授权服务器数: {nscount}")
    print(f"附加记录数: {arcount}")
    
    # 解析问题部分
    offset = 12
    domain_parts = []
    while offset < len(data) and data[offset] != 0:
        length = data[offset]
        offset += 1
        domain_parts.append(data[offset:offset+length].decode('utf-8'))
        offset += length
    domain = '.'.join(domain_parts)
    offset += 1  # 跳过域名结束标记
    
    if offset + 4 <= len(data):
        qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
        offset += 4
        print(f"\n问题部分:")
        print(f"域名: {domain}")
        print(f"查询类型: {'A记录' if qtype == 1 else '其他'}")
        print(f"查询类: {'IN' if qclass == 1 else '其他'}")
    
    # 解析回答部分
    if ancount > 0 and offset < len(data):
        print("\n回答部分:")
        for _ in range(ancount):
            # 检查是否是压缩指针
            if (data[offset] & 0xC0) == 0xC0:
                offset += 2  # 跳过指针
            else:
                # 跳过域名
                while offset < len(data) and data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1
            
            if offset + 10 <= len(data):
                # 解析A记录
                ans_type, ans_class, ttl, data_len = struct.unpack('!HHIH', data[offset:offset+10])
                offset += 10
                
                print(f"回答类型: {'A记录' if ans_type == 1 else '其他'}")
                print(f"回答类: {'IN' if ans_class == 1 else '其他'}")
                print(f"TTL: {ttl}秒")
                print(f"数据长度: {data_len}字节")
                
                if ans_type == 1 and data_len == 4 and offset + 4 <= len(data):  # A记录
                    ip = struct.unpack('!BBBB', data[offset:offset+4])
                    ip_str = f"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}"
                    print(f"IP地址: {ip_str}")
                    
                    # 检查是否为FakeIP
                    if ip_str.startswith("198.18."):
                        print(f"✓ 这是一个FakeIP地址 (198.18.0.0/15 网段)")
                    else:
                        print(f"× 这不是FakeIP地址")
                    
                    return ip_str
                offset += data_len
    
    return None

def query_dns(domain, server_host='127.0.0.1', server_port=6353):
    """查询DNS服务器"""
    # 创建UDP套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    try:
        # 构建DNS查询包
        query_packet = create_dns_query(domain)
        
        print(f"发送查询: {domain}")
        print(f"查询包大小: {len(query_packet)}字节")
        print(f"查询包内容: {query_packet.hex()}")
        
        # 发送查询
        sock.sendto(query_packet, (server_host, server_port))
        
        # 接收响应
        response, addr = sock.recvfrom(512)
        
        print(f"\n收到来自 {addr[0]}:{addr[1]} 的响应")
        print(f"响应大小: {len(response)}字节")
        print(f"响应包内容: {response.hex()}")
        
        # 解析响应
        print("\n解析响应:")
        ip = parse_dns_response(response)
        if ip:
            print(f"\n解析结果: {domain} -> {ip}")
            
            # 检查是否为FakeIP（不影响返回值）
            if ip.startswith("198.18."):
                print(f"✓ 这是一个FakeIP地址 (198.18.0.0/15 网段)")
            else:
                print(f"× 这不是FakeIP地址")
            return ip
        else:
            print(f"\n未解析到IP地址")
            return None
            
    except socket.timeout:
        print("查询超时")
        return None
    except Exception as e:
        print(f"查询出错: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        sock.close()

def simulate_browser(domain, dns_server='127.0.0.1', dns_port=6353):
    """模拟浏览器访问流程：
    1. 通过DNS服务器解析域名
    2. 使用解析到的IP建立TCP连接（注：IP栈只接受SYN包建立的连接）
    3. 发送HTTP请求
    """
    print(f"\n开始模拟浏览器访问 {domain}")
    
    # 1. 先通过DNS获取IP
    print(f"通过DNS服务器 {dns_server}:{dns_port} 解析域名...")
    ip = query_dns(domain, dns_server, dns_port)
    if not ip:
        print("❌ DNS解析失败，无法获取IP地址")
        return
        
    print(f"✅ DNS解析成功: {domain} -> {ip}")
    
    # 2. 建立TCP连接
    print(f"\n建立TCP连接: {ip}:80")
    print("注意：IP栈只接受SYN包作为新连接，这是TCP协议的标准行为")
    print("当通过socket库连接时，系统自动发送SYN包进行三次握手")
    print("连接过程:")
    print("1. 发送SYN包")
    print("2. 等待SYN-ACK响应")
    print("3. 发送ACK完成握手")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    try:
        # 连接到目标服务器（这里会发送SYN包）
        print("正在发送SYN包...")
        sock.connect((ip, 80))
        print("✅ TCP连接建立成功")
        print("  本地地址:", sock.getsockname())
        print("  远程地址:", sock.getpeername())
        
        # 3. 发送HTTP请求
        http_request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        sock.send(http_request.encode())
        print("✅ HTTP请求已发送")
        
        # 4. 接收响应
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
            
        # 打印响应头
        headers = response.split(b"\r\n\r\n")[0]
        print("\nHTTP响应头:")
        print(headers.decode())
        
    except socket.timeout:
        print("❌ 连接超时")
    except Exception as e:
        print(f"❌ 发生错误: {e}")
    finally:
        sock.close()
        print("✅ 连接已关闭")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python test_fakeip_dns.py <domain> [dns_server] [dns_port] [--dns-only]")
        print("示例: python test_fakeip_dns.py baidu.com")
        print("      python test_fakeip_dns.py apple.com 127.0.0.1 6353")
        print("      python test_fakeip_dns.py google.com --dns-only (只进行DNS查询)")
        print("\n参数说明:")
        print("  --dns-only: 只执行DNS查询步骤，不尝试TCP连接")
        print("              当只想测试FakeIP系统的DNS部分时使用此参数")
        sys.exit(1)
        
    domain = sys.argv[1]
    
    # 检查是否只进行DNS查询
    dns_only = "--dns-only" in sys.argv
    if dns_only and "--dns-only" in sys.argv:
        sys.argv.remove("--dns-only")
    
    # 设置DNS服务器
    server_host = '127.0.0.1'
    server_port = 6353
    
    if len(sys.argv) >= 3:
        server_host = sys.argv[2]
    if len(sys.argv) >= 4:
        server_port = int(sys.argv[3])
    
    if dns_only:
        # 只进行DNS查询
        print(f"仅进行DNS查询: {domain}")
        query_dns(domain, server_host, server_port)
    else:
        # 执行完整的浏览器模拟流程
        simulate_browser(domain, server_host, server_port) 