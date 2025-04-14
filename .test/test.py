import socket
import struct
import random

def dns_query(domain, dns_server="8.8.8.8", dns_port=53):
    """向指定DNS服务器查询域名对应的IP地址"""
    # 创建UDP套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    try:
        # 构造DNS请求包
        transaction_id = random.randint(0, 65535)
        
        # 构造请求头
        # transaction_id + flags + questions + answers + auth_rr + additional_rr
        header = struct.pack('!HHHHHH', 
                          transaction_id,  # 随机ID
                          0x0100,          # 标准查询，递归
                          1,               # 1个问题
                          0,               # 0个应答
                          0,               # 0个授权记录
                          0)               # 0个附加记录
        
        # 构造域名部分
        query_parts = []
        for part in domain.split('.'):
            query_parts.append(bytes([len(part)]))
            query_parts.append(part.encode())
        query_parts.append(b'\x00')  # 域名结束符
        
        question = b''.join(query_parts)
        question += struct.pack('!HH', 1, 1)  # 类型A，类IN
        
        # 合并请求
        request = header + question
        
        # 发送请求到DNS服务器
        sock.sendto(request, (dns_server, dns_port))
        
        # 接收响应
        response, _ = sock.recvfrom(512)
        
        # 解析响应
        response_header = struct.unpack('!HHHHHH', response[:12])
        resp_id, flags, qdcount, ancount, nscount, arcount = response_header
        
        # 检查是否有错误
        if flags & 0x000F != 0:
            print(f"DNS查询错误，错误码: {flags & 0x000F}")
            return None
        
        # 跳过问题部分
        offset = 12
        for _ in range(qdcount):
            while True:
                length = response[offset]
                offset += 1
                if length == 0:
                    break
                offset += length
            offset += 4  # 跳过类型和类
        
        # 解析应答部分
        ip_addresses = []
        for _ in range(ancount):
            # 跳过域名（可能是指针）
            if (response[offset] & 0xC0) == 0xC0:
                offset += 2
            else:
                while True:
                    length = response[offset]
                    offset += 1
                    if length == 0:
                        break
                    offset += length
            
            record_type = struct.unpack('!H', response[offset:offset+2])[0]
            offset += 8  # 跳过类型、类和TTL
            
            data_length = struct.unpack('!H', response[offset:offset+2])[0]
            offset += 2
            
            # 如果是A记录（IPv4地址）
            if record_type == 1 and data_length == 4:
                ip = socket.inet_ntoa(response[offset:offset+4])
                ip_addresses.append(ip)
            
            offset += data_length
        
        if ip_addresses:
            print(f"DNS查询成功，{domain} 解析到: {ip_addresses}")
            return ip_addresses[0]
        else:
            print(f"未找到 {domain} 的A记录")
            return None
    except Exception as e:
        print(f"DNS查询异常: {e}")
        return None
    finally:
        sock.close()

def fetch_url(host, port=80, path="/", use_hostname_header=True, original_hostname=None):
    """
    获取URL内容
    
    参数:
        host: 主机名或IP地址
        port: 端口号
        path: 路径
        use_hostname_header: 如果为True且host是IP地址，在Host头中使用原始域名
        original_hostname: 原始域名，用于Host头
    """
    s = socket.socket()
    try:
        s.connect((host, port))
        
        # 如果host是IP地址且use_hostname_header为True，
        # 则使用原始域名作为Host头的值
        host_header = host
        if use_hostname_header and is_ip_address(host) and original_hostname:
            # 使用传入的原始域名作为Host头
            host_header = original_hostname
        
        request = f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
        s.send(request.encode())
        
        # 先读取响应头
        header_data = b""
        while True:
            chunk = s.recv(1)
            if not chunk:
                break
            header_data += chunk
            if header_data.endswith(b"\r\n\r\n"):
                break
        
        # 解析 Content-Length
        headers = header_data.decode().split("\r\n")
        content_length = 0
        for header in headers:
            if header.lower().startswith("content-length:"):
                content_length = int(header.split(":")[1].strip())
                break
        
        # 读取响应体
        body_data = b""
        while len(body_data) < content_length:
            chunk = s.recv(4096)
            if not chunk:
                break
            body_data += chunk
            
        return header_data + body_data
    finally:
        s.close()

def is_ip_address(addr):
    """检查字符串是否是IP地址"""
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False

# 使用示例
target_domain = "example.com"
print(f"正在查询 {target_domain} 的IP地址...")
ip_address = dns_query(target_domain)

if ip_address:
    print(f"使用IP地址 {ip_address} 连接到 {target_domain}...")
    # 传入原始域名作为Host头
    response = fetch_url(ip_address, original_hostname=target_domain)
    print("响应内容:")
    print(response.decode())
else:
    print("DNS查询失败，使用原始域名连接...")
    response = fetch_url(target_domain)
    print("响应内容:")
    print(response.decode())