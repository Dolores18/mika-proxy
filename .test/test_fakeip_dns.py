#!/usr/bin/env python3
import socket
import struct
import sys
import time
import threading
import random
import binascii

def create_dns_query(domain, record_type=1):
    """创建DNS查询包"""
    # 随机ID，使用真正的随机ID而不是固定值
    transaction_id = random.randint(0, 65535)

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
    print("\n🔍 DNS请求详细信息:")
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
    
    print("\n📋 DNS响应详细信息:")
    print(f"交易ID: 0x{transaction_id:04x}")
    print(f"标志: 0x{flags:04x}")
    print(f"问题数: {qdcount}")
    print(f"回答数: {ancount}")
    print(f"授权服务器数: {nscount}")
    print(f"附加记录数: {arcount}")
    
    # 检查响应码
    rcode = flags & 0x000F
    if rcode != 0:
        print(f"⚠️ 响应码: {rcode} (非0表示错误)")
        return None
    
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
        print(f"\n📝 问题部分:")
        print(f"域名: {domain}")
        print(f"查询类型: {'A记录' if qtype == 1 else f'其他({qtype})'}")
        print(f"查询类: {'IN' if qclass == 1 else f'其他({qclass})'}")
    
    # 解析回答部分
    if ancount > 0 and offset < len(data):
        print("\n📌 回答部分:")
        for i in range(ancount):
            print(f"\n回答 #{i+1}:")
            
            # 检查是否是压缩指针
            if (data[offset] & 0xC0) == 0xC0:
                pointer = ((data[offset] & 0x3F) << 8) | data[offset+1]
                print(f"域名压缩指针: 0x{pointer:04x}")
                offset += 2  # 跳过指针
            else:
                # 跳过域名
                name_parts = []
                while offset < len(data) and data[offset] != 0:
                    length = data[offset]
                    offset += 1
                    name_parts.append(data[offset:offset+length].decode('utf-8'))
                    offset += length
                print(f"域名: {'.'.join(name_parts)}")
                offset += 1
            
            if offset + 10 <= len(data):
                # 解析A记录
                ans_type, ans_class, ttl, data_len = struct.unpack('!HHIH', data[offset:offset+10])
                offset += 10
                
                print(f"回答类型: {'A记录' if ans_type == 1 else f'其他({ans_type})'}")
                print(f"回答类: {'IN' if ans_class == 1 else f'其他({ans_class})'}")
                print(f"TTL: {ttl}秒")
                print(f"数据长度: {data_len}字节")
                
                if ans_type == 1 and data_len == 4 and offset + 4 <= len(data):  # A记录
                    ip = struct.unpack('!BBBB', data[offset:offset+4])
                    ip_str = f"{ip[0]}.{ip[1]}.{ip[2]}.{ip[3]}"
                    print(f"IP地址: {ip_str}")
                    
                    # 检查是否为FakeIP
                    if ip[0] == 198 and ip[1] == 18:
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
        
        print(f"🚀 发送查询: {domain}")
        print(f"查询包大小: {len(query_packet)}字节")
        print(f"查询包内容: {binascii.hexlify(query_packet).decode()}")
        
        # 发送查询
        sock.sendto(query_packet, (server_host, server_port))
        
        # 接收响应
        response, addr = sock.recvfrom(512)
        
        print(f"\n📩 收到来自 {addr[0]}:{addr[1]} 的响应")
        print(f"响应大小: {len(response)}字节")
        print(f"响应包内容: {binascii.hexlify(response).decode()}")
        
        # 解析响应
        print("\n🔍 解析响应:")
        ip = parse_dns_response(response)
        if ip:
            print(f"\n✅ 解析结果: {domain} -> {ip}")
            
            # 检查是否为FakeIP（不影响返回值）
            if ip.startswith("198.18."):
                print(f"✓ 这是一个FakeIP地址 (198.18.0.0/15 网段)")
            else:
                print(f"× 这不是FakeIP地址")
            return ip
        else:
            print(f"\n❌ 未解析到IP地址")
            return None
            
    except socket.timeout:
        print("⏱️ 查询超时")
        return None
    except Exception as e:
        print(f"❌ 查询出错: {e}")
        import traceback
        traceback.print_exc()
        return None
    finally:
        sock.close()

def receive_with_timeout(sock, timeout=10):
    """带超时的接收函数，用于解决一直等待响应的问题"""
    sock.settimeout(timeout)
    start_time = time.time()
    response = b""
    
    try:
        print(f"⏱️ 设置接收超时: {timeout}秒")
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    print("✅ 服务器关闭了连接")
                    break
                
                elapsed = time.time() - start_time
                print(f"📦 收到数据包 ({elapsed:.2f}秒): {len(data)}字节")
                
                # 只打印前100个字节，避免输出过多
                hex_preview = binascii.hexlify(data[:min(100, len(data))]).decode()
                if len(data) > 100:
                    hex_preview += "..."
                print(f"数据内容预览: {hex_preview}")
                
                response += data
                
                # 检查是否是HTTP响应，如果已经收到完整响应头和部分内容，可以提前返回
                if b"\r\n\r\n" in response:
                    # 检查是否有Content-Length
                    header_end = response.find(b"\r\n\r\n") + 4
                    headers = response[:header_end].decode('utf-8', errors='ignore')
                    
                    # 查找Content-Length
                    cl_match = None
                    for line in headers.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            try:
                                content_length = int(line.split(":", 1)[1].strip())
                                if len(response) >= header_end + content_length:
                                    print("✅ 已接收完整HTTP响应")
                                    return response
                            except:
                                pass
                    
                    # 检查是否是分块传输
                    if "Transfer-Encoding: chunked" in headers:
                        if response.endswith(b"0\r\n\r\n"):
                            print("✅ 已接收完整的分块传输响应")
                            return response
                
                # 如果已经接收了足够多的数据，可以提前返回
                if len(response) > 8192:  # 8KB
                    print("✅ 已接收足够的数据，提前返回")
                    return response
                
                # 重置超时，确保有持续的数据流入
                sock.settimeout(timeout)
                
            except socket.timeout:
                # 如果已经有一些响应，则返回已收到的部分
                if response:
                    print(f"⏱️ 接收超时，但已收到 {len(response)} 字节的响应")
                    return response
                raise  # 重新抛出异常
    except socket.timeout:
        if response:
            print(f"⏱️ 总体接收超时，返回已收到的 {len(response)} 字节")
            return response
        print("⏱️ 接收超时，未收到任何数据")
        raise
        
    return response

def simulate_browser(domain, dns_server='1.1.1.1', dns_port=50):
    """模拟浏览器访问流程：
    1. 通过DNS服务器解析域名
    2. 使用解析到的IP建立TCP连接
    3. 发送HTTP请求
    4. 设置较短的接收超时，解决一直等待的问题
    """
    print(f"\n🌐 开始模拟浏览器访问 {domain}")
    
    # 1. 先通过DNS获取IP
    print(f"🔍 通过DNS服务器 {dns_server}:{dns_port} 解析域名...")
    ip = query_dns(domain, dns_server, dns_port)
    if not ip:
        print("❌ DNS解析失败，无法获取IP地址")
        return
        
    print(f"✅ DNS解析成功: {domain} -> {ip}")
    
    # 2. 建立TCP连接
    print(f"\n🔌 建立TCP连接: {ip}:80")
    print("注意：IP栈只接受SYN包作为新连接，这是TCP协议的标准行为")
    print("连接过程:")
    print("1. 发送SYN包")
    print("2. 等待SYN-ACK响应")
    print("3. 发送ACK完成握手")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)  # 5秒连接超时
    
    try:
        # 连接到目标服务器（这里会发送SYN包）
        print("🔄 正在发送SYN包...")
        
        # 添加调试信息，显示本地IP和端口
        print(f"本地地址: {socket.gethostbyname(socket.gethostname())}")
        
        # 连接前先获取本地端口
        random_port = random.randint(10000, 65000)  # 随机选择一个端口
        sock.bind(('0.0.0.0', random_port))  # 使用随机端口而不是固定端口
        local_addr = sock.getsockname()
        print(f"本地绑定地址: {local_addr}")
        
        connect_start = time.time()
        sock.connect((ip, 80))
        connect_time = time.time() - connect_start
        
        print(f"✅ TCP连接建立成功 ({connect_time:.2f}秒)")
        print(f"  本地地址: {sock.getsockname()}")
        print(f"  远程地址: {sock.getpeername()}")
        
        # 3. 发送HTTP请求
        http_request = f"""GET / HTTP/1.1
Host: {domain}
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Cache-Control: max-age=0

"""
        print(f"📤 发送HTTP请求:\n{http_request}")
        bytes_sent = sock.send(http_request.encode())
        print(f"✅ HTTP请求已发送，发送了 {bytes_sent} 字节")
        
        # 4. 接收响应 - 使用带超时的接收函数
        try:
            print("⏳ 等待服务器响应（最多10秒）...")
            response = receive_with_timeout(sock, 10)
            
            # 打印响应头
            if response:
                header_end = response.find(b"\r\n\r\n")
                if header_end > 0:
                    headers = response[:header_end].decode('utf-8', errors='ignore')
                    print("\n📄 HTTP响应头:")
                    for line in headers.split("\r\n"):
                        print(f"  {line}")
                    
                    # 打印响应体摘要
                    body = response[header_end+4:]
                    body_preview = body[:min(200, len(body))].decode('utf-8', errors='ignore')
                    if len(body) > 200:
                        body_preview += "..."
                    
                    print(f"\n📝 HTTP响应体 (共 {len(body)} 字节):")
                    print(body_preview)
                else:
                    print("\n⚠️ 无法识别的响应格式:")
                    print(response.decode('utf-8', errors='ignore')[:200])
            else:
                print("❌ 未收到任何响应")
                
        except socket.timeout:
            print("⏱️ 接收响应超时")
        except Exception as e:
            print(f"❌ 接收响应时出错: {e}")
            
    except socket.timeout:
        print("⏱️ 连接超时")
    except ConnectionRefusedError:
        print("❌ 连接被拒绝 - 目标服务器可能未运行或端口未开放")
        print("提示: 如果使用FakeIP，确保你的网络栈正确处理了TCP连接")
    except Exception as e:
        print(f"❌ 发生错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        sock.close()
        print("👋 连接已关闭")

def test_direct_connection(domain, port=80):
    """直接连接到真实IP，用于对比测试"""
    print(f"\n🔄 尝试直接连接到 {domain}:{port} (不使用FakeIP)")
    
    try:
        # 解析真实IP
        print(f"🔍 解析真实IP...")
        real_ip = socket.gethostbyname(domain)
        print(f"✅ 解析结果: {domain} -> {real_ip}")
        
        # 建立连接
        print(f"🔌 建立TCP连接...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        connect_start = time.time()
        sock.connect((real_ip, port))
        connect_time = time.time() - connect_start
        
        print(f"✅ 连接成功 ({connect_time:.2f}秒)")
        print(f"  本地地址: {sock.getsockname()}")
        print(f"  远程地址: {sock.getpeername()}")
        
        # 发送请求
        http_request = f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: Mozilla/5.0 (Direct-Test)\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        print(f"📤 发送HTTP请求...")
        sock.send(http_request.encode())
        
        # 接收响应
        print("⏳ 等待响应...")
        response = receive_with_timeout(sock, 5)
        
        if response:
            header_end = response.find(b"\r\n\r\n")
            if header_end > 0:
                headers = response[:header_end].decode('utf-8', errors='ignore')
                print("\n📄 HTTP响应头:")
                for line in headers.split("\r\n"):
                    print(f"  {line}")
                
                print(f"\n✅ 直接连接测试成功")
            else:
                print("\n⚠️ 收到非标准HTTP响应")
        else:
            print("❌ 未收到响应")
    except Exception as e:
        print(f"❌ 直接连接测试失败: {e}")
    finally:
        try:
            sock.close()
        except:
            pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python test_fakeip_dns.py <domain> [dns_server] [dns_port] [--dns-only] [--compare]")
        print("示例: python test_fakeip_dns.py baidu.com")
        print("      python test_fakeip_dns.py apple.com 127.0.0.1 6353")
        print("      python test_fakeip_dns.py google.com --dns-only (只进行DNS查询)")
        print("      python test_fakeip_dns.py baidu.com --compare (同时测试直接连接)")
        print("\n参数说明:")
        print("  --dns-only: 只执行DNS查询步骤，不尝试TCP连接")
        print("  --compare: 同时测试直接连接到真实IP，用于对比")
        sys.exit(1)
        
    domain = sys.argv[1]
    
    # 检查命令行参数
    dns_only = "--dns-only" in sys.argv
    compare = "--compare" in sys.argv
    
    if dns_only and "--dns-only" in sys.argv:
        sys.argv.remove("--dns-only")
    if compare and "--compare" in sys.argv:
        sys.argv.remove("--compare")
    
    # 设置DNS服务器
    server_host = '127.0.0.1'
    server_port = 6353
    
    if len(sys.argv) >= 3:
        server_host = sys.argv[2]
    if len(sys.argv) >= 4:
        server_port = int(sys.argv[3])
    
    print(f"🚀 测试开始: 域名={domain}, DNS服务器={server_host}:{server_port}")
    
    if dns_only:
        # 只进行DNS查询
        print(f"🔍 仅进行DNS查询: {domain}")
        query_dns(domain, server_host, server_port)
    else:
        # 执行完整的浏览器模拟流程
        simulate_browser(domain, server_host, server_port)
        
        # 如果需要对比测试
        if compare:
            test_direct_connection(domain)
    
    print("\n✅ 测试完成")
