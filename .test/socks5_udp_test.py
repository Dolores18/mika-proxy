#!/usr/bin/env python3
import socket
import struct
import time
import argparse
import sys
import binascii

def send_udp_via_socks5(proxy_host, proxy_port, target_host, target_port, data, verbose=False):
    """通过SOCKS5代理发送UDP数据包

    Args:
        proxy_host: SOCKS5代理服务器地址
        proxy_port: SOCKS5代理服务器端口
        target_host: 目标UDP服务器地址
        target_port: 目标UDP服务器端口
        data: 要发送的数据
        verbose: 是否显示详细日志
    
    Returns:
        接收到的数据或None（如果出错）
    """
    if verbose:
        print(f"[*] 连接SOCKS5代理 {proxy_host}:{proxy_port}")
    
    # 连接到SOCKS5代理
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tcp_sock.connect((proxy_host, proxy_port))
    except Exception as e:
        print(f"[!] 连接SOCKS5代理失败: {e}")
        return None
    
    # SOCKS5握手
    # 发送版本和认证方法 (0x05: SOCKS5, 0x01: 1个认证方法, 0x00: 无认证)
    if verbose:
        print("[*] 发送SOCKS5握手请求")
    tcp_sock.sendall(b"\x05\x01\x00")
    
    # 接收握手响应
    response = tcp_sock.recv(2)
    if response != b"\x05\x00":
        print(f"[!] SOCKS5握手失败: {binascii.hexlify(response)}")
        tcp_sock.close()
        return None
    
    if verbose:
        print("[+] SOCKS5握手成功")
    
    # 解析目标地址
    target_ip = socket.gethostbyname(target_host)
    if verbose:
        print(f"[*] 目标地址解析为: {target_ip}")
    
    # UDP关联请求
    # 0x05: SOCKS5版本
    # 0x03: UDP关联命令
    # 0x00: 保留字段
    # 0x01: IPv4地址类型
    # 0.0.0.0: 客户端地址（让代理自己决定）
    # 0x00 0x00: 端口0（让代理自己决定）
    if verbose:
        print("[*] 发送UDP关联请求")
    tcp_sock.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    
    # 接收UDP关联响应
    response = tcp_sock.recv(10)
    if len(response) < 10 or response[0] != 0x05 or response[1] != 0x00:
        print(f"[!] UDP关联请求失败: {binascii.hexlify(response)}")
        tcp_sock.close()
        return None
    
    # 解析UDP中继地址和端口
    if response[3] == 0x01:  # IPv4
        relay_ip = socket.inet_ntoa(response[4:8])
        relay_port = struct.unpack("!H", response[8:10])[0]
    else:
        print(f"[!] 不支持的地址类型: {response[3]}")
        tcp_sock.close()
        return None
    
    if verbose:
        print(f"[+] UDP中继地址: {relay_ip}:{relay_port}")
    
    # 创建UDP套接字
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # 构建SOCKS5 UDP请求头
        # 0x00 0x00: 保留字段
        # 0x00: 分片编号（0表示不分片）
        # 0x01: IPv4地址类型
        # target_ip: 目标IP地址
        # target_port: 目标端口
        udp_header = b"\x00\x00\x00\x01" + socket.inet_aton(target_ip) + struct.pack("!H", target_port)
        
        # 发送UDP数据
        if verbose:
            print(f"[*] 发送UDP数据到 {target_ip}:{target_port}")
            print(f"[*] 数据内容: {binascii.hexlify(data)}")
        
        udp_sock.sendto(udp_header + data, (relay_ip, relay_port))
        
        # 设置超时
        udp_sock.settimeout(5)
        
        # 接收响应
        if verbose:
            print("[*] 等待响应...")
        
        response_data, _ = udp_sock.recvfrom(4096)
        
        # 解析SOCKS5 UDP响应
        if len(response_data) < 10:
            print("[!] 收到的响应太短")
            return None
            
        # 解析UDP响应头部
        atyp = response_data[3]
        if atyp == 0x01:  # IPv4
            header_size = 10  # 4字节RSV+FRAG+ATYP + 4字节IPv4 + 2字节端口
        elif atyp == 0x03:  # 域名
            domain_len = response_data[4]
            header_size = 5 + domain_len + 2  # 4字节RSV+FRAG+ATYP + 1字节长度 + 域名长度 + 2字节端口
        elif atyp == 0x04:  # IPv6
            header_size = 22  # 4字节RSV+FRAG+ATYP + 16字节IPv6 + 2字节端口
        else:
            print(f"[!] 未知的地址类型: {atyp}")
            return None
            
        actual_data = response_data[header_size:]
        
        if verbose:
            print(f"[+] 收到响应，长度: {len(actual_data)} 字节")
            print(f"[+] 响应内容: {binascii.hexlify(actual_data)}")
            
        return actual_data
        
    except socket.timeout:
        print("[!] 接收响应超时")
    except Exception as e:
        print(f"[!] UDP通信错误: {e}")
    finally:
        udp_sock.close()
        tcp_sock.close()
    
    return None

def domain_to_dns_format(domain):
    """将域名转换为DNS查询格式"""
    result = bytearray()
    for part in domain.split('.'):
        result.append(len(part))
        result.extend(part.encode())
    result.append(0)  # 域名结束符
    return bytes(result)

def test_dns_query(proxy_host="127.0.0.1", proxy_port=1080, domain="google.com", dns_server="8.8.8.8"):
    """测试通过SOCKS5代理发送DNS查询
    
    Args:
        proxy_host: SOCKS5代理地址
        proxy_port: SOCKS5代理端口
        domain: 要查询的域名，默认为google.com
        dns_server: DNS服务器地址
    """
    # 构建DNS查询域名部分
    domain_bytes = domain_to_dns_format(domain)
    
    # 构建简单的DNS查询
    dns_query = (
        b"\x12\x34"  # 事务ID
        b"\x01\x00"  # 标志 - 标准查询
        b"\x00\x01"  # 问题数: 1
        b"\x00\x00"  # 应答数: 0
        b"\x00\x00"  # 授权记录数: 0
        b"\x00\x00"  # 附加记录数: 0
        # 查询部分
    ) + domain_bytes + (
        b"\x00\x01"  # 类型: A
        b"\x00\x01"  # 类: IN
    )
    
    print(f"[*] 查询域名: {domain}")
    result = send_udp_via_socks5(proxy_host, proxy_port, dns_server, 53, dns_query, verbose=True)
    
    if result:
        print("\n[+] DNS查询成功!")
        parse_dns_response(result)
        print("\n[+] 尝试将DNS响应解码为UTF-8:")
        try:
            print(result.decode('utf-8', 'ignore'))
            print("[+] 注意: DNS响应通常包含二进制数据，可能无法正确解码为UTF-8文本")
        except Exception as e:
            print(f"[!] 解码错误: {e}")
    else:
        print("\n[!] DNS查询失败")

def parse_dns_response(response):
    """简单解析DNS响应"""
    # 解析DNS响应头部
    transaction_id = struct.unpack("!H", response[0:2])[0]
    flags = struct.unpack("!H", response[2:4])[0]
    questions = struct.unpack("!H", response[4:6])[0]
    answers = struct.unpack("!H", response[6:8])[0]
    
    print(f"事务ID: 0x{transaction_id:04x}")
    print(f"标志: 0x{flags:04x}")
    print(f"问题数: {questions}")
    print(f"应答数: {answers}")
    
    # 只解析应答部分的IP地址(简化版,只适用于简单查询)
    if answers > 0:
        # 跳过问题部分(不精确)
        pos = 12
        while pos < len(response):
            if response[pos] == 0:
                pos += 5  # 跳过末尾的类型和类
                break
            pos += 1
            
        # 解析应答
        for i in range(answers):
            if pos + 12 > len(response):
                break
                
            # 跳过域名指针
            pos += 2
            
            # 读取类型
            rec_type = struct.unpack("!H", response[pos:pos+2])[0]
            pos += 2
            
            # 跳过类
            pos += 2
            
            # 跳过TTL
            pos += 4
            
            # 读取数据长度
            data_len = struct.unpack("!H", response[pos:pos+2])[0]
            pos += 2
            
            # 读取数据
            if rec_type == 1 and data_len == 4:  # A记录
                ip = socket.inet_ntoa(response[pos:pos+4])
                print(f"IP地址: {ip}")
            
            pos += data_len

def test_simple_udp(proxy_host="127.0.0.1", proxy_port=1080):
    """发送简单的UDP消息到echo服务器"""
    # 注意：需要有支持UDP回显的服务器
    test_data = b"Hello, UDP via SOCKS5!"
    
    # 这里可以换成实际的UDP echo服务器
    result = send_udp_via_socks5(proxy_host, proxy_port, "127.0.0.1", 7, test_data, verbose=True)
    
    if result:
        print(f"\n[+] 收到回显数据: {result.decode('utf-8', errors='ignore')}")
    else:
        print("\n[!] UDP echo测试失败")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='SOCKS5 UDP代理测试工具')
    parser.add_argument('--proxy-host', default='127.0.0.1', help='SOCKS5代理地址')
    parser.add_argument('--proxy-port', type=int, default=1080, help='SOCKS5代理端口')
    parser.add_argument('--test', choices=['dns', 'echo', 'ntp', 'stun'], default='dns', help='要运行的测试类型')
    parser.add_argument('--domain', default='google.com', help='DNS查询的域名 (仅用于DNS测试)')
    parser.add_argument('--dns-server', default='8.8.8.8', help='DNS服务器地址')
    
    args = parser.parse_args()
    
    print("=== SOCKS5 UDP代理测试 ===")
    print(f"代理服务器: {args.proxy_host}:{args.proxy_port}")
    
    if args.test == 'dns':
        print("运行DNS查询测试...")
        test_dns_query(proxy_host=args.proxy_host, proxy_port=args.proxy_port, 
                      domain=args.domain, dns_server=args.dns_server)
    else:
        print("运行UDP echo测试...")
        test_simple_udp(proxy_host=args.proxy_host, proxy_port=args.proxy_port) 