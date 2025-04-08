#!/usr/bin/env python3
import socket
import time
import struct
import binascii

def create_dns_query(domain):
    """创建 DNS 查询数据包"""
    # DNS 头部
    transaction_id = 0x739d
    flags = 0x0120  # 标准查询
    questions = 1
    answer_rrs = 0
    authority_rrs = 0
    additional_rrs = 0

    # 构建 DNS 头部
    header = struct.pack('!HHHHHH', 
                        transaction_id,
                        flags,
                        questions,
                        answer_rrs,
                        authority_rrs,
                        additional_rrs)

    # 构建查询部分
    query = b''
    for part in domain.split('.'):
        query += struct.pack('!B', len(part))
        query += part.encode()
    query += b'\x00'  # 结束标记
    query += struct.pack('!HH', 1, 1)  # 类型 A, 类 IN

    return header + query

def main():
    # 创建 UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)  # 设置超时时间为 5 秒

    # DNS 服务器地址
    dns_server = ('8.8.8.8', 53)
    
    # 要查询的域名
    domain = 'linux.do'
    
    # 创建查询数据包
    query = create_dns_query(domain)
    
    print(f"发送 DNS 查询到 {dns_server[0]}:{dns_server[1]}")
    print(f"查询域名: {domain}")
    print("查询数据包(十六进制):")
    print(binascii.hexlify(query).decode())
    
    try:
        # 发送查询
        sock.sendto(query, dns_server)
        
        # 接收响应
        response, addr = sock.recvfrom(1024)
        print(f"\n收到来自 {addr[0]}:{addr[1]} 的响应")
        print("响应数据包(十六进制):")
        print(binascii.hexlify(response).decode())
        
        # 解析响应
        # 这里可以添加更详细的响应解析代码
        # 例如解析 IP 地址等
        
    except socket.timeout:
        print("查询超时")
    except Exception as e:
        print(f"发生错误: {e}")
    finally:
        sock.close()

if __name__ == '__main__':
    main() 