#!/usr/bin/env python3
import socket
import time
import struct
import binascii

def create_dns_query(domain, query_type=1):
    """创建 DNS 查询数据包
    
    Args:
        domain: 要查询的域名
        query_type: 查询类型 (1=A, 28=AAAA)
    """
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
    query += struct.pack('!HH', query_type, 1)  # 类型, 类 IN

    return header + query

def parse_domain_name(data, offset):
    """解析域名（支持压缩指针）
    
    Returns:
        (domain_name, new_offset)
    """
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 5
    jumps = 0
    
    while True:
        if offset >= len(data):
            break
            
        length = data[offset]
        
        # 检查是否是压缩指针
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            if jumps >= max_jumps:
                break
            # 解析指针
            pointer = struct.unpack('!H', data[offset:offset+2])[0]
            offset = pointer & 0x3FFF
            jumped = True
            jumps += 1
            continue
        
        if length == 0:
            offset += 1
            break
            
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset+length].decode('utf-8', errors='ignore'))
        offset += length
    
    domain = '.'.join(labels)
    return domain, original_offset if jumped else offset

def parse_dns_response(response):
    """解析 DNS 响应数据包"""
    if len(response) < 12:
        return "响应数据包太短"
    
    # 解析头部
    header = struct.unpack('!HHHHHH', response[:12])
    transaction_id = header[0]
    flags = header[1]
    questions = header[2]
    answer_rrs = header[3]
    authority_rrs = header[4]
    additional_rrs = header[5]
    
    # 解析标志位
    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    rcode = flags & 0xF
    
    rcode_names = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED"
    }
    
    result = []
    result.append("=" * 60)
    result.append("DNS 响应解析")
    result.append("=" * 60)
    result.append(f"事务 ID: 0x{transaction_id:04x}")
    result.append(f"标志: 0x{flags:04x}")
    result.append(f"  - QR (查询/响应): {'响应' if qr else '查询'}")
    result.append(f"  - Opcode: {opcode}")
    result.append(f"  - AA (权威应答): {'是' if aa else '否'}")
    result.append(f"  - TC (截断): {'是' if tc else '否'}")
    result.append(f"  - RD (期望递归): {'是' if rd else '否'}")
    result.append(f"  - RA (可递归): {'是' if ra else '否'}")
    result.append(f"  - RCODE: {rcode} ({rcode_names.get(rcode, '未知')})")
    result.append(f"问题数: {questions}")
    result.append(f"回答数: {answer_rrs}")
    result.append(f"权威记录数: {authority_rrs}")
    result.append(f"附加记录数: {additional_rrs}")
    result.append("")
    
    offset = 12
    
    # 跳过问题部分
    result.append("问题部分:")
    for i in range(questions):
        domain, offset = parse_domain_name(response, offset)
        if offset + 4 > len(response):
            break
        qtype, qclass = struct.unpack('!HH', response[offset:offset+4])
        offset += 4
        
        qtype_names = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
        result.append(f"  {domain} (类型: {qtype_names.get(qtype, str(qtype))}, 类: {qclass})")
    result.append("")
    
    # 解析回答部分
    if answer_rrs > 0:
        result.append("回答部分:")
        for i in range(answer_rrs):
            if offset >= len(response):
                break
                
            domain, offset = parse_domain_name(response, offset)
            
            if offset + 10 > len(response):
                break
                
            rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', response[offset:offset+10])
            offset += 10
            
            if offset + rdlength > len(response):
                break
            
            rdata = response[offset:offset+rdlength]
            offset += rdlength
            
            rtype_names = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
            
            result.append(f"  [{i+1}] {domain}")
            result.append(f"      类型: {rtype_names.get(rtype, str(rtype))}")
            result.append(f"      类: {rclass}")
            result.append(f"      TTL: {ttl} 秒")
            result.append(f"      数据长度: {rdlength} 字节")
            
            # 解析不同类型的记录
            if rtype == 1 and rdlength == 4:  # A 记录
                ip = '.'.join(str(b) for b in rdata)
                result.append(f"      IPv4 地址: {ip}")
            elif rtype == 28 and rdlength == 16:  # AAAA 记录
                ip_parts = [f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2)]
                ip = ':'.join(ip_parts)
                result.append(f"      IPv6 地址: {ip}")
            elif rtype == 5:  # CNAME 记录
                cname, _ = parse_domain_name(response, offset - rdlength)
                result.append(f"      别名: {cname}")
            else:
                result.append(f"      数据(十六进制): {binascii.hexlify(rdata).decode()}")
            result.append("")
    
    result.append("=" * 60)
    return '\n'.join(result)

def main():
    import sys
    
    # 解析命令行参数
    if len(sys.argv) < 2:
        print("用法: python dns_test.py <域名> [DNS服务器]")
        print("示例: python dns_test.py qq.com")
        print("示例: python dns_test.py qq.com 1.1.1.1")
        sys.exit(1)
    
    domain = sys.argv[1]
    dns_server_ip = sys.argv[2] if len(sys.argv) > 2 else '8.8.8.8'
    
    # 创建 UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)  # 设置超时时间为 5 秒

    # DNS 服务器地址
    dns_server = (dns_server_ip, 53)
    
    # 创建查询数据包 (1=A记录, 28=AAAA记录)
    query = create_dns_query(domain, query_type=1)
    
    print(f"发送 DNS 查询到 {dns_server[0]}:{dns_server[1]}")
    print(f"查询域名: {domain}")
    print(f"查询类型: A (IPv4)")
    print("查询数据包(十六进制):")
    print(binascii.hexlify(query).decode())
    print()
    
    try:
        # 发送查询
        sock.sendto(query, dns_server)
        
        # 接收响应
        response, addr = sock.recvfrom(1024)
        print(f"收到来自 {addr[0]}:{addr[1]} 的响应")
        print("响应数据包(十六进制):")
        print(binascii.hexlify(response).decode())
        print()
        
        # 解析并打印响应
        parsed = parse_dns_response(response)
        print(parsed)
        
    except socket.timeout:
        print("查询超时")
    except Exception as e:
        print(f"发生错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        sock.close()

if __name__ == '__main__':
    main() 