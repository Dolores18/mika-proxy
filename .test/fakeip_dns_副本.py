#!/usr/bin/env python3
import socket
import struct
import time
import threading
import ipaddress
import traceback

# 配置参数
DNS_HOST = '127.0.0.1'
DNS_PORT = 6353
UPSTREAM_DNS = '8.8.8.8'
UPSTREAM_PORT = 53
FAKEIP_RANGE = ipaddress.IPv4Network('198.18.0.0/15')
TTL = 600  # 缓存生存时间(秒)

# 全局缓存
domain_to_ip = {}  # 域名到IP的映射
ip_to_domain = {}  # IP到域名的映射
last_ip = None     # 上次分配的IP

# 线程锁
cache_lock = threading.Lock()

def generate_fakeip(domain):
    """根据域名生成一个唯一的FakeIP"""
    global last_ip
    
    with cache_lock:
        if domain in domain_to_ip:
            return domain_to_ip[domain]
        
        # 初始化第一个IP
        if last_ip is None:
            last_ip = ipaddress.IPv4Address(FAKEIP_RANGE[1])
        else:
            # 生成下一个IP
            last_ip += 1
            # 环绕回网段开始
            if last_ip >= FAKEIP_RANGE[-1]:
                last_ip = ipaddress.IPv4Address(FAKEIP_RANGE[1])
        
        # 保存映射
        fake_ip = str(last_ip)
        domain_to_ip[domain] = fake_ip
        ip_to_domain[fake_ip] = domain
        
        print(f"分配FakeIP: {domain} -> {fake_ip}")
        return fake_ip

def parse_domain_name(data, offset):
    """解析DNS压缩格式的域名"""
    domain_parts = []
    
    # 最大允许解析的跳转次数，避免循环引用
    jumps_performed = 0
    MAX_JUMPS = 10
    
    original_offset = offset
    is_jumped = False
    final_offset = None
    
    while True:
        length = data[offset]
        
        # 如果高两位为11，表示这是一个指针
        if (length & 0xC0) == 0xC0:
            if not is_jumped:
                final_offset = offset + 2
                is_jumped = True
                
            if jumps_performed >= MAX_JUMPS:
                raise Exception("域名解析中检测到过多跳转，可能存在循环引用")
            
            # 计算指针位置 (去掉高两位)
            pointer = ((length & 0x3F) << 8) | data[offset+1]
            offset = pointer
            jumps_performed += 1
            continue
            
        # 长度为0表示域名结束
        if length == 0:
            break
            
        # 正常域名部分
        offset += 1
        domain_part = data[offset:offset+length].decode('utf-8', errors='replace')
        domain_parts.append(domain_part)
        offset += length
        
    # 计算实际偏移量
    next_offset = final_offset if is_jumped else offset + 1
    
    return '.'.join(domain_parts), next_offset

def parse_dns_packet(data):
    """解析DNS请求包，提取查询域名"""
    try:
        # DNS包头部固定12字节
        header = data[:12]
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack('!HHHHHH', header)
        
        # 解析查询部分
        offset = 12  # 跳过头部
        
        queries = []
        for i in range(qdcount):
            domain, next_offset = parse_domain_name(data, offset)
            offset = next_offset
            
            # 查询类型和类
            qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
            offset += 4
            
            queries.append({
                'domain': domain,
                'qtype': qtype,
                'qclass': qclass
            })
        
        return {
            'id': id,
            'flags': flags,
            'qdcount': qdcount,
            'ancount': ancount,
            'nscount': nscount,
            'arcount': arcount,
            'queries': queries,
            'raw_data': data,
            'question_end_offset': offset
        }
    except Exception as e:
        print(f"解析DNS包错误: {e}")
        traceback.print_exc()
        return None

def build_dns_response(query_info, ip):
    """构造DNS响应包"""
    try:
        if query_info is None or not query_info['queries']:
            return None
            
        # 构建响应头
        packet_id = query_info['id']
        flags = 0x8180  # 标准响应，无错误
        qdcount = query_info['qdcount']
        ancount = len(query_info['queries'])  # 每个查询对应一个回答
        nscount = 0     # 没有授权名称服务器
        arcount = 0     # 没有附加记录
        
        header = struct.pack('!HHHHHH', packet_id, flags, qdcount, ancount, nscount, arcount)
        
        # 保留原始查询部分
        question_section = query_info['raw_data'][12:query_info['question_end_offset']]
        
        # 构建回答部分
        answer_section = bytearray()
        
        for query in query_info['queries']:
            # 只处理A记录查询
            if query['qtype'] == 1:  # A记录
                # 指针指向域名 (0xC00C是指向原始查询中域名的指针)
                answer_section.extend(struct.pack('!H', 0xC00C))
                
                # Type A, Class IN, TTL, 数据长度4字节
                answer_section.extend(struct.pack('!HHIH', 1, 1, TTL, 4))
                
                # IP地址 (A记录)
                octets = list(map(int, ip.split('.')))
                answer_section.extend(struct.pack('!BBBB', octets[0], octets[1], octets[2], octets[3]))
        
        # 组合完整的响应包
        response = header + question_section + answer_section
        return response
        
    except Exception as e:
        print(f"构建响应错误: {e}")
        traceback.print_exc()
        return None

def log_request(client_addr, domain, ip):
    """记录DNS请求"""
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {client_addr[0]}:{client_addr[1]} 查询 {domain} -> {ip}")

def run_dns_server():
    """运行DNS服务器"""
    print(f"FakeIP DNS服务器启动在 {DNS_HOST}:{DNS_PORT}")
    print(f"使用FakeIP范围: {FAKEIP_RANGE}")
    
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind((DNS_HOST, DNS_PORT))
    
    try:
        while True:
            try:
                data, client_addr = udp_socket.recvfrom(1024)
                
                # 解析请求
                query_info = parse_dns_packet(data)
                if not query_info or not query_info['queries']:
                    continue
                    
                # 只处理第一个查询
                domain = query_info['queries'][0]['domain']
                
                # 分配IP
                ip = generate_fakeip(domain)
                
                # 记录请求
                log_request(client_addr, domain, ip)
                
                # 构建响应
                response = build_dns_response(query_info, ip)
                if response:
                    udp_socket.sendto(response, client_addr)
                
            except Exception as e:
                print(f"处理请求出错: {e}")
                traceback.print_exc()
    
    finally:
        udp_socket.close()

if __name__ == "__main__":
    run_dns_server() 