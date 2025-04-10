import socket, struct, sys

# 创建DNS查询
def make_query(domain):
    id = 0x1234
    packet = struct.pack(">H", id)  # 查询ID
    packet += struct.pack(">H", 0x0100)  # 标准查询标志
    packet += struct.pack(">HHHH", 1, 0, 0, 0)  # 1个问题，0个回答，0个权威，0个附加
    
    # 编码域名部分
    for part in domain.split("."):
        packet += struct.pack("B", len(part))
        packet += part.encode()
    packet += struct.pack("B", 0)  # 域名终止符
    
    packet += struct.pack(">HH", 1, 1)  # 查询类型A，类别IN
    return packet

# 创建socket，绑定源端口
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 36988))  # 绑定源端口12345

# 发送查询
query = make_query("linux.do")
print(f"发送{len(query)}字节到8.8.8.8:53")
sock.sendto(query, ("8.8.8.8", 53))

# 接收响应
sock.settimeout(5)
try:
    data, addr = sock.recvfrom(1024)
    print(f"从{addr}收到{len(data)}字节响应")
    
    # 简单解析A记录
    if len(data) >= 12:
        header = struct.unpack(">HHHHHH", data[:12])
        print(f"查询ID: 0x{header[0]:04x}, 问题数: {header[2]}, 回答数: {header[3]}")
        
        # 跳过问题部分找到回答
        idx = 12
        # 跳过域名
        while idx < len(data) and data[idx] != 0:
            if (data[idx] & 0xC0) == 0xC0:  # 压缩指针
                idx += 2
                break
            idx += data[idx] + 1
        idx += 5  # 跳过结束符(0)和类型(2字节)和类别(2字节)
        
        # 解析回答部分
        if len(data) > idx + 12 and header[3] > 0:
            for i in range(header[3]):
                if (data[idx] & 0xC0) == 0xC0:  # 压缩指针
                    idx += 2
                else:
                    while idx < len(data) and data[idx] != 0:
                        idx += data[idx] + 1
                    idx += 1
                
                type_val = struct.unpack(">H", data[idx:idx+2])[0]
                idx += 8  # 跳过类型、类别、TTL
                data_len = struct.unpack(">H", data[idx:idx+2])[0]
                idx += 2
                
                if type_val == 1 and data_len == 4:  # A记录
                    ip = ".".join(str(b) for b in data[idx:idx+4])
                    print(f"A记录: {ip}")
                idx += data_len
except socket.timeout:
    print("查询超时")
