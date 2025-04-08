#!/usr/bin/env python3
import socket
import time
import sys
import threading

# 百度的真实 IP 地址
BAIDU_IP = "39.156.66.10"
PORT = 80

def print_with_timestamp(message):
    """打印带时间戳的消息"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def receive_with_timeout(sock, timeout=10):
    """带超时的接收函数"""
    sock.settimeout(timeout)
    start_time = time.time()
    response = b""
    
    try:
        print_with_timestamp(f"设置接收超时: {timeout}秒")
        while True:
            try:
                data = sock.recv(4096)
                if not data:
                    print_with_timestamp("服务器关闭了连接")
                    break
                
                elapsed = time.time() - start_time
                print_with_timestamp(f"收到数据包 ({elapsed:.2f}秒): {len(data)}字节")
                
                # 显示接收到的数据
                try:
                    print_with_timestamp(f"接收到的数据: \n{data.decode('utf-8', errors='replace')[:500]}")
                    if len(data) > 500:
                        print("...")
                except:
                    print_with_timestamp(f"接收到二进制数据: {data[:100].hex()}")
                
                response += data
                
                # 如果已经接收到完整HTTP响应，可以提前返回
                if b"\r\n\r\n" in response and (b"Content-Length:" in response or b"content-length:" in response):
                    header_end = response.find(b"\r\n\r\n") + 4
                    headers = response[:header_end].decode('utf-8', errors='ignore')
                    
                    for line in headers.split("\r\n"):
                        if line.lower().startswith("content-length:"):
                            try:
                                content_length = int(line.split(":", 1)[1].strip())
                                if len(response) >= header_end + content_length:
                                    print_with_timestamp("已接收完整HTTP响应")
                                    return response
                            except:
                                pass
                
            except socket.timeout:
                if response:
                    print_with_timestamp(f"接收超时，但已收到 {len(response)} 字节的响应")
                    return response
                raise
    except socket.timeout:
        if response:
            print_with_timestamp(f"总体接收超时，返回已收到的 {len(response)} 字节")
            return response
        print_with_timestamp("接收超时，未收到任何数据")
        raise
        
    return response

def connect_with_custom_source_port(ip, port, source_port=None):
    """创建TCP连接，可以指定源端口"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    if source_port:
        try:
            sock.bind(('0.0.0.0', source_port))
            print_with_timestamp(f"绑定到源端口: {source_port}")
        except OSError:
            print_with_timestamp(f"无法绑定到端口 {source_port}，使用随机端口")
    
    sock.settimeout(5)  # 5秒连接超时
    
    try:
        print_with_timestamp(f"连接到 {ip}:{port}...")
        connect_start = time.time()
        sock.connect((ip, port))
        connect_time = time.time() - connect_start
        
        print_with_timestamp(f"TCP连接建立成功 ({connect_time:.2f}秒)")
        print_with_timestamp(f"本地地址: {sock.getsockname()}")
        print_with_timestamp(f"远程地址: {sock.getpeername()}")
        
        return sock
    except Exception as e:
        sock.close()
        raise e

def send_http_request(ip=BAIDU_IP, port=PORT, source_port=None):
    """发送HTTP请求到指定IP"""
    print_with_timestamp(f"准备发送HTTP请求到 {ip}:{port}")
    
    try:
        # 1. 建立TCP连接
        sock = connect_with_custom_source_port(ip, port, source_port)
        
        # 2. 构造HTTP请求
        http_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: www.baidu.com\r\n"
            f"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36\r\n"
            f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
            f"Accept-Language: zh-CN,zh;q=0.9,en;q=0.8\r\n"
            f"Accept-Encoding: identity\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        
        print_with_timestamp(f"发送HTTP请求:\n{http_request}")
        
        # 3. 发送请求
        bytes_sent = sock.send(http_request.encode())
        print_with_timestamp(f"发送了 {bytes_sent} 字节")
        
        # 4. 接收响应
        try:
            print_with_timestamp("等待服务器响应...")
            response = receive_with_timeout(sock, 10)
            
            if response:
                # 尝试将响应解析为HTTP格式
                try:
                    header_end = response.find(b"\r\n\r\n")
                    if header_end > 0:
                        headers = response[:header_end].decode('utf-8', errors='ignore')
                        body = response[header_end+4:]
                        
                        print_with_timestamp("\n--- HTTP响应头 ---")
                        for line in headers.split("\r\n"):
                            print(line)
                        
                        print_with_timestamp(f"\n--- HTTP响应体 (前500字节) ---")
                        try:
                            body_text = body[:500].decode('utf-8', errors='replace')
                            print(body_text)
                            if len(body) > 500:
                                print("...")
                        except:
                            print(f"二进制内容: {body[:100].hex()}")
                    else:
                        print_with_timestamp("接收到非标准HTTP响应")
                except Exception as e:
                    print_with_timestamp(f"解析响应时出错: {e}")
            
        except socket.timeout as e:
            print_with_timestamp(f"接收响应超时: {e}")
        
    except Exception as e:
        print_with_timestamp(f"错误: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except:
            pass
        sock.close()
        print_with_timestamp("连接已关闭")

def main():
    """主函数"""
    # 检查命令行参数
    if len(sys.argv) > 1:
        try:
            source_port = int(sys.argv[1])
            print_with_timestamp(f"将使用指定的源端口: {source_port}")
            send_http_request(source_port=source_port)
        except ValueError:
            print_with_timestamp(f"无效的端口号: {sys.argv[1]}")
            print_with_timestamp("使用: python real_ip.py [源端口]")
    else:
        # 默认不指定源端口
        send_http_request()

if __name__ == "__main__":
    main()
