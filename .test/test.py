import socket

def fetch_url(host, port=80, path="/"):
    s = socket.socket()
    try:
        s.connect((host, port))
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
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

# 使用示例
response = fetch_url("baidu.com")
print(response.decode())