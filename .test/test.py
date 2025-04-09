import socket
s = socket.socket()
s.connect(("39.156.66.10", 80))
s.send(b"GET / HTTP/1.1\r\nHost: baidu.com\r\nConnection: close\r\n\r\n")
print(s.recv(4096))