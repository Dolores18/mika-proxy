# gen_dns_query.py
import dns.message
import sys

q = dns.message.make_query("example.com", "A")
with open("dns_query.bin", "wb") as f:
    f.write(q.to_wire())
