import socket
from scapy.all import IP, UDP, DNS, DNSQR, sr1

def guess_protocol(ip, port, proto, timeout):
    if proto == 'tcp':
        return guess_tcp_protocol(ip, port, timeout)
    elif proto == 'udp':
        return guess_udp_protocol(ip, port, timeout)
    return "-"

def guess_tcp_protocol(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.sendall(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
            data = s.recv(1024)
            if b"HTTP/" in data or b"Server:" in data:
                return "HTTP"
            msg = b"HELLO\r\n"
            s.sendall(msg)
            echo_data = s.recv(1024)
            if msg in echo_data:
                return "ECHO"
    except Exception:
        pass
    return "-"

def guess_udp_protocol(ip, port, timeout):
    try:
        pkt = IP(dst=ip)/UDP(dport=port)/DNS(rd=1, qd=DNSQR(qname="google.com"))
        resp = sr1(pkt, timeout=timeout, verbose=0)
        if resp and resp.haslayer(DNS) and resp[DNS].qr == 1:
            return "DNS"
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            msg = b"HELLO\r\n"
            s.sendto(msg, (ip, port))
            data, _ = s.recvfrom(1024)
            if msg in data:
                return "ECHO"
    except Exception:
        pass
    return "-"