import time
from scapy.all import IP, TCP, UDP, ICMP, sr1, send


def tcp_syn_scan(ip, port, timeout):
    start_time = time.time()
    pkt = IP(dst=ip) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    elapsed = (time.time() - start_time) * 1000

    if resp and resp.haslayer(TCP):
        if resp[TCP].flags == 0x12:  # SYN-ACK
            send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=0)
            return True, elapsed
    return False, elapsed


def udp_scan(ip, port, timeout):
    start_time = time.time()
    pkt = IP(dst=ip) / UDP(dport=port)
    resp = sr1(pkt, timeout=timeout, verbose=0)
    elapsed = (time.time() - start_time) * 1000

    if resp is None:
        return True, elapsed
    elif resp.haslayer(UDP):
        return True, elapsed
    elif resp.haslayer(ICMP):
        if int(resp[ICMP].type) == 3 and int(resp[ICMP].code) == 3:
            return False, elapsed
    return False, elapsed