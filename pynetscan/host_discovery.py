from scapy.all import ARP, Ether, srp, ICMP, IP, sr1
from scapy.all import conf
conf.verb = 0
import ipaddress

def _icmp_ping(ip, timeout=1):
    pkt = IP(dst=str(ip))/ICMP()
    resp = sr1(pkt, timeout=timeout, verbose=False)
    return resp is not None

def discover(subnet):
    # 如果是 loopback/32，直接返回
    net = ipaddress.ip_network(subnet, strict=False)
    if net.num_addresses == 1 and str(net.network_address) == "127.0.0.1":
        return ["127.0.0.1"]

    live_hosts = set()
    # 1) ARP 扫描本地局域网
    if net.prefixlen >= 24 and not net.is_loopback:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet)
        ans, _ = srp(packet, timeout=2, verbose=False)
        live_hosts.update(rcv.psrc for _, rcv in ans)

    # 2) 对剩余地址做 ICMP Ping
    for ip in net.hosts():
        if str(ip) not in live_hosts and _icmp_ping(ip):
            live_hosts.add(str(ip))

    return sorted(live_hosts)