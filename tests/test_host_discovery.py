import os, sys, socket, ipaddress
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from pynetscan.host_discovery import discover

def test_discover_loopback():
    assert "127.0.0.1" in discover("127.0.0.1/32")

def test_discover_local_adapter():
    # 获取本机首个非回环 IPv4 地址
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    cidr = str(ipaddress.IPv4Address(local_ip)) + "/32"
    assert local_ip in discover(cidr)
