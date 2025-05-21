import socket
import concurrent.futures

def tcp_connect_scan(host, ports, timeout=1):
    open_ports = []
    def scan(port):
        try:
            with socket.create_connection((host, port), timeout):
                return port
        except:
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(scan, ports)
    return [p for p in results if p]