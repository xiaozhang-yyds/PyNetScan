import nmap

def detect_os(host):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=host, arguments='-O -Pn')
    try:
        return scanner[host]['osmatch'][0]['name']
    except:
        return "Unknown"