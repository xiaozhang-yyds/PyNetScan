# -*- encoding: utf-8 -*-
import sys
import requests


headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:49.0) Gecko/20100101 Firefox/49.0"}

def islive(ip, port):
    url = f'http://{ip}:{port}/uddiexplorer/'
    url1 = f'https://{ip}:{port}/uddiexplorer/'
    error = ['404', 'Not Found', '找不到', '安全狗', '无权访问', '403']
    try:
        requests.packages.urllib3.disable_warnings()
        r = requests.get(url, headers=headers, verify=False)
        for e in error:
            if r.status_code == 200 and e not in r.text:
                return f"{ip}:{port} vulnerable to CVE-2014-4210"
    except Exception:
        requests.packages.urllib3.disable_warnings()
        try:
            r = requests.get(url1, headers=headers, verify=False)
            for e in error:
                if r.status_code == 200 and e not in r.text:
                    return f"{ip}:{port} vulnerable to CVE-2014-4210"
        except Exception:
            pass
    return None

def run(ip, port):
    """
    PyNetScan 约定接口：接收 ip(str) 和 port(int)，
    返回非空字符串即视为发现漏洞，否则返 None。
    """
    try:
        return islive(ip, port)
    except Exception:
        return None