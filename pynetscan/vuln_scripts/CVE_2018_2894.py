# -*- encoding: utf-8 -*-


import requests

VUL=['CVE-2018-2894']
headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:49.0) Gecko/20100101 Firefox/49.0"}

def islive(ip, port):
	url='http://' + str(ip)+':'+str(port)+'/ws_utc/resources/setting/options/general'
	url1='https://' + str(ip)+':'+str(port)+'/ws_utc/resources/setting/options/general'
	error=['404','Not Found','找不到','安全狗','无权访问','403']
	try:
		requests.packages.urllib3.disable_warnings()  # 禁 HTTPS 证书警告
		r = requests.get(url, headers=headers,verify=False)	 
		for e in error:
			if r.status_code==200 and e not in r.text:
				# print(str(ip) + '\t存在JAVA deserialization漏洞(CVE-2018-2894)')
				# a = ip+":7001:存在JAVA deserialization漏洞(CVE-2018-2894)"
				# return a
				return f"{ip}:{port} vulnerable to CVE-2018-2894"
		else:
			pass
	except:
		requests.packages.urllib3.disable_warnings()
		r = requests.get(url1, headers=headers,verify=False)	 
		for e in error:
			if r.status_code==200 and e not in r.text:
				# print(str(ur) + '\t存在JAVA deserialization漏洞(CVE-2018-2894)')
				# a = ur+":7001:存在JAVA deserialization漏洞(CVE-2018-2894)"
				# return a
				return f"{ip}:{port} vulnerable to CVE-2018-2894"

def run(ip, port):
    """
    PyNetScan 约定接口：接收 ip(str) 和 port(int)，
    返回非空字符串即视为发现漏洞，否则返 None。
    """
    try:
        return islive(ip, port)
    except Exception:
        return None