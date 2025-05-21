from pynetscan.vuln_scan import query_vulnerabilities
res = query_vulnerabilities("OpenSSL")
print("Found", len(res), "vulns")
for v in res[:5]:
    print(" -", v["cve"], "|", v["detail"][:60])