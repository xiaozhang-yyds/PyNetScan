import importlib, pkgutil, requests, os, json
from pathlib import Path

SCRIPTS_DIR = Path(__file__).with_suffix('').parent / "vuln_scripts"

VULNERS_URL = "https://vulners.com/api/v3/burp/software/"
LUCENE_URL = "https://vulners.com/api/v3/search/lucene/"


# def query_vulnerabilities(os_name: str):
#     print(f"[DEBUG] querying Vulners for `{os_name}`")    
#     try:
#         r = requests.get(VULNERS_URL, params={"software": os_name}, timeout=10)
#         print("[DEBUG] status:", r.status_code)
#         data = r.json()
#         print("[DEBUG] raw data keys:", data.keys())
#         hits = data.get("data", {}).get("search", [])
#         print(f"[DEBUG] found {len(hits)} hits")
#         return [
#             {"cve": item["cve"], "detail": item.get("title", "")}
#             for item in hits
#         ]
#     except Exception as e:
#         print("[ERROR] api exception:", e)
#     return []

def query_vulnerabilities(os_name: str):
    
    if not os_name:
        return []

    api_key = os.getenv("VULNERS_API_KEY")
    params = {"query": os_name, "size": 50}
    headers = {}
    if api_key:
        headers["X-Api-Key"] = api_key

    try:
        resp = requests.get(LUCENE_URL, params=params, headers=headers, timeout=10)
        resp.raise_for_status()
        hits = resp.json().get("data", {}).get("search", [])

        results = []
        for item in hits:
            src = item.get("_source", {})
            # cvelist 是一个 CVE 列表，可能包含多个条目
            for cve in src.get("cvelist", []):
                title = src.get("title", "")
                results.append({"cve": cve, "detail": title})
        # 去重，保持原顺序
        seen = set()
        unique = []
        for v in results:
            if v["cve"] not in seen:
                seen.add(v["cve"])
                unique.append(v)
        return unique

    except Exception as e:
        print(f"[ERROR] Vulners Lucene API failed: {e}")
        return []

# ---------- 本地脚本 ----------
SCRIPTS_DIR = Path(__file__).with_suffix('').parent / "vuln_scripts"
def run_local_scripts(host_data):
    findings = []
    if not SCRIPTS_DIR.exists():
        return findings

    for modinfo in pkgutil.iter_modules([str(SCRIPTS_DIR)]):
        module = importlib.import_module(
            f"pynetscan.vuln_scripts.{modinfo.name}"
        )
        for port in host_data["open_ports"]:
            try:
                res = module.run(host_data["ip"], port)   # 约定脚本有 run()
                if res:
                    findings.append({"cve": modinfo.name, "detail": res})
            except Exception:
                continue
    return findings

# ---------- 统一入口 ----------
def scan(host_data, use_api=True, use_local=True):
    vulns = []
    if use_api:
        vulns.extend(query_vulnerabilities(host_data.get("os", "")))
    if use_local:
        vulns.extend(run_local_scripts(host_data))
    # 去重
    uniq = {}
    for v in vulns:
        uniq.setdefault(v["cve"], v)
    return list(uniq.values())