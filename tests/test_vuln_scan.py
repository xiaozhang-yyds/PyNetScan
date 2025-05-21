import pytest, types, sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from pynetscan.vuln_scan import scan

# —— 1) 构造假的 host_data（只含必需字段）
host = {"ip": "1.1.1.1", "open_ports": [7001], "os": "Windows"}

# —— 2) Monkeypatch 远程 API ——只返回一个 CVE
def fake_api(monkeypatch):
    monkeypatch.setattr(
        "pynetscan.vuln_scan.query_vulnerabilities",
        lambda os: [{"cve": "CVE-FAKE-API", "detail": "fake from api"}]
    )

# —— 3) Monkeypatch 本地脚本目录 ——创建一个内存脚本模块
def fake_local(monkeypatch):
    mod = types.ModuleType("pynetscan.vuln_scripts.CVE_FAKE_LOCAL")
    mod.run = lambda ip, port: "fake vuln msg"
    sys.modules[mod.__name__] = mod
    monkeypatch.setattr(
        "pkgutil.iter_modules",
        lambda paths: [types.SimpleNamespace(name="CVE_FAKE_LOCAL")]
    )

def test_api_only(monkeypatch):
    fake_api(monkeypatch)
    vulns = scan(host, use_api=True, use_local=False)
    assert [v["cve"] for v in vulns] == ["CVE-FAKE-API"]

def test_local_only(monkeypatch):
    fake_local(monkeypatch)
    vulns = scan(host, use_api=False, use_local=True)
    assert [v["cve"] for v in vulns] == ["CVE_FAKE_LOCAL"]

def test_api_and_local(monkeypatch):
    fake_api(monkeypatch); fake_local(monkeypatch)
    vulns = scan(host, use_api=True, use_local=True)
    ids = {v["cve"] for v in vulns}
    assert ids == {"CVE-FAKE-API", "CVE_FAKE_LOCAL"}
