import json
from pathlib import Path
import pytest
from pynetscan.report import generate

@pytest.fixture
def scan_data(tmp_path):
    return {
      "scan_info": {"target": "1.2.3.0/24"},
      "hosts": [
        {"ip": "1.2.3.4", "open_ports": [80], "os": "Linux", "vulns": ["CVE-1"]},
      ]
    }

def test_generate_html(tmp_path, scan_data):
    cwd = Path.cwd()
    Path.cwd = lambda *args, **kw: tmp_path  # 强制模板相对路径到 tmp_path
    out = generate(scan_data, fmt="html")
    assert out.endswith(".html")
    content = tmp_path.joinpath(out).read_text()
    assert "1.2.3.4" in content
    assert "CVE-1" in content

def test_generate_json(tmp_path, scan_data):
    out = generate(scan_data, fmt="json")
    data = json.loads(Path(out).read_text())
    assert data["hosts"][0]["ip"] == "1.2.3.4"
