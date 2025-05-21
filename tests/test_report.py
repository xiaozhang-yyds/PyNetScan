import json
from pathlib import Path
import os
import shutil
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

def test_generate_html(tmp_path, scan_data, monkeypatch):
    # 准备模板
    templates_dir = tmp_path / 'templates'
    templates_dir.mkdir(exist_ok=True)
    
    # 创建简单测试模板，明确指定UTF-8编码写入
    template = """<!DOCTYPE html><html><body>目标: {{ scan_info.target }}
    {% for host in hosts %}<div>{{ host.ip }}</div>{% endfor %}</body></html>"""
    (templates_dir / 'report.html.j2').write_text(template, encoding='utf-8')
    
    # 设置测试的工作目录
    os.chdir(tmp_path)
    monkeypatch.setattr(Path, 'cwd', lambda: tmp_path)
    
    # 生成报告
    out_file = generate(scan_data, fmt="html")
    assert out_file.endswith(".html")
    
    # 检查文件是否存在
    report_path = tmp_path / out_file
    assert report_path.exists()
    
    # 明确指定UTF-8编码读取文件
    content = report_path.read_text(encoding='utf-8')
    assert "1.2.3.4" in content

def test_generate_json(tmp_path, scan_data):
    out = generate(scan_data, fmt="json")
    data = json.loads(Path(out).read_text())
    assert data["hosts"][0]["ip"] == "1.2.3.4"
