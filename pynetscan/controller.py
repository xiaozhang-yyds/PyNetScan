import argparse
import ipaddress
import json
import shutil
import sys
from importlib.util import find_spec

# 导入各功能模块
from . import host_discovery, port_scan, os_detect, vuln_scan, report

# ----------★ 自定义 ArgumentParser，让错误提示更友好 ★ ----------
class FriendlyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write(f"\033[31m[!] 参数错误：{message}\033[0m\n\n")
        self.print_help(sys.stderr)
        sys.exit(2)

# ----------★ 构建 CLI 参数解析器 ----------
def build_parser() -> argparse.ArgumentParser:
    p = FriendlyParser(
        prog="PyNetScan",
        description="PyNetScan - 轻量级网络安全扫描器",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-t", "--target", required=False,
                   help="目标 IP 或 CIDR，如 192.168.1.0/24")
    p.add_argument("-p", "--ports", default="1-1024",
                   help="端口范围或列表，如 1-1024 或 22,80,443")
    p.add_argument("--os", action="store_true",
                   help="启用操作系统探测")
    p.add_argument("--vuln-api",   action="store_true",
                   help="仅在线 CVE 匹配")
    p.add_argument("--vuln-local", action="store_true",
                   help="仅本地脚本扫描")
    p.add_argument("--vuln",       action="store_true",
                   help="同时启用 API 和本地脚本扫描")
    p.add_argument("--report", choices=["html", "pdf", "json"],
                   default="html", help="报告格式")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="控制台实时输出扫描详情")
    return p

# ---------- 依赖检查与友好提示 ----------
def check_dependencies(want_pdf=False):
    # 1) Nmap：用于 OS 探测
    if not shutil.which("nmap"):
        sys.stderr.write(
            "\033[33m[!] 未检测到 Nmap，可执行文件未加入 PATH。\n"
            "    下载：https://nmap.org/download.html\n\033[0m"
        )
    # 2) Npcap 驱动（Windows）
    if sys.platform.startswith("win"):
        try:
            import wmi  # type: ignore
            c = wmi.WMI()
            drivers = [s for s in c.Win32_SystemDriver() if s.Name.lower().startswith("npcap")]
            if not drivers:
                raise Exception
        except Exception:
            sys.stderr.write(
                "\033[33m[!] 未检测到 Npcap 驱动，主机发现/半开放扫描可能受限。\n"
                "    下载：https://npcap.com  (安装时勾选 WinPcap 兼容模式)\n\033[0m"
            )
    # 3) PDF 依赖
    if want_pdf and find_spec("weasyprint") is None:
        sys.stderr.write(
            "\033[33m[!] 生成 PDF 需安装 WeasyPrint：\n"
            "    pip install weasyprint==65.*\n"
            "    并确保 GTK/Pango DLL 可用，参见文档。\n\033[0m"
        )

# ---------- 解析端口字符串 ----------
def parse_ports(port_str: str):
    ports = set()
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

# ---------- 主入口 ----------
def run():
    parser = build_parser()

    # 无任何参数 → 打印帮助并退出
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(0)

    args = parser.parse_args()

    # 检查关键依赖
    check_dependencies(want_pdf=(args.report == "pdf"))

    # 解析目标网段
    if not args.target:
        parser.error("必须指定目标，请使用 -t 或 --target 参数")
    try:
        network = ipaddress.ip_network(args.target, strict=False)
        targets = [str(ip) for ip in network.hosts()]
    except Exception as e:
        sys.stderr.write(f"\033[31m[!] 无效目标 '{args.target}': {e}\033[0m\n")
        sys.exit(1)

    # 决定漏洞扫描方式
    use_api   = args.vuln or args.vuln_api
    use_local = args.vuln or args.vuln_local

    # 建立结果结构
    scan_results = {
        "scan_info": {
            "target": args.target,
            "ports": args.ports,
            "os_detect": args.os,
            "vuln_api": use_api,
            "vuln_local": use_local
        },
        "hosts": []
    }

    def log(msg: str):
        if args.verbose:
            print(msg)

    # 主机发现
    print(f"[+] Discovering hosts in {args.target} ...")
    live_hosts = host_discovery.discover(args.target)
    if not live_hosts:
        print("\033[33m[!] 未发现存活主机，检查网络连接或目标范围。\033[0m")
        sys.exit(0)

    # 扫描流程
    for host_ip in live_hosts:
        print(f"[+] Scanning host: {host_ip}")
        host_data = {"ip": host_ip}

        # 端口扫描
        ports_list = parse_ports(args.ports)
        open_ports = port_scan.tcp_connect_scan(host_ip, ports_list)
        host_data["open_ports"] = open_ports
        log(f"    Open ports: {', '.join(map(str, open_ports)) or 'None'}")

        # OS 探测
        if args.os:
            os_name = os_detect.detect_os(host_ip)
            host_data["os"] = os_name
            log(f"    OS guess  : {os_name}")

        # 漏洞扫描
        if use_api or use_local:
            vulns = vuln_scan.scan(host_data, use_api=use_api, use_local=use_local)
            host_data["vulns"] = vulns
            log(f"    Vulns     : {', '.join(v['cve'] for v in vulns) or 'None'}")

        scan_results["hosts"].append(host_data)

    # 报告生成
    print("[+] Generating report...")
    output_path = report.generate(scan_results, args.report)
    print(f"[+] Report saved to {output_path}")

# 允许“python controller.py”直接运行
if __name__ == "__main__":
    run()