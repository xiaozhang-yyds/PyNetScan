# PyNetScan 安装与使用说明文档

## 一、系统要求

- **操作系统**：Windows 10 / 11 x64
- **Python**：3.10 - 3.12（推荐使用虚拟环境）
- **依赖组件**：
  - Nmap（用于操作系统识别）
  - Npcap（支持原始包捕获）
  - WeasyPrint（如需生成 PDF 报告）

------

## 二、安装步骤

### 1. 安装系统依赖

- 安装 [Nmap](https://nmap.org/download.html)，并将其加入环境变量 PATH。

- 安装 [Npcap](https://npcap.com/)，安装时勾选 WinPcap 兼容模式。

- 如需使用 PDF 报告，使用 [MSYS2](https://www.msys2.org/) 安装 GTK + Pango：

  ```bash
  pacman -S mingw-w64-x86_64-pango
  setx WEASYPRINT_DLL_DIRECTORIES "C:\\msys64\\mingw64\\bin"
  ```

### 2. 克隆项目与依赖安装

```bash
# 下载项目
$ git clone https://github.com/xiaozhang-yyds/PyNetScan.git
$ cd PyNetScan

# 创建虚拟环境
$ python -m venv venv
# 推荐使用uv创建
$ uv venv --python >= 3.10
$ .\venv\Scripts\activate

# 安装依赖
(venv) $ pip install -r requirements.txt
```

## 三、使用方法

### 命令格式

```bash
python main.py -t <目标IP或网段> [选项]
```

### 参数

| 参数           | 含义                                 |
| -------------- | ------------------------------------ |
| `-t`           | 目标 IP 或 CIDR（如 192.168.1.0/24） |
| `-p`           | 扫描端口范围（默认 1-1024）          |
| `--os`         | 启用操作系统指纹识别                 |
| `--vuln-api`   | 使用 Vulners API 进行漏洞匹配        |
| `--vuln-local` | 执行本地 PoC 脚本扫描                |
| `--vuln`       | 同时启用 API + 本地脚本              |
| `--report`     | 报告格式：html / pdf / json          |
| `-v`           | 显示扫描详情                         |

### 示例

```bash
# 示例 1：扫描全网段常见端口并生成 PDF 报告
python main.py -t 192.168.3.0/24 --os --vuln --report pdf

# 示例 2：本地测试漏洞脚本
python main.py -t 127.0.0.1/32 -p 7001 --vuln-local -v
```

------

## 四、生成报告

- HTML 格式：默认输出 report.html，可直接浏览器查看
- PDF 格式：需配置 GTK/Pango，输出 report.pdf
- JSON 格式：输出 report.json，结构化数据可供二次处理

------

## 五、错误排查

| 情况          | 排查建议                                 |
| ------------- | ---------------------------------------- |
| 未发现主机    | 确认网络连接 / 检查目标网段              |
| OS 探测失败   | 确认 Nmap 是否安装、路径是否加入环境变量 |
| PDF 报告报错  | 检查 WeasyPrint 安装与 DLL 配置          |
| API 返回 0 条 | 检查关键词拼写或配置 Vulners API-KEY     |

------

