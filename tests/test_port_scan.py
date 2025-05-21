import socket, threading, contextlib, random, os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from pynetscan.port_scan import tcp_connect_scan

@pytest.fixture
def temp_tcp_service():
    """启动一个临时 TCP 监听服务，yield 真实开放端口号。"""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))          # 由 OS 选空闲端口
    port = srv.getsockname()[1]
    srv.listen()

    def _serve():
        with contextlib.suppress(Exception):
            conn, _ = srv.accept()
            conn.close()
        srv.close()

    threading.Thread(target=_serve, daemon=True).start()
    return port

def _pick_closed_port(exclude: int) -> int:
    """找一个与 open_port 不冲突且确实关闭的端口。"""
    while True:
        port = random.randint(50_000, 60_000)
        if port == exclude:
            continue
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)):
                return port

def test_tcp_connect_scan(temp_tcp_service):
    open_port = temp_tcp_service
    closed_port = _pick_closed_port(open_port)

    found = tcp_connect_scan("127.0.0.1", [open_port, closed_port], timeout=0.8)

    # 断言：只那一个端口是开的
    assert found == [open_port]
