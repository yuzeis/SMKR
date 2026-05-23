"""查找游戏进程的活动连接。"""
from __future__ import annotations

import time
import psutil

TARGET_PROCESS_NAME = "NRC-Win64-Shipping.exe"
GAME_SERVER_PORT = 8195


def find_process_pid(process_name: str = TARGET_PROCESS_NAME) -> int | None:
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if proc.info["name"] == process_name:
                return int(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None


def get_established_connections(pid: int, port: int = GAME_SERVER_PORT) -> list[tuple[str, int]]:
    try:
        proc = psutil.Process(pid)
        conns = proc.net_connections(kind="tcp")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []
    out: list[tuple[str, int]] = []
    for conn in conns:
        if conn.status == "ESTABLISHED" and conn.raddr and conn.raddr.port == port:
            out.append((conn.raddr.ip, conn.raddr.port))
    return out


def wait_for_game_server(
    timeout: float = 60.0,
    *,
    process_name: str = TARGET_PROCESS_NAME,
    port: int = GAME_SERVER_PORT,
) -> tuple[str, int] | None:
    start = time.time()
    while time.time() - start < timeout:
        pid = find_process_pid(process_name)
        if pid:
            conns = get_established_connections(pid, port)
            if conns:
                return conns[0]
        time.sleep(0.5)
    return None
