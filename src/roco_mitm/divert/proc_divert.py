"""WinDivert 重定向器。"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from pathlib import Path

import psutil

from ..paths import cache_dir, conn_map_path, project_root
from .connection_watcher import TARGET_PROCESS_NAME, GAME_SERVER_PORT, find_process_pid

LOCAL_PROXY_PORT = 18195
CONN_MAP_PATH = conn_map_path()


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_elevated(argv: list[str]) -> int:
    if os.name != "nt":
        raise RuntimeError("WinDivert 需要管理员权限，当前平台不支持 UAC 自动提权")
    root = project_root()
    launcher = _write_elevated_launcher(root, argv)
    params = subprocess.list2cmdline(["/d", "/k", str(launcher)])
    rc = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        "cmd.exe",
        params,
        str(root),
        1,
    )
    if rc <= 32:
        raise RuntimeError(f"UAC 提权启动失败，ShellExecuteW 返回 {rc}")
    print("[i] 已请求 UAC 提权启动 WinDivert；请在弹窗中确认。")
    return 0


def _write_elevated_launcher(root: Path, argv: list[str]) -> Path:
    launcher = cache_dir() / "run_divert_elevated.cmd"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    python_cmd = subprocess.list2cmdline([sys.executable, "-m", "roco_mitm", "divert", *argv])
    text = "\r\n".join(
        [
            "@echo off",
            "chcp 65001 >nul",
            "title RKMS Divert",
            f'cd /d "{root}"',
            f'set "PYTHONPATH={root / "src"};%PYTHONPATH%"',
            python_cmd,
            "if errorlevel 1 (",
            "  echo.",
            "  echo [ERROR] WinDivert redirector exited with error.",
            "  pause",
            ")",
            "",
        ]
    )
    launcher.write_text(text, encoding="utf-8")
    return launcher


def local_lan_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


class ProcDivert:
    def __init__(self, self_pid: int, redirect_host: str | None = None):
        self.self_pid = self_pid
        self.redirect_host = redirect_host or local_lan_ip()
        self.target_pid_cache: int | None = None
        self.last_refresh = 0.0
        self.endpoint_pid_cache: OrderedDict[tuple[str, int], tuple[int | None, float]] = OrderedDict()
        self.endpoint_cache_ttl = 1.0
        self.endpoint_last_scan = 0.0
        self.endpoint_scan_interval = 0.5
        self.endpoint_cache_limit = 4096
        self.conn_map: OrderedDict[tuple[str, int], tuple[str, int, float]] = OrderedDict()
        self.conn_map_lock = threading.Lock()
        self.conn_map_limit = 4096
        self.conn_map_dirty = False
        self.conn_map_last_persist = 0.0
        self.conn_map_flush_interval = 0.5
        self.conn_map_refresh_persist_interval = 30.0

    def get_target_pid(self) -> int | None:
        now = time.time()
        if now - self.last_refresh > 2.0 or self.target_pid_cache is None:
            self.target_pid_cache = find_process_pid(TARGET_PROCESS_NAME)
            self.last_refresh = now
        return self.target_pid_cache

    def _prune_endpoint_cache(self, now: float) -> None:
        stale = [ep for ep, (_, ts) in self.endpoint_pid_cache.items() if now - ts > self.endpoint_cache_ttl]
        for ep in stale:
            self.endpoint_pid_cache.pop(ep, None)

    def _refresh_endpoint_cache(self, target_pid: int | None) -> None:
        now = time.time()
        self._prune_endpoint_cache(now)
        if now - self.endpoint_last_scan < self.endpoint_scan_interval:
            return
        self.endpoint_last_scan = now
        if target_pid is None:
            return
        try:
            conns = psutil.Process(target_pid).net_connections(kind="tcp")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
            return
        for conn in conns:
            if not conn.laddr:
                continue
            self.endpoint_pid_cache[(conn.laddr.ip, conn.laddr.port)] = (target_pid, now)
        while len(self.endpoint_pid_cache) > self.endpoint_cache_limit:
            self.endpoint_pid_cache.popitem(last=False)

    def get_packet_owner_pid(self, local_addr: str, local_port: int) -> int | None:
        ep = (local_addr, local_port)
        now = time.time()
        cached = self.endpoint_pid_cache.get(ep)
        if cached and now - cached[1] <= self.endpoint_cache_ttl:
            return cached[0]
        self._refresh_endpoint_cache(self.get_target_pid())
        cached = self.endpoint_pid_cache.get(ep)
        return cached[0] if cached else None

    def _remember_conn(self, cli_ip, cli_port, orig_ip, orig_port):
        with self.conn_map_lock:
            key = (cli_ip, cli_port)
            now = time.time()
            old = self.conn_map.get(key)
            self.conn_map[key] = (orig_ip, orig_port, now)
            changed = (
                old is None
                or old[0] != orig_ip
                or old[1] != orig_port
                or now - old[2] > self.conn_map_refresh_persist_interval
            )
            while len(self.conn_map) > self.conn_map_limit:
                self.conn_map.popitem(last=False)
                changed = True
            if changed:
                self.conn_map_dirty = True
                self._persist_conn_map_locked(force=True)

    def _lookup_conn(self, cli_ip, cli_port):
        with self.conn_map_lock:
            e = self.conn_map.get((cli_ip, cli_port))
            return (e[0], e[1]) if e else None

    def _cleanup_conn_map(self):
        while True:
            time.sleep(30)
            now = time.time()
            with self.conn_map_lock:
                stale = [k for k, v in self.conn_map.items() if now - v[2] > 300]
                for k in stale:
                    del self.conn_map[k]
                if stale:
                    self.conn_map_dirty = True
                    self._persist_conn_map_locked(force=True)
                else:
                    self._persist_conn_map_locked()

    def _persist_conn_map_locked(self, *, force: bool = False):
        now = time.time()
        if not self.conn_map_dirty:
            return
        if not force and now - self.conn_map_last_persist < self.conn_map_flush_interval:
            return
        CONN_MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            f"{ip}:{port}": {"orig_ip": oip, "orig_port": op, "ts": ts}
            for (ip, port), (oip, op, ts) in self.conn_map.items()
        }
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        tmp_path = CONN_MAP_PATH.with_suffix(CONN_MAP_PATH.suffix + ".tmp")
        try:
            tmp_path.write_text(text, encoding="utf-8")
            os.replace(tmp_path, CONN_MAP_PATH)
        except PermissionError:
            time.sleep(0.05)
            tmp_path.write_text(text, encoding="utf-8")
            os.replace(tmp_path, CONN_MAP_PATH)
        self.conn_map_dirty = False
        self.conn_map_last_persist = now

    def run(self):
        try:
            import pydivert
        except ImportError as exc:
            raise RuntimeError("pydivert 未安装，无法启用 WinDivert") from exc
        threading.Thread(target=self._cleanup_conn_map, daemon=True).start()
        filter_str = (
            f"tcp and ("
            f"(outbound and tcp.DstPort == {GAME_SERVER_PORT}) or "
            f"(outbound and tcp.SrcPort == {LOCAL_PROXY_PORT})"
            f")"
        )
        print(f"[*] self_pid={self.self_pid}")
        print(f"[*] redirect_host={self.redirect_host}")
        print(f"[*] filter={filter_str}")
        with pydivert.WinDivert(filter_str) as wd:
            for pkt in wd:
                if pkt.dst_port == GAME_SERVER_PORT:
                    owner = self.get_packet_owner_pid(pkt.src_addr, pkt.src_port)
                    if owner == self.self_pid:
                        wd.send(pkt)
                        continue
                    if owner == self.get_target_pid():
                        self._remember_conn(pkt.src_addr, pkt.src_port, pkt.dst_addr, pkt.dst_port)
                        pkt.dst_addr = self.redirect_host
                        pkt.dst_port = LOCAL_PROXY_PORT
                        pkt.recalculate_checksums()
                        wd.send(pkt)
                    else:
                        wd.send(pkt)
                elif pkt.src_port == LOCAL_PROXY_PORT:
                    m = self._lookup_conn(pkt.dst_addr, pkt.dst_port)
                    if m:
                        pkt.src_addr = m[0]
                        pkt.src_port = m[1]
                        pkt.recalculate_checksums()
                    wd.send(pkt)
                else:
                    wd.send(pkt)


def main() -> int:
    parser = argparse.ArgumentParser(description="Roco MITM WinDivert redirector")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--redirect-host", default=None)
    args = parser.parse_args()

    if args.run and not is_admin():
        return relaunch_elevated(sys.argv[1:])

    d = ProcDivert(self_pid=os.getpid(), redirect_host=args.redirect_host)
    print(f"TARGET_PROCESS_NAME={TARGET_PROCESS_NAME}")
    print(f"GAME_SERVER_PORT={GAME_SERVER_PORT}")
    print(f"LOCAL_PROXY_PORT={LOCAL_PROXY_PORT}")
    print(f"REDIRECT_HOST={d.redirect_host}")
    print(f"target_pid={d.get_target_pid()}")
    if not args.run:
        print("[!] WinDivert 默认不启动。确认环境后使用 --run。")
        return 0
    d.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
