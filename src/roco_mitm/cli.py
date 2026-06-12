from __future__ import annotations

import argparse
import asyncio
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path

from .paths import config_dir, logs_dir


DEFAULT_WEB_PORT = 18196
DEFAULT_PROXY_PORT = 18195
DEFAULT_PROXY_HOST = "0.0.0.0"
DEFAULT_WEB_HOST = "127.0.0.1"


USAGE = """Unified entry point.

Usage:
  python -m roco_mitm
  python -m roco_mitm web
  python -m roco_mitm proxy
  python -m roco_mitm divert [--run]
  python -m roco_mitm selftest

Installed console script:
  roco-mitm web
"""


def _install_event_loop_policy() -> None:
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _usage() -> None:
    print(USAGE)


async def _run_web(args: argparse.Namespace) -> None:
    from aiohttp import web as aioweb

    from .proxy import server as proxy_mod
    from .web.app import AppContext, build_app

    package_root = Path(__file__).resolve().parent
    cfg_dir = config_dir()
    cfg_dir.mkdir(parents=True, exist_ok=True)

    log_dir = logs_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "proxy.log"
    fh = open(log_path, "a", encoding="utf-8", buffering=1)
    fh.write(f"\n==== web start {time.strftime('%Y-%m-%d %H:%M:%S')} pid={os.getpid()} ====\n")

    ctx = AppContext(package_root=package_root, config_dir=cfg_dir)
    ctx.set_http_service(host=args.web_host, port=args.web_port)
    loop = asyncio.get_running_loop()
    ctx.bind_loop(loop)
    ctx.install_proxy_hooks()

    def _log_to_file(level: str, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        fh.write(f"[{ts}][{level}] {msg}\n")

    orig_log = proxy_mod.LOG_HOOK

    def _combined_log(level: str, msg: str) -> None:
        _log_to_file(level, msg)
        if orig_log is not None:
            try:
                orig_log(level, msg)
            except Exception:
                pass

    proxy_mod.install_hooks(log=_combined_log)

    app = build_app(ctx)
    runner = aioweb.AppRunner(app)
    await runner.setup()
    site = aioweb.TCPSite(runner, args.web_host, args.web_port)
    try:
        await site.start()
    except OSError as exc:
        print(f"\n[!] Web port {args.web_host}:{args.web_port} is unavailable: {exc}", file=sys.stderr)
        print("    Use --web-port to choose another port.", file=sys.stderr)
        sys.exit(1)

    url = f"http://{args.web_host}:{args.web_port}/"
    _print_banner(url, args, log_path)

    if not args.no_browser:
        threading.Timer(0.6, lambda: _open_browser(url)).start()

    async def _on_proxy_ready() -> None:
        print(f"[ok] MITM proxy listening on {args.listen_host}:{args.listen_port}")
        print(f"[ok] Web UI: {url}")
        print(f"[ok] Log: {log_path}")

    try:
        await proxy_mod.serve(
            args.upstream_ip,
            args.upstream_port,
            args.listen_host,
            args.listen_port,
            on_ready=_on_proxy_ready,
        )
    finally:
        await runner.cleanup()
        fh.close()


def _print_banner(url: str, args: argparse.Namespace, log_path: Path) -> None:
    upstream = f"{args.upstream_ip}:{args.upstream_port}" if args.upstream_ip else "auto via runtime/conn_map.json or process watcher"
    print()
    print("=" * 62)
    print("RocoMITMServer Ver2.3 Untergangsgeweiht (RKMS) - Web Mode")
    print("=" * 62)
    print(f"Web UI : {url}")
    print(f"Proxy  : {args.listen_host}:{args.listen_port}")
    print(f"Upstream: {upstream}")
    print(f"Log    : {log_path}")
    print("=" * 62)
    print()


def _open_browser(url: str) -> None:
    try:
        webbrowser.open_new_tab(url)
    except Exception as exc:
        print(f"[warn] Failed to open browser automatically: {exc}; visit {url}")


def _run_selftest() -> int:
    from . import selftest

    selftest.run_all()
    return 0


def _run_proxy_only(argv: list[str]) -> int:
    from .proxy.server import main as run

    sys.argv = ["roco-mitm:proxy", *argv]
    run()
    return 0


def _run_divert(argv: list[str]) -> int:
    from .divert.proc_divert import main as run

    sys.argv = ["roco-mitm:divert", *argv]
    return int(run() or 0)


def _build_web_parser(prog: str = "roco-mitm web") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=prog, description="Start Web UI + MITM proxy")
    parser.add_argument("--web-host", default=DEFAULT_WEB_HOST, help=f"Web UI host (default {DEFAULT_WEB_HOST})")
    parser.add_argument("--web-port", type=int, default=DEFAULT_WEB_PORT, help=f"Web UI port (default {DEFAULT_WEB_PORT})")
    parser.add_argument("--listen-host", default=DEFAULT_PROXY_HOST, help="Proxy listen host")
    parser.add_argument("--listen-port", type=int, default=DEFAULT_PROXY_PORT, help="Proxy listen port")
    parser.add_argument("--upstream-ip", default=None, help="Upstream game server IP; omit for auto-detection")
    parser.add_argument("--upstream-port", type=int, default=8195, help="Upstream game server port (default 8195)")
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically")
    return parser


def main(argv: list[str] | None = None) -> int:
    _install_event_loop_policy()
    args_in = list(sys.argv[1:] if argv is None else argv)
    cmd = args_in[0] if args_in else "web"
    rest = args_in[1:] if args_in else []

    if cmd in ("-h", "--help", "help"):
        _usage()
        return 0

    if cmd == "selftest":
        return _run_selftest()
    if cmd in ("divert", "proc_divert"):
        return _run_divert(rest)
    if cmd == "proxy":
        return _run_proxy_only(rest)

    if cmd in ("web", "web-ui"):
        parsed = _build_web_parser().parse_args(rest)
    else:
        parsed = _build_web_parser(prog="roco-mitm").parse_args(args_in)

    try:
        asyncio.run(_run_web(parsed))
    except KeyboardInterrupt:
        print("\n[bye] Ctrl-C received, exiting.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
