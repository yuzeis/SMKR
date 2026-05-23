from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    override = os.environ.get("ROCO_MITM_ROOT")
    if override:
        return Path(override).expanduser().resolve()

    package_root = Path(__file__).resolve().parent
    if package_root.parent.name == "src":
        return package_root.parents[1]
    return Path.cwd().resolve()


def config_dir() -> Path:
    override = os.environ.get("ROCO_MITM_CONFIG_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return project_root() / "config"


def runtime_dir() -> Path:
    override = os.environ.get("ROCO_MITM_RUNTIME_DIR")
    if override:
        return Path(override).expanduser().resolve()
    return project_root() / "runtime"


def logs_dir() -> Path:
    return runtime_dir() / "logs"


def pids_dir() -> Path:
    return runtime_dir() / "pids"


def cache_dir() -> Path:
    return runtime_dir() / "cache"


def conn_map_path() -> Path:
    return runtime_dir() / "conn_map.json"


def proxy_log_path() -> Path:
    return logs_dir() / "proxy.log"
