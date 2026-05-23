from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .assembler import assemble_source
from .model import Module


def compile_manifest(source: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(source, dict):
        return _normalize_manifest(source)
    text = source.strip()
    if text.startswith("{"):
        return _normalize_manifest(json.loads(text))
    bindings: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("bind "):
            _, kind, name = line.split(None, 2)
            current = {"kind": kind, "name": name, "audit": True}
            continue
        if line == "end":
            if current is not None:
                bindings.append(current)
                current = None
            continue
        if current is not None:
            key, value = line.split(None, 1)
            current[key] = _manifest_value(value)
    return _normalize_manifest({"format": "rfn.manifest.source.v1", "bindings": bindings})


def compile_source_to_manifest(source: str, *, source_name: str = "<memory>") -> dict[str, Any]:
    module = assemble_source(source)
    functions = []
    for fn in module.functions.values():
        functions.append({
            "name": fn.name,
            "args": [{"name": n, "type": t} for n, t in fn.args],
            "return": fn.return_type,
            "no_side_effect": fn.no_side_effect,
            "deterministic": fn.deterministic,
            "capabilities": [{"name": c.name, **c.scope} for c in fn.capabilities],
            "max_ops": fn.max_ops,
            "timeout_ms": fn.timeout_ms,
        })
    return {
        "format": "rfn.manifest.v1",
        "source": source_name,
        "module": module.name,
        "registry_pin": module.registry_pin,
        "functions": functions,
        "bindings": [],
    }


def write_compiled_manifest(manifest: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")


def _normalize_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    out = dict(manifest)
    out["format"] = "rfn.manifest.v1"
    out.setdefault("functions", [])
    out.setdefault("bindings", [])
    return out


def _manifest_value(value: str) -> Any:
    value = value.strip()
    if value in ("true", "false"):
        return value == "true"
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    return value

