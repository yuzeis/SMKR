from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path
from typing import Any

from .assembler import assemble_source
from .errors import RFNError
from .host import RFNHost
from .model import Module
from .vm import RFNVM


_FUNCTION_RE = re.compile(r"^\s*\.function\s+", re.MULTILINE)
_PRELUDE_RE = re.compile(r"^\s*\.(module|version|target|registry_pin)\s+")
_IMPORT_NAME_RE = re.compile(r"^[A-Za-z0-9_\u4e00-\u9fff][A-Za-z0-9_.\u4e00-\u9fff -]{0,63}$")


def normalize_import_name(name: str) -> str:
    value = str(name or "").strip()
    if value.lower().endswith(".rfn"):
        value = value[:-4].strip()
    if (
        not value
        or not _IMPORT_NAME_RE.match(value)
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
    ):
        raise ValueError(f"invalid RFN import name: {name!r}")
    return value


def is_bare_script(source: str) -> bool:
    return _FUNCTION_RE.search(str(source or "")) is None


def prepare_import_source(source: str, *, args_count: int = 0) -> dict[str, Any]:
    raw = str(source or "").lstrip("\ufeff").strip()
    if not raw:
        raise ValueError("missing RFN source")
    bare = is_bare_script(raw)
    if not bare:
        return {
            "source": raw,
            "bare": False,
            "default_function": "Main",
            "wrapped_function": None,
        }

    prelude: list[str] = []
    body: list[str] = []
    for line in raw.splitlines():
        if _PRELUDE_RE.match(line):
            prelude.append(line)
        else:
            body.append(line)
    arg_decl = ", ".join(f"arg{i}:any" for i in range(max(0, int(args_count))))
    wrapped = [
        *prelude,
        f".function __main__({arg_decl}) -> any",
        ".no_side_effect false",
        ".deterministic false",
        *body,
        ".end",
    ]
    return {
        "source": "\n".join(wrapped),
        "bare": True,
        "default_function": "__main__",
        "wrapped_function": "__main__",
    }


def validate_import_source(source: str, *, args_count: int = 0, module_name: str = "imported") -> dict[str, Any]:
    start = time.time()
    try:
        prepared = prepare_import_source(source, args_count=args_count)
        module = assemble_source(prepared["source"], module_name=module_name)
        return {
            "ok": True,
            "bare": prepared["bare"],
            "default_function": prepared["default_function"],
            "wrapped_function": prepared["wrapped_function"],
            "source_sha256": hashlib.sha256(str(source or "").encode("utf-8")).hexdigest(),
            "functions": _module_functions(module),
            "elapsed_ms": int((time.time() - start) * 1000),
        }
    except RFNError as exc:
        return {
            "ok": False,
            "error_code": exc.code,
            "error": str(exc),
            "elapsed_ms": int((time.time() - start) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error_code": "E_FAIL",
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": int((time.time() - start) * 1000),
        }


def run_import_source(
    source: str,
    *,
    function: str = "",
    args: list[Any] | None = None,
    host: RFNHost | None = None,
    module_name: str = "imported",
) -> dict[str, Any]:
    start = time.time()
    args = list(args or [])
    owns_host = host is None
    host = host or RFNHost()
    try:
        prepared = prepare_import_source(source, args_count=len(args))
        module = assemble_source(prepared["source"], module_name=module_name)
        requested = str(function or "")
        if prepared["bare"] and requested in {"Main", "Function.Main"}:
            requested = ""
        fn_name = str(requested or prepared["default_function"])
        short = fn_name.split("Function.", 1)[1] if fn_name.startswith("Function.") else fn_name
        if short not in module.functions:
            return {
                "ok": False,
                "error_code": "E_NOT_FOUND",
                "error": f"function not found: {fn_name}",
                "functions": _module_functions(module),
                "elapsed_ms": int((time.time() - start) * 1000),
            }
        result = RFNVM(module, host).call(short, *args)
        return {
            "ok": True,
            "function": short,
            "bare": prepared["bare"],
            "default_function": prepared["default_function"],
            "result": _json_safe(result),
            "elapsed_ms": int((time.time() - start) * 1000),
        }
    except RFNError as exc:
        return {
            "ok": False,
            "error_code": exc.code,
            "error": str(exc),
            "elapsed_ms": int((time.time() - start) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "error_code": "E_FAIL",
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_ms": int((time.time() - start) * 1000),
        }
    finally:
        if owns_host:
            host.close()


class RFNImportStore:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for(self, name: str) -> Path:
        safe = normalize_import_name(name)
        return self.root / f"{safe}.rfn"

    def list(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for path in sorted(self.root.glob("*.rfn")):
            source = path.read_text(encoding="utf-8-sig")
            meta = _source_file_meta(path, source)
            validation = validate_import_source(source)
            items.append({**meta, "validation": validation})
        return items

    def get(self, name: str) -> str:
        path = self.path_for(name)
        if not path.exists():
            raise FileNotFoundError(normalize_import_name(name))
        return path.read_text(encoding="utf-8-sig")

    def save(self, name: str, source: str) -> dict[str, Any]:
        safe = normalize_import_name(name)
        path = self.path_for(safe)
        text = str(source or "").lstrip("\ufeff").strip() + "\n"
        validation = validate_import_source(text)
        if not validation.get("ok"):
            return {"ok": False, **validation, "name": safe}
        tmp = path.with_suffix(".rfn.tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(path)
        return {"ok": True, **_source_file_meta(path, text), "validation": validation}

    def delete(self, name: str) -> dict[str, Any]:
        safe = normalize_import_name(name)
        path = self.path_for(safe)
        if not path.exists():
            return {"ok": False, "error_code": "E_NOT_FOUND", "name": safe}
        path.unlink()
        return {"ok": True, "name": safe}


def _module_functions(module: Module) -> list[dict[str, Any]]:
    return [
        {
            "name": fn.name,
            "args": [{"name": name, "type": typ} for name, typ in fn.args],
            "return": fn.return_type,
            "capabilities": [{"name": cap.name, **cap.scope} for cap in fn.capabilities],
            "arity": len(fn.args),
            "no_side_effect": fn.no_side_effect,
            "deterministic": fn.deterministic,
        }
        for fn in module.functions.values()
    ]


def _source_file_meta(path: Path, source: str) -> dict[str, Any]:
    stat = path.stat()
    return {
        "name": path.stem,
        "path": str(path),
        "size": stat.st_size,
        "mtime": stat.st_mtime,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes": len(value), "hex_preview": value[:32].hex()}
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [_json_safe(v) for v in value]
    return value
