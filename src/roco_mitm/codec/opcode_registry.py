"""Opcode and protobuf message registry.

Data sources, in priority order:
  1. config/decoder_overrides.json
  2. config/opcodes/0xXXXX.json, when the editable directory exists
  3. config/opcodes.pack.bin
  4. inline fields in config/opcodes.json

The packed file is the normal runtime format. The JSON directory is treated as
an editable working tree and can be recreated with tools/pack_opcode_schemas.py.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from .opcode_pack import OpcodePackError, read_pack


def _parse_opcode(s: str | int) -> int | None:
    if isinstance(s, int):
        return s
    s = str(s).strip()
    if not s:
        return None
    try:
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except ValueError:
        return None


class OpcodeRegistry:
    def __init__(self, config_dir: Path):
        self.config_dir = Path(config_dir)
        self._lock = threading.RLock()
        self._opcodes: dict[int, dict] = {}
        self._messages: dict[str, dict] = {}
        self._message_aliases: dict[str, str] = {}
        self._opcode_schemas: dict[int, dict] = {}
        self._packed_opcode_details: dict[int, dict] = {}
        self._mtimes: dict[Path, float] = {}
        self._last_mtime_check = 0.0
        self._mtime_check_interval = 1.0

    @property
    def opcodes_index_path(self) -> Path:
        return self.config_dir / "opcodes.json"

    @property
    def messages_index_path(self) -> Path:
        return self.config_dir / "messages.json"

    @property
    def opcodes_dir(self) -> Path:
        return self.config_dir / "opcodes"

    @property
    def opcode_pack_path(self) -> Path:
        return self.config_dir / "opcodes.pack.bin"

    @property
    def overrides_path(self) -> Path:
        return self.config_dir / "decoder_overrides.json"

    def load(self) -> None:
        with self._lock:
            self._opcodes.clear()
            self._messages.clear()
            self._message_aliases.clear()
            self._opcode_schemas.clear()
            self._packed_opcode_details.clear()
            self._mtimes.clear()
            if self.opcodes_dir.exists():
                self._record_mtime(self.opcodes_dir)
                for detail_path in self.opcodes_dir.glob("0x*.json"):
                    self._record_mtime(detail_path)
            self._load_messages_index()
            self._load_opcodes_index()
            self._load_opcode_pack()
            self._load_overrides()

    def _record_mtime(self, p: Path) -> None:
        try:
            self._mtimes[p] = p.stat().st_mtime
        except OSError:
            pass

    def _load_messages_index(self) -> None:
        idx = self.messages_index_path
        if not idx.exists():
            return
        try:
            data = json.loads(idx.read_text(encoding="utf-8"))
        except Exception:
            return
        self._record_mtime(idx)

        raw_messages = data.get("messages") or {}
        for name, schema in raw_messages.items():
            self._messages[name] = {"fields": schema.get("fields", [])}

        short_counts: dict[str, int] = {}
        for name in raw_messages:
            short = str(name).rsplit(".", 1)[-1]
            short_counts[short] = short_counts.get(short, 0) + 1

        for name in raw_messages:
            if str(name).startswith("."):
                self._message_aliases.setdefault(str(name)[1:], name)
            short = str(name).rsplit(".", 1)[-1]
            if short_counts.get(short) == 1:
                self._message_aliases.setdefault(short, name)

    def _load_opcodes_index(self) -> None:
        idx = self.opcodes_index_path
        if not idx.exists():
            return
        try:
            data = json.loads(idx.read_text(encoding="utf-8"))
        except Exception:
            return
        self._record_mtime(idx)
        for hex_key, meta in (data.get("opcodes") or {}).items():
            num = _parse_opcode(hex_key)
            if num is None:
                continue
            self._opcodes[num] = {
                "id": num,
                "hex": f"0x{num:04X}",
                "name": meta.get("name"),
                "direction": meta.get("direction"),
                "category": meta.get("category"),
                "desc": meta.get("desc"),
                "schema_status": meta.get("schema_status"),
                "pair": meta.get("pair"),
                "decode_as": meta.get("decode_as"),
                "proto_name": meta.get("proto_name"),
                "enum_name": meta.get("enum_name"),
                "schema_source": meta.get("schema_source"),
                "schema_source_note": meta.get("schema_source_note"),
                "proto_source": meta.get("proto_source"),
                "proto_source_note": meta.get("proto_source_note"),
            }
            if "fields" in meta:
                self._opcode_schemas[num] = {"fields": meta["fields"], "source": "index"}

    def _load_opcode_pack(self) -> None:
        pack = self.opcode_pack_path
        if not pack.exists():
            return
        try:
            details, _header = read_pack(pack)
        except (OSError, OpcodePackError, ValueError, json.JSONDecodeError):
            return
        self._record_mtime(pack)
        for hex_key, detail in details.items():
            num = _parse_opcode(hex_key)
            if num is not None:
                self._packed_opcode_details[num] = detail

    def _load_overrides(self) -> None:
        ov = self.overrides_path
        if not ov.exists():
            return
        try:
            data = json.loads(ov.read_text(encoding="utf-8"))
        except Exception:
            return
        self._record_mtime(ov)

        for name, schema in (data.get("messages") or {}).items():
            self._messages[name] = {"fields": schema.get("fields", [])}

        for hex_key, override in (data.get("opcodes") or {}).items():
            num = _parse_opcode(hex_key)
            if num is None:
                continue
            meta = self._opcodes.setdefault(num, {"id": num, "hex": f"0x{num:04X}"})
            for k in ("name", "direction", "category", "desc", "schema_status"):
                if k in override:
                    meta[k] = override[k]

            if "fields" in override:
                self._opcode_schemas[num] = {
                    "fields": override["fields"],
                    "source": "override",
                }
                meta["schema_status"] = override.get("schema_status", "override")
            elif "decode_as" in override:
                ref_name = override["decode_as"]
                msg = self.get_message(ref_name)
                if msg is not None:
                    self._opcode_schemas[num] = {
                        "fields": msg.get("fields", []),
                        "source": "override:decode_as",
                        "decode_as": ref_name,
                    }
                    meta["schema_status"] = override.get("schema_status", "override")
                meta["decode_as"] = ref_name

    def get_opcode_meta(self, num: int) -> dict | None:
        with self._lock:
            v = self._opcodes.get(num)
            return dict(v) if v else None

    def get_opcode_schema(self, num: int) -> dict | None:
        with self._lock:
            cached = self._opcode_schemas.get(num)
            if cached is not None:
                return dict(cached)

            detail_path = self.opcodes_dir / f"0x{num:04X}.json"
            if detail_path.exists():
                try:
                    data = json.loads(detail_path.read_text(encoding="utf-8"))
                except Exception:
                    data = None
                if data is not None:
                    self._record_mtime(detail_path)
                    schema = {"fields": data.get("fields", []), "source": "detail"}
                    self._opcode_schemas[num] = schema
                    return dict(schema)

            packed = self._packed_opcode_details.get(num)
            if packed is not None:
                schema = {"fields": packed.get("fields", []), "source": "pack"}
                self._opcode_schemas[num] = schema
                return dict(schema)

            return None

    def get_message(self, name: str) -> dict | None:
        with self._lock:
            v = self._messages.get(name)
            if v:
                return dict(v)

            target = self._message_aliases.get(name)
            if target:
                v = self._messages.get(target)
                return dict(v) if v else None

            alt = name[1:] if name.startswith(".") else f".{name}"
            target = self._message_aliases.get(alt)
            if target:
                v = self._messages.get(target)
                return dict(v) if v else None

            v = self._messages.get(alt)
            return dict(v) if v else None

    def list_opcodes(self) -> list[dict]:
        with self._lock:
            return [dict(v) for v in self._opcodes.values()]

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "opcodes": len(self._opcodes),
                "messages": len(self._messages),
                "schemas_loaded": len(self._opcode_schemas),
                "packed_schemas": len(self._packed_opcode_details),
            }

    def reload_if_changed(self) -> bool:
        with self._lock:
            now = time.monotonic()
            if now - self._last_mtime_check < self._mtime_check_interval:
                return False
            self._last_mtime_check = now
            for p, t in list(self._mtimes.items()):
                try:
                    if not p.exists():
                        self.load()
                        return True
                    if p.stat().st_mtime != t:
                        self.load()
                        return True
                except OSError:
                    continue
            for p in (
                self.messages_index_path,
                self.opcodes_index_path,
                self.opcode_pack_path,
                self.overrides_path,
                self.opcodes_dir,
            ):
                if p.exists() and p not in self._mtimes:
                    self.load()
                    return True
            if self.opcodes_dir.exists():
                for p in self.opcodes_dir.glob("0x*.json"):
                    if p not in self._mtimes:
                        self.load()
                        return True
        return False

    def resolve_message(self, name: str) -> dict | None:
        return self.get_message(name)
