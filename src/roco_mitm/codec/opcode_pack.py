from __future__ import annotations

import hashlib
import json
import struct
import time
import zlib
from pathlib import Path
from typing import Any


MAGIC = b"RKOPC1\0"
FORMAT_VERSION = 1
KIND = "roco_mitm.opcode_schemas"


class OpcodePackError(RuntimeError):
    pass


def canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def normalize_opcode_key(value: str | int) -> str:
    if isinstance(value, int):
        num = value
    else:
        text = str(value).strip()
        num = int(text, 16) if text.lower().startswith("0x") else int(text, 10)
    if not 0 <= num <= 0xFFFF:
        raise ValueError(f"opcode out of range: {value!r}")
    return f"0x{num:04X}"


def load_opcode_details(opcodes_dir: Path) -> dict[str, dict]:
    root = Path(opcodes_dir)
    if not root.exists():
        raise FileNotFoundError(f"opcodes directory not found: {root}")
    details: dict[str, dict] = {}
    for path in sorted(root.glob("0x*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        key = normalize_opcode_key(data.get("opcode") or path.stem)
        details[key] = data
    return details


def write_pack(pack_path: Path, opcode_details: dict[str, dict], *, level: int = 9) -> dict:
    normalized = {
        normalize_opcode_key(key): value
        for key, value in sorted(opcode_details.items())
    }
    payload_doc = {
        "format": FORMAT_VERSION,
        "kind": KIND,
        "opcodes": normalized,
    }
    raw = canonical_json_bytes(payload_doc)
    compressed = zlib.compress(raw, level)
    header = {
        "format": FORMAT_VERSION,
        "kind": KIND,
        "codec": "zlib",
        "count": len(normalized),
        "raw_len": len(raw),
        "compressed_len": len(compressed),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "created_at": int(time.time()),
    }
    header_raw = canonical_json_bytes(header)
    out = MAGIC + struct.pack("<I", len(header_raw)) + header_raw + compressed
    pack_path = Path(pack_path)
    pack_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = pack_path.with_suffix(pack_path.suffix + ".tmp")
    tmp.write_bytes(out)
    tmp.replace(pack_path)
    return header


def read_pack(pack_path: Path) -> tuple[dict[str, dict], dict]:
    data = Path(pack_path).read_bytes()
    min_len = len(MAGIC) + 4
    if len(data) < min_len or data[: len(MAGIC)] != MAGIC:
        raise OpcodePackError(f"invalid opcode pack magic: {pack_path}")
    header_len = struct.unpack("<I", data[len(MAGIC) : min_len])[0]
    header_start = min_len
    header_end = header_start + header_len
    if header_end > len(data):
        raise OpcodePackError("opcode pack header length exceeds file size")
    try:
        header = json.loads(data[header_start:header_end].decode("utf-8"))
    except Exception as exc:
        raise OpcodePackError(f"invalid opcode pack header: {exc}") from exc
    if header.get("format") != FORMAT_VERSION or header.get("kind") != KIND:
        raise OpcodePackError(f"unsupported opcode pack format: {header!r}")
    if header.get("codec") != "zlib":
        raise OpcodePackError(f"unsupported opcode pack codec: {header.get('codec')!r}")
    try:
        raw = zlib.decompress(data[header_end:])
    except Exception as exc:
        raise OpcodePackError(f"opcode pack decompress failed: {exc}") from exc
    digest = hashlib.sha256(raw).hexdigest()
    if digest != header.get("raw_sha256"):
        raise OpcodePackError("opcode pack checksum mismatch")
    payload = json.loads(raw.decode("utf-8"))
    if payload.get("format") != FORMAT_VERSION or payload.get("kind") != KIND:
        raise OpcodePackError("opcode pack payload kind mismatch")
    opcodes = payload.get("opcodes")
    if not isinstance(opcodes, dict):
        raise OpcodePackError("opcode pack payload missing opcodes map")
    return {normalize_opcode_key(k): v for k, v in opcodes.items()}, header


def extract_pack(pack_path: Path, opcodes_dir: Path, *, overwrite: bool = False) -> int:
    details, _header = read_pack(pack_path)
    out_dir = Path(opcodes_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for key, data in sorted(details.items()):
        path = out_dir / f"{key}.json"
        if path.exists() and not overwrite:
            raise FileExistsError(f"refusing to overwrite existing file: {path}")
        text = json.dumps(data, ensure_ascii=False, indent=2)
        path.write_text(text + "\n", encoding="utf-8")
        count += 1
    return count


def compare_details(left: dict[str, dict], right: dict[str, dict]) -> list[str]:
    errors: list[str] = []
    left_keys = set(left)
    right_keys = set(right)
    for key in sorted(left_keys - right_keys):
        errors.append(f"missing from right: {key}")
    for key in sorted(right_keys - left_keys):
        errors.append(f"missing from left: {key}")
    for key in sorted(left_keys & right_keys):
        if canonical_json_bytes(left[key]) != canonical_json_bytes(right[key]):
            errors.append(f"content differs: {key}")
    return errors
