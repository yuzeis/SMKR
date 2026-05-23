"""数据驱动的通用 protobuf 编解码器。

本模块完全不包含任何业务知识 (opcode / 字段名)，所有 schema 都通过参数传入。
schema 形如::

    {
        "fields": [
            {
                "no": 1,                    # 字段号
                "name": "uin",              # 字段名
                "type": "uint32",           # 见 _CANONICAL_TYPES
                "repeated": False,          # 默认 False
                "ref": "FriendRoleInfo",    # type=message/enum 时, 由 registry 解析
                "fields": [...],            # 内联 message schema (替代 ref)
                "desc": "用户ID",            # 仅元数据, 编解码不使用
            },
            ...
        ]
    }
"""
from __future__ import annotations

import struct
from typing import Any, Callable


WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LEN = 2
WIRE_FIXED32 = 5

_VARINT_TYPES = frozenset(
    {"int32", "int64", "uint32", "uint64", "sint32", "sint64", "bool", "enum"}
)
_FIXED32_TYPES = frozenset({"fixed32", "sfixed32", "float"})
_FIXED64_TYPES = frozenset({"fixed64", "sfixed64", "double"})
_LEN_TYPES = frozenset({"string", "bytes", "message"})

_CANONICAL_TYPES = _VARINT_TYPES | _FIXED32_TYPES | _FIXED64_TYPES | _LEN_TYPES


def _strip_generic(t: str) -> str:
    """`enum<X>` -> `enum`,  `message<Y>` -> `message`"""
    if "<" in t:
        return t.split("<", 1)[0].strip()
    return t.strip()


def strip_generic(t: str) -> str:
    """Return the protobuf base type without generic metadata."""
    return _strip_generic(t)


def wire_type_for(type_name: str) -> int:
    base = _strip_generic(type_name)
    if base in _VARINT_TYPES:
        return WIRE_VARINT
    if base in _FIXED32_TYPES:
        return WIRE_FIXED32
    if base in _FIXED64_TYPES:
        return WIRE_FIXED64
    if base in _LEN_TYPES:
        return WIRE_LEN
    raise ValueError(f"未知的 proto 类型: {type_name!r}")


def _is_packable_type(type_name: str) -> bool:
    base = _strip_generic(type_name)
    return base in _VARINT_TYPES or base in _FIXED32_TYPES or base in _FIXED64_TYPES


def encode_varint(v: int) -> bytes:
    if v < 0:
        v &= (1 << 64) - 1  # 64-bit 二进制补码
    out = bytearray()
    while v > 0x7F:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v & 0x7F)
    return bytes(out)


def decode_varint(buf: bytes, i: int) -> tuple[int, int]:
    r = 0
    shift = 0
    while i < len(buf):
        x = buf[i]
        i += 1
        r |= (x & 0x7F) << shift
        shift += 7
        if x < 0x80:
            return r, i
        if shift > 70:
            raise ValueError("varint overflow")
    raise ValueError("varint truncated")


def _zigzag32_encode(v: int) -> int:
    return ((v << 1) ^ (v >> 31)) & 0xFFFFFFFF


def _zigzag32_decode(v: int) -> int:
    return (v >> 1) ^ -(v & 1)


def _zigzag64_encode(v: int) -> int:
    return ((v << 1) ^ (v >> 63)) & ((1 << 64) - 1)


def _zigzag64_decode(v: int) -> int:
    return (v >> 1) ^ -(v & 1)



def encode_tag(field_no: int, wire_type: int) -> bytes:
    return encode_varint((field_no << 3) | wire_type)


def is_valid_tag_byte(b: int) -> bool:
    """启发式: 是否像合法 pb tag 的首字节."""
    wt = b & 7
    fn = b >> 3
    return wt in (0, 1, 2, 5) and fn >= 1



def encode_scalar(type_name: str, value: Any) -> bytes:
    """编码标量值，返回**不含 tag**的字节序列。"""
    base = _strip_generic(type_name)
    if base in ("int32", "int64", "uint32", "uint64", "enum"):
        return encode_varint(int(value))
    if base == "bool":
        return encode_varint(1 if value else 0)
    if base == "sint32":
        return encode_varint(_zigzag32_encode(int(value)))
    if base == "sint64":
        return encode_varint(_zigzag64_encode(int(value)))
    if base == "fixed32":
        return struct.pack("<I", int(value) & 0xFFFFFFFF)
    if base == "sfixed32":
        return struct.pack("<i", int(value))
    if base == "fixed64":
        return struct.pack("<Q", int(value) & ((1 << 64) - 1))
    if base == "sfixed64":
        return struct.pack("<q", int(value))
    if base == "float":
        return struct.pack("<f", float(value))
    if base == "double":
        return struct.pack("<d", float(value))
    if base == "string":
        b = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        return encode_varint(len(b)) + b
    if base == "bytes":
        if isinstance(value, str):
            b = bytes.fromhex(value.replace(" ", "").replace("\n", ""))
        else:
            b = bytes(value)
        return encode_varint(len(b)) + b
    raise ValueError(f"不支持的标量类型: {type_name!r}")



class SchemaError(Exception):
    """schema 缺失或字段未知。"""


# 解析 ref 的接口：传入 callable(name) -> schema dict | None
RefResolver = Callable[[str], "dict | None"]
MessageDecoder = Callable[[dict, bytes, RefResolver | None], dict]


def encode_payload(
    schema: dict,
    value: dict,
    *,
    resolve_message: RefResolver | None = None,
) -> bytes:
    """根据 schema 把 dict 值编码成 protobuf bytes。

    - schema['fields'] 列出顶层字段
    - 字段名匹配 dict 的键；缺失字段 = 不写
    - 对 repeated 字段, value[name] 应为列表
    - message 字段优先用内联 schema['fields'], 否则通过 resolve_message(ref)
    """
    if not isinstance(value, dict):
        raise TypeError(f"encode_payload 需要 dict, 实际 {type(value).__name__}")
    fields = schema.get("fields") or []
    by_name = {f["name"]: f for f in fields}
    out = bytearray()
    for name, val in value.items():
        if name.startswith("_"):
            continue  # 由解码器写入的元字段 (如 _unknown), 编码时跳过
        if name not in by_name:
            raise SchemaError(f"未知字段: {name!r}")
        out += _encode_field(by_name[name], val, resolve_message)
    return bytes(out)


def _encode_field(f: dict, value: Any, resolve_message: RefResolver | None) -> bytes:
    if value is None:
        return b""
    if f.get("repeated"):
        if not isinstance(value, list):
            raise TypeError(f"字段 {f['name']!r} 是 repeated, 期望 list, 实际 {type(value).__name__}")
        if f.get("packed") and _is_packable_type(f["type"]):
            body = b"".join(encode_scalar(f["type"], elem) for elem in value)
            if not body:
                return b""
            return encode_tag(f["no"], WIRE_LEN) + encode_varint(len(body)) + body
        out = bytearray()
        for elem in value:
            out += _encode_one(f, elem, resolve_message)
        return bytes(out)
    return _encode_one(f, value, resolve_message)


def _encode_one(f: dict, value: Any, resolve_message: RefResolver | None) -> bytes:
    type_name = f["type"]
    base = _strip_generic(type_name)
    head = encode_tag(f["no"], wire_type_for(type_name))
    if base == "message":
        sub_schema = _resolve_msg_schema(f, resolve_message, required=True)
        body = encode_payload(sub_schema, value, resolve_message=resolve_message)
        return head + encode_varint(len(body)) + body
    return head + encode_scalar(type_name, value)


def _resolve_msg_schema(
    f: dict, resolve_message: RefResolver | None, *, required: bool
) -> dict | None:
    if f.get("fields"):
        return {"fields": f["fields"]}
    ref = f.get("ref")
    if ref and resolve_message is not None:
        sub = resolve_message(ref)
        if sub is not None:
            return sub
    if required:
        raise SchemaError(
            f"无法解析 message schema: 字段 {f.get('name')!r} ref={f.get('ref')!r}"
        )
    return None



def decode_payload(
    schema: dict | None,
    payload: bytes,
    *,
    resolve_message: RefResolver | None = None,
    auto_skip_prefix: bool = True,
    decode_message: MessageDecoder | None = None,
) -> dict:
    """根据 schema 解码 payload。

    - schema=None 时退化为"扫描所有字段, 不做名字映射", 结果以 `f<N>` 为键
    - auto_skip_prefix: 若首字节不像合法 pb tag, 跳过 1~2 字节再试
      (服务端 0x02A5 / 0x03DD 有此现象)
    - 未在 schema 中声明的字段进入 result['_unknown'] 列表
    """
    if auto_skip_prefix and payload:
        best = None
        for start in range(0, min(8, len(payload) - 1) + 1):
            if start > 0 and not is_valid_tag_byte(payload[start]):
                continue
            candidate = _decode_payload_once(
                schema, payload, resolve_message, start=start, decode_message=decode_message
            )
            out, consumed, field_count, unknown_count = candidate
            consumed_all = consumed >= len(payload)
            has_fields = field_count > 0
            score = (
                1 if has_fields else 0,
                1 if unknown_count == 0 else 0,
                1 if consumed_all else 0,
                -start,
            )
            if score == (1, 1, 1, 0):
                return out
            if best is None or score > best[0]:
                best = (score, out)
        if best is not None:
            return best[1]
    return _decode_payload_once(
        schema, payload, resolve_message, start=0, decode_message=decode_message
    )[0]


def _decode_payload_once(
    schema: dict | None,
    payload: bytes,
    resolve_message: RefResolver | None = None,
    *,
    start: int = 0,
    decode_message: MessageDecoder | None = None,
) -> tuple[dict, int, int, int]:
    fields = (schema or {}).get("fields") or []
    by_no = {f["no"]: f for f in fields}
    out: dict[str, Any] = {}
    unknowns: list[dict] = []
    field_count = 0

    i = start
    while i < len(payload):
        try:
            tag, i = decode_varint(payload, i)
        except Exception:
            break
        fn = tag >> 3
        wt = tag & 7
        try:
            raw, i = _read_wire_value(payload, i, wt)
        except Exception:
            break
        f = by_no.get(fn)
        if f is None:
            unknowns.append({
                "no": fn,
                "wire": wt,
                "value": raw.hex() if isinstance(raw, (bytes, bytearray)) else raw,
            })
            continue
        field_count += 1
        # 与原 rsp_decoder._render 一致: 跳过 wire-type 不匹配的字段
        # (该服务端经常在同一 payload 里以不同 wt 重复出现同字段, 只信第一次匹配的)
        try:
            expected_wt = wire_type_for(f["type"])
        except ValueError:
            unknowns.append({"no": fn, "wire": wt, "value": raw, "reason": "bad_schema_type"})
            continue
        if wt != expected_wt:
            if f.get("repeated") and wt == WIRE_LEN and _is_packable_type(f["type"]):
                try:
                    vals = _decode_packed_values(f, raw)
                except Exception:
                    unknowns.append({
                        "no": fn,
                        "wire": wt,
                        "value": raw.hex() if isinstance(raw, (bytes, bytearray)) else raw,
                        "reason": "bad_packed_repeated",
                    })
                    continue
                out.setdefault(f["name"], []).extend(vals)
                continue
            unknowns.append({
                "no": fn,
                "wire": wt,
                "value": raw.hex() if isinstance(raw, (bytes, bytearray)) else raw,
                "reason": "wire_type_mismatch",
                "expected_wire": expected_wt,
            })
            continue
        decoded = _decode_value(f, wt, raw, resolve_message, decode_message)
        if f.get("repeated"):
            out.setdefault(f["name"], []).append(decoded)
        else:
            # first-wins (与原 rsp_decoder 一致)
            out.setdefault(f["name"], decoded)

    if unknowns:
        out["_unknown"] = unknowns
    return out, i, field_count, len(unknowns)


def decode_payload_once(
    schema: dict | None,
    payload: bytes,
    resolve_message: RefResolver | None = None,
    *,
    start: int = 0,
    decode_message: MessageDecoder | None = None,
) -> tuple[dict, int, int, int]:
    return _decode_payload_once(
        schema, payload, resolve_message, start=start, decode_message=decode_message
    )


def _read_wire_value(buf: bytes, i: int, wt: int):
    if wt == WIRE_VARINT:
        return decode_varint(buf, i)
    if wt == WIRE_LEN:
        L, i = decode_varint(buf, i)
        if L < 0 or i + L > len(buf):
            raise ValueError("len-delim 越界")
        return buf[i : i + L], i + L
    if wt == WIRE_FIXED32:
        if i + 4 > len(buf):
            raise ValueError("fixed32 截断")
        return int.from_bytes(buf[i : i + 4], "little"), i + 4
    if wt == WIRE_FIXED64:
        if i + 8 > len(buf):
            raise ValueError("fixed64 截断")
        return int.from_bytes(buf[i : i + 8], "little"), i + 8
    raise ValueError(f"不支持的 wire type: {wt}")


def _decode_packed_values(f: dict, raw) -> list:
    if not isinstance(raw, (bytes, bytearray)):
        return []
    buf = bytes(raw)
    wt = wire_type_for(f["type"])
    out = []
    i = 0
    if wt == WIRE_VARINT:
        while i < len(buf):
            v, i = decode_varint(buf, i)
            out.append(_decode_value(f, wt, v, None))
        return out
    if wt == WIRE_FIXED32:
        if len(buf) % 4:
            raise ValueError("packed fixed32 length mismatch")
        while i < len(buf):
            v = int.from_bytes(buf[i : i + 4], "little")
            i += 4
            out.append(_decode_value(f, wt, v, None))
        return out
    if wt == WIRE_FIXED64:
        if len(buf) % 8:
            raise ValueError("packed fixed64 length mismatch")
        while i < len(buf):
            v = int.from_bytes(buf[i : i + 8], "little")
            i += 8
            out.append(_decode_value(f, wt, v, None))
        return out
    raise ValueError("not a packable field")


def _decode_value(
    f: dict,
    wt: int,
    raw,
    resolve_message: RefResolver | None,
    decode_message: MessageDecoder | None = None,
):
    type_name = f["type"]
    base = _strip_generic(type_name)
    if base == "message":
        if not isinstance(raw, (bytes, bytearray)):
            return {"_raw": raw}
        sub = _resolve_msg_schema(f, resolve_message, required=False)
        if sub is None:
            return {"_hex": bytes(raw).hex()}
        if decode_message is not None:
            return decode_message(sub, bytes(raw), resolve_message)
        return _decode_payload_once(sub, bytes(raw), resolve_message, start=0)[0]
    if base == "string":
        if isinstance(raw, (bytes, bytearray)):
            try:
                return bytes(raw).decode("utf-8")
            except UnicodeDecodeError:
                return {"_hex": bytes(raw).hex()}
        return raw
    if base == "bytes":
        if isinstance(raw, (bytes, bytearray)):
            return bytes(raw).hex()
        return raw
    if base == "bool":
        return bool(raw)
    if base == "sint32":
        return _zigzag32_decode(raw & 0xFFFFFFFF) if isinstance(raw, int) else raw
    if base == "sint64":
        return _zigzag64_decode(raw & ((1 << 64) - 1)) if isinstance(raw, int) else raw
    if base == "float":
        if isinstance(raw, int):
            return struct.unpack("<f", raw.to_bytes(4, "little"))[0]
        return raw
    if base == "double":
        if isinstance(raw, int):
            return struct.unpack("<d", raw.to_bytes(8, "little"))[0]
        return raw
    if base == "int32":
        # int32 在 proto 中是有符号 32 位
        if isinstance(raw, int) and raw & 0x80000000 and raw < (1 << 32):
            return raw - (1 << 32)
        return raw
    if base == "int64":
        if isinstance(raw, int) and raw & (1 << 63) and raw < (1 << 64):
            return raw - (1 << 64)
        return raw
    return raw  # uint32/uint64/enum/fixed* 直接透传



def scan_fields(payload: bytes, *, auto_skip_prefix: bool = True) -> list[dict]:
    """无 schema 扫描: 返回 [{no, wire, value, kind}], value 已按 wt 解出."""
    out: list[dict] = []
    i = 0
    if auto_skip_prefix and payload and not is_valid_tag_byte(payload[0]):
        for skip in (1, 2):
            if skip < len(payload) and is_valid_tag_byte(payload[skip]):
                i = skip
                break
    while i < len(payload):
        try:
            tag, i = decode_varint(payload, i)
        except Exception:
            break
        fn = tag >> 3
        wt = tag & 7
        try:
            raw, i = _read_wire_value(payload, i, wt)
        except Exception:
            break
        kind = {0: "varint", 1: "fixed64", 2: "len", 5: "fixed32"}[wt]
        if isinstance(raw, (bytes, bytearray)):
            out.append({"no": fn, "wire": wt, "kind": kind, "value": bytes(raw).hex(), "len": len(raw)})
        else:
            out.append({"no": fn, "wire": wt, "kind": kind, "value": raw})
    return out
