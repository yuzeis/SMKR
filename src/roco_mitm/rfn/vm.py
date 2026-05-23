from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from typing import Any

from roco_mitm.codec import proto_codec

from .errors import RFNError, rfn_fail
from .host import RFNHost
from .model import Function, Instruction, Module
from .paths import del_path, get_all_path, get_path, has_path, set_path
from .reader import Reader


class RFNVM:
    def __init__(self, module: Module, host: RFNHost | None = None):
        self.module = module
        self.host = host or RFNHost()

    def call(self, name: str, *args: Any) -> Any:
        short = name.split("Function.", 1)[1] if name.startswith("Function.") else name
        fn = self.module.functions.get(short)
        if fn is None:
            rfn_fail("E_COMPILE", f"unknown function: {name}")
        return self._execute(fn, list(args))

    def _execute(self, fn: Function, args: list[Any]) -> Any:
        if len(args) != len(fn.args):
            rfn_fail("E_ARG", f"{fn.name} expects {len(fn.args)} args, got {len(args)}")
        regs: dict[str, Any] = {f"arg{i}": v for i, v in enumerate(args)}
        pc = 0
        ops = 0
        while pc < len(fn.instructions):
            inst = fn.instructions[pc]
            ops += 1
            if ops > fn.max_ops:
                rfn_fail("E_LIMIT_OPS", f"{fn.name} exceeded max_ops={fn.max_ops}")
            next_pc = pc + 1
            result = self._step(fn, regs, inst)
            if isinstance(result, _Jump):
                next_pc = fn.labels[result.label]
            elif isinstance(result, _Return):
                return result.value
            pc = next_pc
        return None

    def _step(self, fn: Function, r: dict[str, Any], inst: Instruction) -> Any:
        op = inst.op
        a = inst.args
        try:
            if op == "nop":
                return None
            if op == "mov":
                r[str(a[0])] = self._val(r, a[1])
                return None
            if op == "ret":
                return _Return(self._val(r, a[0]) if a else None)
            if op == "fail":
                rfn_fail("E_FAIL", str(self._val(r, a[0])))
            if op == "call":
                dst, target = str(a[0]), str(a[1])
                r[dst] = self.call(target, *(self._val(r, x) for x in a[2:]))
                return None
            if op == "jmp":
                return _Jump(str(a[0]))
            if op in {"jz", "jnz"}:
                cond = bool(self._val(r, a[0]))
                if (op == "jz" and not cond) or (op == "jnz" and cond):
                    return _Jump(str(a[1]))
                return None
            if op in {"jeq", "jne", "jlt", "jle", "jgt", "jge"}:
                left, right = self._val(r, a[0]), self._val(r, a[1])
                ok = {
                    "jeq": left == right,
                    "jne": left != right,
                    "jlt": left < right,
                    "jle": left <= right,
                    "jgt": left > right,
                    "jge": left >= right,
                }[op]
                if ok:
                    return _Jump(str(a[2]))
                return None
            if op.startswith("cmp."):
                r[str(a[0])] = self._cmp(op, self._val(r, a[1]), self._val(r, a[2]) if len(a) > 2 else None)
                return None
            if op.startswith("int."):
                r[str(a[0])] = self._int(op, [self._val(r, x) for x in a[1:]])
                return None
            if op.startswith("cast."):
                r[str(a[0])] = self._cast(op, self._val(r, a[1]))
                return None
            if op.startswith("buf."):
                self._buf(r, op, a)
                return None
            if op.startswith("pb."):
                self._pb(r, op, a)
                return None
            if op.startswith("rd."):
                self._rd(r, op, a)
                return None
            if op.startswith(("obj.", "arr.", "map.")):
                self._object(r, op, a)
                return None
            if op.startswith(("str.", "bytes.", "hash.")):
                self._scalar(r, op, a)
                return None
            if op.startswith(("route.", "schema.", "packet.", "cache.", "buffer.", "db.", "http.", "inject.", "query.", "session.", "schedule.", "event.", "audit.", "file.")):
                self._cap(fn, r, op, a)
                return None
            if op.startswith("dbg."):
                if op == "dbg.assert" and not self._val(r, a[0]):
                    rfn_fail("E_FAIL", str(self._val(r, a[1])))
                return None
        except RFNError:
            raise
        except Exception as exc:
            rfn_fail("E_FAIL", f"{inst.text}: {exc}")
        rfn_fail("E_COMPILE", f"unknown instruction: {op}")

    def _val(self, r: dict[str, Any], x: Any) -> Any:
        if isinstance(x, str) and (re.fullmatch(r"arg\d+|r\d+|tmp\d+", x) or x == "retv"):
            return r.get(x)
        return x

    def _cmp(self, op: str, left: Any, right: Any) -> bool:
        if op == "cmp.eq":
            return left == right
        if op == "cmp.ne":
            return left != right
        if op == "cmp.lt":
            return left < right
        if op == "cmp.le":
            return left <= right
        if op == "cmp.gt":
            return left > right
        if op == "cmp.ge":
            return left >= right
        if op == "cmp.isnil":
            return left is None
        if op == "cmp.exists":
            return left is not None
        rfn_fail("E_COMPILE", f"unknown cmp op: {op}")

    def _int(self, op: str, vals: list[Any]) -> int:
        if op == "int.add":
            return int(vals[0]) + int(vals[1])
        if op == "int.sub":
            return int(vals[0]) - int(vals[1])
        if op == "int.mul":
            return int(vals[0]) * int(vals[1])
        if op == "int.div":
            if int(vals[1]) == 0:
                rfn_fail("E_DIV_ZERO", "division by zero")
            return int(vals[0]) // int(vals[1])
        if op == "int.mod":
            if int(vals[1]) == 0:
                rfn_fail("E_DIV_ZERO", "mod by zero")
            return int(vals[0]) % int(vals[1])
        if op == "int.neg":
            return -int(vals[0])
        if op == "int.and":
            return int(vals[0]) & int(vals[1])
        if op == "int.or":
            return int(vals[0]) | int(vals[1])
        if op == "int.xor":
            return int(vals[0]) ^ int(vals[1])
        if op == "int.not":
            return ~int(vals[0])
        if op == "int.shl":
            return int(vals[0]) << int(vals[1])
        if op in {"int.shr", "int.sar"}:
            return int(vals[0]) >> int(vals[1])
        if op == "int.min":
            return min(int(vals[0]), int(vals[1]))
        if op == "int.max":
            return max(int(vals[0]), int(vals[1]))
        if op == "int.clamp":
            return max(int(vals[1]), min(int(vals[0]), int(vals[2])))
        rfn_fail("E_COMPILE", f"unknown int op: {op}")

    def _cast(self, op: str, value: Any) -> Any:
        if op == "cast.bool":
            return bool(value)
        if op in {"cast.i32", "cast.u32", "cast.i64", "cast.u64"}:
            return int(value)
        if op == "cast.str":
            return str(value)
        if op == "cast.bytes":
            return value if isinstance(value, bytes) else str(value).encode("utf-8")
        if op == "cast.buf":
            return bytearray(value if isinstance(value, (bytes, bytearray)) else bytes(value))
        rfn_fail("E_COMPILE", f"unknown cast op: {op}")

    def _buf(self, r: dict[str, Any], op: str, a: tuple[Any, ...]) -> None:
        if op == "buf.new":
            r[str(a[0])] = bytearray()
        elif op == "buf.from":
            r[str(a[0])] = bytearray(self._val(r, a[1]))
        elif op == "buf.clear":
            self._val(r, a[0]).clear()
        elif op == "buf.len":
            r[str(a[0])] = len(self._val(r, a[1]))
        elif op == "buf.reserve":
            return
        elif op == "buf.append":
            buf = self._val(r, a[0])
            val = self._val(r, a[1])
            buf.extend(val.encode("utf-8") if isinstance(val, str) else bytes(val))
        elif op == "buf.append_int":
            buf = self._val(r, a[0])
            endian = str(self._val(r, a[3]))
            byteorder = "big" if endian == "be" else "little" if endian == "le" else endian
            buf.extend(int(self._val(r, a[1])).to_bytes(int(self._val(r, a[2])), byteorder, signed=bool(self._val(r, a[4]))))
        elif op == "buf.patch_int":
            buf = self._val(r, a[0])
            off = int(self._val(r, a[1]))
            endian = str(self._val(r, a[4]))
            byteorder = "big" if endian == "be" else "little" if endian == "le" else endian
            raw = int(self._val(r, a[2])).to_bytes(int(self._val(r, a[3])), byteorder, signed=bool(self._val(r, a[5])))
            if off < 0 or off + len(raw) > len(buf):
                rfn_fail("E_RANGE", "buf.patch_int out of range")
            buf[off : off + len(raw)] = raw
        elif op == "buf.slice":
            buf = self._val(r, a[1])
            off, n = int(self._val(r, a[2])), int(self._val(r, a[3]))
            r[str(a[0])] = bytes(buf[off : off + n])
        elif op == "buf.take":
            r[str(a[0])] = bytes(self._val(r, a[1]))
        elif op == "buf.hex":
            r[str(a[0])] = bytes(self._val(r, a[1])).hex()
        else:
            rfn_fail("E_COMPILE", f"unknown buf op: {op}")

    def _pb(self, r: dict[str, Any], op: str, a: tuple[Any, ...]) -> None:
        buf = self._val(r, a[0])
        if op == "pb.tag":
            buf.extend(proto_codec.encode_tag(int(self._val(r, a[1])), int(self._val(r, a[2]))))
        elif op == "pb.varint_raw":
            buf.extend(proto_codec.encode_varint(int(self._val(r, a[1]))))
        elif op == "pb.varint":
            buf.extend(proto_codec.encode_tag(int(self._val(r, a[1])), proto_codec.WIRE_VARINT))
            buf.extend(proto_codec.encode_varint(int(self._val(r, a[2]))))
        elif op == "pb.svarint":
            field, value = int(self._val(r, a[1])), int(self._val(r, a[2]))
            buf.extend(proto_codec.encode_payload({"fields": [{"no": field, "name": "v", "type": "sint64"}]}, {"v": value}))
        elif op == "pb.bool":
            buf.extend(proto_codec.encode_tag(int(self._val(r, a[1])), proto_codec.WIRE_VARINT))
            buf.extend(proto_codec.encode_varint(1 if self._val(r, a[2]) else 0))
        elif op == "pb.enum":
            buf.extend(proto_codec.encode_tag(int(self._val(r, a[1])), proto_codec.WIRE_VARINT))
            buf.extend(proto_codec.encode_varint(int(self._val(r, a[2]))))
        elif op == "pb.bytes":
            value = self._val(r, a[2])
            raw = value if isinstance(value, bytes) else bytes(value)
            buf.extend(proto_codec.encode_tag(int(self._val(r, a[1])), proto_codec.WIRE_LEN))
            buf.extend(proto_codec.encode_varint(len(raw)) + raw)
        elif op == "pb.string":
            raw = str(self._val(r, a[2])).encode("utf-8")
            buf.extend(proto_codec.encode_tag(int(self._val(r, a[1])), proto_codec.WIRE_LEN))
            buf.extend(proto_codec.encode_varint(len(raw)) + raw)
        elif op == "pb.message":
            raw = bytes(self._val(r, a[2]))
            buf.extend(proto_codec.encode_tag(int(self._val(r, a[1])), proto_codec.WIRE_LEN))
            buf.extend(proto_codec.encode_varint(len(raw)) + raw)
        elif op == "pb.fixed":
            field, value, width, signed = int(self._val(r, a[1])), self._val(r, a[2]), int(self._val(r, a[3])), bool(self._val(r, a[4]))
            typ = ("s" if signed else "") + ("fixed32" if width == 4 else "fixed64")
            buf.extend(proto_codec.encode_payload({"fields": [{"no": field, "name": "v", "type": typ}]}, {"v": value}))
        elif op == "pb.float32":
            buf.extend(proto_codec.encode_payload({"fields": [{"no": int(self._val(r, a[1])), "name": "v", "type": "float"}]}, {"v": self._val(r, a[2])}))
        elif op == "pb.float64":
            buf.extend(proto_codec.encode_payload({"fields": [{"no": int(self._val(r, a[1])), "name": "v", "type": "double"}]}, {"v": self._val(r, a[2])}))
        elif op == "pb.packed_begin":
            r[str(a[0])] = bytearray()
        elif op == "pb.packed_varint":
            buf.extend(proto_codec.encode_varint(int(self._val(r, a[1]))))
        elif op == "pb.packed_fixed":
            width = int(self._val(r, a[2]))
            buf.extend(int(self._val(r, a[1])).to_bytes(width, "little", signed=bool(self._val(r, a[3]))))
        elif op == "pb.packed_end":
            raw = bytes(self._val(r, a[2]))
            buf.extend(proto_codec.encode_tag(int(self._val(r, a[1])), proto_codec.WIRE_LEN))
            buf.extend(proto_codec.encode_varint(len(raw)) + raw)
        else:
            rfn_fail("E_COMPILE", f"unknown pb op: {op}")

    def _rd(self, r: dict[str, Any], op: str, a: tuple[Any, ...]) -> None:
        if op == "rd.new":
            r[str(a[0])] = Reader(bytes(self._val(r, a[1])))
            return
        reader = self._val(r, a[1] if op in {"rd.pos", "rd.len", "rd.left", "rd.eof"} else a[0])
        if op == "rd.pos":
            r[str(a[0])] = reader.pos
        elif op == "rd.len":
            r[str(a[0])] = len(reader.data)
        elif op == "rd.left":
            r[str(a[0])] = reader.left()
        elif op == "rd.eof":
            r[str(a[0])] = reader.left() == 0
        elif op == "rd.seek":
            reader.seek(int(self._val(r, a[1])))
        elif op == "rd.skip":
            reader.skip(int(self._val(r, a[1])))
        elif op == "rd.int":
            r[str(a[0])] = self._val(r, a[1]).read_int(int(self._val(r, a[2])), str(self._val(r, a[3])), bool(self._val(r, a[4])))
        elif op == "rd.bytes":
            r[str(a[0])] = self._val(r, a[1]).take(int(self._val(r, a[2])))
        elif op == "rd.varint":
            r[str(a[0])] = self._val(r, a[1]).read_varint()
        elif op == "rd.tag":
            tag = self._val(r, a[2]).read_varint()
            r[str(a[0])] = tag >> 3
            r[str(a[1])] = tag & 7
        elif op == "rd.skip_wire":
            rd = self._val(r, a[0])
            wt = int(self._val(r, a[1]))
            if wt == proto_codec.WIRE_VARINT:
                rd.read_varint()
            elif wt == proto_codec.WIRE_FIXED64:
                rd.take(8)
            elif wt == proto_codec.WIRE_LEN:
                rd.take(rd.read_varint())
            elif wt == proto_codec.WIRE_FIXED32:
                rd.take(4)
            else:
                rfn_fail("E_BAD_WIRE", f"bad wire type: {wt}")
        else:
            rfn_fail("E_COMPILE", f"unknown rd op: {op}")

    def _object(self, r: dict[str, Any], op: str, a: tuple[Any, ...]) -> None:
        if op == "obj.get":
            r[str(a[0])] = get_path(self._val(r, a[1]), str(self._val(r, a[2])))
        elif op == "obj.get_all":
            r[str(a[0])] = get_all_path(self._val(r, a[1]), str(self._val(r, a[2])))
        elif op == "obj.has":
            r[str(a[0])] = has_path(self._val(r, a[1]), str(self._val(r, a[2])))
        elif op == "obj.set":
            r[str(a[0])] = set_path(self._val(r, a[1]), str(self._val(r, a[2])), self._val(r, a[3]))
        elif op == "obj.del":
            r[str(a[0])] = del_path(self._val(r, a[1]), str(self._val(r, a[2])))
        elif op == "obj.keys":
            r[str(a[0])] = list((self._val(r, a[1]) or {}).keys())
        elif op == "arr.new":
            r[str(a[0])] = []
        elif op == "arr.from":
            r[str(a[0])] = [self._val(r, x) for x in a[1:]]
        elif op == "arr.len":
            r[str(a[0])] = len(self._val(r, a[1]))
        elif op == "arr.get":
            r[str(a[0])] = self._val(r, a[1])[int(self._val(r, a[2]))]
        elif op == "arr.push":
            arr = list(self._val(r, a[1]))
            arr.append(self._val(r, a[2]))
            r[str(a[0])] = arr
        elif op == "map.new":
            r[str(a[0])] = {}
        elif op == "map.from_pairs":
            r[str(a[0])] = {self._val(r, a[i]): self._val(r, a[i + 1]) for i in range(1, len(a), 2)}
        elif op == "map.get":
            r[str(a[0])] = self._val(r, a[1]).get(self._val(r, a[2]))
        elif op == "map.set":
            m = dict(self._val(r, a[1]) or {})
            m[self._val(r, a[2])] = self._val(r, a[3])
            r[str(a[0])] = m
        else:
            rfn_fail("E_COMPILE", f"unknown object op: {op}")

    def _scalar(self, r: dict[str, Any], op: str, a: tuple[Any, ...]) -> None:
        if op == "str.len":
            r[str(a[0])] = len(str(self._val(r, a[1])))
        elif op == "str.bytes_len":
            r[str(a[0])] = len(str(self._val(r, a[1])).encode("utf-8"))
        elif op == "str.cat":
            r[str(a[0])] = str(self._val(r, a[1])) + str(self._val(r, a[2]))
        elif op == "str.eq_icase":
            r[str(a[0])] = str(self._val(r, a[1])).lower() == str(self._val(r, a[2])).lower()
        elif op == "str.contains":
            r[str(a[0])] = str(self._val(r, a[2])) in str(self._val(r, a[1]))
        elif op == "str.starts":
            r[str(a[0])] = str(self._val(r, a[1])).startswith(str(self._val(r, a[2])))
        elif op == "str.ends":
            r[str(a[0])] = str(self._val(r, a[1])).endswith(str(self._val(r, a[2])))
        elif op == "str.to_lower":
            r[str(a[0])] = str(self._val(r, a[1])).lower()
        elif op == "str.to_upper":
            r[str(a[0])] = str(self._val(r, a[1])).upper()
        elif op == "str.hex_to_bytes":
            r[str(a[0])] = bytes.fromhex(str(self._val(r, a[1])).replace(" ", ""))
        elif op == "bytes.len":
            r[str(a[0])] = len(self._val(r, a[1]))
        elif op == "bytes.slice":
            b = self._val(r, a[1])
            r[str(a[0])] = b[int(self._val(r, a[2])) : int(self._val(r, a[2])) + int(self._val(r, a[3]))]
        elif op == "bytes.eq":
            r[str(a[0])] = self._val(r, a[1]) == self._val(r, a[2])
        elif op == "bytes.starts":
            r[str(a[0])] = self._val(r, a[1]).startswith(self._val(r, a[2]))
        elif op == "bytes.ends":
            r[str(a[0])] = self._val(r, a[1]).endswith(self._val(r, a[2]))
        elif op == "bytes.index_of":
            r[str(a[0])] = self._val(r, a[1]).find(self._val(r, a[2]))
        elif op == "bytes.hex":
            r[str(a[0])] = self._val(r, a[1]).hex()
        elif op.startswith("hash."):
            h = getattr(hashlib, op.split(".", 1)[1])
            r[str(a[0])] = h(bytes(self._val(r, a[1]))).hexdigest()
        else:
            rfn_fail("E_COMPILE", f"unknown scalar op: {op}")

    def _cap(self, fn: Function, r: dict[str, Any], op: str, a: tuple[Any, ...]) -> None:
        if op == "route.resolve":
            r[str(a[0])] = self.host.route_resolve(self._val(r, a[1]))
        elif op.startswith("route."):
            route = self._val(r, a[1])
            key = {"route.opcode": "opcode", "route.opcode_hex": "opcode_hex", "route.name": "name", "route.proto": "proto", "route.has_schema": "has_schema"}[op]
            r[str(a[0])] = route.get(key)
        elif op == "schema.encode":
            r[str(a[0])] = self.host.schema_encode(self._val(r, a[1]), self._val(r, a[2]))
        elif op == "schema.decode":
            r[str(a[0])] = self.host.schema_decode(self._val(r, a[1]), self._val(r, a[2]))
        elif op == "schema.decode_info":
            r[str(a[0])] = self.host.schema_decode_info(self._val(r, a[1]), self._val(r, a[2]))
        elif op == "schema.fields":
            schema = self.host.schema_for(self._val(r, a[1]))
            r[str(a[0])] = (schema or {}).get("fields", [])
        elif op.startswith("packet."):
            pkt = self._val(r, a[1])
            key = op.split(".", 1)[1]
            aliases = {"opcode_hex": "opcode_hex", "payload_len": "payload_len", "decode_source": "decode_source", "gcp_seq": "gcp_seq", "session_id": "session_id", "session_key_hash": "session_key_hash"}
            r[str(a[0])] = pkt.get(aliases.get(key, key))
        elif op == "cache.get":
            self.host.assert_capability(fn, "cache.read", scope=self._val(r, a[1]), prefix=self._val(r, a[2]))
            r[str(a[0])] = self.host.cache_get(str(self._val(r, a[1])), str(self._val(r, a[2])))
        elif op == "cache.set":
            self.host.assert_capability(fn, "cache.write", scope=self._val(r, a[0]), prefix=self._val(r, a[1]))
            self.host.cache_set(str(self._val(r, a[0])), str(self._val(r, a[1])), self._val(r, a[2]), int(self._val(r, a[3])))
        elif op == "cache.del":
            self.host.assert_capability(fn, "cache.write", scope=self._val(r, a[0]), prefix=self._val(r, a[1]))
            self.host.cache_del(str(self._val(r, a[0])), str(self._val(r, a[1])))
        elif op == "cache.has":
            self.host.assert_capability(fn, "cache.read", scope=self._val(r, a[1]), prefix=self._val(r, a[2]))
            r[str(a[0])] = self.host.cache_has(str(self._val(r, a[1])), str(self._val(r, a[2])))
        elif op == "cache.ttl":
            self.host.assert_capability(fn, "cache.read", scope=self._val(r, a[1]), prefix=self._val(r, a[2]))
            r[str(a[0])] = self.host.cache_ttl(str(self._val(r, a[1])), str(self._val(r, a[2])))
        elif op == "cache.incr":
            self.host.assert_capability(fn, "cache.write", scope=self._val(r, a[1]), prefix=self._val(r, a[2]))
            r[str(a[0])] = self.host.cache_incr(str(self._val(r, a[1])), str(self._val(r, a[2])), int(self._val(r, a[3])), int(self._val(r, a[4])))
        elif op == "cache.clear":
            self.host.assert_capability(fn, "cache.write", scope=self._val(r, a[0]), prefix=self._val(r, a[1]))
            self.host.cache_clear(str(self._val(r, a[0])), str(self._val(r, a[1])))
        elif op == "buffer.push":
            self.host.assert_capability(fn, "cache.write", scope=self._val(r, a[0]), prefix=self._val(r, a[1]))
            self.host.buffer_push(str(self._val(r, a[0])), str(self._val(r, a[1])), self._val(r, a[2]), int(self._val(r, a[3])), int(self._val(r, a[4])))
        elif op == "buffer.take":
            self.host.assert_capability(fn, "cache.read", scope=self._val(r, a[1]), prefix=self._val(r, a[2]))
            r[str(a[0])] = self.host.buffer_take(str(self._val(r, a[1])), str(self._val(r, a[2])), int(self._val(r, a[3])))
        elif op == "buffer.latest":
            self.host.assert_capability(fn, "cache.read", scope=self._val(r, a[1]), prefix=self._val(r, a[2]))
            r[str(a[0])] = self.host.buffer_latest(str(self._val(r, a[1])), str(self._val(r, a[2])))
        elif op == "buffer.clear":
            self.host.assert_capability(fn, "cache.write", scope=self._val(r, a[0]), prefix=self._val(r, a[1]))
            self.host.buffer_clear(str(self._val(r, a[0])), str(self._val(r, a[1])))
        elif op == "db.get":
            self.host.assert_capability(fn, "db.read", namespace=self._val(r, a[1]))
            r[str(a[0])] = self.host.db_get(str(self._val(r, a[1])), str(self._val(r, a[2])))
        elif op == "db.put":
            self.host.assert_capability(fn, "db.write", namespace=self._val(r, a[0]))
            self.host.db_put(str(self._val(r, a[0])), str(self._val(r, a[1])), self._val(r, a[2]), int(self._val(r, a[3])))
        elif op == "db.del":
            self.host.assert_capability(fn, "db.write", namespace=self._val(r, a[0]))
            self.host.db_del(str(self._val(r, a[0])), str(self._val(r, a[1])))
        elif op == "db.has":
            self.host.assert_capability(fn, "db.read", namespace=self._val(r, a[1]))
            r[str(a[0])] = self.host.db_has(str(self._val(r, a[1])), str(self._val(r, a[2])))
        elif op == "db.upsert":
            self.host.assert_capability(fn, "db.write", table=self._val(r, a[0]))
            self.host.db_upsert(str(self._val(r, a[0])), dict(self._val(r, a[1]) or {}), self._val(r, a[2]), int(self._val(r, a[3])))
        elif op == "db.select_one":
            self.host.assert_capability(fn, "db.read", table=self._val(r, a[1]))
            r[str(a[0])] = self.host.db_select_one(str(self._val(r, a[1])), dict(self._val(r, a[2]) or {}))
        elif op == "db.select_all":
            self.host.assert_capability(fn, "db.read", table=self._val(r, a[1]))
            r[str(a[0])] = self.host.db_select_all(str(self._val(r, a[1])), dict(self._val(r, a[2]) or {}), int(self._val(r, a[3])))
        elif op == "db.delete_where":
            if len(a) == 3:
                dst, table, where_obj = str(a[0]), self._val(r, a[1]), self._val(r, a[2])
                self.host.assert_capability(fn, "db.write", table=table)
                r[dst] = self.host.db_delete_where(str(table), dict(where_obj or {}))
            else:
                self.host.assert_capability(fn, "db.write", table=self._val(r, a[0]))
                self.host.db_delete_where(str(self._val(r, a[0])), dict(self._val(r, a[1]) or {}))
        elif op == "db.put_blob":
            self.host.assert_capability(fn, "db.write", namespace=self._val(r, a[0]))
            self.host.db_put_blob(str(self._val(r, a[0])), str(self._val(r, a[1])), bytes(self._val(r, a[2])), str(self._val(r, a[3])), int(self._val(r, a[4])))
        elif op == "db.get_blob":
            self.host.assert_capability(fn, "db.read", namespace=self._val(r, a[1]))
            r[str(a[0])] = self.host.db_get_blob(str(self._val(r, a[1])), str(self._val(r, a[2])))
        elif op == "db.expire":
            if len(a) == 2:
                self.host.assert_capability(fn, "db.write", namespace=self._val(r, a[1]))
                r[str(a[0])] = self.host.db_expire(str(self._val(r, a[1])))
            else:
                self.host.assert_capability(fn, "db.write", namespace=self._val(r, a[0]))
                self.host.db_expire(str(self._val(r, a[0])))
        elif op == "db.begin":
            self.host.assert_capability(fn, "db.write")
            r[str(a[0])] = self.host.db_begin()
        elif op == "db.commit":
            self.host.assert_capability(fn, "db.write")
            self.host.db_commit(str(self._val(r, a[0])) if a else "tx")
        elif op == "db.rollback":
            self.host.assert_capability(fn, "db.write")
            self.host.db_rollback(str(self._val(r, a[0])) if a else "tx")
        elif op == "db.exec":
            sql_id = str(self._val(r, a[1]))
            sql = self.host.sql_statements.get(sql_id, "")
            cap_name = "db.read" if sql.lstrip().lower().startswith("select") else "db.write"
            self.host.assert_capability(fn, cap_name)
            r[str(a[0])] = self.host.db_exec(sql_id, dict(self._val(r, a[2]) or {}))
        elif op == "http.req_method":
            self._assert_http_server(fn, self._val(r, a[1]))
            r[str(a[0])] = str((self._val(r, a[1]) or {}).get("method") or "").upper()
        elif op == "http.req_path":
            self._assert_http_server(fn, self._val(r, a[1]))
            r[str(a[0])] = (self._val(r, a[1]) or {}).get("path")
        elif op == "http.req_query":
            req = self._val(r, a[1])
            self._assert_http_server(fn, req)
            r[str(a[0])] = (req.get("query") or {}).get(str(self._val(r, a[2])))
        elif op == "http.req_header":
            req = self._val(r, a[1]) or {}
            self._assert_http_server(fn, req)
            headers = req.get("headers") or {}
            wanted = str(self._val(r, a[2])).lower()
            r[str(a[0])] = next((v for k, v in headers.items() if str(k).lower() == wanted), None)
        elif op == "http.req_json":
            req = self._val(r, a[1]) or {}
            self._assert_http_server(fn, req)
            body = req.get("json")
            if body is None and "body" in req:
                body = _json_body(req.get("body"))
            r[str(a[0])] = body
        elif op == "http.req_bytes":
            req = self._val(r, a[1]) or {}
            self._assert_http_server(fn, req)
            r[str(a[0])] = _bytes_body(req.get("body", b""))
        elif op == "http.resp_json":
            r[str(a[0])] = self.host.http_response_json(int(self._val(r, a[1])), self._val(r, a[2]))
        elif op == "http.resp_text":
            r[str(a[0])] = self.host.http_response_text(int(self._val(r, a[1])), str(self._val(r, a[2])))
        elif op == "http.resp_bytes":
            r[str(a[0])] = self.host.http_response_bytes(int(self._val(r, a[1])), _bytes_body(self._val(r, a[2])), str(self._val(r, a[3])))
        elif op == "http.get":
            url = str(self._val(r, a[1]))
            self.host.assert_capability(fn, "http.client", host=_url_host(url))
            r[str(a[0])] = self.host.http_client("GET", url, dict(self._val(r, a[2]) or {}), None, int(self._val(r, a[3])))
        elif op == "http.post_json":
            url = str(self._val(r, a[1]))
            self.host.assert_capability(fn, "http.client", host=_url_host(url))
            headers = {"content-type": "application/json", **dict(self._val(r, a[2]) or {})}
            r[str(a[0])] = self.host.http_client("POST", url, headers, self._val(r, a[3]), int(self._val(r, a[4])))
        elif op == "http.post_bytes":
            url = str(self._val(r, a[1]))
            self.host.assert_capability(fn, "http.client", host=_url_host(url))
            r[str(a[0])] = self.host.http_client("POST", url, dict(self._val(r, a[2]) or {}), _bytes_body(self._val(r, a[3])), int(self._val(r, a[4])))
        elif op == "http.status":
            r[str(a[0])] = int((self._val(r, a[1]) or {}).get("status") or 0)
        elif op == "http.json":
            r[str(a[0])] = _json_body((self._val(r, a[1]) or {}).get("body"))
        elif op == "http.bytes":
            r[str(a[0])] = _bytes_body((self._val(r, a[1]) or {}).get("body", b""))
        elif op == "inject.ready":
            r[str(a[0])] = self.host.mode in {"live", "replay"}
        elif op == "inject.send":
            target = self._val(r, a[1])
            self.host.assert_capability(fn, "inject.send", targets=target)
            r[str(a[0])] = self.host.inject_send(target, self._val(r, a[2]))
        elif op == "inject.send_hex":
            target = self._val(r, a[1])
            self.host.assert_capability(fn, "inject.send", targets=target)
            r[str(a[0])] = self.host.inject_send_hex(target, str(self._val(r, a[2])))
        elif op == "query.send":
            req, rsp = self._val(r, a[1]), self._val(r, a[3])
            timeout_ms = _optional_timeout_ms(self, r, a, 4)
            self.host.assert_capability(fn, "inject.query", targets=[req, rsp])
            r[str(a[0])] = self.host.query(req, self._val(r, a[2]), rsp, timeout_ms=timeout_ms)
        elif op == "query.where":
            req, rsp, pred_name = self._val(r, a[1]), self._val(r, a[3]), str(a[4])
            timeout_ms = _optional_timeout_ms(self, r, a, 5)
            self.host.assert_capability(fn, "inject.query", targets=[req, rsp])
            pred = lambda decoded, request: bool(self.call(pred_name, decoded, request))
            r[str(a[0])] = self.host.query(req, self._val(r, a[2]), rsp, predicate=pred, timeout_ms=timeout_ms)
        elif op == "query.singleflight_where":
            key, req, rsp, pred_name = str(self._val(r, a[1])), self._val(r, a[2]), self._val(r, a[4]), str(a[5])
            timeout_ms = _optional_timeout_ms(self, r, a, 6)
            self.host.assert_capability(fn, "inject.query", targets=[req, rsp])
            pred = lambda decoded, request: bool(self.call(pred_name, decoded, request))
            r[str(a[0])] = self.host.query(req, self._val(r, a[3]), rsp, predicate=pred, singleflight_key=key, timeout_ms=timeout_ms)
        elif op == "query.singleflight":
            key, req, rsp = str(self._val(r, a[1])), self._val(r, a[2]), self._val(r, a[4])
            timeout_ms = _optional_timeout_ms(self, r, a, 5)
            self.host.assert_capability(fn, "inject.query", targets=[req, rsp])
            r[str(a[0])] = self.host.query(req, self._val(r, a[3]), rsp, singleflight_key=key, timeout_ms=timeout_ms)
        elif op == "inject.ok":
            r[str(a[0])] = bool((self._val(r, a[1]) or {}).get("ok"))
        elif op == "inject.info":
            result = dict(self._val(r, a[1]) or {})
            r[str(a[0])] = {k: v for k, v in result.items() if k not in {"payload", "decoded"}}
        elif op == "inject.decoded":
            r[str(a[0])] = (self._val(r, a[1]) or {}).get("decoded")
        elif op == "inject.payload":
            r[str(a[0])] = (self._val(r, a[1]) or {}).get("payload")
        elif op == "inject.error":
            result = self._val(r, a[1]) or {}
            r[str(a[0])] = result.get("error") or result.get("error_code")
        elif op == "session.disconnect":
            reason = str(self._val(r, a[1])) if len(a) > 1 else "rfn.session.disconnect"
            self.host.assert_capability(fn, "session.control")
            r[str(a[0])] = self.host.session_disconnect(reason)
        elif op == "schedule.after":
            job_key = str(self._val(r, a[4]))
            self.host.assert_capability(fn, "schedule.write", job_prefix=job_key)
            r[str(a[0])] = self.host.schedule_after(int(self._val(r, a[1])), str(a[2]), list(self._val(r, a[3]) or []), job_key)
        elif op == "schedule.every":
            job_key = str(self._val(r, a[4]))
            self.host.assert_capability(fn, "schedule.write", job_prefix=job_key)
            r[str(a[0])] = self.host.schedule_every(int(self._val(r, a[1])), str(a[2]), list(self._val(r, a[3]) or []), job_key)
        elif op == "schedule.cron":
            job_key = str(self._val(r, a[4]))
            self.host.assert_capability(fn, "schedule.write", job_prefix=job_key)
            r[str(a[0])] = self.host.schedule_cron(str(self._val(r, a[1])), str(a[2]), list(self._val(r, a[3]) or []), job_key)
        elif op == "schedule.cancel":
            job_key = str(self._val(r, a[0]))
            self.host.assert_capability(fn, "schedule.write", job_prefix=job_key)
            self.host.schedule_cancel(job_key)
        elif op == "schedule.exists":
            job_key = str(self._val(r, a[1]))
            self.host.assert_capability(fn, "schedule.write", job_prefix=job_key)
            r[str(a[0])] = self.host.schedule_exists(job_key)
        elif op == "schedule.next":
            job_key = str(self._val(r, a[1]))
            self.host.assert_capability(fn, "schedule.write", job_prefix=job_key)
            r[str(a[0])] = self.host.schedule_next(job_key)
        elif op == "event.emit":
            name = str(self._val(r, a[0]))
            self.host.assert_capability(fn, "event.emit", prefix=name)
            self.host.event_emit(name, self._val(r, a[1]))
        elif op == "event.name":
            r[str(a[0])] = (self._val(r, a[1]) or {}).get("name")
        elif op == "event.payload":
            r[str(a[0])] = (self._val(r, a[1]) or {}).get("payload")
        elif op == "audit.write":
            self.host.audit(str(self._val(r, a[0])), str(self._val(r, a[1])), str(self._val(r, a[2])), dict(self._val(r, a[3]) or {}))
        elif op == "audit.metric":
            self.host.audit_metric(str(self._val(r, a[0])), self._val(r, a[1]), dict(self._val(r, a[2]) or {}))
        elif op == "audit.attach_packet":
            if len(a) == 3:
                detail = _attach_packet(dict(self._val(r, a[1]) or {}), self._val(r, a[2]) or {})
                r[str(a[0])] = detail
            else:
                detail = self._val(r, a[0])
                if not isinstance(detail, dict):
                    rfn_fail("E_TYPE", "audit.attach_packet detail must be object")
                detail.update(_packet_audit_fields(self._val(r, a[1]) or {}))
        elif op == "file.exists":
            path = self._val(r, a[1])
            self.host.assert_capability(fn, "file.read", path=path)
            r[str(a[0])] = self.host.file_exists(path)
        elif op == "file.is_file":
            path = self._val(r, a[1])
            self.host.assert_capability(fn, "file.read", path=path)
            r[str(a[0])] = self.host.file_is_file(path)
        elif op == "file.is_dir":
            path = self._val(r, a[1])
            self.host.assert_capability(fn, "file.read", path=path)
            r[str(a[0])] = self.host.file_is_dir(path)
        elif op == "file.stat":
            path = self._val(r, a[1])
            self.host.assert_capability(fn, "file.read", path=path)
            r[str(a[0])] = self.host.file_stat(path)
        elif op == "file.list":
            path = self._val(r, a[1])
            self.host.assert_capability(fn, "file.read", path=path)
            r[str(a[0])] = self.host.file_list(path)
        elif op == "file.read_text":
            path = self._val(r, a[1])
            self.host.assert_capability(fn, "file.read", path=path)
            r[str(a[0])] = self.host.file_read_text(path, str(self._val(r, a[2])), int(self._val(r, a[3])))
        elif op == "file.read_bytes":
            path = self._val(r, a[1])
            self.host.assert_capability(fn, "file.read", path=path)
            r[str(a[0])] = self.host.file_read_bytes(path, int(self._val(r, a[2])))
        elif op == "file.write_text":
            path = self._val(r, a[0])
            self.host.assert_capability(fn, "file.write", path=path)
            self.host.file_write_text(path, str(self._val(r, a[1])), str(self._val(r, a[2])), bool(self._val(r, a[3])))
        elif op == "file.append_text":
            path = self._val(r, a[0])
            self.host.assert_capability(fn, "file.write", path=path)
            self.host.file_append_text(path, str(self._val(r, a[1])), str(self._val(r, a[2])), bool(self._val(r, a[3])))
        elif op == "file.write_bytes":
            path = self._val(r, a[0])
            self.host.assert_capability(fn, "file.write", path=path)
            self.host.file_write_bytes(path, _bytes_body(self._val(r, a[1])), bool(self._val(r, a[2])))
        elif op == "file.mkdir":
            path = self._val(r, a[0])
            self.host.assert_capability(fn, "file.write", path=path)
            self.host.file_mkdir(path)
        elif op == "file.remove":
            path = self._val(r, a[0])
            self.host.assert_capability(fn, "file.write", path=path)
            self.host.file_remove(path)
        elif op == "file.copy":
            src, dst = self._val(r, a[0]), self._val(r, a[1])
            self.host.assert_capability(fn, "file.read", path=src)
            self.host.assert_capability(fn, "file.write", path=dst)
            self.host.file_copy(src, dst, bool(self._val(r, a[2])))
        elif op == "file.move":
            src, dst = self._val(r, a[0]), self._val(r, a[1])
            self.host.assert_capability(fn, "file.write", path=src)
            self.host.assert_capability(fn, "file.write", path=dst)
            self.host.file_move(src, dst, bool(self._val(r, a[2])))
        else:
            rfn_fail("E_COMPILE", f"unsupported capability op: {op}")

    def _assert_http_server(self, fn: Function, req: dict[str, Any] | None) -> None:
        path = (req or {}).get("path")
        if path is None:
            self.host.assert_capability(fn, "http.server")
        else:
            self.host.assert_capability(fn, "http.server", path=path)


def _url_host(url: str) -> str:
    host = urllib.parse.urlparse(url).hostname
    if not host:
        rfn_fail("E_HTTP", f"bad url: {url}")
    return host


def _optional_timeout_ms(vm: RFNVM, r: dict[str, Any], args: tuple[Any, ...], index: int) -> int | None:
    if len(args) <= index:
        return None
    value = vm._val(r, args[index])
    if value in (None, ""):
        return None
    return int(value)


def _json_body(body: Any) -> Any:
    if body is None:
        return None
    if isinstance(body, (dict, list, int, float, bool)):
        return body
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    if isinstance(body, str):
        return json.loads(body)
    return body


def _bytes_body(body: Any) -> bytes:
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, bytearray):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


def _packet_audit_fields(pkt: dict[str, Any]) -> dict[str, Any]:
    return {
        "frame": pkt.get("frame"),
        "opcode": pkt.get("opcode_hex") or pkt.get("opcode"),
        "direction": pkt.get("direction"),
        "session_id": pkt.get("session_id"),
        "gcp_seq": pkt.get("gcp_seq"),
    }


def _attach_packet(detail: dict[str, Any], pkt: dict[str, Any]) -> dict[str, Any]:
    out = dict(detail)
    out.update(_packet_audit_fields(pkt))
    return out


class _Jump:
    def __init__(self, label: str):
        self.label = label


class _Return:
    def __init__(self, value: Any):
        self.value = value
