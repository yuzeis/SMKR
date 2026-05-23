from __future__ import annotations

import json
import re
import shlex
from typing import Any

from .errors import rfn_fail
from .model import Capability, Function, Instruction, Module

_FUNC_RE = re.compile(r"^\.function\s+([A-Za-z_][\w.]*)\((.*?)\)\s*->\s*([\w_]+)")


def assemble_source(source: str, *, module_name: str = "main") -> Module:
    module = Module(name=module_name)
    current: Function | None = None

    for line_no, raw in enumerate(source.splitlines(), 1):
        line = _strip_comment(raw).strip()
        if not line:
            continue
        if line.startswith(".module "):
            module.name = line.split(None, 1)[1].strip()
            continue
        if line.startswith(".version "):
            module.version = line.split(None, 1)[1].strip()
            continue
        if line.startswith(".target "):
            module.target = line.split(None, 1)[1].strip()
            continue
        if line.startswith(".registry_pin "):
            module.registry_pin = json.loads(line.split(None, 1)[1])
            continue
        if line.startswith(".function "):
            if current is not None:
                rfn_fail("E_PARSE", f"nested function at line {line_no}")
            m = _FUNC_RE.match(line)
            if not m:
                rfn_fail("E_PARSE", f"bad function declaration at line {line_no}")
            name, args_s, ret = m.groups()
            current = Function(name=name, args=_parse_args(args_s), return_type=ret)
            continue
        if line == ".end":
            if current is None:
                rfn_fail("E_PARSE", f".end without function at line {line_no}")
            if current.name in module.functions:
                rfn_fail("E_COMPILE", f"duplicate function: {current.name}")
            module.functions[current.name] = current
            current = None
            continue
        if current is None:
            rfn_fail("E_PARSE", f"instruction outside function at line {line_no}")

        if line.startswith("."):
            _parse_attr(current, line, line_no)
            continue
        if line.endswith(":"):
            label = line[:-1].strip()
            if not label:
                rfn_fail("E_PARSE", f"empty label at line {line_no}")
            current.labels[label] = len(current.instructions)
            continue
        inst = _parse_instruction(line, line_no)
        if inst.op == "label":
            current.labels[str(inst.args[0])] = len(current.instructions)
            continue
        current.instructions.append(inst)

    if current is not None:
        rfn_fail("E_PARSE", f"function {current.name} missing .end")
    _check_module(module)
    return module


def _strip_comment(line: str) -> str:
    in_quote = False
    escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_quote:
            escaped = True
            continue
        if ch == '"':
            in_quote = not in_quote
            continue
        if ch == ";" and not in_quote:
            return line[:i]
    return line


def _parse_args(args_s: str) -> list[tuple[str, str]]:
    if not args_s.strip():
        return []
    out: list[tuple[str, str]] = []
    for part in args_s.split(","):
        name_type = part.strip().split("=", 1)[0].strip()
        if ":" not in name_type:
            rfn_fail("E_PARSE", f"bad argument: {part}")
        name, typ = [x.strip() for x in name_type.split(":", 1)]
        out.append((name, typ))
    return out


def _parse_attr(fn: Function, line: str, line_no: int) -> None:
    parts = shlex.split(line, posix=False)
    key = parts[0]
    if key == ".no_side_effect":
        fn.no_side_effect = _parse_bool(parts[1])
    elif key == ".deterministic":
        fn.deterministic = _parse_bool(parts[1])
    elif key == ".pure":
        rfn_fail("E_COMPILE", f".pure is not a v0.1 attribute at line {line_no}")
    elif key == ".capability":
        if len(parts) < 2:
            rfn_fail("E_PARSE", f"missing capability name at line {line_no}")
        name = _unquote(parts[1])
        scope: dict[str, Any] = {}
        for item in parts[2:]:
            if "=" not in item:
                rfn_fail("E_PARSE", f"bad capability scope at line {line_no}: {item}")
            k, v = item.split("=", 1)
            scope[k] = _literal(v)
        fn.capabilities.append(Capability(name=name, scope=scope))
    elif key == ".timeout_ms":
        fn.timeout_ms = int(parts[1])
    elif key == ".max_ops":
        fn.max_ops = int(parts[1])
    elif key == ".max_output_bytes":
        fn.max_output_bytes = int(parts[1])
    elif key == ".desc":
        fn.desc = _unquote(" ".join(parts[1:]))
    else:
        rfn_fail("E_PARSE", f"unknown attribute {key} at line {line_no}")


def _parse_instruction(line: str, line_no: int) -> Instruction:
    lexer = shlex.shlex(line, posix=False)
    lexer.whitespace += ","
    lexer.whitespace_split = True
    tokens = list(lexer)
    if not tokens:
        rfn_fail("E_PARSE", f"empty instruction at line {line_no}")
    return Instruction(tokens[0], tuple(_literal(t) for t in tokens[1:]), line_no, line)


def _literal(token: str) -> Any:
    token = token.strip()
    if token == "true":
        return True
    if token == "false":
        return False
    if token == "nil":
        return None
    if token.startswith('hex"') and token.endswith('"'):
        return bytes.fromhex(token[4:-1].replace(" ", ""))
    if token.startswith('"') and token.endswith('"'):
        return _unquote(token)
    if re.fullmatch(r"-?0x[0-9a-fA-F]+", token):
        return int(token, 16)
    if re.fullmatch(r"-?\d+", token):
        return int(token, 10)
    return token


def _unquote(value: str) -> str:
    value = value.strip()
    if value.startswith('"') and value.endswith('"'):
        return value[1:-1].encode("utf-8").decode("unicode_escape")
    return value


def _parse_bool(value: str) -> bool:
    v = value.strip().lower()
    if v == "true":
        return True
    if v == "false":
        return False
    rfn_fail("E_PARSE", f"bad bool: {value}")


def _check_module(module: Module) -> None:
    for fn in module.functions.values():
        if fn.no_side_effect:
            for cap in fn.capabilities:
                if cap.name not in {"db.read", "cache.read", "file.read"}:
                    rfn_fail("E_PERMISSION", f"{fn.name} is no_side_effect but declares {cap.name}")
        for inst in fn.instructions:
            if inst.op in {"jmp", "jz", "jnz", "jeq", "jne", "jlt", "jle", "jgt", "jge"}:
                label = inst.args[-1]
                if isinstance(label, str) and label not in fn.labels:
                    rfn_fail("E_COMPILE", f"unknown label {label} in {fn.name}")
            if inst.op == "call":
                target = inst.args[1] if len(inst.args) > 1 else None
                if isinstance(target, str) and target.startswith("Function."):
                    short = target.split("Function.", 1)[1]
                    if short not in module.functions:
                        rfn_fail("E_COMPILE", f"unknown call target {target}")
