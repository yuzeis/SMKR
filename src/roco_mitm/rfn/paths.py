from __future__ import annotations

from copy import deepcopy
from typing import Any

from .errors import rfn_fail


def parse_path(path: str) -> list[str | int]:
    parts: list[str | int] = []
    i = 0
    token = ""
    while i < len(path):
        ch = path[i]
        if ch == ".":
            if token:
                parts.append(token)
                token = ""
            i += 1
            continue
        if ch == "[":
            if token:
                parts.append(token)
                token = ""
            end = path.find("]", i)
            if end < 0:
                rfn_fail("E_PARSE", f"bad path: {path}")
            inner = path[i + 1 : end]
            if inner == "*":
                parts.append("*")
            else:
                try:
                    parts.append(int(inner))
                except ValueError:
                    rfn_fail("E_PARSE", f"bad path index: {path}")
            i = end + 1
            continue
        token += ch
        i += 1
    if token:
        parts.append(token)
    return parts


def get_path(obj: Any, path: str) -> Any:
    if "*" in path:
        rfn_fail("E_TYPE", "obj.get does not accept wildcard paths; use obj.get_all")
    cur = obj
    for part in parse_path(path):
        if isinstance(part, int):
            if not isinstance(cur, list) or part < 0 or part >= len(cur):
                return None
            cur = cur[part]
        else:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        if cur is None:
            return None
    return cur


def get_all_path(obj: Any, path: str) -> list[Any]:
    parts = parse_path(path)
    if "*" not in parts:
        rfn_fail("E_TYPE", "obj.get_all requires a wildcard path")

    def walk(value: Any, rest: list[str | int]) -> list[Any]:
        if not rest:
            return [value]
        part = rest[0]
        tail = rest[1:]
        if part == "*":
            if not isinstance(value, list):
                return []
            out: list[Any] = []
            for item in value:
                out.extend(walk(item, tail))
            return out
        if isinstance(part, int):
            if not isinstance(value, list) or part < 0 or part >= len(value):
                return []
            return walk(value[part], tail)
        if not isinstance(value, dict) or part not in value:
            return []
        return walk(value[part], tail)

    return walk(obj, parts)


def has_path(obj: Any, path: str) -> bool:
    return bool(get_all_path(obj, path)) if "*" in path else get_path(obj, path) is not None


def set_path(obj: Any, path: str, value: Any) -> Any:
    if "*" in path:
        rfn_fail("E_TYPE", "obj.set does not accept wildcard paths")
    out = deepcopy(obj)
    cur = out
    parts = parse_path(path)
    for part in parts[:-1]:
        if isinstance(part, int):
            if not isinstance(cur, list) or part < 0 or part >= len(cur):
                rfn_fail("E_RANGE", f"bad path: {path}")
            cur = cur[part]
        else:
            if not isinstance(cur, dict):
                rfn_fail("E_TYPE", f"bad path: {path}")
            cur = cur.setdefault(part, {})
    last = parts[-1]
    if isinstance(last, int):
        if not isinstance(cur, list) or last < 0 or last >= len(cur):
            rfn_fail("E_RANGE", f"bad path: {path}")
        cur[last] = value
    else:
        if not isinstance(cur, dict):
            rfn_fail("E_TYPE", f"bad path: {path}")
        cur[last] = value
    return out


def del_path(obj: Any, path: str) -> Any:
    if "*" in path:
        rfn_fail("E_TYPE", "obj.del does not accept wildcard paths")
    out = deepcopy(obj)
    cur = out
    parts = parse_path(path)
    for part in parts[:-1]:
        cur = cur[part] if isinstance(part, int) else cur.get(part)
        if cur is None:
            return out
    last = parts[-1]
    if isinstance(last, int) and isinstance(cur, list) and 0 <= last < len(cur):
        del cur[last]
    elif isinstance(last, str) and isinstance(cur, dict):
        cur.pop(last, None)
    return out

