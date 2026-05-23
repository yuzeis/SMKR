from __future__ import annotations

import json
import shutil
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from roco_mitm.codec import proto_codec
from roco_mitm.codec.opcode_payload import decode_opcode_payload
from roco_mitm.codec.opcode_registry import OpcodeRegistry

from .errors import rfn_fail
from .model import Capability, Function


@dataclass
class QueryPair:
    req_target: str
    rsp_target: str
    request: dict[str, Any]
    response: dict[str, Any]
    request_frame: int = 0
    response_frame: int = 0
    latency_ms: int = 0


@dataclass
class RFNHost:
    registry: OpcodeRegistry | None = None
    db_path: Path | None = None
    mode: str = "replay"
    packet: dict[str, Any] | None = None
    http_request: dict[str, Any] | None = None
    observed_pairs: list[QueryPair] = field(default_factory=list)
    http_mocks: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    sql_statements: dict[str, str] = field(default_factory=dict)
    file_root: Path | None = None
    inject_func: Callable[[int, bytes, int | None], dict[str, Any]] | None = None
    session_disconnect_func: Callable[[str], dict[str, Any]] | None = None
    query_func: Callable[[Any, Any, Any, Callable[[dict, dict], bool] | None, str | None, int], dict[str, Any]] | None = None
    default_query_timeout_ms: int = 3000

    def __post_init__(self) -> None:
        self._lock = threading.RLock()
        self.cache: dict[tuple[str, str], tuple[Any, float]] = {}
        self.buffers: dict[tuple[str, str], deque[Any]] = {}
        self.audit_events: list[dict[str, Any]] = []
        self.jobs: dict[str, dict[str, Any]] = {}
        self.injected: list[dict[str, Any]] = []
        self.events: list[dict[str, Any]] = []
        self.singleflight_keys: set[str] = set()
        self.metrics: list[dict[str, Any]] = []
        self._db: sqlite3.Connection | None = None
        self._in_tx = False
        if self.db_path is not None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(self.db_path, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            self._init_db()
        self.file_root = (self.file_root or Path.cwd()).resolve()

    def close(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    def assert_capability(self, fn: Function, name: str, **need: Any) -> Capability:
        for cap in fn.capabilities:
            if cap.name != name:
                continue
            if _scope_allows(cap.scope, need):
                return cap
        rfn_fail("E_PERMISSION", f"{fn.name} missing capability {name} scope={need}")

    def route_resolve(self, target: Any) -> dict[str, Any]:
        if isinstance(target, int):
            meta = self.registry.get_opcode_meta(target) if self.registry else None
            return _route_from_meta(target, meta)
        s = str(target)
        if s.lower().startswith("0x"):
            opcode = int(s, 16)
            meta = self.registry.get_opcode_meta(opcode) if self.registry else None
            return _route_from_meta(opcode, meta)
        if self.registry is not None:
            for meta in self.registry.list_opcodes():
                names = {
                    str(meta.get("name") or ""),
                    str(meta.get("decode_as") or ""),
                    str(meta.get("proto_name") or ""),
                    str(meta.get("enum_name") or ""),
                }
                if s in names or f".{s}" in names:
                    return _route_from_meta(int(meta["id"]), meta)
            msg = self.registry.resolve_message(s)
            if msg is not None:
                return {"opcode": None, "opcode_hex": None, "name": s.rsplit(".", 1)[-1], "proto": s, "has_schema": True}
        return {"opcode": None, "opcode_hex": None, "name": s, "proto": s, "has_schema": False}

    def schema_for(self, target: Any) -> dict | None:
        route = self.route_resolve(target)
        if self.registry is None:
            return None
        if route.get("opcode") is not None:
            return self.registry.get_opcode_schema(int(route["opcode"]))
        proto = route.get("proto")
        return self.registry.resolve_message(proto) if proto else None

    def schema_encode(self, target: Any, obj: dict[str, Any]) -> bytes:
        schema = self.schema_for(target)
        if schema is None:
            rfn_fail("E_SCHEMA", f"schema not found: {target}")
        return proto_codec.encode_payload(schema, obj, resolve_message=self._resolve_message)

    def schema_decode(self, target: Any, payload: bytes) -> dict[str, Any]:
        schema = self.schema_for(target)
        if schema is None:
            rfn_fail("E_SCHEMA", f"schema not found: {target}")
        return proto_codec.decode_payload(schema, payload, resolve_message=self._resolve_message)

    def schema_decode_info(self, target: Any, payload: bytes) -> dict[str, Any]:
        schema = self.schema_for(target)
        if schema is None:
            rfn_fail("E_SCHEMA", f"schema not found: {target}")
        if self.registry is None:
            decoded = proto_codec.decode_payload(schema, payload)
            return {"decoded": decoded, "source": "schema", "consumed": len(payload), "unknown": 0}
        result = decode_opcode_payload(schema, payload, self.registry.resolve_message)
        return {
            "decoded": result.decoded,
            "source": result.source,
            "start": result.start,
            "consumed": result.consumed,
            "unknown": result.unknown_recursive,
        }

    def cache_get(self, scope: str, key: str) -> Any:
        with self._lock:
            item = self.cache.get((scope, key))
            if not item:
                return None
            value, expires = item
            if expires and expires <= time.time():
                self.cache.pop((scope, key), None)
                return None
            return value

    def cache_set(self, scope: str, key: str, value: Any, ttl_ms: int) -> bool:
        expires = time.time() + ttl_ms / 1000 if ttl_ms else 0
        with self._lock:
            self.cache[(scope, key)] = (value, expires)
        self.audit("cache.set", key, "ok", {"scope": scope})
        return True

    def cache_del(self, scope: str, key: str) -> bool:
        with self._lock:
            self.cache.pop((scope, key), None)
        self.audit("cache.del", key, "ok", {"scope": scope})
        return True

    def cache_has(self, scope: str, key: str) -> bool:
        return self.cache_get(scope, key) is not None

    def cache_ttl(self, scope: str, key: str) -> int:
        item = self.cache.get((scope, key))
        if not item:
            return 0
        _value, expires = item
        if not expires:
            return 0
        left = int((expires - time.time()) * 1000)
        return max(0, left)

    def cache_incr(self, scope: str, key: str, delta: int, ttl_ms: int) -> int:
        with self._lock:
            value = self.cache_get(scope, key)
            new_value = int(value or 0) + int(delta)
            self.cache_set(scope, key, new_value, ttl_ms)
            return new_value

    def cache_clear(self, scope: str, prefix: str) -> int:
        with self._lock:
            keys = [k for k in self.cache if k[0] == scope and k[1].startswith(prefix)]
            for key in keys:
                self.cache.pop(key, None)
        self.audit("cache.clear", prefix, "ok", {"scope": scope, "count": len(keys)})
        return len(keys)

    def buffer_push(self, scope: str, key: str, value: Any, limit: int, ttl_ms: int) -> bool:
        with self._lock:
            q = self.buffers.setdefault((scope, key), deque(maxlen=max(1, int(limit))))
            expires = time.time() + ttl_ms / 1000 if ttl_ms else 0
            q.append((value, expires))
            self._purge_buffer(scope, key)
            count = len(q)
        self.audit("buffer.push", key, "ok", {"scope": scope, "count": count})
        return True

    def buffer_take(self, scope: str, key: str, limit: int) -> list[Any]:
        with self._lock:
            q = self._purge_buffer(scope, key)
            return [value for value, _expires in list(q)[-int(limit) :]]

    def buffer_latest(self, scope: str, key: str) -> Any:
        with self._lock:
            q = self._purge_buffer(scope, key)
            return q[-1][0] if q else None

    def buffer_clear(self, scope: str, key: str) -> bool:
        with self._lock:
            self.buffers.pop((scope, key), None)
        self.audit("buffer.clear", key, "ok", {"scope": scope})
        return True

    def db_get(self, namespace: str, key: str) -> Any:
        if self._db is None:
            return self.cache_get(f"db:{namespace}", key)
        with self._lock:
            row = self._db.execute(
                "SELECT value_json, expires_at FROM kv WHERE namespace=? AND key=?",
                (namespace, key),
            ).fetchone()
        if row is None:
            return None
        expires = int(row["expires_at"] or 0)
        if expires and expires <= int(time.time() * 1000):
            return None
        return json.loads(row["value_json"])

    def db_put(self, namespace: str, key: str, value: Any, ttl_ms: int) -> bool:
        if self._db is None:
            self.cache_set(f"db:{namespace}", key, value, ttl_ms)
            return True
        now = int(time.time() * 1000)
        expires = now + int(ttl_ms) if ttl_ms else 0
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO kv(namespace,key,value_json,expires_at,session_id,updated_at) VALUES(?,?,?,?,?,?)",
                (namespace, key, json.dumps(value, ensure_ascii=False), expires, "", now),
            )
            self._commit_if_needed()
        self.audit("db.put", key, "ok", {"namespace": namespace})
        return True

    def db_del(self, namespace: str, key: str) -> bool:
        if self._db is None:
            self.cache_del(f"db:{namespace}", key)
            return True
        with self._lock:
            self._db.execute("DELETE FROM kv WHERE namespace=? AND key=?", (namespace, key))
            self._commit_if_needed()
        self.audit("db.del", key, "ok", {"namespace": namespace})
        return True

    def db_has(self, namespace: str, key: str) -> bool:
        return self.db_get(namespace, key) is not None

    def db_upsert(self, table: str, key_obj: dict[str, Any], value_obj: Any, ttl_ms: int) -> bool:
        if self._db is None:
            self.cache_set(f"table:{table}", _json_key(key_obj), value_obj, ttl_ms)
            return True
        now = int(time.time() * 1000)
        expires = now + int(ttl_ms) if ttl_ms else 0
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO tables(name,key_json,value_json,expires_at,updated_at) VALUES(?,?,?,?,?)",
                (table, _json_key(key_obj), json.dumps(value_obj, ensure_ascii=False, sort_keys=True), expires, now),
            )
            self._commit_if_needed()
        self.audit("db.upsert", table, "ok", {"key": key_obj})
        return True

    def db_select_all(self, table: str, where_obj: dict[str, Any], limit: int) -> list[Any]:
        if self._db is None:
            prefix = f"table:{table}"
            out = []
            for (scope, _key), (value, _expires) in self.cache.items():
                if scope == prefix and _matches_where(value, where_obj):
                    out.append(value)
                    if len(out) >= limit:
                        break
            return out
        with self._lock:
            rows = self._db.execute(
                "SELECT key_json,value_json,expires_at FROM tables WHERE name=? ORDER BY updated_at DESC",
                (table,),
            ).fetchall()
        now = int(time.time() * 1000)
        out: list[Any] = []
        for row in rows:
            expires = int(row["expires_at"] or 0)
            if expires and expires <= now:
                continue
            key = json.loads(row["key_json"])
            value = json.loads(row["value_json"])
            merged = dict(value) if isinstance(value, dict) else {"value": value}
            merged.update({f"key.{k}": v for k, v in key.items()})
            if _matches_where(merged, where_obj) or _matches_where(key, where_obj) or _matches_where(value, where_obj):
                out.append(value)
                if len(out) >= int(limit):
                    break
        return out

    def db_select_one(self, table: str, where_obj: dict[str, Any]) -> Any:
        rows = self.db_select_all(table, where_obj, 1)
        return rows[0] if rows else None

    def db_delete_where(self, table: str, where_obj: dict[str, Any]) -> int:
        if self._db is None:
            return 0
        with self._lock:
            rows = self._db.execute("SELECT key_json,value_json FROM tables WHERE name=?", (table,)).fetchall()
            deleted = 0
            for row in rows:
                key = json.loads(row["key_json"])
                value = json.loads(row["value_json"])
                if _matches_where(key, where_obj) or _matches_where(value, where_obj):
                    self._db.execute("DELETE FROM tables WHERE name=? AND key_json=?", (table, row["key_json"]))
                    deleted += 1
            self._commit_if_needed()
        self.audit("db.delete_where", table, "ok", {"count": deleted})
        return deleted

    def db_expire(self, namespace_or_table: str) -> int:
        if self._db is None:
            return 0
        now = int(time.time() * 1000)
        with self._lock:
            cur1 = self._db.execute(
                "DELETE FROM kv WHERE namespace=? AND expires_at>0 AND expires_at<=?",
                (namespace_or_table, now),
            )
            cur2 = self._db.execute(
                "DELETE FROM tables WHERE name=? AND expires_at>0 AND expires_at<=?",
                (namespace_or_table, now),
            )
            self._commit_if_needed()
            count = int(cur1.rowcount or 0) + int(cur2.rowcount or 0)
        self.audit("db.expire", namespace_or_table, "ok", {"count": count})
        return count

    def db_begin(self) -> str:
        if self._db is not None:
            with self._lock:
                if self._in_tx:
                    rfn_fail("E_DB", "transaction already open")
                self._db.execute("BEGIN")
                self._in_tx = True
        return "tx"

    def db_commit(self, tx: str = "tx") -> bool:
        del tx
        if self._db is not None:
            with self._lock:
                self._db.commit()
                self._in_tx = False
        return True

    def db_rollback(self, tx: str = "tx") -> bool:
        del tx
        if self._db is not None:
            with self._lock:
                self._db.rollback()
                self._in_tx = False
        return True

    def db_exec(self, sql_id: str, params: dict[str, Any]) -> dict[str, Any]:
        if self._db is None:
            rfn_fail("E_DB", "db.exec requires sqlite host")
        sql = self.sql_statements.get(sql_id)
        if not sql:
            rfn_fail("E_PERMISSION", f"unregistered sql_id: {sql_id}")
        with self._lock:
            cur = self._db.execute(sql, params)
            if sql.lstrip().lower().startswith("select"):
                rows = [dict(row) for row in cur.fetchall()]
                return {"ok": True, "rows": rows, "rowcount": len(rows)}
            self._commit_if_needed()
            rowcount = cur.rowcount
        self.audit("db.exec", sql_id, "ok", {"rowcount": rowcount})
        return {"ok": True, "rows": [], "rowcount": rowcount}

    def db_put_blob(self, namespace: str, key: str, value: bytes, content_type: str, ttl_ms: int) -> bool:
        if self._db is None:
            self.cache_set(f"blob:{namespace}", key, {"value": value, "content_type": content_type}, ttl_ms)
            return True
        now = int(time.time() * 1000)
        expires = now + int(ttl_ms) if ttl_ms else 0
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO blobs(namespace,key,value,content_type,expires_at,session_id,updated_at) VALUES(?,?,?,?,?,?,?)",
                (namespace, key, value, content_type, expires, "", now),
            )
            self._commit_if_needed()
        self.audit("db.put_blob", key, "ok", {"namespace": namespace, "bytes": len(value)})
        return True

    def db_get_blob(self, namespace: str, key: str) -> dict[str, Any] | None:
        if self._db is None:
            return self.cache_get(f"blob:{namespace}", key)
        with self._lock:
            row = self._db.execute(
                "SELECT value, content_type, expires_at FROM blobs WHERE namespace=? AND key=?",
                (namespace, key),
            ).fetchone()
        if row is None:
            return None
        expires = int(row["expires_at"] or 0)
        if expires and expires <= int(time.time() * 1000):
            return None
        return {"value": bytes(row["value"]), "content_type": row["content_type"]}

    def http_response_json(self, status: int, obj: Any) -> dict[str, Any]:
        return {"status": int(status), "content_type": "application/json", "body": obj}

    def http_response_text(self, status: int, text: str) -> dict[str, Any]:
        return {"status": int(status), "content_type": "text/plain; charset=utf-8", "body": text}

    def http_response_bytes(self, status: int, body: bytes, content_type: str) -> dict[str, Any]:
        return {"status": int(status), "content_type": content_type, "body": body}

    def http_client(self, method: str, url: str, headers: dict[str, Any] | None = None, body: Any = None, timeout_ms: int = 3000) -> dict[str, Any]:
        method = method.upper()
        mock = self.http_mocks.get((method, url))
        if mock is not None:
            return dict(mock)
        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname:
            rfn_fail("E_HTTP", f"bad url: {url}")
        data = None
        if body is not None:
            if isinstance(body, bytes):
                data = body
            else:
                data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={str(k): str(v) for k, v in (headers or {}).items()}, method=method)
        with urllib.request.urlopen(req, timeout=timeout_ms / 1000) as resp:
            raw = resp.read()
            ctype = resp.headers.get("content-type", "application/octet-stream")
            return {"status": resp.status, "headers": dict(resp.headers), "body": raw, "content_type": ctype}

    def file_resolve(self, path: Any) -> Path:
        p = Path(str(path))
        if not p.is_absolute():
            assert self.file_root is not None
            p = self.file_root / p
        return p.resolve()

    def file_exists(self, path: Any) -> bool:
        return self.file_resolve(path).exists()

    def file_is_file(self, path: Any) -> bool:
        return self.file_resolve(path).is_file()

    def file_is_dir(self, path: Any) -> bool:
        return self.file_resolve(path).is_dir()

    def file_stat(self, path: Any) -> dict[str, Any] | None:
        p = self.file_resolve(path)
        if not p.exists():
            return None
        st = p.stat()
        return {
            "path": str(p),
            "name": p.name,
            "exists": True,
            "is_file": p.is_file(),
            "is_dir": p.is_dir(),
            "size": int(st.st_size),
            "mtime_ms": int(st.st_mtime * 1000),
        }

    def file_list(self, path: Any) -> list[dict[str, Any]]:
        p = self.file_resolve(path)
        if not p.is_dir():
            rfn_fail("E_FILE", f"not a directory: {p}")
        return [self.file_stat(child) for child in sorted(p.iterdir(), key=lambda item: item.name.lower())]

    def file_read_text(self, path: Any, encoding: str = "utf-8", max_bytes: int = 16 * 1024 * 1024) -> str:
        raw = self.file_read_bytes(path, max_bytes)
        return raw.decode(encoding)

    def file_read_bytes(self, path: Any, max_bytes: int = 16 * 1024 * 1024) -> bytes:
        p = self.file_resolve(path)
        if not p.is_file():
            rfn_fail("E_FILE", f"not a file: {p}")
        limit = int(max_bytes)
        size = p.stat().st_size
        if limit >= 0 and size > limit:
            rfn_fail("E_LIMIT_OUTPUT", f"file too large: {size} > {limit}")
        return p.read_bytes()

    def file_write_text(self, path: Any, text: str, encoding: str = "utf-8", mkdirs: bool = True) -> bool:
        p = self._prepare_write_path(path, mkdirs)
        with p.open("w", encoding=encoding, newline="") as fh:
            fh.write(str(text))
        self.audit("file.write_text", str(p), "ok", {"bytes": p.stat().st_size})
        return True

    def file_append_text(self, path: Any, text: str, encoding: str = "utf-8", mkdirs: bool = True) -> bool:
        p = self._prepare_write_path(path, mkdirs)
        with p.open("a", encoding=encoding, newline="") as fh:
            fh.write(str(text))
        self.audit("file.append_text", str(p), "ok", {"bytes": p.stat().st_size})
        return True

    def file_write_bytes(self, path: Any, data: bytes, mkdirs: bool = True) -> bool:
        p = self._prepare_write_path(path, mkdirs)
        p.write_bytes(bytes(data))
        self.audit("file.write_bytes", str(p), "ok", {"bytes": len(data)})
        return True

    def file_mkdir(self, path: Any) -> bool:
        p = self.file_resolve(path)
        _reject_dangerous_write_path(p)
        p.mkdir(parents=True, exist_ok=True)
        self.audit("file.mkdir", str(p), "ok", {})
        return True

    def file_remove(self, path: Any) -> bool:
        p = self.file_resolve(path)
        _reject_dangerous_write_path(p)
        if not p.exists():
            return False
        if p.is_dir():
            p.rmdir()
        else:
            p.unlink()
        self.audit("file.remove", str(p), "ok", {})
        return True

    def file_copy(self, src: Any, dst: Any, mkdirs: bool = True) -> bool:
        s = self.file_resolve(src)
        d = self._prepare_write_path(dst, mkdirs)
        if not s.is_file():
            rfn_fail("E_FILE", f"copy source is not a file: {s}")
        shutil.copyfile(s, d)
        self.audit("file.copy", str(d), "ok", {"src": str(s), "bytes": d.stat().st_size})
        return True

    def file_move(self, src: Any, dst: Any, mkdirs: bool = True) -> bool:
        s = self.file_resolve(src)
        d = self._prepare_write_path(dst, mkdirs)
        _reject_dangerous_write_path(s)
        if not s.exists():
            rfn_fail("E_FILE", f"move source does not exist: {s}")
        shutil.move(str(s), str(d))
        self.audit("file.move", str(d), "ok", {"src": str(s)})
        return True

    def inject_send(self, target: Any, value_or_bytes: Any) -> dict[str, Any]:
        route = self.route_resolve(target)
        payload = value_or_bytes if isinstance(value_or_bytes, bytes) else self.schema_encode(target, value_or_bytes)
        result: dict[str, Any] = {"ok": True, "target": route, "payload": payload, "dry_run": self.mode == "replay"}
        if self.mode != "replay" and self.inject_func is not None:
            opcode = route.get("opcode")
            if opcode is None:
                result.update({"ok": False, "error_code": "E_INJECT", "error": f"target has no opcode: {target}"})
            else:
                try:
                    result["info"] = self.inject_func(int(opcode), bytes(payload), None)
                    result["dry_run"] = False
                except Exception as exc:
                    error_code = "E_INJECT_TIMEOUT" if "timeout" in str(exc).lower() else "E_INJECT"
                    result.update({"ok": False, "error_code": error_code, "error": str(exc), "dry_run": False})
        with self._lock:
            self.injected.append(result)
        self.audit("inject.send", str(target), "ok" if result.get("ok") else "error", {"dry_run": result["dry_run"], "error": result.get("error")})
        return result

    def inject_send_hex(self, target: Any, payload_hex: str) -> dict[str, Any]:
        return self.inject_send(target, bytes.fromhex(payload_hex.replace(" ", "")))

    def session_disconnect(self, reason: str = "rfn.session.disconnect") -> dict[str, Any]:
        if self.session_disconnect_func is None:
            result = {
                "ok": False,
                "error_code": "E_UNSUPPORTED",
                "error": "session disconnect is not available in this host",
            }
        else:
            try:
                result = self.session_disconnect_func(str(reason or "rfn.session.disconnect"))
            except Exception as exc:
                result = {"ok": False, "error_code": "E_SESSION", "error": str(exc)}
        self.audit("session.disconnect", str(reason), "ok" if result.get("ok") else "error", {"error": result.get("error")})
        return result

    def query(
        self,
        req_target: Any,
        value_or_bytes: Any,
        rsp_target: Any,
        predicate: Callable[[dict, dict], bool] | None = None,
        singleflight_key: str | None = None,
        timeout_ms: int | None = None,
    ) -> dict[str, Any]:
        request = value_or_bytes if isinstance(value_or_bytes, dict) else {}
        query_timeout_ms = self.default_query_timeout_ms
        if timeout_ms is not None:
            query_timeout_ms = int(timeout_ms) or self.default_query_timeout_ms
        if singleflight_key:
            with self._lock:
                self.singleflight_keys.add(singleflight_key)
        if self.mode == "replay":
            for pair in self.observed_pairs:
                if pair.req_target == str(req_target) and pair.rsp_target == str(rsp_target):
                    if predicate is None or predicate(pair.response, request):
                        return {
                            "ok": True,
                            "req_target": str(req_target),
                            "rsp_target": str(rsp_target),
                            "singleflight_key": singleflight_key,
                            "request_frame": pair.request_frame,
                            "response_frame": pair.response_frame,
                            "latency_ms": pair.latency_ms,
                            "decoded": pair.response,
                            "payload": b"",
                            "match_source": "replay_observed_pair",
                        }
            return {"ok": False, "error_code": "E_REPLAY_MISS", "error": "observed pair not found"}
        if self.query_func is not None:
            return self.query_func(req_target, value_or_bytes, rsp_target, predicate, singleflight_key, query_timeout_ms)
        sent = self.inject_send(req_target, value_or_bytes)
        return {"ok": bool(sent.get("ok")), "decoded": None, "match_source": "live"}

    def schedule_every(self, interval_ms: int, func: str, args: list[Any], job_key: str) -> dict[str, Any]:
        now = int(time.time() * 1000)
        job = {"kind": "every", "interval_ms": int(interval_ms), "func": func, "args": args, "job_key": job_key, "next_run_at": now + int(interval_ms)}
        self.jobs[job_key] = job
        self._store_job(job_key, job)
        self.audit("schedule.every", job_key, "ok", job)
        return {"ok": True, **job}

    def schedule_after(self, delay_ms: int, func: str, args: list[Any], job_key: str) -> dict[str, Any]:
        now = int(time.time() * 1000)
        job = {"kind": "after", "delay_ms": int(delay_ms), "func": func, "args": args, "job_key": job_key, "next_run_at": now + int(delay_ms)}
        self.jobs[job_key] = job
        self._store_job(job_key, job)
        self.audit("schedule.after", job_key, "ok", job)
        return {"ok": True, **job}

    def schedule_cron(self, cron_expr: str, func: str, args: list[Any], job_key: str) -> dict[str, Any]:
        now = int(time.time() * 1000)
        job = {"kind": "cron", "cron_expr": cron_expr, "func": func, "args": args, "job_key": job_key, "next_run_at": _next_cron_run_ms(cron_expr, now)}
        self.jobs[job_key] = job
        self._store_job(job_key, job)
        self.audit("schedule.cron", job_key, "ok", job)
        return {"ok": True, **job}

    def schedule_cancel(self, job_key: str) -> bool:
        self.jobs.pop(job_key, None)
        if self._db is not None:
            with self._lock:
                self._db.execute("DELETE FROM jobs WHERE id=?", (job_key,))
                self._commit_if_needed()
        self.audit("schedule.cancel", job_key, "ok", {})
        return True

    def schedule_set_enabled(self, job_key: str, enabled: bool) -> bool:
        if self._db is not None:
            with self._lock:
                self._db.execute("UPDATE jobs SET enabled=? WHERE id=?", (1 if enabled else 0, job_key))
                self._commit_if_needed()
        if not enabled:
            self.jobs.pop(job_key, None)
        self.audit("schedule.set_enabled", job_key, "ok", {"enabled": bool(enabled)})
        return True

    def schedule_exists(self, job_key: str) -> bool:
        if job_key in self.jobs:
            return True
        if self._db is not None:
            with self._lock:
                row = self._db.execute("SELECT id FROM jobs WHERE id=? AND enabled=1", (job_key,)).fetchone()
            return row is not None
        return job_key in self.jobs

    def schedule_next(self, job_key: str) -> int | None:
        job = self.jobs.get(job_key)
        if job:
            return int(job["next_run_at"])
        if self._db is not None:
            with self._lock:
                row = self._db.execute("SELECT next_run_at FROM jobs WHERE id=? AND enabled=1", (job_key,)).fetchone()
            return int(row["next_run_at"]) if row else None
        return None

    def event_emit(self, name: str, payload: Any) -> bool:
        if not name.startswith("script."):
            rfn_fail("E_PERMISSION", "RFN scripts can only emit script.* events")
        self.events.append({"source": "script", "name": name, "payload": payload})
        return True

    def audit_metric(self, name: str, value: Any, tags: dict[str, Any]) -> bool:
        metric = {"name": name, "value": value, "tags": tags, "ts": int(time.time() * 1000)}
        self.metrics.append(metric)
        self.audit("audit.metric", name, "ok", metric)
        return True

    def audit(self, op: str, target: str, status: str, detail: dict[str, Any]) -> None:
        ev = {"op": op, "target": target, "status": status, "detail": detail, "ts": int(time.time() * 1000)}
        with self._lock:
            self.audit_events.append(ev)
        if self._db is not None:
            with self._lock:
                self._db.execute(
                    "INSERT INTO events(ts,script,trigger,op,target,status,elapsed_ms,session_id,frame,opcode,detail_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (ev["ts"], "", "", op, target, status, 0, "", None, None, json.dumps(detail, ensure_ascii=False)),
                )
                self._commit_if_needed()

    def _resolve_message(self, name: str) -> dict | None:
        return self.registry.resolve_message(name) if self.registry else None


    def list_db_namespaces(self) -> list[dict[str, Any]]:
        if self._db is None:
            return []
        with self._lock:
            kv_rows = self._db.execute(
                "SELECT namespace, COUNT(*) AS n FROM kv GROUP BY namespace ORDER BY namespace"
            ).fetchall()
            tbl_rows = self._db.execute(
                "SELECT name, COUNT(*) AS n FROM tables GROUP BY name ORDER BY name"
            ).fetchall()
            blob_rows = self._db.execute(
                "SELECT namespace, COUNT(*) AS n FROM blobs GROUP BY namespace ORDER BY namespace"
            ).fetchall()
        return [
            *[{"kind": "kv", "name": r["namespace"], "count": int(r["n"])} for r in kv_rows],
            *[{"kind": "table", "name": r["name"], "count": int(r["n"])} for r in tbl_rows],
            *[{"kind": "blob", "name": r["namespace"], "count": int(r["n"])} for r in blob_rows],
        ]

    def list_db_kv(self, namespace: str, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        if self._db is None:
            return []
        now = int(time.time() * 1000)
        with self._lock:
            rows = self._db.execute(
                "SELECT key, value_json, expires_at, updated_at FROM kv WHERE namespace=? "
                "ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (namespace, int(limit), int(offset)),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            expires = int(row["expires_at"] or 0)
            if expires and expires <= now:
                continue
            try:
                value = json.loads(row["value_json"])
            except Exception:
                value = row["value_json"]
            out.append({
                "key": row["key"],
                "value": value,
                "expires_at": expires,
                "updated_at": int(row["updated_at"] or 0),
                "ttl_left_ms": max(0, expires - now) if expires else 0,
            })
        return out

    def list_db_table(self, name: str, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        if self._db is None:
            return []
        now = int(time.time() * 1000)
        with self._lock:
            rows = self._db.execute(
                "SELECT key_json, value_json, expires_at, updated_at FROM tables WHERE name=? "
                "ORDER BY updated_at DESC LIMIT ? OFFSET ?",
                (name, int(limit), int(offset)),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            expires = int(row["expires_at"] or 0)
            if expires and expires <= now:
                continue
            try:
                key = json.loads(row["key_json"])
                value = json.loads(row["value_json"])
            except Exception:
                key, value = row["key_json"], row["value_json"]
            out.append({"key": key, "value": value, "expires_at": expires, "updated_at": int(row["updated_at"] or 0)})
        return out

    def list_db_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if self._db is None:
            return list(self.audit_events[-int(limit):])
        with self._lock:
            rows = self._db.execute(
                "SELECT ts, op, target, status, detail_json FROM events ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            try:
                detail = json.loads(row["detail_json"]) if row["detail_json"] else {}
            except Exception:
                detail = {}
            out.append({
                "ts": int(row["ts"] or 0),
                "op": row["op"],
                "target": row["target"],
                "status": row["status"],
                "detail": detail,
            })
        return out

    def list_db_jobs(self) -> list[dict[str, Any]]:
        if self._db is None:
            return [dict(job) for job in self.jobs.values()]
        with self._lock:
            rows = self._db.execute(
                "SELECT id, name, spec_json, next_run_at, enabled, locked_until FROM jobs ORDER BY id"
            ).fetchall()
        out: list[dict[str, Any]] = []
        for row in rows:
            try:
                spec = json.loads(row["spec_json"]) if row["spec_json"] else {}
            except Exception:
                spec = {}
            out.append({
                "id": row["id"],
                "name": row["name"],
                "spec": spec,
                "next_run_at": int(row["next_run_at"] or 0),
                "enabled": bool(row["enabled"]),
                "locked_until": int(row["locked_until"] or 0),
            })
        return out

    def list_cache(self, *, limit: int = 200) -> list[dict[str, Any]]:
        now = time.time()
        out: list[dict[str, Any]] = []
        with self._lock:
            items = list(self.cache.items())
        for (scope, key), (value, expires) in items:
            if expires and expires <= now:
                continue
            out.append({
                "scope": scope,
                "key": key,
                "value": value,
                "ttl_left_ms": int(max(0, (expires - now) * 1000)) if expires else 0,
            })
            if len(out) >= int(limit):
                break
        return out

    def list_buffer(self, *, limit: int = 200) -> list[dict[str, Any]]:
        now = time.time()
        out: list[dict[str, Any]] = []
        with self._lock:
            scopes = list(self.buffers.items())
        for (scope, key), q in scopes:
            kept = [(v, exp) for v, exp in q if not exp or exp > now]
            if not kept:
                continue
            out.append({
                "scope": scope,
                "key": key,
                "len": len(kept),
                "max": q.maxlen,
                "items": [v for v, _ in kept[-min(8, len(kept)):]],
            })
            if len(out) >= int(limit):
                break
        return out

    def get_db_blob_meta(self, namespace: str, key: str) -> dict[str, Any] | None:
        if self._db is None:
            cached = self.cache_get(f"blob:{namespace}", key)
            if cached is None:
                return None
            value = cached.get("value") if isinstance(cached, dict) else None
            return {
                "namespace": namespace,
                "key": key,
                "size": len(value) if isinstance(value, (bytes, bytearray)) else 0,
                "content_type": cached.get("content_type") if isinstance(cached, dict) else "",
                "expires_at": 0,
            }
        with self._lock:
            row = self._db.execute(
                "SELECT length(value) AS sz, content_type, expires_at, updated_at FROM blobs "
                "WHERE namespace=? AND key=?",
                (namespace, key),
            ).fetchone()
        if row is None:
            return None
        return {
            "namespace": namespace,
            "key": key,
            "size": int(row["sz"] or 0),
            "content_type": row["content_type"] or "",
            "expires_at": int(row["expires_at"] or 0),
            "updated_at": int(row["updated_at"] or 0),
        }

    def _init_db(self) -> None:
        assert self._db is not None
        with self._lock:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS kv(namespace TEXT, key TEXT, value_json TEXT, expires_at INTEGER, session_id TEXT, updated_at INTEGER, PRIMARY KEY(namespace,key));
                CREATE TABLE IF NOT EXISTS tables(name TEXT, key_json TEXT, value_json TEXT, expires_at INTEGER, updated_at INTEGER, PRIMARY KEY(name,key_json));
                CREATE TABLE IF NOT EXISTS blobs(namespace TEXT, key TEXT, value BLOB, content_type TEXT, expires_at INTEGER, session_id TEXT, updated_at INTEGER, PRIMARY KEY(namespace,key));
                CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, name TEXT, spec_json TEXT, next_run_at INTEGER, enabled INTEGER, locked_until INTEGER);
                CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, script TEXT, trigger TEXT, op TEXT, target TEXT, status TEXT, elapsed_ms INTEGER, session_id TEXT, frame INTEGER, opcode TEXT, detail_json TEXT);
                """
            )
            self._db.commit()

    def _commit_if_needed(self) -> None:
        if self._db is not None and not self._in_tx:
            self._db.commit()

    def _purge_buffer(self, scope: str, key: str) -> deque[tuple[Any, float]]:
        q = self.buffers.get((scope, key), deque())
        now = time.time()
        kept = [item for item in q if not item[1] or item[1] > now]
        if len(kept) != len(q):
            self.buffers[(scope, key)] = deque(kept, maxlen=q.maxlen)
            q = self.buffers[(scope, key)]
        return q

    def _store_job(self, job_key: str, job: dict[str, Any]) -> None:
        if self._db is None:
            return
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO jobs(id,name,spec_json,next_run_at,enabled,locked_until) VALUES(?,?,?,?,?,?)",
                (job_key, str(job.get("func") or ""), json.dumps(job, ensure_ascii=False), int(job.get("next_run_at") or 0), 1, 0),
            )
            self._commit_if_needed()

    def _prepare_write_path(self, path: Any, mkdirs: bool) -> Path:
        p = self.file_resolve(path)
        _reject_dangerous_write_path(p)
        if mkdirs:
            p.parent.mkdir(parents=True, exist_ok=True)
        return p


def _route_from_meta(opcode: int, meta: dict | None) -> dict[str, Any]:
    return {
        "opcode": opcode,
        "opcode_hex": f"0x{opcode:04X}",
        "name": (meta or {}).get("name") or f"0x{opcode:04X}",
        "proto": (meta or {}).get("decode_as") or (meta or {}).get("proto_name"),
        "has_schema": bool((meta or {}).get("schema_status") or (meta or {}).get("decode_as")),
    }


def _scope_allows(scope: dict[str, Any], need: dict[str, Any]) -> bool:
    if not need:
        return True
    for key, expected in need.items():
        actual = scope.get(key)
        if actual in (None, "*"):
            continue
        if key in {"prefix", "job_prefix"}:
            if not str(expected).startswith(str(actual)):
                return False
            continue
        if key == "path":
            actual_s = str(actual)
            expected_s = str(expected)
            if actual_s.endswith("*"):
                if not expected_s.startswith(actual_s[:-1]):
                    return False
            elif expected_s != actual_s and not expected_s.startswith(actual_s.rstrip("\\/") + "\\") and not expected_s.startswith(actual_s.rstrip("\\/") + "/"):
                return False
            continue
        if key == "host":
            if str(actual).lower() != str(expected).lower():
                return False
            continue
        if key == "targets":
            allowed = {_target_token(x.strip()) for x in str(actual).split(",") if x.strip()}
            wanted = {_target_token(x) for x in (expected if isinstance(expected, (list, tuple, set)) else [expected])}
            if "*" not in allowed and not wanted.issubset(allowed):
                return False
            continue
        if str(actual) != str(expected):
            return False
    return True


def _reject_dangerous_write_path(path: Path) -> None:
    resolved = path.resolve()
    anchor = Path(resolved.anchor).resolve() if resolved.anchor else None
    exact_protected = {Path.home().resolve()}
    subtree_protected: set[Path] = set()
    if anchor is not None:
        exact_protected.add(anchor)
        subtree_protected.add((anchor / "Windows").resolve())
        subtree_protected.add((anchor / "Program Files").resolve())
        subtree_protected.add((anchor / "Program Files (x86)").resolve())
    for item in exact_protected:
        try:
            if resolved == item:
                rfn_fail("E_PERMISSION", f"dangerous filesystem target: {resolved}")
        except OSError:
            continue
    for item in subtree_protected:
        try:
            if resolved == item or resolved.is_relative_to(item):
                rfn_fail("E_PERMISSION", f"dangerous filesystem target: {resolved}")
        except OSError:
            continue


def _json_key(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _target_token(value: Any) -> str:
    if isinstance(value, int):
        return f"0x{value:04X}"
    text = str(value)
    if text.lower().startswith("0x"):
        try:
            return f"0x{int(text, 16):04X}"
        except ValueError:
            return text
    return text


def _matches_where(value: Any, where_obj: dict[str, Any]) -> bool:
    if not where_obj:
        return True
    if not isinstance(value, dict):
        return False
    for key, expected in where_obj.items():
        if value.get(key) != expected:
            return False
    return True


def _next_cron_run_ms(expr: str, now_ms: int) -> int:
    parts = str(expr).split()
    if len(parts) != 5:
        return now_ms + 60_000
    minute = parts[0]
    if minute.startswith("*/"):
        try:
            every = max(1, int(minute[2:]))
        except ValueError:
            every = 1
        return now_ms + every * 60_000
    return now_ms + 60_000
