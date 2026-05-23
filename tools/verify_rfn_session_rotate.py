"""Live verification helper: capture session_key rotate evidence.

Use case
========
After RFN live runtime is wired into a real 8195 session, this script lets the
operator confirm that an actual session_key change in the game (e.g. switching
zones, re-login) drives ``RFNLiveRuntime.on_session_rotate``. The runtime
auto-fires that hook when proxy emits ``session_key`` with a different hex,
clears all session-scope cache/buffer entries, fails in-flight pending queries
with ``E_SESSION_ROTATE`` and writes a ``session.rotate`` audit row.

Workflow
========
1. Start MITM + RFN runtime + WinDivert + WeGame/NRC and log into the game.
2. Run this script with ``--baseline`` to snapshot current session_key, cache
   contents and the latest session.rotate event id.
3. Trigger a real session_key rotation in the game (zone change / re-login).
4. Run with ``--verify`` to compare against the baseline and assert:
   - session_key actually changed,
   - new session.rotate audit row appeared,
   - session-scope cache entries are gone (or rebuilt).
5. The script never modifies live state. Read-only HTTP GET only.

Both phases write JSON snapshots under ``runtime/cache/rfn_session_rotate/``
so the evidence is reproducible without re-running the game.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any


def fetch_json(base: str, path: str, timeout: float = 4.0) -> Any:
    with urllib.request.urlopen(base + path, timeout=timeout) as rsp:
        return json.loads(rsp.read().decode("utf-8"))


def snapshot(base: str) -> dict[str, Any]:
    status = fetch_json(base, "/api/status")
    rfn_status = fetch_json(base, "/api/rfn/status")
    cache = fetch_json(base, "/api/rfn/cache")
    events = fetch_json(base, "/api/rfn/db/events?limit=200").get("events", [])
    rotate_events = [e for e in events if e.get("op") == "session.rotate"]
    return {
        "ts": int(time.time() * 1000),
        "session_key_hex": status.get("session_key_hex"),
        "session_key_ascii": status.get("session_key_ascii"),
        "session_id_hex": status.get("session_id_hex"),
        "ready_for_inject": status.get("ready_for_inject"),
        "upstream": status.get("upstream"),
        "rfn_packet_seen": (rfn_status.get("stats") or {}).get("packet_seen"),
        "rfn_active_calls": rfn_status.get("active_calls"),
        "rfn_pending_queries": rfn_status.get("pending_queries"),
        "session_scope_cache": [c for c in cache.get("items", []) if str(c.get("scope", "")).startswith("session")],
        "rotate_event_count": len(rotate_events),
        "latest_rotate_event": rotate_events[0] if rotate_events else None,
    }


def write_snapshot(out_dir: Path, name: str, data: dict[str, Any]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.json"
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def cmd_baseline(args: argparse.Namespace) -> int:
    snap = snapshot(args.base_url)
    path = write_snapshot(Path(args.out_dir), "baseline", snap)
    print(f"[baseline] saved to {path}")
    print(f"  session_key_hex={snap['session_key_hex']!r}")
    print(f"  session_id_hex={snap['session_id_hex']!r}")
    print(f"  session_scope_cache_count={len(snap['session_scope_cache'])}")
    print(f"  rotate_event_count={snap['rotate_event_count']}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    baseline_path = out_dir / "baseline.json"
    if not baseline_path.exists():
        print(f"[verify] baseline not found at {baseline_path}; run --baseline first", file=sys.stderr)
        return 2
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    after = snapshot(args.base_url)
    write_snapshot(out_dir, "after", after)

    issues: list[str] = []
    if not baseline.get("session_key_hex"):
        issues.append("baseline session_key_hex is empty (game was not in session?)")
    if baseline.get("session_key_hex") == after.get("session_key_hex") and after.get("session_key_hex"):
        issues.append("session_key_hex did not change since baseline")
    if after.get("rotate_event_count", 0) <= baseline.get("rotate_event_count", 0):
        issues.append("no new session.rotate audit event after baseline")
    base_keys = {(c.get("scope"), c.get("key")) for c in baseline.get("session_scope_cache") or []}
    after_keys = {(c.get("scope"), c.get("key")) for c in after.get("session_scope_cache") or []}
    persisted = base_keys & after_keys
    if persisted:
        issues.append(f"session-scope cache entries persisted across rotate: {sorted(persisted)}")

    print(f"[verify] baseline session_key={baseline.get('session_key_hex')!r}")
    print(f"[verify] after    session_key={after.get('session_key_hex')!r}")
    print(f"[verify] rotate_event_count baseline={baseline.get('rotate_event_count')} after={after.get('rotate_event_count')}")
    print(f"[verify] session_scope_cache_count baseline={len(baseline.get('session_scope_cache') or [])} after={len(after.get('session_scope_cache') or [])}")
    if issues:
        for issue in issues:
            print(f"  ISSUE: {issue}")
        print("[verify] FAIL")
        return 1
    print("[verify] OK: session_key rotated, audit event written, session-scope cleared")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify RFN session_rotate evidence on a real 8195 session.")
    parser.add_argument("--base-url", default="http://127.0.0.1:18196")
    parser.add_argument("--out-dir", default="runtime/cache/rfn_session_rotate")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--baseline", action="store_const", const="baseline", dest="phase",
                       help="snapshot current state before triggering rotate")
    group.add_argument("--verify", action="store_const", const="verify", dest="phase",
                       help="snapshot after rotate and compare against baseline")
    args = parser.parse_args()
    if args.phase == "baseline":
        return cmd_baseline(args)
    if args.phase == "verify":
        return cmd_verify(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())