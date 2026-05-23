from __future__ import annotations

from roco_mitm.proxy.protocol import InternalHeader
from roco_mitm.proxy.server import _is_inject_baseline_candidate


def test_small_session_id_does_not_seed_inject_baseline() -> None:
    heartbeat = InternalHeader(session_id=0x40, sub_id=0x013E)

    assert not _is_inject_baseline_candidate(heartbeat, None)


def test_small_session_id_does_not_replace_real_inject_baseline() -> None:
    current = InternalHeader(session_id=0xC66586E8, sub_id=0x0159)
    heartbeat = InternalHeader(session_id=0x40, sub_id=0x013E)
    normal = InternalHeader(session_id=0xC66586E8, sub_id=0x01A9)

    assert not _is_inject_baseline_candidate(heartbeat, current)
    assert _is_inject_baseline_candidate(normal, current)
