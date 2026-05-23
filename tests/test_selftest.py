from __future__ import annotations

from roco_mitm import selftest


def test_selftest_suite() -> None:
    selftest.run_all()
