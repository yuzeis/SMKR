from __future__ import annotations

from pathlib import Path

from roco_mitm.divert import proc_divert


def test_new_conn_map_entries_flush_immediately(tmp_path: Path) -> None:
    path = tmp_path / "conn_map.json"
    old_path = proc_divert.CONN_MAP_PATH
    try:
        proc_divert.CONN_MAP_PATH = path
        divert = proc_divert.ProcDivert(self_pid=12345, redirect_host="127.0.0.1")

        divert._remember_conn("10.0.0.2", 1111, "1.1.1.1", 8195)
        first = path.read_text(encoding="utf-8")
        divert._remember_conn("10.0.0.2", 2222, "2.2.2.2", 8195)
        second = path.read_text(encoding="utf-8")

        assert "1111" in first
        assert "2222" in second
        assert not divert.conn_map_dirty
    finally:
        proc_divert.CONN_MAP_PATH = old_path
