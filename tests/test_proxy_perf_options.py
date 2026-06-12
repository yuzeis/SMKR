from __future__ import annotations

from roco_mitm.proxy import server as proxy_mod


def test_proxy_options_defaults_and_clamps() -> None:
    defaults = proxy_mod.normalize_proxy_options({})

    assert defaults["s2c_passthrough_after_key"] is False
    assert defaults["observe_s2c"] is True
    assert defaults["allow_s2c_inject"] is False
    assert defaults["observe_c2s"] is True
    assert defaults["c2s_drain_interval_ms"] == 0

    normalized = proxy_mod.normalize_proxy_options({
        "s2c_passthrough_after_key": "false",
        "observe_s2c": "yes",
        "allow_s2c_inject": 1,
        "observe_c2s": 0,
        "c2s_batch_packets": 99999,
        "c2s_batch_bytes": 1,
        "c2s_drain_interval_ms": -10,
        "observe_queue_max": 200000,
    })

    assert normalized["s2c_passthrough_after_key"] is False
    assert normalized["observe_s2c"] is True
    assert normalized["allow_s2c_inject"] is True
    assert normalized["observe_c2s"] is False
    assert normalized["c2s_batch_packets"] == 1024
    assert normalized["c2s_batch_bytes"] == 1024
    assert normalized["c2s_drain_interval_ms"] == 0
    assert normalized["observe_queue_max"] == 100000


def test_install_options_updates_global_options() -> None:
    try:
        installed = proxy_mod.install_options({
            "s2c_passthrough_after_key": False,
            "allow_s2c_inject": True,
            "c2s_batch_packets": 4,
        })
        opts = proxy_mod.get_options()

        assert installed["s2c_passthrough_after_key"] is False
        assert opts.s2c_passthrough_after_key is False
        assert opts.allow_s2c_inject is True
        assert opts.c2s_batch_packets == 4
    finally:
        proxy_mod.install_options({})


def test_perf_detail_records_only_when_enabled() -> None:
    proxy_mod.perf_detail_stop()
    proxy_mod.perf_detail_clear()

    proxy_mod.PERF_DETAIL.record(
        stage="queue_wait",
        direction="c2s",
        elapsed_ns=1_000_000,
        byte_count=8,
    )
    assert proxy_mod.perf_detail_events() == []

    status = proxy_mod.perf_detail_start(max_seconds=30, max_events=100)
    assert status["enabled"] is True

    proxy_mod.PERF_DETAIL.record(
        stage="queue_wait",
        direction="c2s",
        elapsed_ns=1_500_000,
        byte_count=16,
        gcp_seq=7,
    )
    events = proxy_mod.perf_detail_events()
    assert len(events) == 1
    assert events[0]["stage"] == "queue_wait"
    assert events[0]["elapsed_ms"] == 1.5
    assert events[0]["bytes"] == 16
    assert events[0]["gcp_seq"] == 7
    assert '"stage": "queue_wait"' in proxy_mod.perf_detail_export_jsonl()

    proxy_mod.perf_detail_stop()
    proxy_mod.perf_detail_clear()
