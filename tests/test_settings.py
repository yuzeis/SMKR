from __future__ import annotations

from pathlib import Path
import json

from roco_mitm.paths import config_dir
from roco_mitm.web.app import AppContext, SettingsStore


def test_settings_store_save_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    store = SettingsStore(path)

    saved = store.save({"theme": "light", "stream": {"max_events": 1234}})

    assert saved["theme"] == "light"
    assert saved["stream"]["max_events"] == 1234
    reloaded = SettingsStore(path).get()
    assert reloaded["theme"] == "light"
    assert reloaded["stream"]["max_events"] == 1234


def test_settings_store_proxy_and_perf_defaults(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    settings = SettingsStore(path).get()

    assert settings["proxy"]["s2c_passthrough_after_key"] is False
    assert settings["proxy"]["observe_s2c"] is True
    assert settings["proxy"]["allow_s2c_inject"] is False
    assert settings["proxy"]["observe_c2s"] is True
    assert settings["proxy"]["c2s_drain_interval_ms"] == 0
    assert settings["observe"]["auto_decode_packets"] is False
    assert settings["observe"]["decode_on_click"] is True
    assert settings["observe"]["rfn_active_watch_only"] is True
    assert settings["observe"]["rfn_passive_packet_seen"] is False
    assert settings["perf"]["detail_max_seconds"] == 60
    assert settings["perf"]["detail_max_events"] == 20000
    assert settings["perf"]["snapshot_interval_ms"] == 1000


def test_settings_store_normalizes_proxy_and_perf(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    store = SettingsStore(path)

    saved = store.save({
        "proxy": {
            "s2c_passthrough_after_key": False,
            "allow_s2c_inject": True,
            "c2s_batch_packets": 99999,
            "c2s_batch_bytes": 1,
            "c2s_drain_interval_ms": -5,
            "observe_queue_max": 200000,
        },
        "perf": {
            "detail_max_seconds": 99999,
            "detail_max_events": 1,
            "snapshot_interval_ms": 1,
        },
        "observe": {
            "auto_decode_packets": 1,
            "decode_on_click": 0,
            "rfn_active_watch_only": "false",
            "rfn_passive_packet_seen": "yes",
        },
    })

    assert saved["proxy"]["s2c_passthrough_after_key"] is False
    assert saved["proxy"]["allow_s2c_inject"] is True
    assert saved["proxy"]["c2s_batch_packets"] == 1024
    assert saved["proxy"]["c2s_batch_bytes"] == 1024
    assert saved["proxy"]["c2s_drain_interval_ms"] == 0
    assert saved["proxy"]["observe_queue_max"] == 100000
    assert saved["observe"]["auto_decode_packets"] is True
    assert saved["observe"]["decode_on_click"] is False
    assert saved["observe"]["rfn_active_watch_only"] is False
    assert saved["observe"]["rfn_passive_packet_seen"] is True
    assert saved["perf"]["detail_max_seconds"] == 3600
    assert saved["perf"]["detail_max_events"] == 100
    assert saved["perf"]["snapshot_interval_ms"] == 250


def test_settings_store_migrates_legacy_https_to_http(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps(
            {
                "services": {
                    "https": {
                        "enabled": True,
                        "host": "0.0.0.0",
                        "port": 18197,
                        "cert_file": "old.crt",
                        "key_file": "old.key",
                    }
                }
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    settings = SettingsStore(path).get()

    assert "https" not in settings["services"]
    assert settings["services"]["http"]["enabled"] is True
    assert settings["services"]["http"]["host"] == "0.0.0.0"
    assert settings["services"]["http"]["port"] == 18197
    assert settings["services"]["http"]["allow_remote"] is True
    assert "cert_file" not in settings["services"]["http"]
    assert "key_file" not in settings["services"]["http"]


def test_settings_store_save_persists_http_not_https(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    store = SettingsStore(path)

    saved = store.save({
        "services": {
            "http": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 18196,
                "allow_remote": False,
                "public_url": "http://127.0.0.1:18196/",
            },
            "https": {"enabled": True, "port": 18197},
        }
    })
    raw = json.loads(path.read_text(encoding="utf-8"))

    assert "https" not in saved["services"]
    assert "https" not in raw["services"]
    assert raw["services"]["http"]["public_url"] == "http://127.0.0.1:18196/"
    assert raw["services"]["http"]["port"] == 18196


def test_packet_stream_defaults_to_deferred_decode() -> None:
    ctx = AppContext(package_root=Path("src/roco_mitm").resolve(), config_dir=config_dir())
    ctx.rfn.runtime = None
    ev = {
        "type": "packet",
        "ts": 1.0,
        "direction": "s2c",
        "kind": "data",
        "opcode": 0x0260,
        "opcode_hex": "0x0260",
        "payload_hex": (
            "08c6172a2210c88b04180028808df1cf06420710f403180220014a0710f4031802200150646000"
            "3804400248ece3fdf5bba694035000"
        ),
    }

    ctx._enqueue_packet_event(ev)
    history = ctx.bus.history_snapshot(10)

    packets = [item for item in history if item.get("type") == "packet"]
    updates = [item for item in history if item.get("type") == "packet_update"]
    assert packets[0]["decode_status"] == "deferred"
    assert "decoded" not in packets[0]
    assert updates == []
    assert ctx._packet_queue is None


def test_settings_template_has_valid_save_controls() -> None:
    text = Path("src/roco_mitm/web/static/assets/template.html").read_text(encoding="utf-8")

    assert 'v-model="settings.services.mcp.auth_token" placeholder="可留空" />' in text
    assert '@click="saveSettings"' in text
    assert "{{ settingsSaving ? '保存中...' : '保存设置' }}" in text


def test_settings_template_uses_http_service_not_https_cert_controls() -> None:
    text = Path("src/roco_mitm/web/static/assets/template.html").read_text(encoding="utf-8")

    assert "HTTP 服务" in text
    assert "settings.services.http.enabled" in text
    assert "settings.services.http.host" in text
    assert "settings.services.http.port" in text
    assert "settings.services.http.allow_remote" in text
    assert "settings.services.http.public_url" in text
    assert "HTTPS 服务" not in text
    assert "settings.services.https" not in text
    assert "cert_file" not in text
    assert "key_file" not in text


def test_settings_template_exposes_proxy_and_perf_controls() -> None:
    text = Path("src/roco_mitm/web/static/assets/template.html").read_text(encoding="utf-8")

    assert "settings.proxy.s2c_passthrough_after_key" in text
    assert "settings.proxy.observe_s2c" in text
    assert "settings.proxy.allow_s2c_inject" in text
    assert "settings.proxy.c2s_batch_packets" in text
    assert "settings.observe.auto_decode_packets" in text
    assert "settings.observe.rfn_active_watch_only" in text
    assert "settings.perf.detail_max_seconds" in text
    assert 'href="/perf"' in text
    assert "证书" not in text
    assert "私钥" not in text
