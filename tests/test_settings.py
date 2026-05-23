from __future__ import annotations

from pathlib import Path
import json

from roco_mitm.web.app import SettingsStore


def test_settings_store_save_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    store = SettingsStore(path)

    saved = store.save({"theme": "light", "stream": {"max_events": 1234}})

    assert saved["theme"] == "light"
    assert saved["stream"]["max_events"] == 1234
    reloaded = SettingsStore(path).get()
    assert reloaded["theme"] == "light"
    assert reloaded["stream"]["max_events"] == 1234


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
    assert "证书" not in text
    assert "私钥" not in text
