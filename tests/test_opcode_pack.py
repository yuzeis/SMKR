from __future__ import annotations

import json
from pathlib import Path

from roco_mitm.codec.opcode_pack import (
    compare_details,
    extract_pack,
    load_opcode_details,
    read_pack,
    write_pack,
)
from roco_mitm.codec.opcode_registry import OpcodeRegistry


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def test_opcode_pack_roundtrip_extracts_editable_json(tmp_path: Path) -> None:
    opcodes_dir = tmp_path / "opcodes"
    detail = {
        "opcode": "0x025F",
        "name": "ZoneShopGetInfoReq",
        "fields": [{"no": 1, "name": "shop_id", "type": "uint32"}],
    }
    _write_json(opcodes_dir / "0x025F.json", detail)

    pack_path = tmp_path / "opcodes.pack.bin"
    source = load_opcode_details(opcodes_dir)
    write_pack(pack_path, source)
    packed, header = read_pack(pack_path)

    assert header["count"] == 1
    assert compare_details(source, packed) == []

    extract_dir = tmp_path / "extract"
    count = extract_pack(pack_path, extract_dir)

    assert count == 1
    assert json.loads((extract_dir / "0x025F.json").read_text(encoding="utf-8")) == detail


def test_registry_loads_pack_without_opcodes_directory(tmp_path: Path) -> None:
    _write_json(tmp_path / "messages.json", {"messages": {}})
    _write_json(
        tmp_path / "opcodes.json",
        {"opcodes": {"0x025F": {"name": "ZoneShopGetInfoReq"}}},
    )
    write_pack(
        tmp_path / "opcodes.pack.bin",
        {
            "0x025F": {
                "opcode": "0x025F",
                "fields": [{"no": 1, "name": "shop_id", "type": "uint32"}],
            }
        },
    )

    registry = OpcodeRegistry(tmp_path)
    registry.load()
    schema = registry.get_opcode_schema(0x025F)

    assert schema is not None
    assert schema["source"] == "pack"
    assert schema["fields"][0]["name"] == "shop_id"
    assert registry.stats()["packed_schemas"] == 1


def test_registry_edit_directory_overrides_pack(tmp_path: Path) -> None:
    _write_json(tmp_path / "messages.json", {"messages": {}})
    _write_json(tmp_path / "opcodes.json", {"opcodes": {"0x025F": {"name": "Req"}}})
    write_pack(
        tmp_path / "opcodes.pack.bin",
        {
            "0x025F": {
                "opcode": "0x025F",
                "fields": [{"no": 1, "name": "shop_id", "type": "uint32"}],
            }
        },
    )
    _write_json(
        tmp_path / "opcodes" / "0x025F.json",
        {
            "opcode": "0x025F",
            "fields": [{"no": 2, "name": "edited_shop_id", "type": "uint32"}],
        },
    )

    registry = OpcodeRegistry(tmp_path)
    registry.load()
    schema = registry.get_opcode_schema(0x025F)

    assert schema is not None
    assert schema["source"] == "detail"
    assert schema["fields"][0]["name"] == "edited_shop_id"
