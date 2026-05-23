from __future__ import annotations

from pathlib import Path

from roco_mitm.paths import config_dir
from roco_mitm.web.app import AppContext


def _ctx() -> AppContext:
    return AppContext(package_root=Path("src/roco_mitm").resolve(), config_dir=config_dir())


def test_flattened_rsp_decodes_as_nested_message() -> None:
    ctx = _ctx()
    schema = ctx.registry.get_opcode_schema(0x0260)
    assert schema is not None
    payload = bytes.fromhex(
        "08c6172a2210c88b04180028808df1cf06420710f403180220014a0710f4031802200150646000"
        "3804400248ece3fdf5bba694035000"
    )

    decoded, source = ctx._decode_opcode_payload(0x0260, schema, payload)

    assert source == "flattened:shop_data"
    assert decoded["id"] == 3014
    assert decoded["max_refresh_count"] == 4
    assert decoded["refresh_count"] == 2
    assert decoded["version"] == 1778132545663468
    assert "_unknown" not in decoded
    assert decoded["goods_data"][0]["goods_id"] == 67016
    assert decoded["goods_data"][0]["origin_price"]["num"] == 500


def test_full_rsp_payload_decodes_as_outer_schema() -> None:
    ctx = _ctx()
    schema = ctx.registry.get_opcode_schema(0x0260)
    assert schema is not None
    payload = bytes.fromhex(
        "123608863f2a2610fe8c01180028c082b3d006420710b018180220024a0710b01818022002"
        "500160bfdef3cf0648828197a4c3a694035000"
    )

    decoded, source = ctx._decode_opcode_payload(0x0260, schema, payload)

    assert source == "schema"
    assert decoded["shop_data"]["id"] == 8070
    assert decoded["shop_data"]["goods_data"][0]["goods_id"] == 18046


def test_inject_reply_gets_decode_priority() -> None:
    ctx = _ctx()

    inject_priority = ctx._decode_priority({"kind": "inject", "opcode": 0x03DC, "direction": "c2s"})
    reply_priority = ctx._decode_priority({"kind": "data", "opcode": 0x03DD, "direction": "s2c"})
    normal_priority = ctx._decode_priority({"kind": "data", "opcode": 0x0260, "direction": "s2c"})

    assert inject_priority == 0
    assert reply_priority == 0
    assert normal_priority > reply_priority


def test_raw_string_payload_maps_to_primary_string_field() -> None:
    ctx = _ctx()
    schema = {
        "fields": [
            {"no": 1, "name": "report_data", "type": "string"},
            {"no": 2, "name": "type", "type": "int32"},
        ]
    }

    decoded, source = ctx._decode_opcode_payload(0x1412, schema, b"0000001006a10000")

    assert source == "raw_string:report_data"
    assert decoded == {"report_data": "0000001006a10000"}


def test_raw_string_payload_maps_through_single_nested_string_field() -> None:
    ctx = _ctx()
    schema = ctx.registry.get_opcode_schema(0x158C)
    assert schema is not None

    decoded, source = ctx._decode_opcode_payload(0x158C, schema, b"mark_create_life_flower")

    assert source == "raw_string:text_info.text_id"
    assert decoded == {"text_info": {"text_id": "mark_create_life_flower"}}


def test_raw_little_endian_struct_payload_maps_numeric_fields() -> None:
    ctx = _ctx()
    schema = ctx.registry.get_opcode_schema(0x013D)
    assert schema is not None

    decoded, source = ctx._decode_opcode_payload(0x013D, schema, bytes.fromhex("0000000064000000"))

    assert source == "raw_struct"
    assert decoded == {"heartbeat_seq": 0, "server_logic_tick_ivl": 100}
