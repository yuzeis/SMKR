from __future__ import annotations

from roco_mitm.codec import proto_codec


def test_codec_roundtrip_nested_repeated() -> None:
    schema = {
        "fields": [
            {"no": 1, "name": "id", "type": "uint32"},
            {"no": 2, "name": "tags", "type": "string", "repeated": True},
            {
                "no": 3,
                "name": "inner",
                "type": "message",
                "fields": [
                    {"no": 1, "name": "x", "type": "sint32"},
                    {"no": 2, "name": "y", "type": "bool"},
                ],
            },
        ]
    }
    value = {"id": 42, "tags": ["a", "bb"], "inner": {"x": -7, "y": True}}

    raw = proto_codec.encode_payload(schema, value)
    decoded = proto_codec.decode_payload(schema, raw)

    assert decoded == value


def test_shop_get_info_payload_is_standard_protobuf_after_prefix_restore() -> None:
    schema = {"fields": [{"no": 1, "name": "shop_id", "type": "uint32"}]}

    assert proto_codec.decode_payload(schema, bytes.fromhex("08863f")) == {"shop_id": 8070}
    assert proto_codec.encode_payload(schema, {"shop_id": 8070}) == bytes.fromhex("08863f")
