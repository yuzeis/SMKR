"""离线自检。覆盖核心 wire 不变量 + 新通用 codec 路径。"""
from __future__ import annotations

from pathlib import Path

if __package__ in (None, ""):
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from roco_mitm.proxy.crypto import GcpCipher, CORRECT_IV, TSF4G_MARKER
    from roco_mitm.proxy.protocol import InternalHeader, GcpHead, CMD_DATA, split_plaintext
    from roco_mitm.proxy.wire_builder import build_wire_packet, compose_counter2, resolve_counter2
    from roco_mitm.codec import proto_codec
    from roco_mitm.codec.opcode_registry import OpcodeRegistry
    from roco_mitm.rfn import RFNVM, assemble_source
    from roco_mitm.paths import config_dir
else:
    from .proxy.crypto import GcpCipher, CORRECT_IV, TSF4G_MARKER
    from .proxy.protocol import InternalHeader, GcpHead, CMD_DATA, split_plaintext
    from .proxy.wire_builder import build_wire_packet, compose_counter2, resolve_counter2
    from .codec import proto_codec
    from .codec.opcode_registry import OpcodeRegistry
    from .rfn import RFNVM, assemble_source
    from .paths import config_dir


def _registry() -> OpcodeRegistry:
    reg = OpcodeRegistry(config_dir())
    reg.load()
    return reg


def test_pb_encoding():
    """通用 codec 编码 0x03DC payload, 应等于历史硬编码结果."""
    reg = _registry()
    sch = reg.get_opcode_schema(0x03DC)
    assert sch is not None, "0x03DC schema 缺失, 检查 decoder_overrides.json"
    raw = proto_codec.encode_payload(sch, {"uin": 1852750}, resolve_message=reg.resolve_message)
    assert raw == bytes.fromhex("08ce8a71"), f"编码不匹配: {raw.hex()}"
    print(f"[ok] pb encoding 0x03DC uin=1852750 -> {raw.hex()}")


def test_crypto_roundtrip():
    key = b"wCJsnxBWPrgMrxfc"
    cipher = GcpCipher(key)
    plain = b"hello world payload 0123456789"
    trailer = cipher.build_tsf4g_trailer(len(plain))
    assert trailer[-6:-1] == TSF4G_MARKER
    raw = plain + trailer
    assert len(raw) % 16 == 0
    ct = cipher.encrypt_body(raw)
    assert cipher.decrypt_body(ct) == raw
    print(f"[ok] AES-CBC roundtrip IV={CORRECT_IV.hex()} len={len(raw)}")


def test_wire_packet_build():
    """build_wire_packet 必须产生与原版一致的 wire 结构."""
    key = b"wCJsnxBWPrgMrxfc"
    cipher = GcpCipher(key)
    baseline = InternalHeader(counter1=100, session_id=0x0C0E86E8, sub_id=0, counter2=500)
    payload = bytes.fromhex("08ce8a71")
    wire = build_wire_packet(
        cipher=cipher, baseline=baseline, payload=payload,
        sub_id=0x03DC, gcp_sequence=7, counter2=baseline.counter2 + 1, emit=None,
    )
    head = GcpHead.unpack(wire)
    assert head.command == CMD_DATA
    assert head.sequence == 7
    body = wire[head.head_length : head.head_length + head.body_length]
    plain = cipher.decrypt_body(body)
    plain_no_trail, trailer = cipher.split_trailer(plain)
    assert trailer[-6:-1] == TSF4G_MARKER
    internal, decoded_payload = split_plaintext(plain_no_trail)
    assert internal.counter1 == 7
    assert internal.session_id == 0x0C0E86E8
    assert internal.sub_id == 0x03DC
    assert internal.counter2 == compose_counter2(baseline.counter2 + 1, payload)
    assert internal.body_length == 26 + len(payload)
    assert decoded_payload == payload
    print(f"[ok] wire packet build sub_id=0x{internal.sub_id:04X} payload={decoded_payload.hex()}")


def test_c2s_rewrite_roundtrip():
    """验证重写 wire seq 后, 密文里 counter1 同步更新, 其它字段不变."""
    key = b"wCJsnxBWPrgMrxfc"
    cipher = GcpCipher(key)
    baseline = InternalHeader(counter1=50, session_id=0x0A83CD08, sub_id=0x03DC, counter2=0x231001)
    payload = bytes.fromhex("08ce8a71")
    orig = build_wire_packet(
        cipher=cipher, baseline=baseline, payload=payload,
        sub_id=0x03DC, gcp_sequence=50, counter2=0x231001, emit=None,
    )
    orig_head = GcpHead.unpack(orig)
    assert orig_head.sequence == 50

    offset = 1
    new_seq = (orig_head.sequence + offset) & 0xFFFFFFFF
    out = bytearray(orig)
    out[9:13] = new_seq.to_bytes(4, "big")
    body_off = orig_head.head_length
    body = bytes(out[body_off : body_off + orig_head.body_length])
    plain = cipher.decrypt_body(body)
    new_plain = new_seq.to_bytes(4, "big") + plain[4:]
    new_body = cipher.encrypt_body(new_plain)
    assert len(new_body) == len(body)
    out[body_off : body_off + orig_head.body_length] = new_body
    rewritten = bytes(out)

    r_head = GcpHead.unpack(rewritten)
    assert r_head.sequence == 51
    r_body = rewritten[r_head.head_length : r_head.head_length + r_head.body_length]
    r_plain = cipher.decrypt_body(r_body)
    r_plain_nt, _ = cipher.split_trailer(r_plain)
    r_internal, _ = split_plaintext(r_plain_nt)
    assert r_internal.counter1 == 51
    assert r_internal.session_id == 0x0A83CD08
    assert r_internal.sub_id == 0x03DC
    assert r_internal.counter2 == compose_counter2(0x231001, payload)
    print(f"[ok] _rewrite_c2s_seq: wire_seq 50→51 同步 counter1 50→51, 其它字段不变")


def test_resolve_counter2():
    last = {0x03DC: 0x231001}
    v, src = resolve_counter2(last, 0x03DC)
    assert v == 0x231001 + 0x10000 and "observed" in src

    v, src = resolve_counter2(last, 0x9999, fallback_opcode=0x03DC)
    assert v == 0x231001 + 0x10000 and "borrow" in src

    v, src = resolve_counter2({}, 0x9999)
    assert v == 0x00401001 and "cold_start" in src
    print(f"[ok] resolve_counter2: observed / borrow / cold_start 三条路径")


def test_codec_decode_real_samples():
    """用真实抓包样本验证通用解码路径."""
    reg = _registry()

    sample_02a5 = bytes.fromhex(
        "010a133133393435333538303031343639393036323010ce8a71"
        "1a06e99988e6958f2200302f4000480250ecbc86cf065a15e981"
        "a5e69c9be6989fe6b5b7e79a84e78e8be5baa7600370087"
        "8ce8895ce068801029001d908980165a001a101ba01040800"
    )
    sch = reg.get_opcode_schema(0x02A5)
    out = proto_codec.decode_payload(sch, sample_02a5, resolve_message=reg.resolve_message)
    assert out.get("uin") == 1852750, f"uin={out.get('uin')}"
    assert out.get("name") == "陈敏", f"name={out.get('name')!r}"

    sample_03dd = bytes.fromhex(
        "080218d90820652a15e981a5e69c9be6989fe6b5b7e79a84e78e"
        "8be5baa730a101424108c5b7ef0908e5c4f5090885d2fb0908a5"
        "df810a08c5ec870a08e5f98d0a0885f1c40a20082a03089b012a"
        "0208522a02086d2a030887012a0308b1012a030892011a002001"
        "2800300038ce8895ce0640004803520845727427417269615a00"
        "60a80f"
    )
    sch = reg.get_opcode_schema(0x03DD)
    out2 = proto_codec.decode_payload(sch, sample_03dd, resolve_message=reg.resolve_message)
    assert out2.get("card_signature") == "遥望星海的王座", f"signature={out2.get('card_signature')!r}"
    print(f"[ok] codec real-sample decode: 陈敏 / 遥望星海的王座")


def test_codec_unknown_opcode_fallback():
    """未知 opcode 应能 scan_fields 工作而不抛错."""
    fields = proto_codec.scan_fields(bytes.fromhex("08ce8a71"))
    assert len(fields) == 1
    assert fields[0]["no"] == 1 and fields[0]["value"] == 1852750
    print(f"[ok] scan_fields fallback path")


def test_codec_repeated_and_message():
    """validate repeated + nested message round-trip."""
    schema = {
        "fields": [
            {"no": 1, "name": "id", "type": "uint32"},
            {"no": 2, "name": "tags", "type": "string", "repeated": True},
            {"no": 3, "name": "inner", "type": "message", "fields": [
                {"no": 1, "name": "x", "type": "sint32"},
                {"no": 2, "name": "y", "type": "bool"},
            ]},
        ]
    }
    value = {"id": 42, "tags": ["a", "bb", "ccc"], "inner": {"x": -7, "y": True}}
    raw = proto_codec.encode_payload(schema, value)
    back = proto_codec.decode_payload(schema, raw)
    assert back["id"] == 42
    assert back["tags"] == ["a", "bb", "ccc"]
    assert back["inner"]["x"] == -7 and back["inner"]["y"] is True
    print(f"[ok] codec repeated + nested message round-trip")


def test_codec_packed_repeated_decode():
    """validate packed repeated numeric decode path."""
    schema = {
        "fields": [
            {"no": 1, "name": "ids", "type": "uint32", "repeated": True},
            {"no": 2, "name": "flags", "type": "bool", "repeated": True, "packed": True},
        ]
    }
    raw = (
        proto_codec.encode_tag(1, proto_codec.WIRE_LEN)
        + proto_codec.encode_varint(4)
        + b"\x01\x02\xac\x02"
        + proto_codec.encode_payload(schema, {"flags": [True, False, True]})
    )
    back = proto_codec.decode_payload(schema, raw)
    assert back["ids"] == [1, 2, 300]
    assert back["flags"] == [True, False, True]
    print(f"[ok] codec packed repeated decode/encode")


def test_rfn_core_vm():
    """RFN core smoke: assembler + VM + protobuf builder."""
    module = assemble_source(
        """
        .function Build(v:u32) -> bytes
        .no_side_effect true
        .deterministic true
          buf.new r0
          pb.varint r0, 1, arg0
          buf.take r1, r0
          ret r1
        .end
        """
    )
    raw = RFNVM(module).call("Build", 1852750)
    assert raw == bytes.fromhex("08ce8a71")
    print(f"[ok] RFN core VM build payload -> {raw.hex()}")


def run_all() -> None:
    test_pb_encoding()
    test_crypto_roundtrip()
    test_wire_packet_build()
    test_c2s_rewrite_roundtrip()
    test_resolve_counter2()
    test_codec_decode_real_samples()
    test_codec_unknown_opcode_fallback()
    test_codec_repeated_and_message()
    test_codec_packed_repeated_decode()
    test_rfn_core_vm()
    print("\nALL ROCO_MITM SELFTESTS PASSED")


if __name__ == "__main__":
    run_all()
