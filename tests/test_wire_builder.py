from __future__ import annotations

from roco_mitm.proxy.crypto import GcpCipher, TSF4G_MARKER
from roco_mitm.proxy.protocol import CMD_DATA, GcpHead, InternalHeader, split_plaintext
from roco_mitm.proxy.wire_builder import build_wire_packet, compose_counter2


def test_wire_packet_builds_encrypted_data_packet() -> None:
    cipher = GcpCipher(b"wCJsnxBWPrgMrxfc")
    baseline = InternalHeader(counter1=100, session_id=0x0C0E86E8, sub_id=0, counter2=500)
    payload = bytes.fromhex("08ce8a71")

    wire = build_wire_packet(
        cipher=cipher,
        baseline=baseline,
        payload=payload,
        sub_id=0x03DC,
        gcp_sequence=7,
        counter2=baseline.counter2 + 1,
    )

    head = GcpHead.unpack(wire)
    body = wire[head.head_length : head.head_length + head.body_length]
    plain = cipher.decrypt_body(body)
    plain_no_trail, trailer = cipher.split_trailer(plain)
    internal, decoded_payload = split_plaintext(plain_no_trail)

    assert head.command == CMD_DATA
    assert head.sequence == 7
    assert trailer[-6:-1] == TSF4G_MARKER
    assert internal.session_id == 0x0C0E86E8
    assert internal.sub_id == 0x03DC
    assert internal.counter2 == compose_counter2(baseline.counter2 + 1, payload)
    assert internal.body_length == 26 + len(payload)
    assert decoded_payload == payload


def test_internal_header_payload_starts_at_byte_30() -> None:
    plain = bytes.fromhex(
        "000002d255aa0000001d0000000000016bd6d3680001025f39630000003f08863f"
    )

    internal, payload = split_plaintext(plain)

    assert internal.counter1 == 722
    assert internal.sub_id == 0x025F
    assert internal.counter2 == 0x003F0886
    assert payload == bytes.fromhex("08863f")
