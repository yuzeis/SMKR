"""注入包构造与计数选择 (通用版)。

不再绑定具体业务 opcode; encode payload 由 proto_codec.encode_payload 在调用方完成,
本模块只负责把 payload + 内部头打包成 wire bytes.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping

from .crypto import GcpCipher
from .protocol import CMD_DATA, INTERNAL_HEADER_LEN, INTERNAL_PREFIX_LEN, GcpHead, InternalHeader


_COUNTER2_INCREMENT = 0x10000
_COUNTER2_COLD_START = 0x00401001


def resolve_counter2(
    last_c2_by_opcode: Mapping[int, int], opcode: int, *, fallback_opcode: int | None = None
) -> tuple[int, str]:
    """选择 counter2 值。

    1. 同 opcode 上次观察值 + 0x10000
    2. fallback_opcode (可选, 通常是历史抓包丰富的 opcode) 的观察值 + 0x10000
    3. 冷启动常量 0x00401001
    """
    observed = last_c2_by_opcode.get(opcode)
    if observed is not None:
        return observed + _COUNTER2_INCREMENT, f"observed+0x10000 (raw=0x{observed:08X})"
    if fallback_opcode is not None:
        borrowed = last_c2_by_opcode.get(fallback_opcode)
        if borrowed is not None:
            return (
                borrowed + _COUNTER2_INCREMENT,
                f"borrow_0x{fallback_opcode:04X}+0x10000 (raw=0x{borrowed:08X})",
            )
    return _COUNTER2_COLD_START, f"cold_start_const=0x{_COUNTER2_COLD_START:08X}"


def compose_counter2(counter2: int, payload: bytes) -> int:
    """Return the wire-visible counter2 composite for this payload."""
    prefix = payload[:INTERNAL_PREFIX_LEN].ljust(INTERNAL_PREFIX_LEN, b"\x00")
    return ((counter2 >> 16) & 0xFFFF) << 16 | int.from_bytes(prefix, "big")


def build_wire_packet(
    *,
    cipher: GcpCipher,
    baseline: InternalHeader,
    payload: bytes,
    sub_id: int,
    gcp_sequence: int,
    counter2: int,
    emit: Callable[[str], None] | None = None,
) -> bytes:
    """组装一个加密的 DATA wire 包。

    plaintext = internal_header(32B) + payload + tsf4g_trailer
    body      = AES-CBC-Encrypt(plaintext)
    wire      = TGCPBase header (21B) + ExtHead (4B) + body
    """
    internal = InternalHeader(
        counter1=gcp_sequence,
        session_id=baseline.session_id,
        sub_id=sub_id,
        counter2=counter2,
    )
    if emit is not None:
        emit(
            f"[INJECT-BUILD] seq={gcp_sequence} c1={internal.counter1} "
            f"c2={compose_counter2(counter2, payload)} "
            f"sid=0x{internal.session_id:08X} sub_id=0x{sub_id:04X} "
            f"payload_hex={payload.hex()}"
        )
    # 第一遍计算 body_length, 第二遍才真正编码
    internal.body_length = INTERNAL_HEADER_LEN + len(payload) - 4
    plain_no_trailer = internal.pack(payload[:INTERNAL_PREFIX_LEN]) + payload[INTERNAL_PREFIX_LEN:]
    trailer = cipher.build_tsf4g_trailer(len(plain_no_trailer))
    raw = plain_no_trailer + trailer
    body = cipher.encrypt_body(raw)
    head = GcpHead(
        command=CMD_DATA,
        encrypted=1,
        sequence=gcp_sequence,
        head_length=25,
        body_length=len(body),
        ext_bytes=b"\x00\x00\x00\x00",
    )
    return head.pack() + body
