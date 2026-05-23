"""TGCP wire and internal DATA header helpers."""
from __future__ import annotations

import struct
from dataclasses import dataclass


TGCP_MAGIC = 0x3366
HEAD_VERSION = 0x000B
BODY_VERSION = 0x000B
CMD_ACK = 0x1002
CMD_DATA = 0x4013

GCP_BASE_HEAD_LEN = 21
INTERNAL_HEADER_LEN = 30
INTERNAL_PREFIX_LEN = 2


@dataclass
class GcpHead:
    """21-byte big-endian TGCP header plus ExtHead bytes."""

    command: int = CMD_DATA
    encrypted: int = 1
    sequence: int = 0
    head_length: int = 25
    body_length: int = 0
    ext_bytes: bytes = b"\x00\x00\x00\x00"
    magic: int = TGCP_MAGIC
    head_version: int = HEAD_VERSION
    body_version: int = BODY_VERSION

    def pack(self) -> bytes:
        base = struct.pack(
            ">HHHHBIII",
            self.magic,
            self.head_version,
            self.body_version,
            self.command,
            self.encrypted,
            self.sequence,
            self.head_length,
            self.body_length,
        )
        expected_ext = self.head_length - GCP_BASE_HEAD_LEN
        if len(self.ext_bytes) != expected_ext:
            raise ValueError(f"ext_bytes length {len(self.ext_bytes)} != head_length-21={expected_ext}")
        return base + self.ext_bytes

    @classmethod
    def unpack(cls, data: bytes) -> "GcpHead":
        if len(data) < GCP_BASE_HEAD_LEN:
            raise ValueError("data shorter than 21-byte GCP header")
        (magic, hv, bv, cmd, enc, seq, hl, bl) = struct.unpack(">HHHHBIII", data[:GCP_BASE_HEAD_LEN])
        if len(data) < hl:
            raise ValueError("data shorter than head_length")
        return cls(
            command=cmd,
            encrypted=enc,
            sequence=seq,
            head_length=hl,
            body_length=bl,
            ext_bytes=bytes(data[GCP_BASE_HEAD_LEN:hl]),
            magic=magic,
            head_version=hv,
            body_version=bv,
        )


@dataclass
class InternalHeader:
    """30-byte plaintext DATA header.

    The two bytes after this fixed header are the first bytes of the protobuf
    payload. Older code parsed them as the low 16 bits of counter2; this class
    still exposes that 32-bit composite as counter2 for display and sequencing.
    """

    counter1: int = 0
    magic_55aa: bytes = b"\x55\xaa\x00\x00"
    body_length: int = 0
    zeros0: bytes = b"\x00\x00"
    const1: bytes = b"\x00\x00\x00\x01"
    session_id: int = 0
    magic2: int = 0x0001
    sub_id: int = 0
    const2: bytes = b"\x39\x63\x00\x00"
    counter2: int = 0

    def pack(self, payload_prefix: bytes = b"\x00\x00") -> bytes:
        prefix = bytes(payload_prefix[:INTERNAL_PREFIX_LEN])
        counter2_hi = (self.counter2 >> 16) & 0xFFFF
        return struct.pack(
            ">I4sH2s4sIHH4sH",
            self.counter1,
            self.magic_55aa,
            self.body_length,
            self.zeros0,
            self.const1,
            self.session_id,
            self.magic2,
            self.sub_id,
            self.const2,
            counter2_hi,
        ) + prefix

    @classmethod
    def unpack(cls, data: bytes) -> "InternalHeader":
        if len(data) < INTERNAL_HEADER_LEN:
            raise ValueError(f"internal header needs {INTERNAL_HEADER_LEN} bytes")
        (c1, m1, bl, z0, c_1, sid, m2, sub, c_2, c2_hi) = struct.unpack(
            ">I4sH2s4sIHH4sH", data[:INTERNAL_HEADER_LEN]
        )
        prefix = data[INTERNAL_HEADER_LEN : INTERNAL_HEADER_LEN + INTERNAL_PREFIX_LEN]
        c2_lo = int.from_bytes(prefix.ljust(INTERNAL_PREFIX_LEN, b"\x00"), "big")
        c2 = ((c2_hi & 0xFFFF) << 16) | c2_lo
        return cls(c1, m1, bl, z0, c_1, sid, m2, sub, c_2, c2)


def split_plaintext(plaintext_no_trailer: bytes) -> tuple[InternalHeader, bytes]:
    if len(plaintext_no_trailer) < INTERNAL_HEADER_LEN:
        raise ValueError(f"plaintext length below {INTERNAL_HEADER_LEN}")
    return InternalHeader.unpack(plaintext_no_trailer), plaintext_no_trailer[INTERNAL_HEADER_LEN:]
