from __future__ import annotations

from dataclasses import dataclass

from roco_mitm.codec import proto_codec

from .errors import rfn_fail


@dataclass
class Reader:
    data: bytes
    pos: int = 0

    def left(self) -> int:
        return max(0, len(self.data) - self.pos)

    def seek(self, off: int) -> None:
        if off < 0 or off > len(self.data):
            rfn_fail("E_RANGE", f"reader seek out of range: {off}")
        self.pos = off

    def skip(self, n: int) -> None:
        self.seek(self.pos + n)

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            rfn_fail("E_RANGE", f"reader read out of range: {n}")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def read_int(self, width: int, endian: str, signed: bool) -> int:
        if width not in (1, 2, 4, 8):
            rfn_fail("E_ARG", f"invalid int width: {width}")
        if endian not in ("be", "le", "big", "little"):
            rfn_fail("E_ARG", f"invalid endian: {endian}")
        byteorder = "big" if endian == "be" else "little" if endian == "le" else endian
        return int.from_bytes(self.take(width), byteorder, signed=signed)

    def read_varint(self) -> int:
        try:
            value, new_pos = proto_codec.decode_varint(self.data, self.pos)
        except ValueError as exc:
            rfn_fail("E_BAD_WIRE", str(exc))
        self.pos = new_pos
        return value
