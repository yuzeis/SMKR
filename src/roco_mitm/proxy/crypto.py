"""AES-128-CBC 加解密与 tsf4g trailer 处理。"""
from __future__ import annotations

import os
from Crypto.Cipher import AES

CORRECT_IV = bytes(range(16))
TSF4G_MARKER = b"tsf4g"
TSF4G_MIN_TRAILER_LEN = 6


class GcpCipher:
    """封装 AES-128-CBC 加解密 + tsf4g trailer 处理。"""

    def __init__(self, session_key: bytes):
        if len(session_key) != 16:
            raise ValueError(f"session_key 必须 16 字节，实际 {len(session_key)}")
        self.session_key = session_key

    def decrypt_body(self, body: bytes) -> bytes:
        if len(body) < 16 or len(body) % 16 != 0:
            raise ValueError(f"body 长度非法: {len(body)}")
        return AES.new(self.session_key, AES.MODE_CBC, CORRECT_IV).decrypt(body)

    def encrypt_body(self, raw_plain: bytes) -> bytes:
        if len(raw_plain) < 16 or len(raw_plain) % 16 != 0:
            raise ValueError(f"raw_plain 长度非法: {len(raw_plain)}")
        return AES.new(self.session_key, AES.MODE_CBC, CORRECT_IV).encrypt(raw_plain)

    @staticmethod
    def build_tsf4g_trailer(input_len: int) -> bytes:
        """按 16 字节对齐规则补 tsf4g trailer。"""
        rem = input_len % 16
        trailer_len = 16 - rem if rem <= 10 else 32 - rem
        if not (TSF4G_MIN_TRAILER_LEN <= trailer_len <= 22):
            raise ValueError(f"非法 trailer_len={trailer_len}")
        random_len = trailer_len - TSF4G_MIN_TRAILER_LEN
        return os.urandom(random_len) + TSF4G_MARKER + bytes([trailer_len])

    @staticmethod
    def split_trailer(plaintext: bytes) -> tuple[bytes, bytes]:
        """返回 (body_without_trailer, trailer)。失败抛错。"""
        if len(plaintext) < TSF4G_MIN_TRAILER_LEN:
            raise ValueError("plaintext 太短")
        trailer_len = plaintext[-1]
        if not (TSF4G_MIN_TRAILER_LEN <= trailer_len <= len(plaintext)):
            raise ValueError(f"非法 trailer_len={trailer_len}")
        trailer = plaintext[-trailer_len:]
        if trailer[-6:-1] != TSF4G_MARKER:
            raise ValueError("未找到 tsf4g 标记")
        return plaintext[:-trailer_len], trailer
