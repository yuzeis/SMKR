from __future__ import annotations


class RFNError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def rfn_fail(code: str, message: str) -> None:
    raise RFNError(code, message)

