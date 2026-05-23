from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Capability:
    name: str
    scope: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Instruction:
    op: str
    args: tuple[Any, ...] = ()
    line: int = 0
    text: str = ""


@dataclass
class Function:
    name: str
    args: list[tuple[str, str]]
    return_type: str
    instructions: list[Instruction] = field(default_factory=list)
    labels: dict[str, int] = field(default_factory=dict)
    no_side_effect: bool = True
    deterministic: bool = True
    capabilities: list[Capability] = field(default_factory=list)
    timeout_ms: int = 3000
    max_ops: int = 10000
    max_output_bytes: int = 1048576
    desc: str = ""


@dataclass
class Module:
    name: str = "main"
    version: str = "0.1"
    target: str = "rfn-vm-0.1"
    functions: dict[str, Function] = field(default_factory=dict)
    registry_pin: dict[str, Any] = field(default_factory=dict)

