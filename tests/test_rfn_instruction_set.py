from __future__ import annotations

import pytest

from roco_mitm.rfn import RFNError, RFNVM, assemble_source


def _run(src: str, func: str, *args):
    module = assemble_source(src)
    return RFNVM(module).call(func, *args)


def test_rfn_builds_protobuf_payload_with_slim_buffer_instruction() -> None:
    src = """
    .function Build(shop_id:u32) -> bytes
    .no_side_effect true
    .deterministic true
      buf.new r0
      pb.varint r0, 1, arg0
      buf.append_int r0, 0x55AA, 2, "be", false
      buf.take r1, r0
      ret r1
    .end
    """
    assert _run(src, "Build", 8000) == bytes.fromhex("08c03e55aa")


def test_rfn_reader_control_flow_and_math() -> None:
    src = """
    .function ReadAndClamp(payload:bytes) -> u32
    .no_side_effect true
    .deterministic true
      rd.new r0, arg0
      rd.int r1, r0, 2, "be", false
      int.add r2, r1, 10
      int.clamp r3, r2, 0, 100
      cmp.eq r4, r3, 100
      jnz r4, done
      fail "unexpected"
    done:
      ret r3
    .end
    """
    assert _run(src, "ReadAndClamp", bytes.fromhex("00fa")) == 100


def test_rfn_object_paths_are_type_stable() -> None:
    src = """
    .function Extract(data:obj) -> arr
    .no_side_effect true
    .deterministic true
      obj.get r0, arg0, "player.uin"
      obj.get_all r1, arg0, "items[*].item_id"
      arr.push r2, r1, r0
      ret r2
    .end
    """
    value = {"player": {"uin": 1852750}, "items": [{"item_id": 1}, {"item_id": 2}]}
    assert _run(src, "Extract", value) == [1, 2, 1852750]


def test_rfn_obj_get_rejects_wildcard() -> None:
    src = """
    .function Bad(data:obj) -> any
    .no_side_effect true
    .deterministic true
      obj.get r0, arg0, "items[*].id"
      ret r0
    .end
    """
    with pytest.raises(RFNError) as got:
        _run(src, "Bad", {"items": [{"id": 1}]})
    assert got.value.code == "E_TYPE"


def test_rfn_rejects_old_pure_attribute() -> None:
    src = """
    .function Bad() -> bool
    .pure true
      ret true
    .end
    """
    with pytest.raises(RFNError) as got:
        assemble_source(src)
    assert got.value.code == "E_COMPILE"


def test_rfn_max_ops_limit() -> None:
    src = """
    .function Loop() -> bool
    .no_side_effect true
    .deterministic true
    .max_ops 8
    again:
      jmp again
    .end
    """
    with pytest.raises(RFNError) as got:
        _run(src, "Loop")
    assert got.value.code == "E_LIMIT_OPS"

