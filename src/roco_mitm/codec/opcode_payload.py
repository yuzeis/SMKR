"""Generic opcode payload decoding strategies.

The generated protobuf schema is still the source of truth.  This module only
models transport shapes observed around that schema: direct protobuf payloads,
flattened nested message bodies, short leading prefixes, and raw scalar/string
payloads that are not protobuf encoded.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from . import proto_codec


MessageResolver = Callable[[str], dict | None]


@dataclass(frozen=True)
class DecodeResult:
    decoded: dict[str, Any]
    source: str
    start: int
    consumed: int
    payload_len: int
    matched_keys: int
    unknown_top: int
    unknown_recursive: int

    @property
    def consumed_all(self) -> bool:
        return self.consumed >= self.payload_len

    @property
    def complete_without_unknowns(self) -> bool:
        return self.consumed_all and self.matched_keys > 0 and self.unknown_recursive == 0


def count_unknowns(value: Any) -> int:
    if isinstance(value, dict):
        total = 0
        unknown = value.get("_unknown")
        if isinstance(unknown, list):
            total += len(unknown)
        for key, item in value.items():
            if key == "_unknown":
                continue
            total += count_unknowns(item)
        return total
    if isinstance(value, list):
        return sum(count_unknowns(item) for item in value)
    return 0


def decode_opcode_payload(
    schema: dict,
    payload: bytes,
    resolve_message: MessageResolver,
    *,
    max_depth: int = 3,
) -> DecodeResult:
    best: DecodeResult | None = None
    for candidate in _protobuf_candidates(schema, payload, resolve_message, max_depth=max_depth):
        if best is None or _candidate_score(candidate) > _candidate_score(best):
            best = candidate
        if _is_strong_complete(candidate):
            best = candidate
            break

    if best is None or not best.complete_without_unknowns:
        raw = list(_raw_candidates(schema, payload, resolve_message))
        if raw:
            raw_best = max(raw, key=_candidate_score)
            if best is None or _candidate_score(raw_best) > _candidate_score(best):
                best = raw_best

    if best is None:
        return DecodeResult({}, "schema", 0, 0, len(payload), 0, 0, 0)
    return best


def _is_strong_complete(candidate: DecodeResult) -> bool:
    if not candidate.complete_without_unknowns:
        return False
    if "#mixed:" in candidate.source or "#continued:" in candidate.source:
        return True
    if candidate.source == "schema" and candidate.start == 0:
        return True
    if candidate.matched_keys > 1 and not candidate.source.startswith("raw_"):
        return True
    return False


def _protobuf_candidates(
    schema: dict,
    payload: bytes,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> Iterable[DecodeResult]:
    yield from _scan_schema("schema", schema, payload, resolve_message, max_depth=max_depth)
    yield from _mixed_parent_message_candidates("schema", schema, payload, resolve_message, max_depth=max_depth)
    yield from _message_continuation_candidates("schema", schema, payload, resolve_message, max_depth=max_depth)
    yield from _parent_prefix_flattened_candidates("schema", schema, payload, resolve_message, max_depth=max_depth)
    for source, nested in _nested_message_candidates(schema, resolve_message, max_depth=max_depth):
        yield from _scan_schema(source, nested, payload, resolve_message, max_depth=max_depth)
        yield from _implicit_schema_candidates(source, nested, payload, resolve_message, max_depth=max_depth)


def _nested_message_candidates(
    schema: dict,
    resolve_message: MessageResolver,
    *,
    prefix: str = "flattened",
    depth: int = 0,
    max_depth: int = 3,
) -> Iterable[tuple[str, dict]]:
    if depth >= max_depth:
        return
    message_fields = [
        field
        for field in schema.get("fields") or []
        if proto_codec.strip_generic(str(field.get("type") or "")) == "message"
    ]
    # Large action/union containers (for example SpaceActionCollection) explode
    # combinatorially if every branch is tried as a top-level payload.  Recurse
    # only through compact wrapper/container messages; direct children are still
    # tried by their parent.
    if depth > 0 and len(message_fields) > 8:
        return
    for field in message_fields:
        ref = field.get("ref")
        if not ref:
            continue
        nested = resolve_message(str(ref))
        if nested is None:
            continue
        name = str(field.get("name") or ref)
        source = f"{prefix}:{name}" if prefix == "flattened" else f"{prefix}.{name}"
        yield source, nested
        yield from _nested_message_candidates(
            nested, resolve_message, prefix=source, depth=depth + 1, max_depth=max_depth
        )


def _scan_schema(
    source: str,
    schema: dict,
    payload: bytes,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> Iterable[DecodeResult]:
    if not payload:
        decoded, consumed, _field_count, unknown_top = _decode_once(
            schema, payload, resolve_message, start=0, max_depth=max_depth
        )
        yield _make_result(decoded, source, 0, consumed, len(payload), unknown_top)
        return

    max_start = min(8, max(0, len(payload) - 1))
    for start in range(0, max_start + 1):
        if start > 0 and not proto_codec.is_valid_tag_byte(payload[start]):
            continue
        decoded, consumed, _field_count, unknown_top = _decode_once(
            schema, payload, resolve_message, start=start, max_depth=max_depth
        )
        if start > 0:
            decoded = dict(decoded)
            decoded["_prefix_hex"] = payload[:start].hex()
        candidate_source = source if start == 0 else f"{source}@+{start}"
        yield _make_result(decoded, candidate_source, start, consumed, len(payload), unknown_top)


def _implicit_schema_candidates(
    source: str,
    schema: dict,
    payload: bytes,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> Iterable[DecodeResult]:
    if not payload:
        return
    max_start = min(8, max(0, len(payload) - 1))
    for start in range(0, max_start + 1):
        decoded, consumed, matched = _decode_implicit_first_field_prefix(
            schema, payload, start, resolve_message, max_depth=max_depth
        )
        if decoded is None or matched <= 0 or consumed != len(payload):
            continue
        if start > 0:
            decoded = dict(decoded)
            decoded["_prefix_hex"] = payload[:start].hex()
        first = _first_field(schema)
        field_name = str((first or {}).get("name") or "field")
        candidate_source = f"{source}#implicit:{field_name}" if start == 0 else f"{source}#implicit:{field_name}@+{start}"
        yield _make_result(decoded, candidate_source, start, consumed, len(payload), 0)


def _mixed_parent_message_candidates(
    source: str,
    schema: dict,
    payload: bytes,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> Iterable[DecodeResult]:
    """Decode flattened leading message bodies followed by parent fields.

    Several Roco payloads omit the outer tag for the first repeated/message
    field but resume normal parent-level protobuf tags afterwards.  This keeps
    the schema as the authority: the prefix must decode as the child message and
    the suffix must decode as the parent schema.
    """
    if not payload:
        return
    message_fields = [
        field
        for field in schema.get("fields") or []
        if proto_codec.strip_generic(str(field.get("type") or "")) == "message"
    ]
    if not message_fields:
        return
    max_start = min(8, max(0, len(payload) - 1))
    for field in message_fields:
        nested = _field_message_schema(field, resolve_message)
        if nested is None:
            continue
        field_no = _field_no(field)
        if field_no is None:
            continue
        field_name = _field_name(field)
        for start in range(0, max_start + 1):
            attempts: list[tuple[str, dict[str, Any], int, int]] = []

            decoded, pos, matched = _decode_schema_prefix(
                nested, payload, start, resolve_message, max_depth=max_depth
            )
            if decoded is not None and matched > 0 and pos > start:
                attempts.append(("flat", decoded, pos, matched))

            decoded, pos, matched = _decode_implicit_first_field_prefix(
                nested, payload, start, resolve_message, max_depth=max_depth
            )
            if decoded is not None and matched > 0 and pos > start:
                attempts.append(("implicit", decoded, pos, matched))

            decoded, pos, matched = _decode_length_prefixed_union_prefix(
                nested, payload, start, resolve_message, max_depth=max_depth
            )
            if decoded is not None and matched > 0 and pos > start:
                attempts.append(("len_union", decoded, pos, matched))

            decoded, pos, matched = _decode_union_branch_prefix(
                nested, payload, start, resolve_message, max_depth=max_depth
            )
            if decoded is not None and matched > 0 and pos > start:
                attempts.append(("union", decoded, pos, matched))

            for mode, child_decoded, pos, _matched in attempts:
                suffix = _decode_parent_suffix(
                    schema, payload, pos, resolve_message, max_depth=max_depth, min_field_no=field_no
                )
                if suffix is None:
                    continue
                suffix_decoded, consumed = suffix
                if not suffix_decoded and mode not in {"len_union", "union"}:
                    continue
                combined = _combine_parent_child(field, child_decoded, suffix_decoded)
                if start > 0:
                    combined = dict(combined)
                    combined["_prefix_hex"] = payload[:start].hex()
                candidate_source = f"{source}#mixed:{field_name}:{mode}"
                if start > 0:
                    candidate_source += f"@+{start}"
                yield _make_result(combined, candidate_source, start, consumed, len(payload), 0)


def _message_continuation_candidates(
    source: str,
    schema: dict,
    payload: bytes,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> Iterable[DecodeResult]:
    """Decode parent message fields whose later child fields are flattened.

    Some packets start with a normal parent message field and then place more
    fields from that child message at parent level before the next parent field.
    """
    if not payload:
        return
    message_fields = [
        field
        for field in schema.get("fields") or []
        if proto_codec.strip_generic(str(field.get("type") or "")) == "message"
    ]
    max_start = min(8, max(0, len(payload) - 1))
    for field in message_fields:
        nested = _field_message_schema(field, resolve_message)
        field_no = _field_no(field)
        if nested is None or field_no is None:
            continue
        field_name = _field_name(field)
        for start in range(0, max_start + 1):
            read = _read_matching_field(field, payload, start, resolve_message, max_depth=max_depth)
            if read is None:
                continue
            initial_value, pos = read
            cont_decoded, cont_pos, cont_matched = _decode_schema_prefix(
                nested, payload, pos, resolve_message, max_depth=max_depth
            )
            if cont_decoded is None or cont_matched <= 0 or cont_pos <= pos:
                continue
            suffix = _decode_parent_suffix(
                schema, payload, cont_pos, resolve_message, max_depth=max_depth, min_field_no=field_no + 1
            )
            if suffix is None:
                continue
            suffix_decoded, consumed = suffix
            merged_child = _merge_child_continuation(initial_value, cont_decoded, repeated=bool(field.get("repeated")))
            combined = _combine_parent_child(field, merged_child, suffix_decoded, child_is_value=True)
            if start > 0:
                combined = dict(combined)
                combined["_prefix_hex"] = payload[:start].hex()
            candidate_source = f"{source}#continued:{field_name}"
            if start > 0:
                candidate_source += f"@+{start}"
            yield _make_result(combined, candidate_source, start, consumed, len(payload), 0)


def _parent_prefix_flattened_candidates(
    source: str,
    schema: dict,
    payload: bytes,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> Iterable[DecodeResult]:
    if not payload:
        return
    message_fields = [
        field
        for field in schema.get("fields") or []
        if proto_codec.strip_generic(str(field.get("type") or "")) == "message"
    ]
    if not message_fields:
        return
    max_start = min(8, max(0, len(payload) - 1))
    for start in range(0, max_start + 1):
        prefix_decoded, pos, prefix_matched = _decode_schema_prefix(
            schema, payload, start, resolve_message, max_depth=max_depth
        )
        if prefix_decoded is None or prefix_matched <= 0 or pos <= start or pos >= len(payload):
            continue
        for field in message_fields:
            field_no = _field_no(field)
            nested = _field_message_schema(field, resolve_message)
            if field_no is None or nested is None:
                continue
            for path, child_decoded, child_pos, child_matched in _descendant_prefix_candidates(
                nested, payload, pos, resolve_message, max_depth=max_depth
            ):
                if child_matched <= 0 or child_pos <= pos:
                    continue
                suffix = _decode_parent_suffix(
                    schema,
                    payload,
                    child_pos,
                    resolve_message,
                    max_depth=max_depth,
                    min_field_no=field_no + 1,
                )
                if suffix is None:
                    continue
                suffix_decoded, consumed = suffix
                combined = _merge_decoded_dict(prefix_decoded, {_field_name(field): child_decoded})
                combined = _merge_decoded_dict(combined, suffix_decoded)
                if start > 0:
                    combined = dict(combined)
                    combined["_prefix_hex"] = payload[:start].hex()
                candidate_source = f"{source}#segmented:{_field_name(field)}.{path}"
                if start > 0:
                    candidate_source += f"@+{start}"
                yield _make_result(combined, candidate_source, start, consumed, len(payload), 0)


def _decode_once(
    schema: dict,
    payload: bytes,
    resolve_message: MessageResolver,
    *,
    start: int,
    max_depth: int,
) -> tuple[dict, int, int, int]:
    message_decoder = None
    if max_depth > 0:
        def message_decoder(sub_schema: dict, raw: bytes, resolver: proto_codec.RefResolver | None) -> dict:
            resolved = resolver or resolve_message
            return decode_opcode_payload(
                sub_schema,
                raw,
                resolved,
                max_depth=max_depth - 1,
            ).decoded

    return proto_codec.decode_payload_once(
        schema,
        payload,
        resolve_message,
        start=start,
        decode_message=message_decoder,
    )


def _field_no(field: dict) -> int | None:
    try:
        return int(field.get("no"))
    except (TypeError, ValueError):
        return None


def _field_name(field: dict) -> str:
    return str(field.get("name") or f"f{field.get('no')}")


def _first_field(schema: dict) -> dict | None:
    fields = schema.get("fields") or []
    if not fields:
        return None
    return min(fields, key=lambda f: _field_no(f) or 0x7FFFFFFF)


def _field_message_schema(field: dict, resolve_message: MessageResolver) -> dict | None:
    if field.get("fields"):
        return {"fields": field.get("fields") or []}
    ref = field.get("ref")
    return resolve_message(str(ref)) if ref else None


def _message_decoder(
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> proto_codec.MessageDecoder | None:
    if max_depth <= 0:
        return None

    def decoder(sub_schema: dict, raw: bytes, resolver: proto_codec.RefResolver | None) -> dict:
        resolved = resolver or resolve_message
        return decode_opcode_payload(
            sub_schema,
            raw,
            resolved,
            max_depth=max_depth - 1,
        ).decoded

    return decoder


def _decode_field_value(
    field: dict,
    wt: int,
    raw: Any,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> Any:
    return proto_codec._decode_value(  # type: ignore[attr-defined]
        field,
        wt,
        raw,
        resolve_message,
        _message_decoder(resolve_message, max_depth=max_depth),
    )


def _append_field(out: dict[str, Any], field: dict, value: Any) -> None:
    name = _field_name(field)
    if field.get("repeated"):
        out.setdefault(name, []).append(value)
    else:
        out.setdefault(name, value)


def _merge_decoded_dict(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    out = dict(left)
    for key, value in right.items():
        if key in out and isinstance(out[key], list) and isinstance(value, list):
            out[key] = [*out[key], *value]
        elif key in out and isinstance(out[key], dict) and isinstance(value, dict):
            out[key] = _merge_decoded_dict(out[key], value)
        else:
            out.setdefault(key, value)
    return out


def _read_matching_field(
    field: dict,
    payload: bytes,
    pos: int,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> tuple[Any, int] | None:
    if pos >= len(payload):
        return None
    try:
        tag, tag_end = proto_codec.decode_varint(payload, pos)
    except Exception:
        return None
    if (tag >> 3) != _field_no(field):
        return None
    wt = tag & 7
    try:
        raw, end = proto_codec._read_wire_value(payload, tag_end, wt)  # type: ignore[attr-defined]
        expected = proto_codec.wire_type_for(str(field.get("type") or ""))
    except Exception:
        return None
    if wt != expected:
        return None
    return _decode_field_value(field, wt, raw, resolve_message, max_depth=max_depth), end


def _decode_schema_prefix(
    schema: dict,
    payload: bytes,
    start: int,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> tuple[dict[str, Any] | None, int, int]:
    fields = schema.get("fields") or []
    by_no = {_field_no(field): field for field in fields if _field_no(field) is not None}
    out: dict[str, Any] = {}
    matched = 0
    pos = start
    while pos < len(payload):
        tag_pos = pos
        try:
            tag, value_pos = proto_codec.decode_varint(payload, pos)
        except Exception:
            break
        field = by_no.get(tag >> 3)
        if field is None:
            break
        wt = tag & 7
        try:
            raw, end = proto_codec._read_wire_value(payload, value_pos, wt)  # type: ignore[attr-defined]
            expected = proto_codec.wire_type_for(str(field.get("type") or ""))
        except Exception:
            break
        if wt != expected:
            if field.get("repeated") and wt == proto_codec.WIRE_LEN and proto_codec._is_packable_type(str(field.get("type") or "")):  # type: ignore[attr-defined]
                try:
                    values = proto_codec._decode_packed_values(field, raw)  # type: ignore[attr-defined]
                except Exception:
                    break
                for value in values:
                    _append_field(out, field, value)
                matched += 1
                pos = end
                continue
            break
        value = _decode_field_value(field, wt, raw, resolve_message, max_depth=max_depth)
        _append_field(out, field, value)
        matched += 1
        pos = end
        if pos == tag_pos:
            break
    return out, pos, matched


def _decode_implicit_first_field_prefix(
    schema: dict,
    payload: bytes,
    start: int,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> tuple[dict[str, Any] | None, int, int]:
    first = _first_field(schema)
    if first is None or start >= len(payload):
        return None, start, 0
    base = proto_codec.strip_generic(str(first.get("type") or ""))
    if base == "message":
        message_field_count = sum(
            1
            for field in schema.get("fields") or []
            if proto_codec.strip_generic(str(field.get("type") or "")) == "message"
        )
        if message_field_count > 8:
            return None, start, 0
    out: dict[str, Any] = {}
    try:
        wt = proto_codec.wire_type_for(str(first.get("type") or ""))
    except Exception:
        return None, start, 0

    pos = start
    try:
        if wt == proto_codec.WIRE_VARINT:
            raw, pos = proto_codec.decode_varint(payload, pos)
        elif wt == proto_codec.WIRE_FIXED32:
            if pos + 4 > len(payload):
                return None, start, 0
            raw = int.from_bytes(payload[pos : pos + 4], "little")
            pos += 4
        elif wt == proto_codec.WIRE_FIXED64:
            if pos + 8 > len(payload):
                return None, start, 0
            raw = int.from_bytes(payload[pos : pos + 8], "little")
            pos += 8
        elif wt == proto_codec.WIRE_LEN:
            size, body_start = proto_codec.decode_varint(payload, pos)
            body_end = body_start + size
            if size < 0 or body_end > len(payload):
                return None, start, 0
            raw = payload[body_start:body_end]
            pos = body_end
        else:
            return None, start, 0
    except Exception:
        return None, start, 0

    if base == "message" and not raw:
        return None, start, 0
    value = _decode_field_value(first, wt, raw, resolve_message, max_depth=max_depth)
    _append_field(out, first, value)
    rest, pos, matched = _decode_schema_prefix(
        schema, payload, pos, resolve_message, max_depth=max_depth
    )
    if rest:
        out = _merge_decoded_dict(out, rest)
    return out, pos, matched + 1


def _decode_length_prefixed_union_prefix(
    schema: dict,
    payload: bytes,
    start: int,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> tuple[dict[str, Any] | None, int, int]:
    fields = [
        field
        for field in schema.get("fields") or []
        if proto_codec.strip_generic(str(field.get("type") or "")) == "message"
    ]
    if len(fields) < 3 or start >= len(payload):
        return None, start, 0
    try:
        size, body_start = proto_codec.decode_varint(payload, start)
    except Exception:
        return None, start, 0
    body_end = body_start + size
    if size <= 0 or body_end > len(payload):
        return None, start, 0
    body = payload[body_start:body_end]

    decoded, pos, matched = _decode_schema_prefix(
        schema, body, 0, resolve_message, max_depth=max(0, max_depth - 1)
    )
    if decoded is not None and matched > 0 and pos == len(body) and count_unknowns(decoded) == 0:
        return decoded, body_end, matched

    best: tuple[tuple[int, int, int], dict[str, Any], dict] | None = None
    for field in fields:
        nested = _field_message_schema(field, resolve_message)
        if nested is None:
            continue
        decoded, pos, matched = _decode_schema_prefix(
            nested, body, 0, resolve_message, max_depth=0
        )
        if decoded is None or matched <= 0 or pos != len(body) or count_unknowns(decoded) != 0:
            continue
        score = (matched, len(decoded), -len(nested.get("fields") or []))
        if best is None or score > best[0]:
            best = (score, decoded, field)
    if best is None:
        return None, start, 0
    _score, decoded, field = best
    return {_field_name(field): decoded}, body_end, 1


def _decode_union_branch_prefix(
    schema: dict,
    payload: bytes,
    start: int,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
) -> tuple[dict[str, Any] | None, int, int]:
    fields = [
        field
        for field in schema.get("fields") or []
        if proto_codec.strip_generic(str(field.get("type") or "")) == "message"
    ]
    if len(fields) < 8 or start >= len(payload):
        return None, start, 0
    try:
        tag, value_pos = proto_codec.decode_varint(payload, start)
    except Exception:
        return None, start, 0
    fn = tag >> 3
    wt = tag & 7
    best: tuple[tuple[int, int, int], dict[str, Any], dict, int] | None = None
    for field in fields:
        nested = _field_message_schema(field, resolve_message)
        if nested is None:
            continue
        nested_fields = nested.get("fields") or []
        first_match = next((sub for sub in nested_fields if _field_no(sub) == fn), None)
        if first_match is None:
            continue
        try:
            if proto_codec.wire_type_for(str(first_match.get("type") or "")) != wt:
                continue
        except Exception:
            continue
        decoded, pos, matched = _decode_schema_prefix(
            nested, payload, start, resolve_message, max_depth=0
        )
        if decoded is None or matched <= 0 or pos <= value_pos or count_unknowns(decoded):
            continue
        score = (matched, pos - start, -len(nested_fields))
        if best is None or score > best[0]:
            best = (score, decoded, field, pos)
    if best is None:
        return None, start, 0
    _score, decoded, field, pos = best
    return {_field_name(field): decoded}, pos, 1


def _descendant_prefix_candidates(
    schema: dict,
    payload: bytes,
    start: int,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
    depth: int = 0,
) -> Iterable[tuple[str, dict[str, Any], int, int]]:
    decoded, pos, matched = _decode_schema_prefix(
        schema, payload, start, resolve_message, max_depth=max_depth
    )
    if decoded is not None and matched > 0 and pos > start and count_unknowns(decoded) == 0:
        yield "self", decoded, pos, matched

    decoded, pos, matched = _decode_implicit_first_field_prefix(
        schema, payload, start, resolve_message, max_depth=max_depth
    )
    if decoded is not None and matched > 0 and pos > start and count_unknowns(decoded) == 0:
        yield "implicit", decoded, pos, matched

    decoded, pos, matched = _decode_union_branch_prefix(
        schema, payload, start, resolve_message, max_depth=max_depth
    )
    if decoded is not None and matched > 0 and pos > start and count_unknowns(decoded) == 0:
        yield "union", decoded, pos, matched

    if depth >= 1:
        return
    for field in schema.get("fields") or []:
        if proto_codec.strip_generic(str(field.get("type") or "")) != "message":
            continue
        nested = _field_message_schema(field, resolve_message)
        if nested is None:
            continue
        for sub_path, sub_decoded, sub_pos, sub_matched in _descendant_prefix_candidates(
            nested,
            payload,
            start,
            resolve_message,
            max_depth=max(0, max_depth - 1),
            depth=depth + 1,
        ):
            yield f"{_field_name(field)}.{sub_path}", {_field_name(field): sub_decoded}, sub_pos, sub_matched


def _decode_parent_suffix(
    schema: dict,
    payload: bytes,
    pos: int,
    resolve_message: MessageResolver,
    *,
    max_depth: int,
    min_field_no: int,
) -> tuple[dict[str, Any], int] | None:
    if pos == len(payload):
        return {}, pos
    suffix_fields = [
        field
        for field in schema.get("fields") or []
        if (_field_no(field) or -1) >= min_field_no
    ]
    if not suffix_fields:
        return None
    decoded, consumed, field_count, unknown_top = proto_codec.decode_payload_once(
        {"fields": suffix_fields},
        payload,
        resolve_message,
        start=pos,
        decode_message=_message_decoder(resolve_message, max_depth=max_depth),
    )
    if field_count <= 0 or unknown_top or consumed != len(payload) or count_unknowns(decoded):
        return None
    return decoded, consumed


def _combine_parent_child(
    field: dict,
    child_decoded: Any,
    suffix_decoded: dict[str, Any],
    *,
    child_is_value: bool = False,
) -> dict[str, Any]:
    name = _field_name(field)
    out = dict(suffix_decoded)
    if field.get("repeated"):
        prefix_values = child_decoded if child_is_value and isinstance(child_decoded, list) else [child_decoded]
        suffix_values = out.pop(name, [])
        if not isinstance(suffix_values, list):
            suffix_values = [suffix_values]
        out = {name: [*prefix_values, *suffix_values], **out}
    else:
        value = child_decoded
        if child_is_value and isinstance(child_decoded, list):
            value = child_decoded[-1] if child_decoded else {}
        out = {name: value, **out}
    return out


def _merge_child_continuation(initial_value: Any, continuation: dict[str, Any], *, repeated: bool) -> Any:
    if repeated:
        if isinstance(initial_value, list):
            values = list(initial_value)
        else:
            values = [initial_value]
        if values and isinstance(values[-1], dict):
            values[-1] = _merge_decoded_dict(values[-1], continuation)
        else:
            values.append(continuation)
        return values
    if isinstance(initial_value, dict):
        return _merge_decoded_dict(initial_value, continuation)
    return continuation


def _make_result(
    decoded: dict[str, Any],
    source: str,
    start: int,
    consumed: int,
    payload_len: int,
    unknown_top: int,
) -> DecodeResult:
    matched = sum(1 for key in decoded if not str(key).startswith("_"))
    return DecodeResult(
        decoded=decoded,
        source=source,
        start=start,
        consumed=consumed,
        payload_len=payload_len,
        matched_keys=matched,
        unknown_top=unknown_top,
        unknown_recursive=count_unknowns(decoded),
    )


def _candidate_score(candidate: DecodeResult) -> tuple[int, int, int, int, int, int]:
    source_priority = 2 if candidate.source == "schema" else 1
    if candidate.source.startswith("raw_"):
        source_priority = 0
    return (
        1 if candidate.complete_without_unknowns else 0,
        1 if candidate.consumed_all else 0,
        -candidate.unknown_recursive,
        source_priority,
        -candidate.start,
        candidate.matched_keys,
    )


def _raw_candidates(
    schema: dict,
    payload: bytes,
    resolve_message: MessageResolver,
) -> Iterable[DecodeResult]:
    if not payload:
        return
    text = _try_decode_printable(payload)
    if text is not None:
        yield from _raw_string_candidates(schema, payload, text, resolve_message)

    varint_value = _try_single_varint(payload)
    if varint_value is not None:
        yield from _raw_varint_candidates(schema, payload, varint_value, resolve_message)

    struct_decoded = _try_raw_struct(schema, payload, resolve_message)
    if struct_decoded is not None:
        yield DecodeResult(
            decoded=struct_decoded,
            source="raw_struct",
            start=0,
            consumed=len(payload),
            payload_len=len(payload),
            matched_keys=sum(1 for key in struct_decoded if key != "_unknown"),
            unknown_top=0,
            unknown_recursive=0,
        )


def _try_decode_printable(payload: bytes) -> str | None:
    if b"\x00" in payload:
        return None
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    if all(ch in "\r\n\t" or 0x20 <= ord(ch) <= 0x7E for ch in text):
        return text
    return None


def _raw_string_candidates(
    schema: dict,
    payload: bytes,
    text: str,
    resolve_message: MessageResolver,
) -> Iterable[DecodeResult]:
    for path, decoded in _string_paths(schema, text, resolve_message):
        yield DecodeResult(
            decoded=decoded,
            source=f"raw_string:{path}",
            start=0,
            consumed=len(payload),
            payload_len=len(payload),
            matched_keys=sum(1 for key in decoded if key != "_unknown"),
            unknown_top=0,
            unknown_recursive=0,
        )


def _string_paths(
    schema: dict,
    text: str,
    resolve_message: MessageResolver,
) -> Iterable[tuple[str, dict[str, Any]]]:
    fields = schema.get("fields") or []
    direct_matches: list[tuple[str, dict[str, Any]]] = []
    for field in fields:
        base = proto_codec.strip_generic(str(field.get("type") or ""))
        name = str(field.get("name") or f"f{field.get('no')}")
        if base == "string":
            direct_matches.append((name, {name: text}))
        elif base == "bytes":
            direct_matches.append((name, {name: text.encode("utf-8").hex()}))
    yield from direct_matches

    message_fields = [field for field in fields if proto_codec.strip_generic(str(field.get("type") or "")) == "message"]
    for field in message_fields:
        ref = field.get("ref")
        nested = resolve_message(str(ref)) if ref else None
        if nested is None:
            continue
        nested_matches = list(_direct_string_paths(nested, text))
        if len(nested_matches) != 1:
            continue
        nested_path, nested_decoded = nested_matches[0]
        name = str(field.get("name") or ref)
        yield f"{name}.{nested_path}", {name: nested_decoded}


def _direct_string_paths(schema: dict, text: str) -> Iterable[tuple[str, dict[str, Any]]]:
    for field in schema.get("fields") or []:
        base = proto_codec.strip_generic(str(field.get("type") or ""))
        name = str(field.get("name") or f"f{field.get('no')}")
        if base == "string":
            yield name, {name: text}
        elif base == "bytes":
            yield name, {name: text.encode("utf-8").hex()}


def _try_single_varint(payload: bytes) -> int | None:
    try:
        value, end = proto_codec.decode_varint(payload, 0)
    except Exception:
        return None
    return value if end == len(payload) else None


def _raw_varint_candidates(
    schema: dict,
    payload: bytes,
    value: int,
    resolve_message: MessageResolver,
) -> Iterable[DecodeResult]:
    for path, decoded in _numeric_paths(schema, value, resolve_message):
        yield DecodeResult(
            decoded=decoded,
            source=f"raw_varint:{path}",
            start=0,
            consumed=len(payload),
            payload_len=len(payload),
            matched_keys=sum(1 for key in decoded if key != "_unknown"),
            unknown_top=0,
            unknown_recursive=0,
        )


def _numeric_paths(
    schema: dict,
    value: int,
    resolve_message: MessageResolver,
) -> Iterable[tuple[str, dict[str, Any]]]:
    fields = schema.get("fields") or []
    for field in fields:
        base = proto_codec.strip_generic(str(field.get("type") or ""))
        if base not in {"int32", "int64", "uint32", "uint64", "sint32", "sint64", "enum", "bool"}:
            continue
        name = str(field.get("name") or f"f{field.get('no')}")
        yield name, {name: bool(value) if base == "bool" else value}

    message_fields = [field for field in fields if proto_codec.strip_generic(str(field.get("type") or "")) == "message"]
    for field in message_fields:
        ref = field.get("ref")
        nested = resolve_message(str(ref)) if ref else None
        if nested is None:
            continue
        nested_matches = list(_numeric_paths(nested, value, resolve_message))
        if len(nested_matches) != 1:
            continue
        nested_path, nested_decoded = nested_matches[0]
        name = str(field.get("name") or ref)
        yield f"{name}.{nested_path}", {name: nested_decoded}


def _try_raw_struct(
    schema: dict,
    payload: bytes,
    resolve_message: MessageResolver,
) -> dict[str, Any] | None:
    fields = schema.get("fields") or []
    decoded, offset = _consume_struct_fields(fields, payload, 0, resolve_message)
    if decoded is None or offset != len(payload):
        return None
    return decoded


def _consume_struct_fields(
    fields: list[dict],
    payload: bytes,
    offset: int,
    resolve_message: MessageResolver,
) -> tuple[dict[str, Any] | None, int]:
    out: dict[str, Any] = {}
    for index, field in enumerate(fields):
        name = str(field.get("name") or f"f{field.get('no')}")
        base = proto_codec.strip_generic(str(field.get("type") or ""))
        remaining = len(payload) - offset
        if remaining < 0:
            return None, offset

        if base == "message" and str(field.get("ref") or "").endswith(".RetInfo"):
            if remaining < 4:
                return None, offset
            out[name] = {"ret_code": int.from_bytes(payload[offset : offset + 4], "little")}
            offset += 4
            continue

        if base in {"string", "bytes"}:
            if index != len(fields) - 1:
                return None, offset
            raw = payload[offset:]
            offset = len(payload)
            if base == "string":
                text = raw.rstrip(b"\x00").decode("utf-8", errors="replace")
                out[name] = text
            else:
                out[name] = raw.hex()
            continue

        widths = _struct_widths(base)
        if not widths:
            return None, offset

        chosen = None
        for width in widths:
            if offset + width > len(payload):
                continue
            suffix = fields[index + 1 :]
            trial_out, trial_offset = _consume_struct_fields(suffix, payload, offset + width, resolve_message)
            if suffix and trial_out is None:
                continue
            if not suffix and trial_offset != len(payload):
                continue
            chosen = (width, trial_out or {}, trial_offset)
            break
        if chosen is None:
            return None, offset
        width, suffix_decoded, final_offset = chosen
        out[name] = _decode_raw_number(base, payload[offset : offset + width])
        out.update(suffix_decoded)
        return out, final_offset
    return out, offset


def _struct_widths(base: str) -> tuple[int, ...]:
    if base in {"bool"}:
        return (4, 1)
    if base in {"int32", "uint32", "sint32", "enum", "fixed32", "sfixed32", "float"}:
        return (4,)
    if base in {"int64", "uint64", "sint64", "fixed64", "sfixed64", "double"}:
        return (8, 4)
    return ()


def _decode_raw_number(base: str, raw: bytes) -> Any:
    if base == "bool":
        return bool(int.from_bytes(raw, "little"))
    signed = base in {"int32", "int64", "sint32", "sint64", "sfixed32", "sfixed64"}
    return int.from_bytes(raw, "little", signed=signed)
