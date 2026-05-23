from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from google.protobuf.descriptor_pb2 import (
    FieldDescriptorProto,
    FileDescriptorSet,
)


FIELD_TYPE_MAP = {
    FieldDescriptorProto.TYPE_DOUBLE: "double",
    FieldDescriptorProto.TYPE_FLOAT: "float",
    FieldDescriptorProto.TYPE_INT64: "int64",
    FieldDescriptorProto.TYPE_UINT64: "uint64",
    FieldDescriptorProto.TYPE_INT32: "int32",
    FieldDescriptorProto.TYPE_FIXED64: "fixed64",
    FieldDescriptorProto.TYPE_FIXED32: "fixed32",
    FieldDescriptorProto.TYPE_BOOL: "bool",
    FieldDescriptorProto.TYPE_STRING: "string",
    FieldDescriptorProto.TYPE_BYTES: "bytes",
    FieldDescriptorProto.TYPE_UINT32: "uint32",
    FieldDescriptorProto.TYPE_SFIXED32: "sfixed32",
    FieldDescriptorProto.TYPE_SFIXED64: "sfixed64",
    FieldDescriptorProto.TYPE_SINT32: "sint32",
    FieldDescriptorProto.TYPE_SINT64: "sint64",
}

PACKABLE_TYPES = {
    FieldDescriptorProto.TYPE_DOUBLE,
    FieldDescriptorProto.TYPE_FLOAT,
    FieldDescriptorProto.TYPE_INT64,
    FieldDescriptorProto.TYPE_UINT64,
    FieldDescriptorProto.TYPE_INT32,
    FieldDescriptorProto.TYPE_FIXED64,
    FieldDescriptorProto.TYPE_FIXED32,
    FieldDescriptorProto.TYPE_BOOL,
    FieldDescriptorProto.TYPE_UINT32,
    FieldDescriptorProto.TYPE_ENUM,
    FieldDescriptorProto.TYPE_SFIXED32,
    FieldDescriptorProto.TYPE_SFIXED64,
    FieldDescriptorProto.TYPE_SINT32,
    FieldDescriptorProto.TYPE_SINT64,
}

SUFFIXES = (
    "NtyAck",
    "NotifyAck",
    "Req",
    "Rsp",
    "Notify",
    "Nty",
    "Ack",
)

VERBS = {
    "Add",
    "Batch",
    "Cancel",
    "Change",
    "Check",
    "Choose",
    "Claim",
    "Clear",
    "Close",
    "Confirm",
    "Create",
    "Delete",
    "Del",
    "End",
    "Enter",
    "Exchange",
    "Exit",
    "Finish",
    "Force",
    "Get",
    "Login",
    "Logout",
    "Modify",
    "Open",
    "Query",
    "Receive",
    "Refresh",
    "Register",
    "Remove",
    "Report",
    "Reward",
    "Select",
    "Set",
    "Start",
    "Stop",
    "Sync",
    "Unlock",
    "Update",
    "Upgrade",
    "Use",
}

SCALAR_TYPES = set(FIELD_TYPE_MAP.values())
LEGACY_PROTO_SOURCE_TAG = "S1.0"
LEGACY_PROTO_SOURCE_NOTE = "第一赛季第一版proto的剩余"

CMD_TOKEN_OVERRIDES = {
    "AI": "Ai",
    "AOI": "Aoi",
    "BP": "Bp",
    "CS": "Cs",
    "EXP": "Exp",
    "GM": "Gm",
    "HB": "Hb",
    "HP": "Hp",
    "ID": "Id",
    "MP": "Mp",
    "NPC": "Npc",
    "PK": "Pk",
    "PVP": "Pvp",
    "QQ": "Qq",
    "UI": "Ui",
    "URL": "Url",
    "VIP": "Vip",
}


def default_paths() -> tuple[Path, Path]:
    repo_root = Path(__file__).resolve().parents[1]
    data_root = repo_root.parent / "Roco-Kingdom-World-Data-main"
    config_dir = repo_root / "config"
    return data_root, config_dir


def full_name(package: str, prefix: str, name: str) -> str:
    body = f"{prefix}{name}"
    return f".{package}.{body}" if package else f".{body}"


def field_to_schema(field: FieldDescriptorProto) -> dict[str, Any]:
    item: dict[str, Any] = {
        "no": field.number,
        "name": field.name,
    }
    if field.type == FieldDescriptorProto.TYPE_MESSAGE:
        item["type"] = "message"
        item["ref"] = field.type_name
    elif field.type == FieldDescriptorProto.TYPE_ENUM:
        item["type"] = f"enum<{field.type_name}>"
    else:
        item["type"] = FIELD_TYPE_MAP.get(field.type, f"unknown_{field.type}")

    if field.label == FieldDescriptorProto.LABEL_REPEATED:
        item["repeated"] = True
        if field.type in PACKABLE_TYPES and field.options.HasField("packed") and field.options.packed:
            item["packed"] = True
    return item


def collect_descriptor(fds: FileDescriptorSet) -> tuple[dict[str, dict], dict[str, dict], dict[int, str]]:
    messages: dict[str, dict] = {}
    enums: dict[str, dict] = {}
    cmd_enum_names: dict[int, str] = {}

    def walk_enum(package: str, prefix: str, enum) -> None:
        enum_name = full_name(package, prefix, enum.name)
        values = {v.name: v.number for v in enum.value}
        enums[enum_name] = {"values": values}
        if enum.name.endswith("Cmd") or enum.name.endswith("SvrCmd"):
            for v in enum.value:
                cmd_enum_names.setdefault(v.number, v.name)

    def walk_message(package: str, prefix: str, msg) -> None:
        msg_name = full_name(package, prefix, msg.name)
        messages[msg_name] = {"fields": [field_to_schema(field) for field in msg.field]}
        nested_prefix = f"{prefix}{msg.name}."
        for enum in msg.enum_type:
            walk_enum(package, nested_prefix, enum)
        for nested in msg.nested_type:
            if not nested.options.map_entry:
                walk_message(package, nested_prefix, nested)

    for fd in fds.file:
        for enum in fd.enum_type:
            walk_enum(fd.package, "", enum)
        for msg in fd.message_type:
            walk_message(fd.package, "", msg)
    return messages, enums, cmd_enum_names


def strip_proto_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//.*", "", text)


def find_matching_brace(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError(f"unclosed brace at offset {open_index}")


def without_nested_type_blocks(body: str) -> str:
    pieces: list[str] = []
    pos = 0
    pattern = re.compile(r"\b(?:message|enum)\s+\w+\s*\{")
    while match := pattern.search(body, pos):
        pieces.append(body[pos : match.start()])
        end = find_matching_brace(body, match.end() - 1)
        pieces.append(" " * (end + 1 - match.start()))
        pos = end + 1
    pieces.append(body[pos:])
    return "".join(pieces)


def normalize_type_ref(type_name: str, package: str, owner_name: str, known_names: set[str]) -> str:
    if type_name.startswith("."):
        return type_name
    if "." in type_name:
        return f".{type_name}"

    package_parts = package.split(".") if package else []
    owner_parts = owner_name.strip(".").split(".") if owner_name else []
    for length in range(len(owner_parts), len(package_parts), -1):
        candidate = "." + ".".join([*owner_parts[:length], type_name])
        if candidate in known_names:
            return candidate
    if package:
        return f".{package}.{type_name}"
    return f".{type_name}"


def parse_field_statement(statement: str) -> dict[str, Any] | None:
    statement = re.sub(r"\boneof\s+\w+\s*\{", " ", statement)
    statement = statement.replace("}", " ")
    statement = " ".join(statement.split())
    if not statement or statement.startswith(("option ", "reserved ", "extensions ")):
        return None
    match = re.search(
        r"(?:(repeated|optional|required)\s+)?([.\w]+)\s+(\w+)\s*=\s*(-?\d+)(?:\s*\[(.*?)\])?$",
        statement,
    )
    if not match:
        return None
    label, type_name, field_name, number, options = match.groups()
    return {
        "no": int(number),
        "name": field_name,
        "raw_type": type_name,
        "repeated": label == "repeated",
        "packed": bool(options and re.search(r"\bpacked\s*=\s*true\b", options)),
    }


def parse_message_fields(body: str) -> list[dict[str, Any]]:
    top_level_body = without_nested_type_blocks(body)
    fields: list[dict[str, Any]] = []
    for statement in top_level_body.split(";"):
        field = parse_field_statement(statement)
        if field:
            fields.append(field)
    return fields


def parse_enum_values(body: str) -> dict[str, int]:
    top_level_body = without_nested_type_blocks(body)
    values: dict[str, int] = {}
    for name, number in re.findall(r"\b([A-Za-z_]\w*)\s*=\s*(-?\d+)\b", top_level_body):
        values[name] = int(number)
    return values


def parse_proto_block(
    text: str,
    package: str,
    prefix: str,
    raw_messages: dict[str, dict[str, Any]],
    enums: dict[str, dict[str, Any]],
    cmd_enum_names: dict[int, str],
) -> None:
    pos = 0
    pattern = re.compile(r"\b(message|enum)\s+(\w+)\s*\{")
    while match := pattern.search(text, pos):
        kind, name = match.groups()
        open_index = match.end() - 1
        close_index = find_matching_brace(text, open_index)
        body = text[open_index + 1 : close_index]
        full = full_name(package, prefix, name)
        if kind == "message":
            raw_messages[full] = {
                "fields": parse_message_fields(body),
                "package": package,
            }
            parse_proto_block(body, package, f"{prefix}{name}.", raw_messages, enums, cmd_enum_names)
        else:
            values = parse_enum_values(body)
            enums[full] = {"values": values}
            if name.endswith("Cmd") or name.endswith("SvrCmd"):
                for value_name, number in values.items():
                    cmd_enum_names.setdefault(number, value_name)
        pos = close_index + 1


def resolve_raw_messages(raw_messages: dict[str, dict[str, Any]], enums: dict[str, dict[str, Any]]) -> dict[str, dict]:
    messages: dict[str, dict] = {}
    known_messages = set(raw_messages)
    known_enums = set(enums)
    known_names = known_messages | known_enums
    for message_name, raw_message in raw_messages.items():
        package = raw_message["package"]
        fields: list[dict[str, Any]] = []
        for raw_field in raw_message["fields"]:
            raw_type = raw_field["raw_type"]
            item: dict[str, Any] = {
                "no": raw_field["no"],
                "name": raw_field["name"],
            }
            if raw_type in SCALAR_TYPES:
                item["type"] = raw_type
            else:
                resolved = normalize_type_ref(raw_type, package, message_name, known_names)
                if resolved in known_enums:
                    item["type"] = f"enum<{resolved}>"
                else:
                    item["type"] = "message"
                    item["ref"] = resolved
            if raw_field["repeated"]:
                item["repeated"] = True
                if raw_field["packed"]:
                    item["packed"] = True
            fields.append(item)
        messages[message_name] = {"fields": fields}
    return messages


def collect_proto_out(proto_out_dir: Path) -> tuple[dict[str, dict], dict[str, dict], dict[int, str]]:
    raw_messages: dict[str, dict[str, Any]] = {}
    enums: dict[str, dict[str, Any]] = {}
    cmd_enum_names: dict[int, str] = {}
    if not proto_out_dir.exists():
        raise FileNotFoundError(proto_out_dir)
    for path in sorted(proto_out_dir.glob("*.proto")):
        text = strip_proto_comments(path.read_text(encoding="utf-8-sig"))
        package_match = re.search(r"\bpackage\s+([\w.]+)\s*;", text)
        package = package_match.group(1) if package_match else ""
        parse_proto_block(text, package, "", raw_messages, enums, cmd_enum_names)
    return resolve_raw_messages(raw_messages, enums), enums, cmd_enum_names


def cmd_enum_to_message_name(enum_name: str) -> str:
    parts = [part for part in enum_name.split("_") if part]
    return "".join(CMD_TOKEN_OVERRIDES.get(part, part[:1] + part[1:].lower()) for part in parts)


def build_proto_map_from_cmds(cmd_enum_names: dict[int, str], messages: dict[str, dict]) -> dict[str, str]:
    message_names = set(messages)
    proto_map: dict[str, str] = {}
    package_by_short: dict[str, str] = {}
    for full in message_names:
        package_by_short.setdefault(short_name(full), full.rsplit(".", 1)[0].lstrip("."))

    for opcode, enum_name in sorted(cmd_enum_names.items()):
        message_name = cmd_enum_to_message_name(enum_name)
        package = package_by_short.get(message_name, "Next")
        proto_name = f".{package}.{message_name}" if package else f".{message_name}"
        if proto_name not in message_names:
            alternatives: list[str] = []
            if message_name.endswith("Notify"):
                alternatives.append(f"{message_name[:-6]}Nty")
            elif message_name.endswith("Nty"):
                alternatives.append(f"{message_name[:-3]}Notify")
            for alternative in alternatives:
                alt_package = package_by_short.get(alternative, package)
                alt_proto_name = f".{alt_package}.{alternative}" if alt_package else f".{alternative}"
                if alt_proto_name in message_names:
                    proto_name = alt_proto_name
                    message_name = alternative
                    break
        proto_map[str(opcode)] = proto_name
    return proto_map


def short_name(proto_name: str) -> str:
    return proto_name.rsplit(".", 1)[-1]


def strip_suffix(name: str) -> str:
    for suffix in SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def infer_direction(name: str) -> str | None:
    if name.endswith(("NtyAck", "NotifyAck", "Ack", "Req")):
        return "c2s"
    if name.endswith(("Rsp", "Notify", "Nty")):
        return "s2c"
    return None


def infer_category(name: str) -> str | None:
    base = strip_suffix(name)
    base = re.sub(r"^(Zone|Battle|Gm)", "", base)
    words = re.findall(r"[A-Z]+(?=[A-Z][a-z]|$)|[A-Z][a-z0-9]*", base)
    if not words:
        return None
    if words[0] in VERBS and len(words) > 1:
        return words[1].lower()
    return words[0].lower()


def build_pairs(proto_map: dict[str, str]) -> dict[str, str]:
    by_base: dict[str, dict[str, int]] = {}
    for opcode_text, proto_name in proto_map.items():
        name = short_name(proto_name)
        opcode = int(opcode_text)
        if name.endswith("Req"):
            by_base.setdefault(name[:-3], {})["Req"] = opcode
        elif name.endswith("Rsp"):
            by_base.setdefault(name[:-3], {})["Rsp"] = opcode

    pairs: dict[str, str] = {}
    for endpoints in by_base.values():
        req = endpoints.get("Req")
        rsp = endpoints.get("Rsp")
        if req is not None and rsp is not None:
            pairs[f"0x{req:04X}"] = f"0x{rsp:04X}"
            pairs[f"0x{rsp:04X}"] = f"0x{req:04X}"
    return pairs


def generated_header(data_root: Path, base_config_dir: Path | None = None) -> dict[str, Any]:
    source: dict[str, Any] = {
        "proto_json": str(data_root / "PB" / "proto.json"),
        "descriptor": str(data_root / "PB" / "all.pb"),
        "proto_out": str(data_root / "PB" / "proto_out"),
    }
    if base_config_dir is not None:
        source["base_config"] = str(base_config_dir)
    return {
        "_generated_by": "tools/gen_proto_schema.py",
        "_source": source,
    }


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_source_data(data_root: Path) -> tuple[dict[str, str], dict[str, dict], dict[str, dict], dict[int, str], str]:
    proto_json_path = data_root / "PB" / "proto.json"
    descriptor_path = data_root / "PB" / "all.pb"
    if proto_json_path.exists() and descriptor_path.exists():
        proto_map: dict[str, str] = json.loads(proto_json_path.read_text(encoding="utf-8"))
        fds = FileDescriptorSet()
        fds.ParseFromString(descriptor_path.read_bytes())
        messages, enums, cmd_enum_names = collect_descriptor(fds)
        return proto_map, messages, enums, cmd_enum_names, "descriptor"

    messages, enums, cmd_enum_names = collect_proto_out(data_root / "PB" / "proto_out")
    proto_map = build_proto_map_from_cmds(cmd_enum_names, messages)
    return proto_map, messages, enums, cmd_enum_names, "proto_out"


def load_base_config(base_config_dir: Path | None) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    if base_config_dir is None:
        return {}, {}, {}

    messages: dict[str, dict] = {}
    enums: dict[str, dict] = {}
    opcodes: dict[str, dict] = {}

    messages_path = base_config_dir / "messages.json"
    if messages_path.exists():
        data = json.loads(messages_path.read_text(encoding="utf-8"))
        messages = dict(data.get("messages") or {})
        enums = dict(data.get("enums") or {})

    opcodes_path = base_config_dir / "opcodes.json"
    if opcodes_path.exists():
        data = json.loads(opcodes_path.read_text(encoding="utf-8"))
        opcodes = dict(data.get("opcodes") or {})

    return messages, enums, opcodes


def merge_proto_defs(base_items: dict[str, dict], source_items: dict[str, dict]) -> dict[str, dict]:
    merged = {name: dict(schema) for name, schema in source_items.items()}
    for name, schema in base_items.items():
        if name in merged:
            continue
        item = dict(schema)
        item.pop("schema_source", None)
        item.pop("schema_source_note", None)
        item["proto_source"] = LEGACY_PROTO_SOURCE_TAG
        item["proto_source_note"] = LEGACY_PROTO_SOURCE_NOTE
        merged[name] = item
    return merged


def merge_opcode_sets(
    base_opcodes: dict[str, dict],
    source_proto_map: dict[str, str],
    source_messages: dict[str, dict],
    cmd_enum_names: dict[int, str],
) -> tuple[dict[str, dict], dict[str, str], int, int]:
    pairs = build_pairs(source_proto_map)
    opcodes: dict[str, dict] = {hex_key: dict(meta) for hex_key, meta in base_opcodes.items()}
    source_hex_keys: set[str] = set()
    missing_message_count = 0

    for opcode_text, proto_name in sorted(source_proto_map.items(), key=lambda kv: int(kv[0])):
        opcode = int(opcode_text)
        hex_key = f"0x{opcode:04X}"
        source_hex_keys.add(hex_key)
        name = short_name(proto_name)
        if proto_name not in source_messages:
            missing_message_count += 1
        meta = {
            "id": opcode,
            "hex": hex_key,
            "name": name,
            "direction": infer_direction(name),
            "category": infer_category(name),
            "schema_status": "generated" if proto_name in source_messages else "missing_message",
            "decode_as": proto_name,
            "proto_name": proto_name,
            "enum_name": cmd_enum_names.get(opcode),
            "pair": pairs.get(hex_key),
        }
        opcodes[hex_key] = {k: v for k, v in meta.items() if v is not None}

    retained_old_only = 0
    for hex_key, meta in opcodes.items():
        if hex_key in source_hex_keys:
            continue
        retained_old_only += 1
        meta["retained_from_previous_opcode"] = True
        meta.pop("schema_source", None)
        meta.pop("schema_source_note", None)
        meta["proto_source"] = LEGACY_PROTO_SOURCE_TAG
        meta["proto_source_note"] = LEGACY_PROTO_SOURCE_NOTE

    return opcodes, pairs, missing_message_count, retained_old_only


def generate(data_root: Path, config_dir: Path, base_config_dir: Path | None = None) -> dict[str, Any]:
    proto_map, messages, enums, cmd_enum_names, source_format = load_source_data(data_root)
    base_messages, base_enums, base_opcodes = load_base_config(base_config_dir)
    merged_messages = merge_proto_defs(base_messages, messages)
    merged_enums = merge_proto_defs(base_enums, enums)
    opcodes, _pairs, missing_message_count, retained_old_only = merge_opcode_sets(
        base_opcodes,
        proto_map,
        messages,
        cmd_enum_names,
    )
    source_opcode_count = len(proto_map)

    messages_json = {
        **generated_header(data_root, base_config_dir),
        "messages": merged_messages,
        "enums": merged_enums,
    }
    write_json(config_dir / "messages.json", messages_json)

    detail_dir = config_dir / "opcodes"
    detail_dir.mkdir(parents=True, exist_ok=True)
    for stale_path in detail_dir.glob("0x*.json"):
        stale_path.unlink()

    for hex_key, meta in sorted(opcodes.items(), key=lambda kv: int(kv[0], 16)):
        opcode = int(hex_key, 16)
        proto_name = meta.get("decode_as") or meta.get("proto_name")
        name = short_name(proto_name)
        fields = merged_messages.get(proto_name, {}).get("fields", [])
        write_json(
            detail_dir / f"{hex_key}.json",
            {
                **generated_header(data_root, base_config_dir),
                "opcode": hex_key,
                "id": opcode,
                "name": meta.get("name") or name,
                "decode_as": proto_name,
                "fields": fields,
            },
        )

    opcodes_json = {
        **generated_header(data_root, base_config_dir),
        "opcodes": opcodes,
    }
    write_json(config_dir / "opcodes.json", opcodes_json)

    return {
        "opcodes": len(opcodes),
        "source_opcodes": source_opcode_count,
        "retained_old_only_opcodes": retained_old_only,
        "messages": len(merged_messages),
        "source_messages": len(messages),
        "retained_old_only_messages": len(set(base_messages) - set(messages)),
        "enums": len(merged_enums),
        "source_enums": len(enums),
        "retained_old_only_enums": len(set(base_enums) - set(enums)),
        "missing_messages": missing_message_count,
        "source_format": source_format,
    }


def main() -> int:
    data_root_default, config_dir_default = default_paths()
    parser = argparse.ArgumentParser(description="Generate RKMS opcode/message JSON from Roco protobuf descriptors.")
    parser.add_argument("--data-root", type=Path, default=data_root_default)
    parser.add_argument("--config-dir", type=Path, default=config_dir_default)
    parser.add_argument(
        "--base-config-dir",
        type=Path,
        default=None,
        help="Optional previous config directory to retain old opcodes/messages not present in the new source.",
    )
    args = parser.parse_args()

    stats = generate(
        args.data_root.resolve(),
        args.config_dir.resolve(),
        args.base_config_dir.resolve() if args.base_config_dir is not None else None,
    )
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
