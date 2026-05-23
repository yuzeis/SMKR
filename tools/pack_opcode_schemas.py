from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from roco_mitm.codec.opcode_pack import (  # noqa: E402
    compare_details,
    extract_pack,
    load_opcode_details,
    read_pack,
    write_pack,
)


def _config_dir(value: str) -> Path:
    return Path(value).expanduser().resolve()


def cmd_build(args: argparse.Namespace) -> int:
    config_dir = _config_dir(args.config_dir)
    opcodes_dir = config_dir / "opcodes"
    pack_path = config_dir / args.pack_name
    details = load_opcode_details(opcodes_dir)
    header = write_pack(pack_path, details, level=args.level)
    packed_details, _ = read_pack(pack_path)
    errors = compare_details(details, packed_details)
    if errors:
        print("[ERROR] pack verification failed after build:", file=sys.stderr)
        for item in errors[:20]:
            print(f"  {item}", file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "pack": str(pack_path), **header}, ensure_ascii=False, indent=2))
    if args.remove_json:
        removed = 0
        for path in sorted(opcodes_dir.glob("0x*.json")):
            path.unlink()
            removed += 1
        print(json.dumps({"removed_json": removed, "directory": str(opcodes_dir)}, ensure_ascii=False))
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    config_dir = _config_dir(args.config_dir)
    pack_path = config_dir / args.pack_name
    count = extract_pack(pack_path, config_dir / "opcodes", overwrite=args.overwrite)
    print(json.dumps({"ok": True, "extracted": count, "directory": str(config_dir / "opcodes")}, ensure_ascii=False))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    config_dir = _config_dir(args.config_dir)
    pack_path = config_dir / args.pack_name
    packed_details, header = read_pack(pack_path)
    opcodes_dir = config_dir / "opcodes"
    errors: list[str] = []
    if opcodes_dir.exists() and any(opcodes_dir.glob("0x*.json")):
        json_details = load_opcode_details(opcodes_dir)
        errors = compare_details(json_details, packed_details)
    if errors:
        print(json.dumps({"ok": False, "errors": errors[:50]}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    print(json.dumps({"ok": True, "pack": str(pack_path), **header}, ensure_ascii=False, indent=2))
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    config_dir = _config_dir(args.config_dir)
    pack_path = config_dir / args.pack_name
    details, header = read_pack(pack_path)
    print(json.dumps({"pack": str(pack_path), "count": len(details), **header}, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Pack or extract config/opcodes/*.json")
    parser.add_argument("--config-dir", default="config")
    parser.add_argument("--pack-name", default="opcodes.pack.bin")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_build = sub.add_parser("build", help="build opcodes.pack.bin from config/opcodes/*.json")
    p_build.add_argument("--level", type=int, default=9)
    p_build.add_argument("--remove-json", action="store_true", help="remove config/opcodes/0x*.json after verified build")
    p_build.set_defaults(func=cmd_build)

    p_extract = sub.add_parser("extract", help="extract opcodes.pack.bin into config/opcodes/*.json")
    p_extract.add_argument("--overwrite", action="store_true")
    p_extract.set_defaults(func=cmd_extract)

    p_verify = sub.add_parser("verify", help="verify pack integrity and compare with json directory when present")
    p_verify.set_defaults(func=cmd_verify)

    p_info = sub.add_parser("info", help="print pack metadata")
    p_info.set_defaults(func=cmd_info)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
