"""CLI entry point for protobuf-fuzz-guard."""

import argparse
import json
import sys
from pathlib import Path

from .harness_gen import generate_all
from .models import get_patterns
from .proto_parser import parse_proto
from .scanner import scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="protofuzz",
        description="Cross-language protobuf fuzz harness generator with CVE-pattern detection",
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    scan_cmd = sub.add_parser("scan", help="Scan .proto files for known CVE patterns")
    scan_cmd.add_argument("files", nargs="+", help=".proto files to scan")
    scan_cmd.add_argument("--json", action="store_true", help="Output as JSON")

    # generate
    gen_cmd = sub.add_parser("generate", help="Generate fuzz harnesses")
    gen_cmd.add_argument("files", nargs="+", help=".proto files")
    gen_cmd.add_argument(
        "--lang", "-l", action="append", choices=["python", "cpp", "go"],
        help="Target language(s). Default: all",
    )
    gen_cmd.add_argument("--output", "-o", help="Output directory", default="fuzz_harnesses")

    # patterns
    sub.add_parser("patterns", help="List known CVE patterns")

    args = parser.parse_args(argv)

    if args.command == "scan":
        return _cmd_scan(args)
    elif args.command == "generate":
        return _cmd_generate(args)
    elif args.command == "patterns":
        return _cmd_patterns()
    else:
        parser.print_help()
        return 1


def _cmd_scan(args: argparse.Namespace) -> int:
    all_findings = []
    for path in args.files:
        content = Path(path).read_text()
        proto = parse_proto(content, file_path=str(path))
        findings = scan(proto)
        all_findings.extend(findings)

    if args.json:
        data = [
            {
                "severity": f.severity,
                "pattern_id": f.pattern.id if f.pattern else None,
                "message": f.message,
                "file": f.file_path,
            }
            for f in all_findings
        ]
        print(json.dumps(data, indent=2))
    else:
        if not all_findings:
            print("No findings. Clean.")
            return 0
        for f in all_findings:
            icon = {"critical": "!!", "warning": "!", "info": "i"}[f.severity]
            pattern_tag = f" [{f.pattern.id}]" if f.pattern else ""
            print(f"  [{icon}] {f.severity.upper()}{pattern_tag} {f.message}")
            if f.file_path:
                print(f"       file: {f.file_path}")
            print()

    has_critical = any(f.severity == "critical" for f in all_findings)
    return 1 if has_critical else 0


def _cmd_generate(args: argparse.Namespace) -> int:
    out_dir = Path(args.output)
    languages = args.lang or ["python", "cpp", "go"]

    for path in args.files:
        content = Path(path).read_text()
        proto = parse_proto(content, file_path=str(path))
        harnesses = generate_all(proto, languages=languages)

        for lang, items in harnesses.items():
            lang_dir = out_dir / lang
            lang_dir.mkdir(parents=True, exist_ok=True)
            for msg_name, code in items:
                ext = {"python": ".py", "cpp": ".cc", "go": "_test.go"}[lang]
                fname = f"fuzz_{msg_name.lower()}{ext}"
                (lang_dir / fname).write_text(code)
                print(f"  Generated: {lang_dir / fname}")

    print(f"\nHarnesses written to {out_dir}/")
    return 0


def _cmd_patterns() -> int:
    for p in get_patterns():
        langs = ", ".join(p.affected_languages)
        print(f"  {p.id}")
        print(f"    Title: {p.title}")
        print(f"    Languages: {langs}")
        print(f"    {p.description}")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
