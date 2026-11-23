"""Command line entry point: ``redactscope`` or ``python -m redactscope``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import audit, redact


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="redactscope",
        description="Find and redact secrets in a JSON message, a message log or plain text.",
    )
    parser.add_argument("path", nargs="?", type=Path, metavar="FILE", help="default: stdin")
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if anything is found, without printing the redacted form",
    )
    parser.add_argument("--mask", default="***")
    parser.add_argument(
        "--keys-only",
        action="store_true",
        help="mask secret-looking keys but leave values in other strings alone",
    )
    args = parser.parse_args(argv)

    try:
        text = args.path.read_text(encoding="utf-8") if args.path else sys.stdin.read()
    except OSError as error:
        print(f"cannot read {args.path}: {error}", file=sys.stderr)
        return 2

    payload: object
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = text
    else:
        payload = text

    patterns = () if args.keys_only else None
    findings = audit(payload) if patterns is None else audit(payload, patterns=patterns)

    if args.check:
        for finding in findings:
            print(f"{finding.path}: {finding.kind}", file=sys.stderr)
        print(f"{len(findings)} secret(s) found", file=sys.stderr)
        return 1 if findings else 0

    if isinstance(payload, str):
        print(redact(payload, mask=args.mask) if patterns is None else payload)
    else:
        cleaned = redact(payload, mask=args.mask)
        print(json.dumps(cleaned, indent=2, ensure_ascii=False))
    print(f"{len(findings)} secret(s) found", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
