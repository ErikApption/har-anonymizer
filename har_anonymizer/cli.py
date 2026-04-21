"""Command-line interface for har-anonymizer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .anonymizer import anonymize


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="har-anonymizer",
        description=(
            "Anonymize a HAR file captured from Chrome or Edge, "
            "removing cookies, auth tokens, passwords, credit-card numbers, "
            "and other sensitive data so it can be safely shared with AI tools."
        ),
    )
    parser.add_argument(
        "input",
        type=Path,
        metavar="INPUT",
        help="Path to the source .har file",
    )
    parser.add_argument(
        "output",
        type=Path,
        nargs="?",
        metavar="OUTPUT",
        default=None,
        help=(
            "Path where the anonymized .har file will be written. "
            "Defaults to INPUT with '.anonymized.har' appended."
        ),
    )
    parser.add_argument(
        "--redact-emails",
        action="store_true",
        default=False,
        help="Also replace e-mail addresses with [REDACTED].",
    )
    parser.add_argument(
        "--redact-ips",
        action="store_true",
        default=False,
        help="Replace IPv4 addresses (including serverIPAddress) with 0.0.0.0.",
    )
    parser.add_argument(
        "--indent",
        type=int,
        default=2,
        metavar="N",
        help="JSON indentation level for the output file (default: 2).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point; returns an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    input_path: Path = args.input
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}", file=sys.stderr)
        return 1
    if not input_path.is_file():
        print(f"Error: input path is not a file: {input_path}", file=sys.stderr)
        return 1

    output_path: Path = (
        args.output
        if args.output is not None
        else input_path.with_suffix("").with_name(input_path.stem + ".anonymized.har")
    )

    try:
        raw = input_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error reading {input_path}: {exc}", file=sys.stderr)
        return 1

    try:
        har = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"Error: {input_path} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    result = anonymize(
        har,
        redact_emails=args.redact_emails,
        redact_ips=args.redact_ips,
    )

    try:
        output_path.write_text(
            json.dumps(result, indent=args.indent, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"Error writing {output_path}: {exc}", file=sys.stderr)
        return 1

    print(f"Anonymized HAR written to: {output_path}")
    return 0


def run() -> None:
    """Thin wrapper so the entry-point script can call sys.exit cleanly."""
    sys.exit(main())


if __name__ == "__main__":
    run()
