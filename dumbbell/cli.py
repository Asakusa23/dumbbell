from __future__ import annotations

import argparse
import dataclasses
import sys
from pathlib import Path

from . import __version__
from .models import ScanResult, Severity
from .report import to_json, to_markdown, to_sarif
from .rules import RULES
from .scanner import scan_path


def _filtered(result: ScanResult, minimum: Severity) -> ScanResult:
    findings = [finding for finding in result.findings if finding.severity.value >= minimum.value]
    return dataclasses.replace(result, findings=findings)


def _print_rules() -> None:
    print(f"{'ID':<10} {'SEVERITY':<9} {'CATEGORY':<26} TITLE")
    print("-" * 104)
    for rule in sorted(RULES, key=lambda item: item.id):
        print(f"{rule.id:<10} {rule.severity.name:<9} {rule.category[:26]:<26} {rule.title}")


def _print_text(result: ScanResult) -> None:
    counts = result.severity_counts()
    print("DUMBBELL // static security audit")
    print(f"target   : {result.root}")
    print(f"files    : {result.files_scanned} scanned, {result.files_skipped} skipped")
    print(f"elapsed  : {result.elapsed:.2f}s")
    print(f"findings : {len(result.findings)}")
    print(f"risk     : {result.risk_score()}/100")
    print()
    for finding in result.findings:
        print(f"[{finding.severity.name}] {finding.rule.id}  {finding.location(result.root)}")
        print(f"  {finding.rule.title}")
        if finding.snippet:
            print(f"  {finding.snippet}")
        print(f"  fix: {finding.rule.remediation}")
        print()
    print("summary: " + ", ".join(f"{name.lower()}={value}" for name, value in counts.items()))


def _render(result: ScanResult, output_format: str) -> str:
    if output_format == "json":
        return to_json(result)
    if output_format == "md":
        return to_markdown(result)
    if output_format == "sarif":
        return to_sarif(result)
    return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dumbbell",
        description="DUMBBELL static security audit for source code and configuration.",
    )
    parser.add_argument("target", nargs="?", help="file or directory to scan")
    parser.add_argument(
        "--format",
        choices=("text", "json", "md", "sarif"),
        default="text",
        help="report format (default: text)",
    )
    parser.add_argument("-o", "--output", type=Path, help="write the report to a file")
    parser.add_argument(
        "--min-severity",
        choices=[severity.name.lower() for severity in Severity.ordered()],
        default="info",
        help="hide findings below this severity (default: info)",
    )
    parser.add_argument(
        "--fail-on",
        choices=[severity.name.lower() for severity in Severity.ordered()] + ["none"],
        default="high",
        help="exit with status 1 when a finding at or above this severity exists (default: high)",
    )
    parser.add_argument("--list-rules", action="store_true", help="print the rule catalogue and exit")
    parser.add_argument("--no-ignore", action="store_true", help="do not read .dumbbellignore")
    parser.add_argument("--exclude", action="append", default=[], metavar="DIR", help="directory name to skip")
    parser.add_argument(
        "--extensions",
        default=None,
        help="comma-separated walk filter, for example py,js,php (rules still apply to every scanned file)",
    )
    parser.add_argument("--max-size", type=int, default=1_000_000, help="maximum file size in bytes")
    parser.add_argument("--version", action="version", version=f"DUMBBELL {__version__}")
    args = parser.parse_args(argv)

    if args.list_rules:
        _print_rules()
        return 0

    if not args.target:
        parser.error("target is required unless --list-rules is used")

    extensions = None
    if args.extensions:
        extensions = [part.strip() for part in args.extensions.split(",") if part.strip()]

    try:
        result = scan_path(
            args.target,
            use_ignore=not args.no_ignore,
            exclude_dirs=args.exclude,
            max_file_size=args.max_size,
            extensions=extensions,
        )
    except FileNotFoundError as exc:
        print(f"error: target not found: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    minimum = Severity.parse(args.min_severity)
    filtered = _filtered(result, minimum)

    if args.output:
        if args.format == "text":
            content = _render_text_to_string(filtered)
        else:
            content = _render(filtered, args.format)
        try:
            args.output.write_text(content, encoding="utf-8")
        except OSError as exc:
            print(f"error: could not write report: {exc}", file=sys.stderr)
            return 2
        print(f"[+] report written to {args.output}", file=sys.stderr)
    else:
        if args.format == "text":
            _print_text(filtered)
        else:
            print(_render(filtered, args.format))

    if args.fail_on != "none":
        threshold = Severity.parse(args.fail_on)
        if any(finding.severity.value >= threshold.value for finding in result.findings):
            return 1
    return 0


def _render_text_to_string(result: ScanResult) -> str:
    counts = result.severity_counts()
    lines = [
        "DUMBBELL // static security audit",
        f"target   : {result.root}",
        f"files    : {result.files_scanned} scanned, {result.files_skipped} skipped",
        f"elapsed  : {result.elapsed:.2f}s",
        f"findings : {len(result.findings)}",
        f"risk     : {result.risk_score()}/100",
        "",
    ]
    for finding in result.findings:
        lines.append(f"[{finding.severity.name}] {finding.rule.id}  {finding.location(result.root)}")
        lines.append(f"  {finding.rule.title}")
        if finding.snippet:
            lines.append(f"  {finding.snippet}")
        lines.append(f"  fix: {finding.rule.remediation}")
        lines.append("")
    lines.append("summary: " + ", ".join(f"{name.lower()}={value}" for name, value in counts.items()))
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    sys.exit(main())
