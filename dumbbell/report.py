from __future__ import annotations

import json
from datetime import datetime, timezone

from . import __version__
from .models import ScanResult, Severity


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _scan_metadata(result: ScanResult) -> dict:
    return {
        "target": result.root,
        "timestamp": _timestamp(),
        "elapsed_seconds": round(result.elapsed, 3),
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "bytes_scanned": result.bytes_scanned,
        "cancelled": result.cancelled,
    }


def _summary(result: ScanResult) -> dict:
    return {
        "total": len(result.findings),
        "risk_score": result.risk_score(),
        "severity": result.severity_counts(),
    }


def to_json(result: ScanResult) -> str:
    payload = {
        "tool": {"name": "DUMBBELL", "version": __version__},
        "scan": _scan_metadata(result),
        "summary": _summary(result),
        "findings": [finding.as_dict(result.root) for finding in result.findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def to_markdown(result: ScanResult) -> str:
    counts = result.severity_counts()
    lines = [
        "# DUMBBELL security report",
        "",
        f"- **Target:** `{result.root}`",
        f"- **Generated:** {_timestamp()}",
        f"- **Tool version:** {__version__}",
        f"- **Files scanned:** {result.files_scanned} ({result.files_skipped} skipped)",
        f"- **Elapsed:** {result.elapsed:.2f}s",
        f"- **Risk score:** {result.risk_score()}/100",
        f"- **Findings:** {len(result.findings)}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in Severity.ordered():
        lines.append(f"| {severity.name} | {counts[severity.name]} |")
    lines.append("")
    if not result.findings:
        lines.extend(["No findings. The target looks clean for the loaded rule set.", ""])
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    for finding in result.findings:
        lines.append(f"### [{finding.severity.name}] {finding.rule.id} — {finding.rule.title}")
        lines.append("")
        lines.append(f"- **Location:** `{finding.location(result.root)}`")
        lines.append(f"- **Category:** {finding.rule.category}")
        if finding.rule.cwe:
            lines.append(f"- **CWE:** {finding.rule.cwe}")
        lines.append(f"- **Description:** {finding.rule.description}")
        lines.append(f"- **Remediation:** {finding.rule.remediation}")
        lines.append("")
        lines.append("```text")
        lines.append(finding.snippet)
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def to_sarif(result: ScanResult) -> str:
    rule_index: dict[str, int] = {}
    rules: list[dict] = []
    for finding in result.findings:
        rule = finding.rule
        if rule.id in rule_index:
            continue
        rule_index[rule.id] = len(rules)
        rules.append(
            {
                "id": rule.id,
                "name": rule.title,
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.remediation},
                "properties": {
                    "severity": rule.severity.name,
                    "category": rule.category,
                    "cwe": rule.cwe,
                    "tags": [rule.category],
                },
            }
        )

    levels = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }
    results = []
    for finding in result.findings:
        results.append(
            {
                "ruleId": finding.rule.id,
                "ruleIndex": rule_index[finding.rule.id],
                "level": levels[finding.severity],
                "message": {"text": f"{finding.rule.title}. {finding.rule.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.display_path(result.root).replace("\\", "/")
                            },
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                                "snippet": {"text": finding.snippet},
                            },
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity.name,
                    "cwe": finding.rule.cwe,
                },
            }
        )

    payload = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DUMBBELL",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
