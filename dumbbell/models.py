from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    @property
    def label(self) -> str:
        return self.name

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value}") from exc

    @classmethod
    def ordered(cls) -> list["Severity"]:
        return [cls.CRITICAL, cls.HIGH, cls.MEDIUM, cls.LOW, cls.INFO]


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    remediation: str
    pattern: str
    cwe: str = ""
    extensions: tuple[str, ...] = ()
    flags: int = 0
    redact: bool = False

    def __post_init__(self) -> None:
        import re

        self._compiled = re.compile(self.pattern, self.flags | re.MULTILINE)

    def matches_extension(self, suffix: str, name: str) -> bool:
        """Every rule is evaluated against every text file, whatever its extension."""
        return True

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.name,
            "category": self.category,
            "cwe": self.cwe,
            "description": self.description,
            "remediation": self.remediation,
        }


@dataclass
class Finding:
    rule: Rule
    path: str
    line: int
    column: int
    snippet: str

    @property
    def severity(self) -> Severity:
        return self.rule.severity

    def display_path(self, root: str | Path | None = None) -> str:
        if root is None:
            return self.path
        try:
            return str(Path(self.path).resolve().relative_to(Path(root).resolve()))
        except ValueError:
            return self.path

    def location(self, root: str | Path | None = None) -> str:
        return f"{self.display_path(root)}:{self.line}:{self.column}"

    def as_dict(self, root: str | Path | None = None) -> dict[str, Any]:
        return {
            "rule": self.rule.id,
            "title": self.rule.title,
            "severity": self.severity.name,
            "category": self.rule.category,
            "cwe": self.rule.cwe,
            "file": self.display_path(root),
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "description": self.rule.description,
            "remediation": self.rule.remediation,
        }


@dataclass
class ScanResult:
    root: str
    findings: list[Finding]
    files_scanned: int
    files_skipped: int
    bytes_scanned: int
    elapsed: float
    cancelled: bool = False

    def severity_counts(self) -> dict[str, int]:
        counts = {severity.name: 0 for severity in Severity.ordered()}
        for finding in self.findings:
            counts[finding.severity.name] += 1
        return counts

    def risk_score(self) -> int:
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        score = sum(weights[finding.severity] for finding in self.findings)
        return min(100, score)
