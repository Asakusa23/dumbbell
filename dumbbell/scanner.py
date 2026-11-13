from __future__ import annotations

import bisect
import codecs
import fnmatch
import os
import time
from pathlib import Path
from typing import Callable, Iterable, Sequence

from .models import Finding, Rule, ScanResult
from .rules import RULES

DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "virtualenv",
        "site-packages",
        "dist",
        "build",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".idea",
        ".vscode",
        ".cache",
        ".next",
        ".nuxt",
        "target",
        "vendor",
        "coverage",
        "htmlcov",
        ".eggs",
    }
)

DEFAULT_MAX_FILE_SIZE = 1_000_000

ProgressCallback = Callable[[int, int, str], None]
FindingCallback = Callable[[Finding], None]


def _read_ignore_file(directory: Path) -> list[str]:
    ignore_file = directory / ".dumbbellignore"
    if not ignore_file.is_file():
        return []
    patterns: list[str] = []
    try:
        content = ignore_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return patterns
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def load_ignore_patterns(root: str | Path) -> list[str]:
    base = Path(root)
    if base.is_file():
        base = base.parent
    return _read_ignore_file(base)


def _matches_ignore(relative_path: str, patterns: Sequence[str]) -> bool:
    if not patterns:
        return False
    relative_path = relative_path.replace("\\", "/")
    name = Path(relative_path).name
    for pattern in patterns:
        pattern = pattern.replace("\\", "/").strip()
        if not pattern:
            continue
        if pattern.endswith("/"):
            pattern += "*"
        if fnmatch.fnmatch(relative_path, pattern):
            return True
        if fnmatch.fnmatch(relative_path, "*/" + pattern):
            return True
        if pattern.endswith("/*") and relative_path == pattern[:-2]:
            return True
        if "/" not in pattern and fnmatch.fnmatch(name, pattern):
            return True
    return False


def _is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def _decode_text(data: bytes) -> str | None:
    if data.startswith(codecs.BOM_UTF16_LE) or data.startswith(codecs.BOM_UTF16_BE):
        return data.decode("utf-16", errors="replace")
    if _is_binary(data):
        return None
    return data.decode("utf-8", errors="replace")


def iter_files(
    root: str | Path,
    ignore_patterns: Sequence[str] | None,
    exclude_dirs: Iterable[str],
    extensions: set[str] | None,
) -> Iterable[Path]:
    root_path = Path(root)
    if root_path.is_file():
        yield root_path
        return
    excluded = set(exclude_dirs)
    nested_cache: dict[Path, list[str]] = {}

    def ignore_sets(current: Path) -> list[tuple[Path, Sequence[str]]]:
        if ignore_patterns is None:
            return []
        sets: list[tuple[Path, Sequence[str]]] = []
        if ignore_patterns:
            sets.append((root_path, ignore_patterns))
        base = root_path
        for part in current.relative_to(root_path).parts:
            base = base / part
            if base not in nested_cache:
                nested_cache[base] = _read_ignore_file(base)
            patterns = nested_cache[base]
            if patterns:
                sets.append((base, patterns))
        return sets

    def ignored(path: Path, sets: Sequence[tuple[Path, Sequence[str]]]) -> bool:
        for base, patterns in sets:
            if _matches_ignore(path.relative_to(base).as_posix(), patterns):
                return True
        return False

    for dirpath, dirnames, filenames in os.walk(root_path):
        current = Path(dirpath)
        active_ignores = ignore_sets(current)
        kept: list[str] = []
        for directory in sorted(dirnames):
            if directory in excluded or directory.endswith(".egg-info"):
                continue
            path = current / directory
            if ignored(path, active_ignores):
                continue
            kept.append(directory)
        dirnames[:] = kept
        for filename in sorted(filenames):
            path = current / filename
            if ignored(path, active_ignores):
                continue
            if extensions is not None:
                suffix = path.suffix.lower()
                name = path.name.lower()
                if suffix not in extensions and name not in extensions:
                    if not any(name.startswith(ext + ".") for ext in extensions if ext.startswith(".")):
                        continue
            yield path


def _make_snippet(
    text: str,
    line_start: int,
    line_end: int,
    match_start: int,
    match_end: int,
    redact: bool,
) -> str:
    line_text = text[line_start:line_end]
    if redact:
        relative_start = max(0, match_start - line_start)
        relative_end = min(len(line_text), match_end - line_start)
        if relative_end > relative_start:
            line_text = line_text[:relative_start] + "***REDACTED***" + line_text[relative_end:]
        else:
            line_text = "***REDACTED***"
    line_text = line_text.strip()
    if len(line_text) > 240:
        line_text = line_text[:237] + "..."
    return line_text


def scan_path(
    root: str | Path,
    rules: Sequence[Rule] = RULES,
    *,
    on_finding: FindingCallback | None = None,
    on_progress: ProgressCallback | None = None,
    cancel_event=None,
    use_ignore: bool = True,
    exclude_dirs: Iterable[str] | None = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    extensions: Iterable[str] | None = None,
) -> ScanResult:
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(str(root_path))

    excluded = set(DEFAULT_EXCLUDE_DIRS)
    if exclude_dirs:
        excluded.update(exclude_dirs)

    extension_filter: set[str] | None = None
    if extensions:
        extension_filter = set()
        for extension in extensions:
            extension = extension.strip().lower()
            if not extension:
                continue
            extension_filter.add(extension if extension.startswith(".") else "." + extension)

    ignore_patterns = load_ignore_patterns(root_path) if use_ignore else None
    files = list(iter_files(root_path, ignore_patterns, excluded, extension_filter))
    total = len(files)

    if on_progress is not None:
        on_progress(0, total, "")

    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    files_scanned = 0
    files_skipped = 0
    bytes_scanned = 0
    cancelled = False
    started = time.perf_counter()

    for index, path in enumerate(files, start=1):
        if cancel_event is not None and cancel_event.is_set():
            cancelled = True
            break
        try:
            size = path.stat().st_size
        except OSError:
            files_skipped += 1
            continue
        if size > max_file_size:
            files_skipped += 1
            continue
        try:
            data = path.read_bytes()
        except OSError:
            files_skipped += 1
            continue
        text = _decode_text(data)
        if text is None:
            files_skipped += 1
            continue

        bytes_scanned += len(data)
        files_scanned += 1
        suffix = path.suffix.lower()
        name = path.name
        newlines = [position for position, character in enumerate(text) if character == "\n"]

        for rule in rules:
            if not rule.matches_extension(suffix, name):
                continue
            for match in rule._compiled.finditer(text):
                start = match.start()
                newline_index = bisect.bisect_right(newlines, start)
                line = newline_index + 1
                line_start = newlines[newline_index - 1] + 1 if newline_index > 0 else 0
                line_end = newlines[newline_index] if newline_index < len(newlines) else len(text)
                column = start - line_start + 1
                key = (rule.id, str(path), line)
                if key in seen:
                    continue
                seen.add(key)
                snippet = _make_snippet(text, line_start, line_end, start, match.end(), rule.redact)
                finding = Finding(rule=rule, path=str(path), line=line, column=column, snippet=snippet)
                findings.append(finding)
                if on_finding is not None:
                    on_finding(finding)

        if on_progress is not None:
            on_progress(index, total, str(path))

    findings.sort(key=lambda finding: (-finding.severity.value, finding.path, finding.line, finding.rule.id))
    elapsed = time.perf_counter() - started
    return ScanResult(
        root=str(root_path),
        findings=findings,
        files_scanned=files_scanned,
        files_skipped=files_skipped,
        bytes_scanned=bytes_scanned,
        elapsed=elapsed,
        cancelled=cancelled,
    )
