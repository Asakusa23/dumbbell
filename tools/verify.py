from __future__ import annotations

import compileall
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dumbbell import __version__
from dumbbell.icon import ASCII_LOGO
from dumbbell.rules import RULES
from dumbbell.scanner import scan_path


def _check(label: str, condition: bool, detail: str = "") -> None:
    status = "ok" if condition else "FAIL"
    suffix = f"  {detail}" if detail else ""
    print(f"[{status}] {label}{suffix}")
    if not condition:
        raise SystemExit(1)


def _project_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    try:
        import tomllib

        return tomllib.loads(text)["project"]["version"]
    except ModuleNotFoundError:
        match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        return match.group(1) if match else ""


def main() -> int:
    print("DUMBBELL // pre-release verification")
    print()

    _check("version matches pyproject.toml", _project_version() == __version__, __version__)
    _check("rule identifiers are unique", len({rule.id for rule in RULES}) == len(RULES), f"{len(RULES)} rules")
    _check("every rule has remediation", all(len(rule.remediation) >= 20 for rule in RULES))
    logo = ASCII_LOGO.splitlines()
    _check("ASCII logo is 3D", len(logo) == 7 and any("=" in line for line in logo) and any("#" in line for line in logo))

    compiled = all(
        compileall.compile_dir(str(ROOT / folder), quiet=1, force=True)
        for folder in ("dumbbell", "tests", "tools")
    )
    _check("all Python files compile", compiled)

    tests = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    _check("unit tests pass", tests.returncode == 0, tests.stderr.strip().splitlines()[-1] if tests.stderr else "")

    self_scan = scan_path(ROOT)
    _check("project self-scan is clean", not self_scan.findings, f"{self_scan.files_scanned} files")

    package_scan = scan_path(ROOT / "dumbbell")
    _check("package self-scan is clean", not package_scan.findings, f"{package_scan.files_scanned} files")

    safe_scan = scan_path(ROOT / "samples" / "safe_app.py")
    _check("safe sample is clean", not safe_scan.findings)

    sample_scan = scan_path(ROOT / "samples" / "multilang", use_ignore=False)
    expected = {"SQLI-007", "CMDI-021", "CMDI-023", "CMDI-025", "CRY-019", "DESER-003"}
    found = {finding.rule.id for finding in sample_scan.findings}
    _check("multilanguage samples produce findings", expected.issubset(found), f"{len(sample_scan.findings)} findings")
    _check(
        "every sample finding has remediation",
        all(finding.rule.remediation for finding in sample_scan.findings),
    )

    assets = ROOT / "dumbbell" / "assets"
    _check("icon PNG exists", (assets / "icon.png").is_file())
    _check("icon ICO exists", (assets / "icon.ico").is_file())
    _check("header logo exists", (assets / "logo_header.png").is_file())

    print()
    print("verification passed: ready to publish")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
