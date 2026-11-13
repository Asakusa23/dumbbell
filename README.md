# DUMBBELL

```text
 .-----.        .-----. 
/  ___  \      /  ___  \
| /###\ |------| /###\ |
| |###| |======| |###| |
| \###/ |------| \###/ |
\  '--' /      \  '--' /
 '-----'        '-----' 
```

DUMBBELL is a static security audit tool for source code and configuration
files. It ships with a terminal-style desktop GUI and a scriptable command line
interface. Everything is written in pure Python with the standard library only:
no external dependencies, no network access, no telemetry.

The scanner uses a curated set of regular-expression rules to flag common
security defects such as SQL injection, command injection, hardcoded secrets,
unsafe deserialization, disabled TLS verification, path traversal, SSRF, XXE,
and dangerous framework configuration.

## Features

- 151 rules across 20 categories, evaluated against every text file type:
  Python, JavaScript, TypeScript, Rust, Go, Java, C#, Ruby, C/C++, shell,
  configuration files, and extensionless files.
- Monochrome terminal GUI built with tkinter: severity filters, findings tree,
  details panel, live log, progress bar, and report export.
- CLI with text, JSON, Markdown, and SARIF 2.1.0 reports.
- Every finding includes concrete remediation advice; the GUI can copy it.
- Secret redaction in snippets, so reports do not leak credentials.
- `.dumbbellignore` support with gitignore-style patterns.
- Universal text-file scanning with UTF-16 decoding, size limits, binary
  detection, and safe directory exclusions. `--extensions` only narrows the walk.
- Exit code 1 when findings at or above a configurable severity are present.
- Photo logo for the GUI header and window icon, with a pure-Python 3D-shaded
  dumbbell icon as fallback (PNG and ICO, no runtime Pillow dependency).
- Unit tests with `unittest` and intentionally vulnerable sample files.

## Requirements

- Python 3.10 or newer.
- tkinter for the GUI. On Windows and macOS it is part of the standard Python
  installer. On Debian/Ubuntu install `python3-tk`.

## Quick start

Run the GUI from the repository root:

```powershell
python -m dumbbell
```

Run a scan from the command line:

```powershell
python -m dumbbell samples
python -m dumbbell samples --min-severity high
python -m dumbbell samples --format json -o reports/sample.json
python -m dumbbell samples --format sarif -o reports/sample.sarif
python -m dumbbell --list-rules
```

Install as a package to get the `dumbbell` and `dumbbell-gui` commands:

```powershell
python -m pip install -e .
dumbbell samples
dumbbell-gui
```

## CLI reference

```text
dumbbell [target] [options]

  --format {text,json,md,sarif}   report format (default: text)
  -o, --output PATH               write the report to a file
  --min-severity LEVEL            hide findings below LEVEL (default: info)
  --fail-on LEVEL|none            exit 1 on findings at or above LEVEL (default: high)
  --list-rules                    print the rule catalogue
  --no-ignore                     do not read .dumbbellignore
  --exclude DIR                   skip an additional directory (repeatable)
  --extensions LIST               comma-separated walk filter, for example py,js,php
                                  (rules still apply to every scanned file)
  --max-size BYTES                maximum file size (default: 1000000)
  --version                       print the version
```

Severity levels, from highest to lowest: `critical`, `high`, `medium`, `low`,
`info`.

Exit codes:

- `0`: scan completed and no finding reached the `--fail-on` threshold.
- `1`: scan completed and at least one finding reached the threshold.
- `2`: invalid target or report write error.

## Ignore file

Create `.dumbbellignore` next to the scan target, or in any subdirectory.
Patterns follow the usual glob syntax and are matched against paths relative to
the directory that contains the ignore file:

```text
reports/
__pycache__/
*.min.js
samples/
```

## GUI

The GUI keeps the same monochrome terminal aesthetic as the CLI:

- Clean dark header with a soft-cornered logo, a quiet caption, and no
  background animation.
- Hover highlight in the findings tree.
- Target entry with Browse and Scan controls.
- Severity toggles that filter the findings tree immediately.
- Findings tree with severity, rule, file, line, and title.
- Details panel with the rule description, snippet, CWE, and highlighted
  remediation advice.
- COPY FIX button that puts the remediation text on the clipboard.
- Live scan log and a progress bar with a cancel button.
- Report export to JSON, Markdown, and SARIF.

Keyboard shortcuts: `Ctrl+O` browse, `F5` rescan, `Esc` stop, `Ctrl+E` export.

## Rule catalogue

| Category | Rules |
| --- | ---: |
| Web Security | 22 |
| SQL Injection | 18 |
| Command Injection | 18 |
| Secrets | 16 |
| Transport Security | 13 |
| Insecure Deserialization | 11 |
| Path Traversal | 10 |
| Cryptography | 9 |
| SSRF | 9 |
| Code Injection | 6 |
| Container Security | 4 |
| XXE | 3 |
| Authentication | 2 |
| Insecure Temporary File | 2 |
| Sensitive Data Exposure | 2 |
| Supply Chain | 2 |
| Broken Access Control | 1 |
| Memory Safety | 1 |
| Network Exposure | 1 |
| Permissions | 1 |

Run `dumbbell --list-rules` for the full list with identifiers, severities, and
titles.

## Project layout

```text
dumbbell/
  dumbbell/
    __init__.py       version
    __main__.py       python -m dumbbell entry point
    cli.py            command line interface
    gui.py            tkinter GUI
    icon.py           ASCII fallback logo and PNG/ICO generation
    models.py         Severity, Rule, Finding, ScanResult
    report.py         JSON, Markdown, and SARIF writers
    rules.py          rule catalogue
    scanner.py        file walker, matcher, redaction
    assets/           logo source plus generated icon and header images
  samples/            intentionally vulnerable fixtures in many languages
  tests/              unittest suite
  tools/make_icon.py  regenerate the icon assets
  tools/make_logo_assets.py  build header/icon assets from assets/logo.png
  tools/verify.py     pre-release verification script
  .github/workflows/  CI verification on push and pull request
```

## Tests

```powershell
python -m unittest discover -s tests -v
python tools\verify.py
```

The suite covers rule compilation, multilanguage scanning, UTF-16 files,
secret redaction, ignore files, remediation output, report formats, and icon
generation. `tools/verify.py` runs the full pre-release check: compilation,
tests, self-scan, sample scan, remediation coverage, and icon assets.

Regenerate the icon and header assets after changing `assets/logo.png` (requires
Pillow) or `icon.py`:

```powershell
python tools/make_logo_assets.py
python tools/make_icon.py
```

## Limitations

DUMBBELL is a lightweight, regex-based scanner. It is fast and dependency-free,
but it cannot replace data-flow analysis or a full SAST product. Treat findings
as leads: confirm each one, and use the remediation text as a starting point.
The files in `samples/` are deliberately insecure and must never be deployed.

## License

MIT. See `LICENSE`.
