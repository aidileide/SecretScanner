# SecretScanner

English | [简体中文](README.md)

Local credential scanning for files, Git worktrees, staged changes, and bounded
commit history. Reports mask matched values by default. No credential verification,
telemetry, or uploads are performed by the CLI.

## Install from this repository

Requires Python 3.11+ and Git. With pipx already installed:

```bash
pipx install "git+https://github.com/aidileide/SecretScanner.git"
secretscanner version
```

This project is **not published on PyPI**. The PyPI package `secretscanner` belongs
to another author. Do not use `pip install secretscanner` to install this project.
The distribution name here is `aidileide-secretscanner`; the executable and Python
import remain `secretscanner`.

For reproducible installs, append `@<reviewed-commit-sha>` to the Git URL.

## Quick start

```bash
secretscanner scan ./project
secretscanner git . --include-untracked
secretscanner staged .
secretscanner history . --max-commits 50
secretscanner scan . --format json --output findings.json
secretscanner scan . --format sarif --output findings.sarif
```

Exit codes: `0` means no finding at the configured threshold, `1` means a finding
meets that threshold, and `2` means a configuration/runtime error or incomplete
scan. Set `--fail-on medium` to change the default `high` threshold.

## Configuration and integrations

- Configure rules, severity, exclusions, and limits with
  [`.secretscanner.example.yml`](.secretscanner.example.yml).
- Add path patterns in `.secretscannerignore`.
- Use `secretscanner baseline create . --output baseline.json`, then
  `secretscanner scan . --baseline baseline.json` for reviewed historical findings.
- The [pre-commit hook](.pre-commit-hooks.yaml) checks staged additions. Pin its
  `rev` to a reviewed tag or commit, including the commit containing required fixes.
- The [GitHub Actions workflow](.github/workflows/secrets.yml) shows SARIF reporting.
  Uploading SARIF is an explicit workflow step, separate from local scanning.

Regex and entropy detection can produce false positives and false negatives.
Use synthetic examples in bug reports. Do not publish real credentials or use
`--show-secrets` in shared logs. See [SECURITY.md](SECURITY.md) for reporting policy.

## Develop and validate

```bash
git clone https://github.com/aidileide/SecretScanner.git
cd SecretScanner
python -m venv .venv
```

Activate the environment:

```powershell
# Windows PowerShell
.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
source .venv/bin/activate
```

Then install and run checks:

```bash
python -m pip install -e ".[dev]"
ruff format --check .
ruff check .
pytest
python -m build
python -m twine check dist/*
```

CI covers Python 3.11–3.13 on Windows and Linux, with a separate clean wheel
installation check. See [CONTRIBUTING.md](CONTRIBUTING.md),
[CHANGELOG.md](CHANGELOG.md), and the [MIT license](LICENSE).
