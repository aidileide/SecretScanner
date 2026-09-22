# Contributing

## Set up

```bash
git clone https://github.com/aidileide/SecretScanner.git
cd SecretScanner
python -m venv .venv
python -m pip install -e ".[dev]"
```

Create a focused branch. Add or update tests for behavior changes. Test data must use synthetic, nonfunctional credentials.

## Checks

```bash
ruff format --check .
ruff check .
pytest
python -m build
twine check dist/*
```

Pull requests should explain trigger, resulting behavior, security impact, and validation. Never paste real secrets into issues, commits, logs, fixtures, or screenshots.

Rules should be conservative, precompiled, documented, and covered by positive and negative tests. Network validation and active credential testing are outside project scope.
