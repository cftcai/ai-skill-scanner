# Contributing

Thanks for your interest in improving ai-skill-scanner.

## Development setup

```bash
git clone https://github.com/cftcai/ai-skill-scanner.git
cd ai-skill-scanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Before opening a pull request

Run the same checks CI runs:

```bash
ruff check .
mypy scanner.py
pytest tests/ -q
```

All three must pass. New behavior needs a test.

## Guidelines

- **Detection rules.** Prefer adding rules to the [ai-skill-signatures](https://github.com/cftcai/ai-skill-signatures) repository (so they ship without a scanner release). Structural checks that don't fit a regex (AST, filename-aware, redaction) belong in the scanner as always-on checks.
- **Never write secrets to the report.** Redact any matched credential in snippets.
- **Bound work on untrusted input.** Respect the file-size and per-line caps; avoid patterns prone to catastrophic backtracking.
- **Keep it stdlib-only at runtime.** Runtime code must not add third-party dependencies.
- **The malicious fixture** (`tests/malicious_skill.py`) is intentional bad code and is excluded from linting — do not "clean it up."

## Reporting security issues

Do not open public issues for vulnerabilities — see [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the MIT License.
