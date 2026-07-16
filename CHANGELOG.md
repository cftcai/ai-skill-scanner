# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
calendar-adjacent semantic versioning.

## [Unreleased]

### Added
- Hardcoded-secret detection (AWS/GitHub/Slack/Google/OpenAI tokens, private keys) with **redacted** report snippets.
- Supply-chain checks: unpinned / URL-or-VCS dependencies in `requirements.txt`; `curl | sh` and disabled-TLS steps in Dockerfiles.
- Multi-language detection for shell and JavaScript/TypeScript (`child_process`, `eval`/`Function`, `exec`/`spawn`, `curl | sh`); `.js/.ts/.sh/.bash` are now scanned.
- `ruff` + `mypy` tooling and a `[dev]` extra, both enforced in CI.
- `SECURITY.md`, `CONTRIBUTING.md`, and this changelog.

### Changed
- `.txt` files are now scanned as code (closes a coverage gap).
- Findings carry the exact `rule_id` and curated severity; the dedup severity lookup is crash-safe.

### Security
- Skip symlinked files/dirs when scanning (prevents local file disclosure via a malicious symlink).
- Reset the signatures cache to the trusted pinned commit; treat offline updates as non-fatal.
- Validate `--github-url` and pass it after `--` to `git clone` (blocks argument injection).
- File-size cap (2 MiB) and per-line length guard to bound resource use / ReDoS.
- Least-privilege `permissions` and SHA-pinned Actions across all workflows.

## [1.2.0]

### Added
- SARIF 2.1.0 output (`--format sarif`) for GitHub code scanning.
- Client-side signature pinning (`PINNED_SIGNATURES_SHA`, `--signatures-sha`, `--allow-unpinned`) replacing the placebo manifest SHA check.
- Import-alias resolution so `from os import system` / `import subprocess as sp` cannot bypass AST checks.

### Fixed
- Single-file `--path` scans (previously reported zero findings).
- False-positive rate: documentation/config files skip code heuristics; benign-host allowlist; per-line dedup.
- Findings use repo-relative paths (no absolute host-path leak).
