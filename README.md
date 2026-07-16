# ai-skill-scanner

Standalone security scanner for publicly available or downloaded AI agent skills.

Detects code execution primitives, data exfiltration callbacks, prompt injection in skill definitions, obfuscated payloads, and supply chain risks before integration into agent runtimes.

**Web interface**: https://github.com/cftcai/ai-skill-scanner-web

## GitHub Actions

Our automation is powered by GitHub Actions. All workflows are in `.github/workflows/`.

**CI & Quality**  
🚀 **ci.yml** — Linting • Self-scan • Docker build • Weekly scheduled scans  
[![CI](https://github.com/cftcai/ai-skill-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/cftcai/ai-skill-scanner/actions/workflows/ci.yml)

**Deployment**  
📦 **pages.yml** (ai-skill-scanner-web) — Static site deployment to GitHub Pages

**Security Examples**  
🔐 **oidc-demo.yml** — OIDC token exchange example (no long-lived secrets, demonstrates audience claims)

**Testing**  
🧪 Uses the canonical **mock malicious_skill.py** fixture via `test_malicious_skill_fixture`  
This is the reference test case for high-severity detection (dangerous execution, exfiltration, prompt injection, obfuscation).

**Best practices followed**  
- Least-privilege permissions  
- No long-lived secrets in OIDC example  
- Lightweight static workflows

View all workflows → [Actions tab](https://github.com/cftcai/ai-skill-scanner/actions)

## Why This Exists

Public AI skills (Python modules, SKILL.md prompt files, tool definitions) represent a growing attack surface. Malicious or compromised skills can execute arbitrary code, exfiltrate agent memory or environment variables via callbacks, poison prompts, or persist via file system changes. This tool provides a fast, local, self-contained first line of defense.

## Quick Start

Clone and run directly:

```bash
git clone https://github.com/cftcai/ai-skill-scanner.git
cd ai-skill-scanner
python scanner.py --help
```

Scan a public skill repository:

```bash
python scanner.py --github-url https://github.com/example/vulnerable-skill-repo
```

Scan local path:

```bash
python scanner.py --path /path/to/your/skills --output my_report.json
```

Install as command (recommended):

```bash
pip install -e .
ai-skill-scanner --path .
```

Emit SARIF for GitHub code scanning (surfaces findings in the Security tab):

```bash
ai-skill-scanner --path . --format sarif --output ai-skill-scanner.sarif
```

Then upload with `github/codeql-action/upload-sarif` (see `.github/workflows/ci.yml`). Severity maps to SARIF levels: high → error, medium → warning, low → note.

## Docker (Recommended for Isolation)

```bash
docker build -t ai-skill-scanner .
docker run --rm -v $(pwd)/target-skill:/scan:ro ai-skill-scanner --path /scan
```

For GitHub URL scans the container needs temporary network access for git clone.

## Detection Coverage

The scanner performs static analysis across these vectors:

- Dangerous Python execution (eval, exec, subprocess, pickle deserialization), including aliased and `from`-imports (`import subprocess as sp`, `from os import system`)
- Network exfiltration and callback patterns (requests to non-allowlisted hosts, secret leakage)
- Prompt injection and override instructions inside SKILL.md and markdown definitions
- High-entropy obfuscated strings and decode chains
- Supply chain indicators in requirements.txt, setup.py, and workflow files
- File persistence attempts

Each finding carries the rule id that fired, its curated severity (high/medium/low), the line number, a snippet, and a recommendation.

## Architecture

- Pure stdlib implementation. No external dependencies at runtime.
- AST traversal for precise Python call detection, with import-alias resolution so aliased/`from` imports cannot bypass checks.
- Rules are `(regex, id, severity, description)`; the matched rule's metadata flows through to every finding.
- Regex + Shannon entropy for pattern and obfuscation discovery, scanned line-by-line with size/length caps to bound work on hostile input.
- Special handling for skill definition files (SKILL.md).
- Temporary directory cloning with automatic cleanup.
- Structured JSON output for CI/CD ingestion or further automation.

The design follows defense-in-depth principles used in modern SAST tools and recent AI agent security scanners. It is intentionally static. Pair with container runtime controls and optional dynamic tracing for production use.

## Signature Updates and Client-Side Pinning

Detection rules live in the separate [ai-skill-signatures](https://github.com/cftcai/ai-skill-signatures) repository. The scanner shallow-clones them into a local cache (`~/.cache/ai-skill-signatures`) and refreshes with `git pull` on each run, so rules evolve independently of the scanner.

Integrity is enforced by **client-side pinning** (trust-on-first-use). The scanner hard-codes `PINNED_SIGNATURES_SHA` — a signatures commit it trusts — and uses the fetched rules **only** when the cloned `HEAD` matches that pin. On a mismatch it refuses the fetched rules and falls back to the built-in patterns. The pin is held by the scanner, not read from the signatures repo, so a compromised upstream cannot vouch for itself (unlike a SHA stored inside the repo).

Review and re-pin after a signatures release:

```bash
# Fetch and compare the fetched HEAD against the pin
ai-skill-scanner --update-signatures
# If the change is expected, set PINNED_SIGNATURES_SHA to the fetched HEAD
# (or trust it for one run without editing the source):
ai-skill-scanner --path /my/skills --signatures-sha <fetched-sha>
```

Use `--allow-unpinned` to skip verification entirely (not recommended).

## GitHub Actions Integration

Add the following workflow to scan skills on pull requests or schedule:

```yaml
name: Skill Security Scan
on: [pull_request, schedule: [{cron: '0 3 * * 1'}]]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run ai-skill-scanner
        run: |
          pip install -e .
          ai-skill-scanner --path . --output scan-report.json
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: skill-scan-report
          path: scan-report.json
```

## Limitations and Recommendations

- Static analysis only. Behavioral confirmation requires sandbox execution.
- May produce false positives on legitimate dynamic or metaprogramming code. Always triage high severity items.
- Does not execute any skill code or contact external services during scan.
- For maximum safety run inside Docker with read-only mounts and seccomp.

Extend the tool by adding custom regex rules or integrating YARA signatures and local LLM judges for semantic analysis.

## Contributing

Issues and pull requests welcome. Focus areas: additional detection patterns, improved taint tracking, support for more skill formats, and container hardening.

## License

MIT License. See LICENSE file.

## Security Policy

Report security issues privately via repository security advisories. Do not open public issues for vulnerabilities.