# ai-skill-scanner

Standalone security scanner for publicly available or downloaded AI agent skills.

Detects code execution primitives, data exfiltration callbacks, prompt injection in skill definitions, obfuscated payloads, and supply chain risks before integration into agent runtimes.

**Web frontend demo**: https://github.com/cftcai/ai-skill-scanner-web (instant demo with the mock malicious skill fixture)

## GitHub Actions

Our automation is powered by GitHub Actions. All workflows are in `.github/workflows/`.

**CI & Quality**  
🚀 **ci.yml** — Linting • Self-scan • Docker build • Weekly scheduled scans  
[![CI](https://github.com/cftcai/ai-skill-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/cftcai/ai-skill-scanner/actions/workflows/ci.yml)

**Deployment**  
📦 **pages.yml** (ai-skill-scanner-web) — Static site deployment to GitHub Pages

**Demo & Security**  
🔐 **oidc-demo.yml** — OIDC token exchange example (no long-lived secrets, demonstrates audience claims)

**Testing**  
🧪 Uses the canonical **mock malicious_skill.py** fixture via `test_malicious_skill_fixture`  
This is the EICAR-equivalent test case for high-severity detection (dangerous execution, exfiltration, prompt injection, obfuscation).

**Best practices followed**  
- Least-privilege permissions  
- No long-lived secrets in OIDC demo  
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

## Docker (Recommended for Isolation)

```bash
docker build -t ai-skill-scanner .
docker run --rm -v $(pwd)/target-skill:/scan:ro ai-skill-scanner --path /scan
```

For GitHub URL scans the container needs temporary network access for git clone.

## Detection Coverage

The scanner performs static analysis across these vectors:

- Dangerous Python execution (eval, exec, subprocess, pickle deserialization)
- Network exfiltration and callback patterns (requests to non-allowlisted hosts, secret leakage)
- Prompt injection and override instructions inside SKILL.md and markdown definitions
- High-entropy obfuscated strings and decode chains
- Supply chain indicators in requirements.txt, setup.py, and workflow files
- File persistence attempts

See the JSON report for per-finding severity (high/medium/low), line numbers, snippets, and recommendations.

## Architecture

- Pure stdlib implementation. No external dependencies at runtime.
- AST traversal for precise Python call detection.
- Regex + Shannon entropy for pattern and obfuscation discovery.
- Special handling for skill definition files (SKILL.md).
- Temporary directory cloning with automatic cleanup.
- Structured JSON output for CI/CD ingestion or further automation.

The design follows defense-in-depth principles used in modern SAST tools and recent AI agent security scanners. It is intentionally static. Pair with container runtime controls and optional dynamic tracing for production use.

## Signature Updates

The scanner supports an optional --update-signatures flag (planned for full implementation in v1.1). When present it will pull the latest patterns from the ai-skill-signatures repository using git shallow clone into a local signatures/ cache. The git pull update model keeps the scanner binary stable while allowing independent evolution of detection rules.

Example:

```bash
ai-skill-scanner --path /my/skills --update-signatures --output report.json
```

See the ai-skill-signatures repository for the manifest version comparison logic.

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