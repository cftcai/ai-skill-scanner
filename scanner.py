#!/usr/bin/env python3
"""
ai-skill-scanner: End-to-end standalone public AI skill security scanner.

Scans GitHub repositories or local paths containing AI agent skills for dangerous
code execution, data exfiltration, prompt injection, and obfuscation.

New in this version:
- Dynamic signature loading from ai-skill-signatures repository
- --update-signatures flag with SHA integrity verification
- Backward compatible with hardcoded patterns

Usage examples:
  python scanner.py --github-url https://github.com/example/some-skill
  python scanner.py --update-signatures
  python scanner.py --path /path/to/skill --output report.json
"""

import argparse
import ast
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__version__ = "1.2.0"

# Default cache location for signatures
SIGNATURES_CACHE = Path.home() / ".cache" / "ai-skill-signatures"
SIGNATURES_REPO = "https://github.com/cftcai/ai-skill-signatures.git"

# Client-side pin (trust-on-first-use): the ai-skill-signatures commit this
# scanner build trusts. Fetched rules are only used when the cloned HEAD matches
# this SHA, so a tampered or unexpectedly-changed upstream cannot silently inject
# rules. This must be pinned by the scanner (not read from the signatures repo),
# because a repo an attacker controls could otherwise vouch for itself. Bump it
# with `--update-signatures` after reviewing the fetched changes.
PINNED_SIGNATURES_SHA = "91848886271b742055ee060b3baa9902237a070b"

# Human-readable descriptions for each finding type, surfaced as SARIF rules.
RULE_DESCRIPTIONS: dict[str, str] = {
    "dangerous_code_execution": "Dangerous code execution primitive (eval/exec/subprocess/deserialization).",
    "suspicious_pattern": "Potential exfiltration, network callback, or prompt-injection indicator.",
    "high_entropy_obfuscation": "High-entropy string that may conceal an encoded payload.",
    "prompt_injection_risk": "Prompt-injection or exfiltration language in a skill definition.",
    "syntax_error": "File could not be parsed.",
    "read_error": "File could not be read.",
}

# SARIF level per scanner severity.
_SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}

# Dangerous function targets detected via AST
DANGEROUS_FUNCS: set[str] = {
    "eval", "exec", "compile", "__import__",
    "subprocess.call", "subprocess.Popen", "subprocess.run", "subprocess.check_output",
    "os.system", "os.popen",
    "pickle.loads", "marshal.loads", "builtins.exec", "builtins.eval"
}

# Hosts that are common in documentation, packaging, and CI and are not
# meaningful exfiltration targets. Subdomains are allowed (see the lookahead).
BENIGN_HOSTS = (
    r"api\.openai\.com|api\.anthropic\.com|api\.groq\.com|api\.x\.ai|"
    r"github\.com|githubusercontent\.com|githubassets\.com|pypi\.org|"
    r"files\.pythonhosted\.org|python\.org|readthedocs\.io|shields\.io|"
    r"example\.(?:com|org|net)|w3\.org|json-schema\.org|schema\.org|"
    r"opensource\.org|apache\.org|mozilla\.org"
)

# Fallback hardcoded patterns (used if no signatures repo is available)
EXFIL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'https?://(?!(?:[\w-]+\.)*(?:' + BENIGN_HOSTS + r')|localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s"\'`]{8,}', re.IGNORECASE),
    re.compile(r'(?:requests|urllib3?|httpx|http\.client|socket)\s*\.\s*(?:post|get|request|send|connect|create_connection)', re.IGNORECASE),
    re.compile(r'(?:os\.environ(?:\.get)?|os\.getenv|getenv|environ)\s*[\[(]\s*["\']?[A-Za-z_][A-Za-z0-9_]*', re.IGNORECASE),
    re.compile(r'(?:ignore|disregard|override|forget|discard).*?(?:previous|all|system|prior|earlier|instructions|rules|policies|guidelines)', re.IGNORECASE),
    re.compile(r'(?:exfiltrat|leak|steal|exfil|beacon|callback|phonehome|upload|transmit).*?(?:data|secret|key|token|env|memory|context|prompt|user|agent|history)', re.IGNORECASE),
    re.compile(r'base64\.(?:b64encode|b64decode|standard_b64decode|urlsafe_b64decode)', re.IGNORECASE),
    re.compile(r'marshal\.loads|zlib\.decompress|codecs\.decode.*rot', re.IGNORECASE),
]

# Prose / configuration files. The generic regex and entropy heuristics are
# tuned for code; running them over documentation and packaging metadata (which
# naturally discuss and contain these tokens) is the dominant false-positive
# source. Such files still get the dedicated prompt-injection check below.
PROSE_SUFFIXES: set[str] = {".md", ".markdown", ".txt", ".rst", ".toml", ".cfg", ".ini"}

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string. Values >4.5 often indicate encoded payloads."""
    if not data or len(data) < 20:
        return 0.0
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def _git_head(repo: Path) -> str | None:
    """Return the current HEAD commit SHA of a git repo, or None on failure."""
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True, timeout=15
        ).strip()
    except (subprocess.SubprocessError, OSError):
        return None


def load_signatures_from_repo(pinned_sha: str | None = PINNED_SIGNATURES_SHA,
                              allow_unpinned: bool = False) -> list[re.Pattern[str]]:
    """Load and compile regex patterns from the ai-skill-signatures repository.

    Verifies the fetched HEAD against a client-side pinned commit SHA. Fetched
    rules are used only on a match; otherwise the built-in patterns are used.
    """
    try:
        if not SIGNATURES_CACHE.exists():
            print("Cloning signatures repository (first run)...")
            SIGNATURES_CACHE.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--depth", "1", SIGNATURES_REPO, str(SIGNATURES_CACHE)],
                check=True, timeout=60, capture_output=True
            )
        else:
            subprocess.run(
                ["git", "-C", str(SIGNATURES_CACHE), "pull", "--ff-only"],
                check=True, timeout=30, capture_output=True
            )

        # Client-side pin verification (trust-on-first-use). The pin is held by
        # the scanner, not read from the fetched repo, so a compromised upstream
        # cannot vouch for itself.
        head = _git_head(SIGNATURES_CACHE)
        pin_active = bool(pinned_sha) and not str(pinned_sha).startswith("PLACEHOLDER")
        if not allow_unpinned and pin_active and head != pinned_sha:
            print(f"WARNING: signatures HEAD ({head}) does not match the pinned "
                  f"SHA ({pinned_sha}).")
            print("Refusing fetched rules and using built-in patterns. If this "
                  "update is expected, review it and re-pin via --update-signatures.")
            return EXFIL_PATTERNS

        manifest_path = SIGNATURES_CACHE / "manifest.json"
        if not manifest_path.exists():
            print("WARNING: manifest.json not found. Using fallback patterns.")
            return EXFIL_PATTERNS

        manifest = json.loads(manifest_path.read_text())

        patterns: list[re.Pattern[str]] = []
        for sig_file in manifest.get("signatures", []):
            sig_path = SIGNATURES_CACHE / sig_file
            if not sig_path.exists():
                continue
            try:
                rules = json.loads(sig_path.read_text())
                for rule in rules:
                    pattern_str = rule.get("pattern", "")
                    ignorecase = rule.get("ignorecase", True)
                    if pattern_str:
                        flags = re.IGNORECASE if ignorecase else 0
                        patterns.append(re.compile(pattern_str, flags))
            except Exception as e:
                print(f"WARNING: Failed to load {sig_file}: {e}")

        if patterns:
            print(f"Loaded {len(patterns)} signature patterns from ai-skill-signatures repo.")
            return patterns
        return EXFIL_PATTERNS

    except Exception as e:
        print(f"WARNING: Could not load signatures ({e}). Using fallback patterns.")
        return EXFIL_PATTERNS

def _display_path(filepath: Path, base: Path | None) -> str:
    """Path shown in findings: relative to the scan root when possible, so
    reports are portable and do not leak absolute host paths."""
    if base is not None:
        try:
            return filepath.relative_to(base).as_posix()
        except ValueError:
            pass
    return filepath.name


def scan_single_file(filepath: Path, patterns: list[re.Pattern[str]],
                     base: Path | None = None) -> list[dict[str, Any]]:
    """Scan one file using provided patterns."""
    findings: list[dict[str, Any]] = []
    rel_path = _display_path(filepath, base)
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError) as e:
        findings.append({
            "file": rel_path,
            "line": 0,
            "type": "read_error",
            "severity": "low",
            "description": f"Unable to read file: {e}",
            "snippet": ""
        })
        return findings

    lines = content.splitlines(keepends=False)

    # AST based detection for Python
    if filepath.suffix == ".py":
        try:
            tree = ast.parse(content, filename=str(filepath))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name: str | None = None
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                        func_name = f"{node.func.value.id}.{node.func.attr}"
                    if func_name in DANGEROUS_FUNCS:
                        line_no = getattr(node, "lineno", 0)
                        snippet = lines[line_no - 1].strip()[:200] if 0 < line_no <= len(lines) else ""
                        findings.append({
                            "file": rel_path,
                            "line": line_no,
                            "type": "dangerous_code_execution",
                            "severity": "high",
                            "description": f"Dangerous execution primitive detected: {func_name}",
                            "snippet": snippet,
                            "recommendation": "Review for untrusted input. Prefer sandboxed or restricted execution."
                        })
        except SyntaxError as e:
            findings.append({
                "file": rel_path,
                "line": getattr(e, "lineno", 0) or 0,
                "type": "syntax_error",
                "severity": "low",
                "description": f"Python parse failure: {str(e)[:100]}",
                "snippet": ""
            })

    is_prose = filepath.suffix.lower() in PROSE_SUFFIXES

    # Regex + entropy heuristics run on code only. Prose/config files are
    # covered by the dedicated skill check below.
    if not is_prose:
        for pattern in patterns:
            # A bare URL is a weak signal on its own; keyword patterns
            # (exfiltration / prompt override) are the strong ones.
            is_url_only = pattern.pattern.startswith("https?://")
            is_high = any(kw in pattern.pattern.lower() for kw in ["exfil", "ignore", "leak", "override"])
            severity = "low" if is_url_only else ("high" if is_high else "medium")
            for match in pattern.finditer(content):
                line_no = content[:match.start()].count("\n") + 1
                snippet = lines[line_no - 1].strip()[:200] if 0 < line_no <= len(lines) else match.group(0)[:120]
                findings.append({
                    "file": rel_path,
                    "line": line_no,
                    "type": "suspicious_pattern",
                    "severity": severity,
                    "description": "Potential exfiltration, callback, or prompt injection indicator",
                    "snippet": snippet,
                    "recommendation": "Inspect data flow to network or secret sinks. Block untrusted patterns."
                })

        # High entropy detection
        for match in re.finditer(r'["\']([A-Za-z0-9+/=_-]{30,})["\']', content):
            candidate = match.group(1)
            entropy = calculate_shannon_entropy(candidate)
            if entropy > 4.8:
                line_no = content[:match.start()].count("\n") + 1
                findings.append({
                    "file": rel_path,
                    "line": line_no,
                    "type": "high_entropy_obfuscation",
                    "severity": "medium",
                    "description": f"High entropy encoded string (entropy={entropy:.2f}) may conceal payload",
                    "snippet": candidate[:60] + "...",
                    "recommendation": "Manually decode and review. Typical of packed malware or stolen data."
                })

    # Skill definition checks. Markers are imperative injection *payloads*
    # (instructions aimed at the agent), not topic words, so documentation that
    # merely describes these attacks does not trigger a finding.
    if "SKILL" in filepath.name.upper() or filepath.suffix in {".md", ".markdown"}:
        injection_markers = [
            r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|above)\s+instructions",
            r"disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|above)\s+(?:instructions|context)",
            r"forget\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|earlier|above)\s+(?:instructions|context)",
            r"override\s+(?:your\s+|the\s+)?(?:safety|security|system)\s+(?:policy|policies|instructions|rules|guidelines)",
            r"exfiltrat\w*\s+(?:the\s+|all\s+|entire\s+)?(?:user|agent|memory|context|conversation|secrets?|environment)",
            r"send\s+(?:the\s+|all\s+|your\s+)?(?:user|agent|memory|context|secrets?|history|environment)\b[^.\n]{0,40}\bto\b",
            r"reveal\s+(?:your\s+|the\s+)?(?:system\s+)?prompt",
        ]
        marker = next((m for m in injection_markers if re.search(m, content, re.IGNORECASE)), None)
        if marker:
            hit = re.search(marker, content, re.IGNORECASE)
            line_no = content[:hit.start()].count("\n") + 1
            findings.append({
                "file": rel_path,
                "line": line_no,
                "type": "prompt_injection_risk",
                "severity": "high",
                "description": "Skill definition file contains high risk prompt injection or exfiltration language",
                "snippet": lines[line_no - 1].strip()[:200] if 0 < line_no <= len(lines) else content[:200],
                "recommendation": "Do not load skill. Treat definition as untrusted input to the agent runtime."
            })

    # Collapse duplicate findings on the same line and type (multiple patterns
    # frequently match the same construct), keeping the highest severity.
    deduped: dict[tuple[int, str], dict[str, Any]] = {}
    for f in findings:
        key = (f["line"], f["type"])
        existing = deduped.get(key)
        if existing is None or _SEVERITY_RANK[f["severity"]] > _SEVERITY_RANK[existing["severity"]]:
            deduped[key] = f
    return list(deduped.values())

def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    """Convert a scan report into SARIF 2.1.0 for GitHub code scanning."""
    findings = report.get("findings", [])
    types_present = sorted({f["type"] for f in findings})
    rules = [
        {
            "id": t,
            "name": t,
            "shortDescription": {"text": RULE_DESCRIPTIONS.get(t, t)},
            "helpUri": "https://github.com/cftcai/ai-skill-scanner",
        }
        for t in types_present
    ]

    results = []
    for f in findings:
        start_line = f.get("line") or 0
        message = f.get("description") or RULE_DESCRIPTIONS.get(f["type"], f["type"])
        snippet = f.get("snippet") or ""
        fingerprint = hashlib.sha1(
            f"{f.get('file','')}:{start_line}:{f['type']}:{snippet}".encode("utf-8")
        ).hexdigest()
        results.append({
            "ruleId": f["type"],
            "level": _SARIF_LEVEL.get(f.get("severity", "low"), "note"),
            "message": {"text": f"{message} {snippet}".strip()},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file", "")},
                    # SARIF regions are 1-based; clamp file-level findings to 1.
                    "region": {"startLine": max(1, start_line)},
                }
            }],
            "partialFingerprints": {"aiSkillScanner/v1": fingerprint},
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ai-skill-scanner",
                "version": report.get("version", __version__),
                "informationUri": "https://github.com/cftcai/ai-skill-scanner",
                "rules": rules,
            }},
            "results": results,
        }],
    }


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="ai-skill-scanner",
        description="Standalone scanner for public AI skills with dynamic, client-side-pinned signatures."
    )
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--github-url", metavar="URL", help="Public GitHub repository URL to clone and scan")
    group.add_argument("--path", metavar="PATH", help="Local directory or single file to scan")
    parser.add_argument("--output", metavar="FILE", default="skill_scan_report.json",
                        help="Path for report output")
    parser.add_argument("--format", choices=["json", "sarif"], default="json",
                        help="Report format: json (native) or sarif (GitHub code scanning)")
    parser.add_argument("--update-signatures", action="store_true",
                        help="Fetch signatures and report the fetched HEAD vs the pinned SHA")
    parser.add_argument("--signatures-sha", metavar="SHA", default=None,
                        help="Override the trusted ai-skill-signatures commit SHA (client-side pin)")
    parser.add_argument("--allow-unpinned", action="store_true",
                        help="Skip client-side signature pin verification (use with caution)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    pinned_sha = args.signatures_sha or PINNED_SIGNATURES_SHA

    if args.update_signatures:
        print("Fetching signatures from ai-skill-signatures...")
        load_signatures_from_repo(pinned_sha=pinned_sha, allow_unpinned=True)
        head = _git_head(SIGNATURES_CACHE)
        print(f"Fetched signatures HEAD: {head}")
        print(f"Scanner trusts (pin):    {pinned_sha}")
        if head == pinned_sha:
            print("Pin matches — fetched signatures are trusted.")
        else:
            print("Pin MISMATCH. Review the fetched changes, then set "
                  "PINNED_SIGNATURES_SHA (or pass --signatures-sha) to the fetched "
                  "HEAD to trust it.")
        return

    # Require either --github-url or --path when not updating signatures
    if not args.github_url and not args.path:
        parser.error("one of the arguments --github-url --path is required")

    active_patterns = load_signatures_from_repo(pinned_sha=pinned_sha,
                                                allow_unpinned=args.allow_unpinned)

    target_dir: str | None = None
    cleanup: bool = False

    if args.github_url:
        target_dir = tempfile.mkdtemp(prefix="skillscan_")
        cleanup = True
        print(f"Cloning repository {args.github_url} (depth 1)...")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", args.github_url, target_dir],
                check=True, timeout=120, capture_output=True
            )
        except subprocess.CalledProcessError as e:
            print(f"ERROR: Git clone failed.\n{e.stderr}")
            shutil.rmtree(target_dir, ignore_errors=True)
            sys.exit(2)
        except subprocess.TimeoutExpired:
            print("ERROR: Git clone timed out after 120 seconds.")
            shutil.rmtree(target_dir, ignore_errors=True)
            sys.exit(2)
        except FileNotFoundError:
            print("ERROR: git executable not found in PATH.")
            shutil.rmtree(target_dir, ignore_errors=True)
            sys.exit(2)
    else:
        target_path = Path(args.path).resolve()
        if not target_path.exists():
            print(f"ERROR: Path does not exist: {target_path}")
            sys.exit(1)
        target_dir = str(target_path)

    root = Path(target_dir)
    all_findings: list[dict[str, Any]] = []
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules", "dist", "build"}

    def _should_scan(filename: str) -> bool:
        return (filename.endswith((".py", ".md", ".markdown", ".txt", ".yaml", ".yml")) or
                "SKILL" in filename.upper() or
                filename in {"requirements.txt", "setup.py", "pyproject.toml", "Dockerfile"})

    # Collect target files. A single file passed via --path must be scanned
    # directly: os.walk() over a file yields nothing, which previously caused
    # single-file scans to silently report zero findings.
    files_to_scan: list[Path] = []
    if root.is_file():
        # An explicitly named file is always scanned, regardless of extension.
        files_to_scan.append(root)
    else:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for filename in filenames:
                if _should_scan(filename):
                    files_to_scan.append(Path(dirpath) / filename)

    # Base for relative paths in findings: the directory itself, or the parent
    # of a single scanned file, so URIs are portable (e.g. tests/skill.py).
    base = root if root.is_dir() else root.parent

    print(f"Scanning {len(files_to_scan)} file(s) under {root} ...")
    for fpath in files_to_scan:
        all_findings.extend(scan_single_file(fpath, active_patterns, base))

    high_sev = sum(1 for f in all_findings if f.get("severity") == "high")
    medium_sev = sum(1 for f in all_findings if f.get("severity") == "medium")

    report: dict[str, Any] = {
        "scanner": "ai-skill-scanner",
        "version": __version__,
        "target": args.github_url or str(Path(args.path).resolve()),
        "scan_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(all_findings),
        "high_severity": high_sev,
        "medium_severity": medium_sev,
        "low_severity": len(all_findings) - high_sev - medium_sev,
        "findings": all_findings,
        "signatures_source": "ai-skill-signatures repo" if active_patterns != EXFIL_PATTERNS else "fallback hardcoded"
    }

    output_path = Path(args.output).resolve()
    document = to_sarif(report) if args.format == "sarif" else report
    output_path.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Scan finished. {len(all_findings)} findings ({high_sev} high, {medium_sev} medium).")
    print(f"Report ({args.format}) written to {output_path}")

    if cleanup and target_dir:
        shutil.rmtree(target_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
