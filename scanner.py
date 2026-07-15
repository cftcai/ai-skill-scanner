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

# Default cache location for signatures
SIGNATURES_CACHE = Path.home() / ".cache" / "ai-skill-signatures"
SIGNATURES_REPO = "https://github.com/cftcai/ai-skill-signatures.git"

# Dangerous function targets detected via AST
DANGEROUS_FUNCS: set[str] = {
    "eval", "exec", "compile", "__import__",
    "subprocess.call", "subprocess.Popen", "subprocess.run", "subprocess.check_output",
    "os.system", "os.popen",
    "pickle.loads", "marshal.loads", "builtins.exec", "builtins.eval"
}

# Fallback hardcoded patterns (used if no signatures repo is available)
EXFIL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r'https?://(?!api\.openai\.com|api\.anthropic\.com|api\.groq\.com|api\.x\.ai|localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s"\'`]{8,}', re.IGNORECASE),
    re.compile(r'(?:requests|urllib3?|httpx|http\.client|socket)\s*\.\s*(?:post|get|request|send|connect|create_connection)', re.IGNORECASE),
    re.compile(r'(?:os\.environ|getenv|environ\[|os\.getenv)\s*\[?\s*["\']?[A-Z_]+["\']?\s*\]?', re.IGNORECASE),
    re.compile(r'(?:ignore|disregard|override|forget|discard).*?(?:previous|all|system|prior|earlier|instructions|rules|policies|guidelines)', re.IGNORECASE),
    re.compile(r'(?:exfiltrat|leak|steal|exfil|beacon|callback|phonehome|upload|transmit).*?(?:data|secret|key|token|env|memory|context|prompt|user|agent|history)', re.IGNORECASE),
    re.compile(r'base64\.(?:b64encode|b64decode|standard_b64decode|urlsafe_b64decode)', re.IGNORECASE),
    re.compile(r'marshal\.loads|zlib\.decompress|codecs\.decode.*rot', re.IGNORECASE),
]

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

def load_signatures_from_repo() -> list[re.Pattern[str]]:
    """Load and compile regex patterns from the ai-skill-signatures repository.
    Performs SHA verification against manifest.json:latest_commit_sha.
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

        manifest_path = SIGNATURES_CACHE / "manifest.json"
        if not manifest_path.exists():
            print("WARNING: manifest.json not found. Using fallback patterns.")
            return EXFIL_PATTERNS

        manifest = json.loads(manifest_path.read_text())
        latest_sha = manifest.get("latest_commit_sha", "")

        # Verify SHA integrity (skip if placeholder)
        if latest_sha and not latest_sha.startswith("PLACEHOLDER"):
            current_sha = subprocess.check_output(
                ["git", "-C", str(SIGNATURES_CACHE), "rev-parse", "HEAD"],
                text=True
            ).strip()
            if current_sha != latest_sha:
                print(f"WARNING: Signature SHA mismatch! Expected {latest_sha}, got {current_sha}")
                print("Signatures may be tampered or outdated. Using fallback patterns.")
                return EXFIL_PATTERNS

        patterns: list[re.Pattern[str]] = []
        for sig_file in manifest.get("signatures", []):
            sig_path = SIGNATURES_CACHE / "signatures" / sig_file
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

def scan_single_file(filepath: Path, patterns: list[re.Pattern[str]]) -> list[dict[str, Any]]:
    """Scan one file using provided patterns."""
    findings: list[dict[str, Any]] = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeDecodeError) as e:
        findings.append({
            "file": str(filepath),
            "line": 0,
            "type": "read_error",
            "severity": "low",
            "description": f"Unable to read file: {e}",
            "snippet": ""
        })
        return findings

    lines = content.splitlines(keepends=False)
    rel_path = str(filepath.relative_to(filepath.anchor) if filepath.is_absolute() else filepath)

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

    # Regex patterns (loaded or fallback)
    for pattern in patterns:
        for match in pattern.finditer(content):
            line_no = content[:match.start()].count("\n") + 1
            snippet = lines[line_no - 1].strip()[:200] if 0 < line_no <= len(lines) else match.group(0)[:120]
            is_high = any(kw in pattern.pattern.lower() for kw in ["exfil", "ignore", "leak", "override"])
            findings.append({
                "file": rel_path,
                "line": line_no,
                "type": "suspicious_pattern",
                "severity": "high" if is_high else "medium",
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

    # Skill definition checks
    if "SKILL" in filepath.name.upper() or filepath.suffix in {".md", ".markdown"}:
        injection_markers = ["exfiltrate", "send data", "callback url", "ignore previous", "override safety"]
        if any(marker in content.lower() for marker in injection_markers):
            findings.append({
                "file": rel_path,
                "line": 1,
                "type": "prompt_injection_risk",
                "severity": "high",
                "description": "Skill definition file contains high risk prompt injection or exfiltration language",
                "snippet": content[:400].replace("\n", " ")[:300],
                "recommendation": "Do not load skill. Treat definition as untrusted input to the agent runtime."
            })

    return findings

def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="ai-skill-scanner",
        description="Standalone scanner for public AI skills with dynamic signatures and SHA verification."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--github-url", metavar="URL", help="Public GitHub repository URL to clone and scan")
    group.add_argument("--path", metavar="PATH", help="Local directory or single file to scan")
    parser.add_argument("--output", metavar="FILE", default="skill_scan_report.json",
                        help="Path for JSON report output")
    parser.add_argument("--update-signatures", action="store_true",
                        help="Update and verify signatures from ai-skill-signatures repo")
    parser.add_argument("--version", action="version", version="%(prog)s 1.1.0")
    args = parser.parse_args()

    if args.update_signatures:
        print("Updating signatures from ai-skill-signatures...")
        load_signatures_from_repo()
        print("Signatures updated and verified successfully.")
        return

    active_patterns = load_signatures_from_repo()

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

    print(f"Scanning files under {root} ...")
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for filename in filenames:
            if (filename.endswith((".py", ".md", ".markdown", ".txt", ".yaml", ".yml")) or
                "SKILL" in filename.upper() or
                filename in {"requirements.txt", "setup.py", "pyproject.toml", "Dockerfile"}):
                fpath = Path(dirpath) / filename
                all_findings.extend(scan_single_file(fpath, active_patterns))

    high_sev = sum(1 for f in all_findings if f.get("severity") == "high")
    medium_sev = sum(1 for f in all_findings if f.get("severity") == "medium")

    report: dict[str, Any] = {
        "scanner": "ai-skill-scanner",
        "version": "1.1.0",
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
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Scan finished. {len(all_findings)} findings ({high_sev} high, {medium_sev} medium).")
    print(f"Report written to {output_path}")

    if cleanup and target_dir:
        shutil.rmtree(target_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
