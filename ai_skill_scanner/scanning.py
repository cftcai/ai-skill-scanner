"""Per-file scanning: AST checks, regex/entropy heuristics, secrets,
supply-chain, and multi-language detection."""
import ast
import re
from pathlib import Path
from typing import Any

from .astcheck import _build_alias_map, _resolve_call_name
from .entropy import calculate_shannon_entropy
from .rules import (
    _CODE_LANG_SUFFIXES,
    _LANG_RULES,
    _SECRET_ASSIGN,
    _SECRET_RULES,
    _SEVERITY_RANK,
    DANGEROUS_FUNCS,
    MAX_FILE_BYTES,
    MAX_SCAN_LINE,
    PROSE_SUFFIXES,
    Rule,
)


def _display_path(filepath: Path, base: Path | None) -> str:
    """Path shown in findings: relative to the scan root when possible, so
    reports are portable and do not leak absolute host paths."""
    if base is not None:
        try:
            return filepath.relative_to(base).as_posix()
        except ValueError:
            pass
    return filepath.name


def _redact(value: str) -> str:
    """Mask a secret so it is never written to the report in cleartext."""
    return (value[:4] + "***") if len(value) > 8 else "***"


def _scan_secrets(rel_path: str, lines: list[str], is_code: bool) -> list[dict[str, Any]]:
    """Detect hardcoded secrets. Snippets are redacted."""
    findings: list[dict[str, Any]] = []
    for line_no, line in enumerate(lines, 1):
        if len(line) > MAX_SCAN_LINE:
            continue
        for rule in _SECRET_RULES:
            m = rule.regex.search(line)
            if m:
                findings.append({
                    "file": rel_path, "line": line_no, "type": "hardcoded_secret",
                    "rule_id": rule.id, "severity": rule.severity, "description": rule.description,
                    "snippet": _redact(m.group(0)),
                    "recommendation": "Remove the secret, rotate it, and load credentials from the environment or a secret manager.",
                })
        if is_code and (m := _SECRET_ASSIGN.search(line)):
            findings.append({
                "file": rel_path, "line": line_no, "type": "hardcoded_secret",
                "rule_id": "SEC-ASSIGN", "severity": "medium",
                "description": "Possible hardcoded credential in an assignment.",
                # Redact the quoted value, keep the variable name for context.
                "snippet": re.sub(r"""(["'])[^"']{8,}\1""", r"\1***\1", line.strip())[:200],
                "recommendation": "Do not hardcode credentials; load them from the environment or a secret manager.",
            })
    return findings


def _scan_lang_rules(rel_path: str, lines: list[str]) -> list[dict[str, Any]]:
    """Shell / JavaScript dangerous-construct detection."""
    findings: list[dict[str, Any]] = []
    for line_no, line in enumerate(lines, 1):
        if len(line) > MAX_SCAN_LINE:
            continue
        for rule in _LANG_RULES:
            if rule.regex.search(line):
                findings.append({
                    "file": rel_path, "line": line_no, "type": "dangerous_code_execution",
                    "rule_id": rule.id, "severity": rule.severity, "description": rule.description,
                    "snippet": line.strip()[:200],
                    "recommendation": "Review for untrusted input; avoid shelling out or dynamic execution.",
                })
    return findings


def _scan_supply_chain(filepath: Path, rel_path: str, lines: list[str]) -> list[dict[str, Any]]:
    """Filename-aware supply-chain checks for dependency and build files."""
    findings: list[dict[str, Any]] = []
    name = filepath.name.lower()

    def add(line_no: int, rule_id: str, severity: str, desc: str, snippet: str) -> None:
        findings.append({
            "file": rel_path, "line": line_no, "type": "supply_chain_risk",
            "rule_id": rule_id, "severity": severity, "description": desc,
            "snippet": snippet[:200],
            "recommendation": "Pin dependencies to trusted, hash/version-locked releases; avoid installing from arbitrary URLs.",
        })

    if name.startswith("requirements") and name.endswith(".txt"):
        for line_no, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            low = line.lower()
            if low.startswith(("http://", "https://", "git+", "-e ")) or "git+" in low:
                add(line_no, "SC-REQ-URL", "medium",
                    "Dependency installed from a URL/VCS rather than a pinned package.", line)
            elif not line.startswith("-") and not re.search(r"==|@|/", line):
                add(line_no, "SC-REQ-UNPINNED", "low",
                    "Unpinned dependency (no exact == version).", line)
    elif name == "dockerfile" or name.endswith(".dockerfile"):
        for line_no, raw in enumerate(lines, 1):
            line = raw.strip()
            if re.search(r"(?:curl|wget)\s[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)", line, re.IGNORECASE):
                add(line_no, "SC-DOCKER-PIPE", "high",
                    "Dockerfile pipes a download straight into a shell.", line)
            if re.search(r"--(?:no-check-certificate|trusted-host|insecure)\b", line, re.IGNORECASE):
                add(line_no, "SC-DOCKER-INSECURE", "medium",
                    "Dockerfile disables TLS certificate verification.", line)
    return findings


def scan_single_file(filepath: Path, rules: list[Rule],
                     base: Path | None = None) -> list[dict[str, Any]]:
    """Scan one file using the provided detection rules."""
    findings: list[dict[str, Any]] = []
    rel_path = _display_path(filepath, base)
    try:
        if filepath.stat().st_size > MAX_FILE_BYTES:
            findings.append({
                "file": rel_path,
                "line": 0,
                "type": "skipped_large_file",
                "severity": "low",
                "description": f"File exceeds the {MAX_FILE_BYTES}-byte scan cap and was skipped.",
                "snippet": "",
                "recommendation": "Review large/binary blobs manually; they are not statically scanned."
            })
            return findings
    except OSError:
        pass
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
            alias_map = _build_alias_map(tree)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Resolve through import aliases so `from os import system`
                    # and `import subprocess as sp` cannot bypass detection.
                    func_name = _resolve_call_name(node.func, alias_map)
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
    # covered by the dedicated skill check below. Scanning is line-based and
    # skips very long (minified/data) lines so a single crafted line cannot
    # drive pathological regex backtracking.
    _entropy_re = re.compile(r'["\']([A-Za-z0-9+/=_-]{30,})["\']')
    if not is_prose:
        for line_no, line in enumerate(lines, 1):
            if len(line) > MAX_SCAN_LINE:
                continue
            for rule in rules:
                if rule.regex.search(line):
                    findings.append({
                        "file": rel_path,
                        "line": line_no,
                        "type": "suspicious_pattern",
                        "rule_id": rule.id,
                        "severity": rule.severity,
                        "description": rule.description,
                        "snippet": line.strip()[:200],
                        "recommendation": "Inspect data flow to network or secret sinks. Block untrusted patterns."
                    })

            # High entropy detection
            for m in _entropy_re.finditer(line):
                candidate = m.group(1)
                entropy = calculate_shannon_entropy(candidate)
                if entropy > 4.8:
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
        hit = None
        for marker in injection_markers:
            hit = re.search(marker, content, re.IGNORECASE)
            if hit:
                break
        if hit:
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

    # Always-on checks, independent of the active rule set (built-in vs repo).
    findings.extend(_scan_secrets(rel_path, lines, is_code=not is_prose))
    if filepath.suffix.lower() in _CODE_LANG_SUFFIXES:
        findings.extend(_scan_lang_rules(rel_path, lines))
    findings.extend(_scan_supply_chain(filepath, rel_path, lines))

    # Collapse duplicate findings on the same line and type (multiple patterns
    # frequently match the same construct), keeping the highest severity. The
    # severity rank is looked up defensively so an unexpected value never crashes.
    deduped: dict[tuple[int, str], dict[str, Any]] = {}
    for f in findings:
        key = (f["line"], f["type"])
        existing = deduped.get(key)
        if existing is None or _SEVERITY_RANK.get(f["severity"], 0) > _SEVERITY_RANK.get(existing["severity"], 0):
            deduped[key] = f
    return list(deduped.values())
