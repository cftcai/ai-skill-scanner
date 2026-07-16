"""SARIF 2.1.0 serialization for GitHub code scanning."""
import hashlib
from typing import Any

from . import __version__
from .rules import _SARIF_LEVEL, RULE_DESCRIPTIONS


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
        rule_id = f.get("rule_id")
        if rule_id:
            message = f"[{rule_id}] {message}"
        snippet = f.get("snippet") or ""
        fingerprint = hashlib.sha1(
            f"{f.get('file','')}:{start_line}:{f['type']}:{rule_id or ''}:{snippet}".encode()
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

