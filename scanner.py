#!/usr/bin/env python3
"""Backward-compatible facade for ai-skill-scanner.

The implementation now lives in the ``ai_skill_scanner`` package. This module is
kept so that ``import scanner``, ``python scanner.py``, and the ``scanner:main``
entry point continue to work unchanged.
"""
import subprocess  # noqa: F401  (re-exported for tests that patch scanner.subprocess)

from ai_skill_scanner import __version__
from ai_skill_scanner.cli import main
from ai_skill_scanner.entropy import calculate_shannon_entropy
from ai_skill_scanner.rules import (
    BUILTIN_RULES,
    DANGEROUS_FUNCS,
    MAX_FILE_BYTES,
    MAX_SCAN_LINE,
    Rule,
)
from ai_skill_scanner.sarif import to_sarif
from ai_skill_scanner.scanning import _display_path, scan_single_file
from ai_skill_scanner.signatures import (
    PINNED_SIGNATURES_SHA,
    SIGNATURES_CACHE,
    SIGNATURES_REPO,
    _git_head,
    load_signatures_from_repo,
)

__all__ = [
    "__version__",
    "main",
    "calculate_shannon_entropy",
    "BUILTIN_RULES",
    "DANGEROUS_FUNCS",
    "MAX_FILE_BYTES",
    "MAX_SCAN_LINE",
    "Rule",
    "to_sarif",
    "_display_path",
    "scan_single_file",
    "PINNED_SIGNATURES_SHA",
    "SIGNATURES_CACHE",
    "SIGNATURES_REPO",
    "_git_head",
    "load_signatures_from_repo",
]

if __name__ == "__main__":
    main()
