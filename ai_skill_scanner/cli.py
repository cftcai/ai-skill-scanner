"""Command-line interface."""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .rules import BUILTIN_RULES
from .sarif import to_sarif
from .scanning import scan_single_file
from .signatures import (
    PINNED_SIGNATURES_SHA,
    SIGNATURES_CACHE,
    _git_head,
    load_signatures_from_repo,
)


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
        # Reject anything that is not a recognized remote URL. This blocks
        # argument injection (a value like "--upload-pack=..." that git would
        # treat as an option) and local-path scanning via --github-url.
        if not (re.match(r"^(https?|git|ssh)://", args.github_url)
                or re.match(r"^[A-Za-z0-9._-]+@[^/]+:", args.github_url)):
            print("ERROR: --github-url must be an https://, http://, git://, "
                  "ssh://, or user@host:path URL.")
            sys.exit(2)
        target_dir = tempfile.mkdtemp(prefix="skillscan_")
        cleanup = True
        print(f"Cloning repository {args.github_url} (depth 1)...")
        try:
            # "--" ensures the URL is never parsed as a git option even if
            # validation is ever loosened.
            subprocess.run(
                ["git", "clone", "--depth", "1", "--quiet", "--", args.github_url, target_dir],
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
        return (filename.endswith((".py", ".md", ".markdown", ".txt", ".yaml", ".yml",
                                   ".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".sh", ".bash")) or
                "SKILL" in filename.upper() or
                filename.lower() == "dockerfile" or
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
            # Do not descend symlinked directories (os.walk default), and skip
            # symlinked files entirely: following a symlink such as
            # `SKILL.md -> /etc/passwd` in an untrusted repo would read and
            # report the contents of arbitrary local files.
            dirnames[:] = [
                d for d in dirnames
                if d not in skip_dirs and not (Path(dirpath) / d).is_symlink()
            ]
            for filename in filenames:
                fpath = Path(dirpath) / filename
                if fpath.is_symlink():
                    continue
                if _should_scan(filename):
                    files_to_scan.append(fpath)

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
        "target": args.github_url or args.path,
        "scan_timestamp_utc": datetime.now(UTC).isoformat(),
        "total_findings": len(all_findings),
        "high_severity": high_sev,
        "medium_severity": medium_sev,
        "low_severity": len(all_findings) - high_sev - medium_sev,
        "findings": all_findings,
        "signatures_source": "fallback hardcoded" if active_patterns is BUILTIN_RULES else "ai-skill-signatures repo"
    }

    output_path = Path(args.output).resolve()
    document = to_sarif(report) if args.format == "sarif" else report
    output_path.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Scan finished. {len(all_findings)} findings ({high_sev} high, {medium_sev} medium).")
    print(f"Report ({args.format}) written to {output_path}")

    if cleanup and target_dir:
        shutil.rmtree(target_dir, ignore_errors=True)
