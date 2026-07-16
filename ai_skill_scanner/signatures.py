"""Load detection rules from the ai-skill-signatures repo, verified against a
client-side pinned commit."""
import contextlib
import json
import re
import subprocess
from pathlib import Path

from .rules import BUILTIN_RULES, Rule

# Default cache location for signatures
SIGNATURES_CACHE = Path.home() / ".cache" / "ai-skill-signatures"
SIGNATURES_REPO = "https://github.com/cftcai/ai-skill-signatures.git"

# Client-side pin (trust-on-first-use): the ai-skill-signatures commit this
# scanner build trusts. Fetched rules are only used when the cloned HEAD matches
# this SHA, so a tampered or unexpectedly-changed upstream cannot silently inject
# rules. This must be pinned by the scanner (not read from the signatures repo),
# because a repo an attacker controls could otherwise vouch for itself. Bump it
# with `--update-signatures` after reviewing the fetched changes.
PINNED_SIGNATURES_SHA = "695e7df419656cafc768936ba2d697fc8095ddfe"

def _git_head(repo: Path) -> str | None:
    """Return the current HEAD commit SHA of a git repo, or None on failure."""
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True, timeout=15
        ).strip()
    except (subprocess.SubprocessError, OSError):
        return None

def load_signatures_from_repo(pinned_sha: str | None = PINNED_SIGNATURES_SHA,
                              allow_unpinned: bool = False) -> list[Rule]:
    """Load and compile detection rules from the ai-skill-signatures repository.

    Verifies the fetched HEAD against a client-side pinned commit SHA. Fetched
    rules are used only on a match; otherwise the built-in rules are used. Each
    returned Rule keeps its id/severity/description for the report.
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
            # A failed update (e.g. offline) is non-fatal: fall through to verify
            # and use the already-cached copy rather than dropping all rules.
            try:
                subprocess.run(
                    ["git", "-C", str(SIGNATURES_CACHE), "pull", "--ff-only"],
                    check=True, timeout=30, capture_output=True
                )
            except (subprocess.SubprocessError, OSError):
                print("WARNING: could not update signatures (offline?); using the cached copy.")

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
            return BUILTIN_RULES

        # Reset the working tree to the trusted commit so a locally-modified
        # cache (files changed without moving HEAD) cannot inject rules.
        # HEAD is already verified above; the checkout is defense-in-depth.
        if pin_active and not allow_unpinned:
            with contextlib.suppress(subprocess.SubprocessError, OSError):
                subprocess.run(
                    ["git", "-C", str(SIGNATURES_CACHE), "checkout", "--force", str(pinned_sha)],
                    check=True, timeout=30, capture_output=True
                )

        manifest_path = SIGNATURES_CACHE / "manifest.json"
        if not manifest_path.exists():
            print("WARNING: manifest.json not found. Using fallback patterns.")
            return BUILTIN_RULES

        manifest = json.loads(manifest_path.read_text())

        rules: list[Rule] = []
        for sig_file in manifest.get("signatures", []):
            sig_path = SIGNATURES_CACHE / sig_file
            if not sig_path.exists():
                continue
            try:
                for entry in json.loads(sig_path.read_text()):
                    pattern_str = entry.get("pattern", "")
                    if not pattern_str:
                        continue
                    flags = re.IGNORECASE if entry.get("ignorecase", True) else 0
                    rules.append(Rule(
                        re.compile(pattern_str, flags),
                        entry.get("id", "SIG"),
                        entry.get("severity", "medium"),
                        entry.get("description", "Signature match."),
                    ))
            except Exception as e:
                print(f"WARNING: Failed to load {sig_file}: {e}")

        if rules:
            print(f"Loaded {len(rules)} signature rules from ai-skill-signatures repo.")
            return rules
        return BUILTIN_RULES

    except Exception as e:
        print(f"WARNING: Could not load signatures ({e}). Using fallback patterns.")
        return BUILTIN_RULES
