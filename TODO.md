# ai-skill-scanner TODO

## Completed (2026-07-16)
- fix(scanner): single-file `--path` targets are now scanned (os.walk over a file scanned nothing) (#1)
- fix(ci): unit tests now run in CI (pytest step) so detection regressions surface (#1)
- fix(scanner): reduced false positives — prose/config files skip code heuristics, benign-host allowlist, bare URLs downgraded, per-line dedup, imperative-only injection markers (#2)
- feat(scanner): SARIF 2.1.0 output via `--format sarif`; CI validates + publishes the SARIF artifact, with a documented `upload-sarif` step for downstream code scanning (#3)
- fix(scanner): findings now use repo-relative paths (no absolute host-path leak)
- chore: single `__version__` source (1.2.0), aligned across CLI and report
- feat(scanner): client-side signature pinning replaces the placebo manifest SHA check — fetched rules are trusted only when HEAD matches `PINNED_SIGNATURES_SHA`; adds `--signatures-sha`, `--allow-unpinned`, and `--update-signatures` re-pin reporting (#4)

## Completed (2026-07-15)
- feat(workflow): scan-url.yml added for lightweight web backend (workflow_dispatch with url input)
- GitHub Actions section reorganized; web frontend UX improved

## Completed (2026-07-16, hardening + detection round)
- harden(scanner): reject non-URL `--github-url` + `--` separator (git arg-injection); 2 MiB file cap + per-line length guard (ReDoS/OOM) (#7, #8)
- feat(scanner): import-alias resolution so `from os import system` / `import subprocess as sp` cannot bypass AST detection (#10)
- feat(scanner): rules are `(regex, id, severity, description)`; findings and SARIF now cite the rule id and use curated severities (#11)

## In Progress / Next
- Deeper detection: taint tracking to cut dual-use (env/subprocess) noise
- Automate the signature re-pin (CI opens a PR bumping `PINNED_SIGNATURES_SHA` when ai-skill-signatures main advances)

## Not Done
- Make repositories public + add topics (use bulk script --make-public after validation)
- Add secret scanning / dependency review to CI
- Publish as PyPI package + hosted demo

## Recommended Strategy
Short-term: Finish scanner flag + schema validation and test the scan-url workflow end-to-end.
Medium-term: Add real dispatch button or API call from web demo.
Long-term: Decide on public hosting and packaging.