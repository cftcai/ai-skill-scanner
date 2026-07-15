# ai-skill-scanner TODO

## Not Done
- Full --update-signatures flag implementation with git pull logic and manifest version comparison
- Inline schema validation function called on every signature load in scanner.py
- GitHub Actions OIDC workflow example for authenticated signature updates
- Bulk visibility script --make-public mode with automatic topic addition
- Repository topics on both repos (awaiting public visibility)
- GitHub release tagging and assets (signatures.tar.gz)
- Fine-grained UPDATE_TOKEN secret creation and usage in workflows
- Python regex performance benchmarks in documentation

## Partially Done
- Named groups and non-capturing explanation in signatures README (done)
- JSON schema documentation in signatures README (done)
- Obfuscation signature file with references array (done)
- Manifest updated with third file and version bump (done)
- Scanner README documents update model and flag (stub)
- validate-signatures workflow active (done)
- bulk_visibility.sh advanced version committed with error handling (done)
- Status table in conversation history (needs refinement in docs)

## Optimizations Recommended
- Compile all regex patterns once at module load instead of per file
- Add LRU cache for entropy calculations on repeated strings
- Use pathlib more consistently and avoid repeated Path() calls
- Add type hints and mypy in CI
- Containerize the updater script for air-gapped use

## Next Development Pass
1. Implement full --update-signatures and schema validation in scanner.py
2. Extend bulk_visibility.sh with --make-public and topic logic
3. Add OIDC example workflow
4. Create TODO.md (this file) and keep it updated
5. Tag v1.0.0 on both repos after public
6. Review and merge optimizations