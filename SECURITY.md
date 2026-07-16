# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

- Preferred: open a [GitHub private security advisory](https://github.com/cftcai/ai-skill-scanner/security/advisories/new).
- We aim to acknowledge reports within a few days and to ship a fix or mitigation as quickly as the severity warrants.

When reporting, please include: affected version/commit, a minimal reproduction, and the impact you observed.

## Scope

This project statically analyzes untrusted input. Security-relevant areas include:

- File handling of untrusted repositories (path traversal, symlink following, resource exhaustion).
- The signature-loading path (`--update-signatures`, client-side pin verification).
- Argument handling that reaches `git` or the shell.
- The CI/release workflows (injection, token scope, action pinning).

## Handling untrusted skills safely

The scanner performs **static** analysis and never executes scanned code. For defense in depth when scanning hostile repositories, run it inside the provided Docker image with a read-only mount:

```bash
docker run --rm --network none -v "$(pwd)/target:/scan:ro" ai-skill-scanner --path /scan
```

(Use `--network none` for local `--path` scans; `--github-url` needs network for the clone.)

## Supported versions

The latest release on `main` receives security fixes. Older versions are not maintained.
