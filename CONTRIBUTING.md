# Contributing

Thank you for your interest in AgentZone.

## Identity — commit as the repo owner

All commits and pull requests must be authored by the repository owner.
Do not commit under an agent/AI-service identity. See `AGENTS.md` §1.

## Privacy — never commit personal, server, or user data

This repository is intended to be publicly shareable. See `AGENTS.md` §2
for the full list of forbidden data and safe substitutes. Run
`bash scripts/check_no_pii.sh --staged` before every commit (or install it
as a pre-commit hook with `bash scripts/install-git-hooks.sh`).

## Development setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

Tests do not require root or a real Ubuntu box: the privileged helper
script (`app/scripts/agentzone_helper.sh`) is checked statically (syntax
+ security invariants), and the Python service layer is unit-tested with
the helper mocked out.

## Pull requests

- Keep changes focused; explain the "why", not just the "what".
- Add or update tests for any behavior change.
- Run `bash scripts/check_no_pii.sh --staged` before opening the PR.
