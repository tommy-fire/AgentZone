#!/usr/bin/env bash
# scripts/install-git-hooks.sh — install the PII guard as a git pre-commit hook.
#
# This installs .git/hooks/pre-commit so the guard runs automatically
# on every commit. Operators may bypass it with `git commit --no-verify`
# — but the rule in AGENTS.md §1 says "bypass with --no-verify only if
# you have an explicit reason, and document the reason in the commit
# message body".
#
# Re-run this script to update the hook after the guard script changes.
set -Eeuo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO_ROOT" ]]; then
    echo "error: not inside a git repository" >&2
    exit 1
fi

HOOK="$REPO_ROOT/.git/hooks/pre-commit"
GUARD="$REPO_ROOT/scripts/check_no_pii.sh"

if [[ ! -x "$GUARD" ]]; then
    echo "error: $GUARD is missing or not executable" >&2
    exit 1
fi

cat > "$HOOK" <<EOF
#!/usr/bin/env bash
# Auto-installed by scripts/install-git-hooks.sh — runs the PII guard
# before every commit. See AGENTS.md for the rules.
#
# --staged scans ONLY the files in the next commit (after git add).
# Run `git add` before `git commit` so the guard sees the change.
set -e
exec bash "$GUARD" --staged
EOF
chmod +x "$HOOK"

echo "Installed: $HOOK"
echo "  runs: bash $GUARD --staged  (scans files in the next commit)"
echo "  bypass: git commit --no-verify  (document the reason in the commit body)"
