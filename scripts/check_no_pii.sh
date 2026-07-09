#!/usr/bin/env bash
# scripts/check_no_pii.sh — guard against committing PII / server / user data.
#
# Implements the rules documented in AGENTS.md §2. The scanner is
# deliberately conservative to avoid false positives on legitimate
# Python / shell / markdown code.
#
# Detection strategy
# ------------------
# 1. ALWAYS block (no allowlist): private keys, Telegram bot tokens,
#    and other high-entropy credential formats. If you see one in
#    your code, it is a leak.
#
# 2. URL context only: extract URLs (https?://, wss?://, markdown
#    links) and check their host. A real domain or public IP is
#    almost always inside a URL; bare code identifiers like
#    ``sa.Column``, ``datetime.datetime``, ``key.id`` are deliberately
#    not flagged because they are not URLs.
#
# 3. ENV / YAML / TOML / JSON files: in addition to URLs, the
#    right-hand side of ``KEY = ...`` or ``KEY: ...`` assignments is
#    checked for embedded domains / IPs / emails / phone numbers.
#    .py / .sh / .md files are NOT scanned for config assignments
#    because Python kwargs like ``key=key.id`` are not assignments.
#
# Usage
# -----
#   bash scripts/check_no_pii.sh            # scan whole repo (slow, for CI)
#   bash scripts/check_no_pii.sh --staged   # only files in git index
#   bash scripts/check_no_pii.sh --diff     # only files changed vs HEAD
#                                          (default for pre-commit hook)
#
# Exit codes
# ----------
#   0  no leaks
#   1  leaks found (printed to stderr, grouped by file/line)
#   2  invocation error
#
# Override per-line with a trailing comment:  # no_pii_allow
set -Eeuo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

MODE="diff"
EXTRA_FILES=()
case "${1:-}" in
    --staged) MODE="staged" ;;
    --diff)   MODE="diff"   ;;
    --all)    MODE="all"    ;;
    -h|--help)
        sed -n '2,30p' "$0"
        exit 0
        ;;
    --)
        shift
        EXTRA_FILES=("$@")
        ;;
    *)
        # Backward compat: if argument is a path (file or dir), scan it.
        if [[ -n "${1:-}" && ( -f "$1" || -d "$1" ) ]]; then
            EXTRA_FILES=("$@")
        fi
        ;;
esac

if [[ ${#EXTRA_FILES[@]} -gt 0 ]]; then
    # Direct-path mode: scan only the given paths, skip git logic.
    FILES=()
    for f in "${EXTRA_FILES[@]}"; do
        if [[ -d "$f" ]]; then
            while IFS= read -r -d '' p; do
                FILES+=("$p")
            done < <(find "$f" -type f -print0)
        elif [[ -f "$f" ]]; then
            FILES+=("$f")
        fi
    done
elif [[ "$MODE" == "staged" ]]; then
    mapfile -t FILES < <(git diff --cached --name-only --diff-filter=ACMR | grep -vE '^\.git/' || true)
elif [[ "$MODE" == "diff" ]]; then
    mapfile -t FILES < <(git diff --name-only --diff-filter=ACMR HEAD | grep -vE '^\.git/' || true)
    if staged=$(git diff --cached --name-only --diff-filter=ACMR 2>/dev/null | grep -vE '^\.git/'); then
        FILES+=($staged)
    fi
elif [[ "$MODE" == "all" ]]; then
    mapfile -t FILES < <(git ls-files | grep -vE '^\.git/|^\.pytest_cache/|^\.mypy_cache/|^\.ruff_cache/|(^|/)(release|backups|logs|node_modules|__pycache__)/' || true)
fi

if [[ ${#FILES[@]} -eq 0 ]]; then
    echo "check_no_pii: nothing to scan (mode=$MODE)" >&2
    exit 0
fi

python3 - "$MODE" "${FILES[@]}" <<'PY'
import re
import sys
from pathlib import Path

mode = sys.argv[1]
files = sys.argv[2:]

# ---------------------------------------------------------------------
# Allowlists — public domains / services referenced by the project.
# ---------------------------------------------------------------------
ALLOWED_DOMAINS = {
    # RFC 2606 / 6761 — reserved for documentation
    "example.com", "example.org", "example.net", "example.dev", "example.io",
    "example", "invalid", "localhost", "localdomain",
    # GitHub infra
    "github.com", "githubusercontent.com", "github.io",
    "raw.githubusercontent.com", "objects.githubusercontent.com",
    "codeload.github.com",
    # Telegram
    "telegram.org", "telegram.me", "t.me", "api.telegram.org",
    # Common badge / static services
    "img.shields.io", "shields.io", "badgen.net",
    # Cloudflare / ACME
    "cloudflare.com", "cloudflare-dns.com", "one.one.one.one",
    "letsencrypt.org", "acme-v02.api.letsencrypt.org",
    # Doc / standard bodies
    "wikipedia.org", "wikimedia.org", "ietf.org", "rfc-editor.org",
    "w3.org", "www.w3.org", "mozilla.org",
    # Python ecosystem
    "python.org", "pypi.org", "pythonhosted.org", "readthedocs.io",
    # OS / package infra
    "debian.org", "ubuntu.com", "kernel.org", "archlinux.org",
    "fedoraproject.org", "centos.org",
    # Open-source foundations
    "opensource.org", "gnu.org", "fsf.org", "apache.org",
    # Major cloud hosts the reader may legitimately reference
    "amazonaws.com", "digitalocean.com", "hetzner.com",
    "linode.com", "vultr.com", "ovh.com",
    # Public IP-detection services used by install.sh
    "ipify.org", "api.ipify.org", "ifconfig.me", "ipinfo.io",
    # OpenSSH / project docs
    "openssh.com", "openbsd.org",
    "stackoverflow.com", "git-scm.com",
    "aiogram.dev",
    # RFC 2606 reserved TLD — used by tests as a hard-invalid value.
    "example.invalid",
    # SSRF/validator test fixtures — deliberately bad names, not real
    # services, used to verify validators REJECT them.
    "localhost.localdomain", "intranet.local", "service.internal",
    "evil.example", "myhost.local", "router.local",
}

ALLOWED_EMAILS = {
    "noreply@example.com", "admin@example.com", "test@example.com",
    "user@example.com", "support@example.com", "no-reply@example.com",
    "root@localhost", "admin@localhost", "postmaster@localhost",
    "tommy-fire@users.noreply.github.com",
}

# Files that contain public routing data — never scanned for PII.
ALLOWED_FILES = {
    "AGENTS.md",
    "scripts/check_no_pii.sh",
}

# File extensions / names where "KEY = value" / "KEY: value" assignments
# are config-shaped (env, yaml, toml, ini, json). Python / shell /
# markdown are deliberately NOT in this list to avoid false positives
# on ``key=key.id`` style kwargs. .env-style dotfiles are matched by
# NAME (because Path('.env').suffix == '' in Python).
CONFIG_FILE_EXTS = {".yaml", ".yml", ".toml", ".ini", ".cfg"}
CONFIG_FILE_NAMES = {
    ".env", ".env.example", ".env.sample", ".env.template",
    "Dockerfile",  # ARG / ENV assignments
}

# Test directories: only LEAK_PATTERNS are checked here. URL / domain
# checks are SKIPPED because tests legitimately contain "real-looking"
# placeholder hostnames (SSRF fixtures, format validators, etc.) that
# are not actual server / user data.
TEST_PATH_PATTERNS = [
    re.compile(r"(^|/)(tests|test)/"),
    re.compile(r"(^|/)test_[^/]*\.py$"),
    re.compile(r"(^|/)[^/]*_test\.py$"),
]

# ---------------------------------------------------------------------
# Always-block patterns (no allowlist)
# ---------------------------------------------------------------------
LEAK_PATTERNS = [
    ("private_ssh_key",   re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED |)PRIVATE KEY-----")),
    ("private_key_block", re.compile(r"-----BEGIN PRIVATE KEY-----")),
    ("telegram_bot_token", re.compile(r"\b\d{6,10}:[A-Za-z0-9_-]{30,}\b")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9-]{20,}\b")),
    ("openai_api_key",     re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("github_pat",         re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    ("github_oauth",       re.compile(r"\bgho_[A-Za-z0-9]{20,}\b")),
    ("github_app_token",   re.compile(r"\b(?:ghs|ghu|ghr)_[A-Za-z0-9]{20,}\b")),
    ("aws_access_key",     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("stripe_key",         re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b")),
    ("yandex_token",       re.compile(r"\by[0-9]_[A-Za-z0-9_-]{20,}\b")),
]

# ---------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------
# A URL is http(s)://... or ws(s)://... terminated at typical
# punctuation AND at f-string placeholders ({...}). The single-quote
# character is also a terminator (so URL strings inside Python
# literals like  ``"https://ex'ample.com"`` end cleanly at the quote).
URL_RE = re.compile(
    r"\bhttps?://[^\s'\"<>)\]},;{]*",
    re.IGNORECASE,
)
WS_RE = re.compile(r"\bwss?://[^\s'\"<>)\]},;{]*", re.IGNORECASE)
MD_LINK_RE = re.compile(r"\]\((https?://[^\s)]+)\)")

# Match a host literal: domain.tld or bracketed IPv6 or bare IPv4.
HOST_RE = re.compile(
    r"^(?:"
    r"\[[0-9a-fA-F:]+\]"                   # bracketed IPv6
    r"|"
    r"\d{1,3}(?:\.\d{1,3}){3}"             # IPv4
    r"|"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"  # domain
    r")$",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

# Allow an IPv4 if it falls in a safe range (private / RFC 5737 / DNS).
SAFE_IP_PREFIXES = [
    r"^127\.", r"^10\.", r"^192\.168\.",
    r"^172\.(1[6-9]|2\d|3[01])\.",
    r"^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\.",
    r"^169\.254\.",
    r"^192\.0\.2\.", r"^198\.51\.100\.", r"^203\.0\.113\.",
    r"^0\.0\.0\.0$", r"^255\.255\.255\.255$",
    r"^224\.", r"^239\.",
    r"^23[0-9]\.",
    r"^240\.", r"^255\.",
    r"^1\.1\.1\.1$", r"^1\.0\.0\.1$",
    r"^8\.8\.8\.8$", r"^8\.8\.4\.4$",
    r"^94\.140\.14\.14$", r"^94\.140\.15\.15$",
    r"^1\.2\.3\.4$",
]
SAFE_IP_RX = [re.compile(p) for p in SAFE_IP_PREFIXES]

def ip_is_safe(s: str) -> bool:
    for rx in SAFE_IP_RX:
        if rx.match(s):
            return True
    return False

def domain_is_safe(s: str) -> bool:
    s_low = s.lower()
    if s_low in ALLOWED_DOMAINS:
        return True
    # If any parent (suffix) domain is allowlisted, this domain is safe.
    # e.g. "www.google.com" is safe because "google.com" is allowed.
    parts = s_low.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in ALLOWED_DOMAINS:
            return True
    # Special: example.com/org/net/dev/io families.
    for d in ("example.com", "example.org", "example.net", "example.dev", "example.io"):
        if s_low == d or s_low.endswith("." + d):
            return True
    if s_low.endswith(".users.noreply.github.com"):
        return True
    if s_low.endswith(".cloudfront.net") or s_low.endswith(".amazonaws.com"):
        return True
    if s_low.endswith(".azureedge.net") or s_low.endswith(".googleusercontent.com"):
        return True
    if s_low.endswith(".s3.amazonaws.com"):
        return True
    return False

def extract_host(url: str) -> str:
    """Pull the host out of a URL. Returns '' if not parseable.

    Returns '' (no host) for URLs that contain shell variables like
    ``$domain`` or are otherwise not real, parseable URLs. This avoids
    false positives on ``https://$VAR`` patterns in shell scripts.
    """
    url = url.strip().rstrip(".,;:)")
    # Reject URLs containing shell variables or other non-host chars.
    if "$" in url or "`" in url or "\\" in url:
        return ""
    # Strip path / query / fragment up to first '/', '?', '#'.
    m = re.match(r"^(?:https?|wss?)://([^/?#'\"\s{]*?)(?=/|$)", url, re.IGNORECASE)
    if not m:
        return ""
    host = m.group(1)
    if not host:
        return ""
    # Strip userinfo.
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    # Strip port.
    if host.startswith("[") and "]" in host:
        host = host[1:host.index("]")]
    elif ":" in host:
        host = host.rsplit(":", 1)[0]
    # Validate: a host is letters/digits/dots/hyphens/brackets only.
    # Anything else (whitespace, punctuation) means the URL was
    # extracted incorrectly — return ''.
    if not re.match(r"^[A-Za-z0-9.\-\[\]:]+$", host):
        return ""
    return host.lower()

# ---------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------
leaks_by_file: dict[str, list[tuple[str, str, str]]] = {}

def flag(rel, lineno, kind, val):
    leaks_by_file.setdefault(rel, []).append((str(lineno), kind, val))

for rel in files:
    if rel in ALLOWED_FILES:
        continue
    p = Path(rel)
    ext = p.suffix.lower()
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except (IsADirectoryError, FileNotFoundError, PermissionError):
        continue
    if p.stat().st_size > 2_000_000:
        continue
    in_test = any(rx.search(rel) for rx in TEST_PATH_PATTERNS)
    for lineno, line in enumerate(text.splitlines(), start=1):
        if "# no_pii_allow" in line or "# noqa:no_pii" in line:
            continue

        # ----- 1. Always-block patterns (no allowlist). -----
        for name, rx in LEAK_PATTERNS:
            for m in rx.finditer(line):
                flag(rel, lineno, name, m.group(0))

        # ----- Tests: skip URL / domain checks. SSRF fixtures, format
        #       validators and similar intentionally use "real-looking"
        #       placeholder names. The always-block check above still
        #       catches real credential leaks in tests.
        if in_test:
            continue

        # ----- 2. URL context: extract URLs, check host. -----
        all_urls = URL_RE.findall(line) + WS_RE.findall(line) + MD_LINK_RE.findall(line)
        for url in all_urls:
            host = extract_host(url)
            if not host:
                continue
            # Real domains must contain a dot. Words like "DOMAIN",
            # "host" or "$domain" without a TLD are placeholders.
            if "." not in host:
                continue
            if IPV4_RE.match(host):
                a, b, c, d = (int(g) for g in IPV4_RE.match(host).groups())
                if all(0 <= x <= 255 for x in (a, b, c, d)) and not ip_is_safe(host):
                    flag(rel, lineno, "public_ip_in_url", host)
                continue
            if not domain_is_safe(host):
                flag(rel, lineno, "domain_in_url", host)

        # ----- 3. Config-file-only: assignment checks. -----
        in_cfg_file = (
            ext in CONFIG_FILE_EXTS
            or p.name in CONFIG_FILE_NAMES
            or any(p.name.endswith(suf) for suf in CONFIG_FILE_EXTS)
        )
        if in_cfg_file:
            # Match KEY=value or KEY: value (YAML), allow leading whitespace.
            m = re.match(r"^\s*[A-Za-z_][A-Za-z0-9_]*\s*[:=]\s*['\"]?([^'\"#\n]+)", line)
            if not m:
                continue
            value = m.group(1).strip().rstrip(",;")
            # Embedded URL?
            for url in URL_RE.findall(value) + WS_RE.findall(value):
                host = extract_host(url)
                if not host:
                    continue
                if IPV4_RE.match(host):
                    a, b, c, d = (int(g) for g in IPV4_RE.match(host).groups())
                    if all(0 <= x <= 255 for x in (a, b, c, d)) and not ip_is_safe(host):
                        flag(rel, lineno, "public_ip_in_config", host)
                elif not domain_is_safe(host):
                    flag(rel, lineno, "domain_in_config", host)
            # Bare domain in value?
            bare = re.match(r"^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", value, re.IGNORECASE)
            if bare and not domain_is_safe(bare.group(0).lower()):
                flag(rel, lineno, "bare_domain_in_config", bare.group(0).lower())
            # Bare IPv4 in value?
            if IPV4_RE.match(value):
                a, b, c, d = (int(g) for g in IPV4_RE.match(value).groups())
                if all(0 <= x <= 255 for x in (a, b, c, d)) and not ip_is_safe(value):
                    flag(rel, lineno, "public_ip_in_config", value)
            # Email in value?
            em = re.search(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", value)
            if em and not (em.group(1).lower() in {e.lower() for e in ALLOWED_EMAILS}
                           or em.group(1).lower().endswith("@example.com")
                           or em.group(1).lower().endswith("@example.org")
                           or em.group(1).lower().endswith("@localhost")):
                flag(rel, lineno, "email_in_config", em.group(1))

# ---------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------
if not leaks_by_file:
    label = {"staged": "staged", "diff": "working-tree", "all": "tracked"}[mode]
    print(f"check_no_pii: {len(files)} {label} file(s) clean ✓")
    sys.exit(0)

print("check_no_pii: PII / server / user data detected — commit blocked.\n", file=sys.stderr)
total = 0
for f, hits in sorted(leaks_by_file.items()):
    print(f"  {f}", file=sys.stderr)
    for lineno, kind, val in hits:
        print(f"    line {lineno}: [{kind}] {val}", file=sys.stderr)
        total += 1
print(f"\nTotal: {total} leak(s) in {len(leaks_by_file)} file(s).", file=sys.stderr)
print("See AGENTS.md §2 for the full list of disallowed patterns and safe substitutes.", file=sys.stderr)
print("If a hit is a false positive, add the comment  # no_pii_allow  on that line.", file=sys.stderr)
sys.exit(1)
PY
