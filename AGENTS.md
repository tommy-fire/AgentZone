# AGENTS.md — Rules for AI coding agents working on this repo

> **Read this first.** This file is the single source of truth for how any
> AI coding assistant (GitHub Copilot, Claude Code, Cursor, etc.) MUST
> behave when writing code, files, or commits to this repository. Human
> contributors: see `CONTRIBUTING.md` for the equivalent rules that apply
> to you.

---

## 1. Identity — commit as the repo owner

**ALL writes to GitHub must be authored by the repository owner.** Do NOT
commit under any agent name, AI service name, or generic "Agent" identity.
The commit author that appears on `github.com` must be the same person who
owns the repo.

### How to set identity

Before doing any commit in a fresh clone:

```bash
git config user.name  "tommy-fire"
git config user.email "tommy-fire@users.noreply.github.com"
```

(The GitHub-provided `users.noreply.github.com` address is intentional —
it links the commit to the owner's public profile without exposing their
real email.)

### Verify before pushing

```bash
git log --format='%h | %an <%ae>' -10
# All rows should show the repo owner.
```

---

## 2. Privacy — never commit personal, server, or user data

This repository is intended to be **publicly shareable**. Anything that
could identify the admin, the infrastructure, or any user MUST stay out of
the code, tests, fixtures, comments, docs, and commit messages.

### Never commit

| Category | Examples (DO NOT commit) | Safe substitute |
|---|---|---|
| Real domain names | `myserver.example`, `panel.company.io` | `example.com` |
| Real public IPv4 addresses | `185.123.45.67` | RFC 5737: `192.0.2.1`, `198.51.100.1`, `203.0.113.1` |
| Real email addresses | `admin@gmail.com` | `noreply@example.com`, GitHub noreply |
| Phone numbers | `+79001234567` | `+10000000000` |
| Telegram bot tokens | `123456789:AAH-...` | `0:test` (fixture) |
| SSH private keys | `-----BEGIN OPENSSH PRIVATE KEY-----` | NEVER commit |
| Passwords / secrets | any real value | environment variable only |
| Server hostnames | `vps-hetzner-01` | `controller`, `node-1`, `localhost` |
| Real Telegram user IDs | real `tg_id` | `0`, `123456789` (fixture) |
| `.env` with real values | `.env` with `BOT_TOKEN=...` | `.env.example` with placeholders |

### Allowed placeholders

- Domains: `example.com`, `example.org`, `example.net`, `localhost`.
- IPv4: RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
  RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), loopback (`127.0.0.0/8`).
- Email: `*@example.com`, `*@users.noreply.github.com`.

## 3. Automated guard: `scripts/check_no_pii.sh`

Run before every commit:

```bash
bash scripts/check_no_pii.sh --staged
```

CI (`.github/workflows/no-pii.yml`) runs the same guard on every push/PR.

## 4. If you discover leaked data already in the repo

1. **Stop.** Do not delete or rewrite the file blindly.
2. **Report to the owner** with file path, line number, the leaked value,
   and a suggested replacement.
3. **Wait for explicit approval** before committing a fix.

## 5. Quick checklist before every commit

- [ ] `git config user.name` / `user.email` show the repo owner.
- [ ] `bash scripts/check_no_pii.sh --staged` exits 0.
- [ ] No real domains, IPs, emails, phone numbers, bot tokens, SSH private
      keys, `.env` values, or real Telegram IDs appear in the diff.
- [ ] Commit message describes what the change does and why.
