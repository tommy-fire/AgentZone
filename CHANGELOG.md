# Changelog

## v1.0.0 — 2026-07-10

Initial stable public release.

### Highlights
- one-command installer for Ubuntu/Debian
- Telegram long-polling bot with a single-admin grant / list / revoke flow
- one Linux user and one SSH port per grant
- root-owned privileged helper with a narrow sudoers rule
- per-grant firewall open/close with UFW
- automatic expiry via timer, bot monitor, and kernel fallback
- repository PII guard and CI checks

### Hardening completed before release
- installer prevents password-only admin lockout
- grant ports are verified before success is reported
- same-day TTL grants no longer expire immediately
- grant keys are isolated to the grant port and cannot be reused on the admin SSH port
- helper uses a stable PATH for firewall tooling
- UFW/iptables readiness is validated during installation
- bot refresh flow ignores harmless Telegram "message is not modified" errors
- grant local sudo password policy raised to a 12-character minimum
- systemd bot unit keeps compatible hardening while preserving helper functionality
