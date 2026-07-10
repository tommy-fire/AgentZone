# Security policy

## Design goals

AgentZone exists to grant an AI agent (or any third party) temporary,
tightly-scoped SSH access to a server, and to guarantee that access is
fully and verifiably gone the moment it is revoked. See the header comment
in `app/scripts/agentzone_helper.sh` for the exact mechanisms; summary:

- **Public-key SSH only.** `PasswordAuthentication no` is set globally by
  `install.sh`. The password an admin sets for a grant is a local
  credential used only for `sudo` on the box — it is never a valid SSH
  login method, so it cannot be brute-forced over the network.
- **One port per grant.** Every grant gets its own TCP port, opened in the
  firewall and bound to exactly one Linux user via sshd's
  `Match LocalPort <port>` + `AllowUsers`. No port is listed in sshd
  config, and no port is open in the firewall, unless a grant for it is
  currently active. There is nothing for a port scan to find outside an
  active grant's window.
- **No NOPASSWD sudo.** A leaked SSH key alone is never enough to reach
  root — the grant's password is still required for `sudo`.
- **Defense in depth on expiry.** A grant's TTL is enforced three separate
  ways: a systemd timer calling `agentzone-helper expire-check` every
  minute, an in-process monitor loop inside the bot, and the kernel's own
  `chage -E` account-expiry date as a coarse day-granularity fallback.
  (`chage` on Ubuntu/Debian expires the account at the start of the chosen
  day, so AgentZone deliberately sets it to the day *after* the exact TTL
  deadline to avoid locking a same-day grant out early.) Any one of the
  three timer/monitor layers failing does not leave the grant active.
- **No public attack surface beyond SSH.** The bot uses Telegram long
  polling only — no webhook, no HTTP server, no web panel. The server's
  public IP is only ever sent to the admin in a private Telegram message.
- **Revocation is destructive by design.** Revoking a grant removes the
  sshd config block, the firewall rule, the sudoers file, kills all of
  that user's active sessions, deletes the Linux account and its home
  directory, and best-effort scrubs `wtmp`/`btmp`/`lastlog` entries for
  that username. journald is append-only and cannot be selectively edited
  without corrupting it; `agentzone-helper purge-journal` is provided as
  an explicit, separate, admin-triggered action for when a full journal
  wipe is genuinely wanted.

## Repository hygiene — no personal / server / user data

All code, configuration, documentation, tests, fixtures, and commit
messages in this repository must be free of real personal, server, or
user data. See `AGENTS.md` for the full list of disallowed patterns and
the safe placeholders to use instead. Enforced by
`scripts/check_no_pii.sh` and `.github/workflows/no-pii.yml`.

## Reporting a vulnerability

Please do not publish security issues publicly before the maintainer has
had a chance to respond. Report privately through the contact method
listed on the repository owner's GitHub profile. Include: affected
version, steps to reproduce, expected impact, and logs with secrets
removed.
