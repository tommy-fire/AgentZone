# AgentZone

A tiny, self-hosted Telegram bot that grants and revokes **temporary SSH
access** to a server — built for handing a scoped, time-boxed shell to an
AI coding agent without leaving anything behind once the work is done.

One admin. One job. No database, no web panel, no webhook — just a bot
that talks to a small root-owned helper script.

## Why

Giving an AI agent SSH access to a real server is useful, but "useful"
and "safe" pull in different directions:

- You don't want to hand out your own key or a shared account.
- You don't want a forgotten grant to sit open forever.
- You don't want the box's IP or any of this to be discoverable from the
  open internet.
- You don't want a leaked key to be enough, by itself, to reach root.

AgentZone's answer to each of those:

| Concern | Mechanism |
|---|---|
| Shared/forgotten credentials | Every grant creates its own Linux user, its own SSH key, its own password. |
| Open-ended access | TTL in minutes (or "until revoked"), enforced by a minute-level timer + bot monitor, plus a coarse day-granularity kernel fallback (`chage -E`) — see [Security](SECURITY.md). |
| Discoverability | No domain, no web server, no webhook. The bot only uses Telegram long polling. The server IP is sent to the admin in a private message, never logged or exposed. |
| Port scanning / admin-port crossover | Every grant gets its **own SSH port**, opened only while the grant is active. The grant key is enabled only on that port; the same agent account cannot authenticate on the normal admin SSH port. |
| Leaked key ⇒ root | SSH is public-key only; the grant's password is a **local-only** secret used solely for `sudo`, never a valid network login method. |

Full design rationale: [`SECURITY.md`](SECURITY.md).

## Install

Fresh Ubuntu 22.04+/Debian 12+ server, run as root:

```bash
apt-get update && apt-get install -y git
git clone https://github.com/tommy-fire/AgentZone.git agentzone
cd agentzone
sudo bash install.sh
```

You'll be asked for:

1. **Telegram bot token** (from [@BotFather](https://t.me/BotFather)).
2. **Your Telegram numeric ID** — the single admin who can use the bot.
3. **The SSH port you're currently connected on** — so the installer
   knows which port to keep open for you; it never touches this port.
4. **Your admin SSH public key** *only if* the current admin user does not
   already have an existing `authorized_keys` entry. The installer refuses
   to disable password SSH logins until it has confirmed a key-based admin
   path back in, preventing accidental lockout on a fresh password-only box.

The public IP is auto-detected. If your server image does not have `curl`
yet, the installer bootstraps it first. If auto-detection still fails, the
installer asks for the IPv4 manually (or, in non-interactive mode, you can
set `AGENTZONE_SERVER_IP`). No domain is ever requested — AgentZone has no
reason to run anything a domain would front.

For automated provisioning / cloud-init, a fully non-interactive install
looks like this:

```bash
sudo AGENTZONE_NONINTERACTIVE=true \
  AGENTZONE_BOT_TOKEN='123456789:replace-me' \
  AGENTZONE_ADMIN_ID='123456789' \
  AGENTZONE_SSH_ADMIN_PORT='22' \
  AGENTZONE_SERVER_IP='203.0.113.10' \
  AGENTZONE_ADMIN_SSH_PUBLIC_KEY='ssh-ed25519 AAAA... admin@laptop' \
  bash install.sh
```

The installer then:

- Installs the bot as `agentzone-bot.service` (systemd, auto-restart,
  with compatible systemd hardening that does not break the privileged helper path).
- Installs `agentzone-helper` as a **root-owned**, narrowly-scoped script
  the bot can invoke via a single sudoers rule — the bot process itself
  never runs as root.
- Hardens sshd (key-only SSH, password auth disabled globally, root password login disabled).
- Enables UFW, opening only your current admin SSH port.
- Installs a systemd timer that sweeps expired grants every minute.

## Use

Open a chat with your bot and send `/start`. From the menu:

1. **Grant access** — enter a lowercase Linux username, the agent's SSH
   public key, a password (used only for local `sudo`, not for SSH login;
   minimum 12 characters), and a TTL.
2. The bot creates the account and replies with a ready-to-use
   `ssh -p <port> <user>@<ip>` command — sent only to you.
3. **Active grants** — see remaining time, revoke individually, or revoke
   everything at once.

Revoking a grant deletes the Linux account, its home directory, its
sshd/firewall rules, kills its active sessions, and scrubs its login
traces from `wtmp`/`btmp`/`lastlog`. See [`SECURITY.md`](SECURITY.md) for
exactly what is (and isn't) cleaned up, and why.

## Repository layout

```
app/agentzone/      Python package: config, handlers, messages, helper bridge
app/scripts/        agentzone_helper.sh — the only privileged code
install.sh          one-command installer
scripts/            repo hygiene helpers (PII guard, git hooks)
tests/              unit tests + static checks on install.sh / helper.sh
```

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pytest
```

If you prefer the old-style requirements workflow, `requirements.txt` and
`requirements-dev.txt` are still kept in sync.

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT — see [`LICENSE`](LICENSE).
