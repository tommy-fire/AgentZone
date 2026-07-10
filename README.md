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
| Open-ended access | TTL in minutes (or "until revoked"), enforced three independent ways — see [Security](SECURITY.md). |
| Discoverability | No domain, no web server, no webhook. The bot only uses Telegram long polling. The server IP is sent to the admin in a private message, never logged or exposed. |
| Port scanning | Every grant gets its **own SSH port**, opened only while the grant is active. Nothing listens on it, and nothing references it in `sshd_config`, otherwise. |
| Leaked key ⇒ root | SSH is public-key only; the grant's password is a **local-only** secret used solely for `sudo`, never a valid network login method. |

Full design rationale: [`SECURITY.md`](SECURITY.md).

## Install

Fresh Ubuntu 22.04+/Debian 12+ server, run as root:

```bash
apt-get update && apt-get install -y git
git clone <this-repo-url> agentzone
cd agentzone
sudo bash install.sh
```

You'll be asked for:

1. **Telegram bot token** (from [@BotFather](https://t.me/BotFather)).
2. **Your Telegram numeric ID** — the single admin who can use the bot.
3. **The SSH port you're currently connected on** — so the installer
   knows which port to keep open for you; it never touches this port.

The public IP is auto-detected. No domain is ever requested — AgentZone
has no reason to run anything a domain would front.

The installer then:

- Installs the bot as `agentzone-bot.service` (systemd, auto-restart).
- Installs `agentzone-helper` as a **root-owned**, narrowly-scoped script
  the bot can invoke via a single sudoers rule — the bot process itself
  never runs as root.
- Hardens sshd (key-only auth, no root login).
- Enables UFW, opening only your current admin SSH port.
- Installs a systemd timer that sweeps expired grants every minute.

## Use

Open a chat with your bot and send `/start`. From the menu:

1. **Grant access** — enter a username, the agent's SSH public key, a
   password (used only for local `sudo`, not for SSH login), and a TTL.
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
app/bot/            aiogram bot: handlers, keyboards, config
app/bot/services/   grants.py (helper wrapper), expiry_monitor.py
app/scripts/        agentzone_helper.sh — the only privileged code
install.sh          one-command installer
tests/              unit tests + static checks on install.sh / helper.sh
```

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

MIT — see [`LICENSE`](LICENSE).
