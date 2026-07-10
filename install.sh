#!/usr/bin/env bash
set -Eeuo pipefail

# AgentZone one-command installer for Ubuntu 22.04+ / Debian 12+.
# Run from the repo root: sudo bash install.sh

APP_NAME="agentzone"
APP_USER="agentzone"
APP_DIR="/opt/agentzone"
BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_SRC="$BUNDLE_DIR/app"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[1;34m'; NC='\033[0m'
log(){ echo -e "${BLUE}[+]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }
fail(){ echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Run as root: sudo bash install.sh"
[[ -d "$APP_SRC" ]] || fail "Bundle app directory not found: $APP_SRC"

if [[ -r /etc/os-release ]]; then . /etc/os-release; fi
[[ "${ID:-}" == "ubuntu" || "${ID_LIKE:-}" == *"debian"* ]] || warn "Installer was tested on Ubuntu/Debian; current OS: ${PRETTY_NAME:-unknown}"

# ---------------------------------------------------------------------------
# Input validation — every value that ends up inside a heredoc/config file
# must be checked first, or a malicious/typo'd value could break out of its
# intended context (shell injection via unquoted heredocs, sshd_config
# directive injection, etc).
# ---------------------------------------------------------------------------
validate_bot_token(){
  local value="$1" left right
  [[ "$value" =~ [[:space:]] ]] && fail "Invalid BOT_TOKEN format (must not contain spaces)"
  left="${value%%:*}"
  right="${value#*:}"
  [[ "$value" == *:* && "$left" =~ ^[0-9]+$ && -n "$right" && "$right" =~ ^[A-Za-z0-9_-]+$ ]] \
    || fail "Invalid BOT_TOKEN format (expected '<numeric-id>:<token>')"
}

validate_admin_id(){
  local value="$1"
  [[ "$value" =~ ^[0-9]{1,15}$ ]] || fail "Invalid ADMIN_ID: $value (must be a bare Telegram numeric ID)"
}

validate_port_range(){
  local start="$1" end="$2"
  [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]] || fail "Port range must be numeric"
  [[ "$start" -ge 1024 && "$end" -le 65535 && "$start" -lt "$end" ]] || fail "Invalid port range: $start-$end"
}

validate_ipv4(){
  local value="$1" o1 o2 o3 o4 octet
  [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "Invalid IPv4: $value"
  IFS='.' read -r o1 o2 o3 o4 <<< "$value"
  for octet in "$o1" "$o2" "$o3" "$o4"; do
    [[ "$octet" =~ ^[0-9]{1,3}$ && "$octet" -ge 0 && "$octet" -le 255 ]] || fail "Invalid IPv4: $value"
  done
}

ensure_bootstrap_command(){
  local bin="$1" package="$2"
  command -v "$bin" >/dev/null 2>&1 && return 0
  log "Bootstrapping missing command '$bin' via apt ($package)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq "$package" >/dev/null
  command -v "$bin" >/dev/null 2>&1 || fail "Required bootstrap command '$bin' is unavailable even after installing package '$package'"
}

echo
log "AgentZone installer"
echo

AGENTZONE_NONINTERACTIVE="${AGENTZONE_NONINTERACTIVE:-false}"
if [[ "$AGENTZONE_NONINTERACTIVE" =~ ^([Tt]rue|1|[Yy]es)$ ]]; then
  BOT_TOKEN="${AGENTZONE_BOT_TOKEN:-}"
  ADMIN_ID="${AGENTZONE_ADMIN_ID:-}"
  SSH_ADMIN_PORT="${AGENTZONE_SSH_ADMIN_PORT:-22}"
  SERVER_IP="${AGENTZONE_SERVER_IP:-}"
  [[ -n "$BOT_TOKEN" ]] || fail "AGENTZONE_BOT_TOKEN is required"
  [[ -n "$ADMIN_ID" ]] || fail "AGENTZONE_ADMIN_ID is required"
else
  read -rp "Telegram BOT_TOKEN: " BOT_TOKEN
  [[ -n "$BOT_TOKEN" ]] || fail "BOT_TOKEN is required"
  read -rp "Your Telegram numeric ID (ADMIN_ID): " ADMIN_ID
  [[ -n "$ADMIN_ID" ]] || fail "ADMIN_ID is required"
  read -rp "Current SSH port used for THIS admin session [22]: " SSH_ADMIN_PORT
  SSH_ADMIN_PORT="${SSH_ADMIN_PORT:-22}"
fi
validate_bot_token "$BOT_TOKEN"
validate_admin_id "$ADMIN_ID"
[[ "$SSH_ADMIN_PORT" =~ ^[0-9]+$ ]] && [ "$SSH_ADMIN_PORT" -ge 1 ] && [ "$SSH_ADMIN_PORT" -le 65535 ] || fail "Invalid SSH port: $SSH_ADMIN_PORT"

PORT_RANGE_START="20000"
PORT_RANGE_END="20100"
validate_port_range "$PORT_RANGE_START" "$PORT_RANGE_END"

if [[ -n "${SERVER_IP:-}" ]]; then
  validate_ipv4 "$SERVER_IP"
  log "Using public IP from AGENTZONE_SERVER_IP"
else
  ensure_bootstrap_command curl curl
  log "Detecting public server IP"
  SERVER_IP="$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || curl -4fsS --max-time 5 https://ifconfig.me/ip 2>/dev/null || true)"
  if [[ -z "$SERVER_IP" ]]; then
    if [[ "$AGENTZONE_NONINTERACTIVE" =~ ^([Tt]rue|1|[Yy]es)$ ]]; then
      fail "Could not auto-detect the public IP. Set AGENTZONE_SERVER_IP and re-run."
    fi
    warn "Could not auto-detect the public IP. Enter it manually."
    read -rp "Public server IPv4: " SERVER_IP
  fi
  validate_ipv4 "$SERVER_IP"
fi
log "Public IP: $SERVER_IP (shown only to you, in the bot's private chat)"

export DEBIAN_FRONTEND=noninteractive
log "Installing system packages"
apt-get update -qq
# rsync: used below to deploy app code. Not preinstalled on every minimal
#   cloud/server image (only "rsync" package on the desktop/server ISO,
#   not on the stripped-down cloud-init images many VPS providers ship).
# passwd: provides chpasswd/chage/useradd/userdel, all used by the
#   privileged helper when granting/revoking access.
# procps: provides pkill, used by the helper to kill a revoked user's
#   sessions. Normally part of Ubuntu's minimal base install already, but
#   listed explicitly so a stripped-down/custom image cannot silently
#   break grant/revoke.
apt-get install -y -qq python3 python3-venv python3-pip openssh-server ufw sudo curl util-linux openssl rsync passwd procps >/dev/null

# Some minimal cloud images ship the openssh-server package without ever
# enabling/starting its service. Make sure it is actually running before
# we start writing sshd_config.d drop-ins and testing them with `sshd -t`.
systemctl enable --now ssh.service 2>/dev/null || systemctl enable --now sshd.service 2>/dev/null || true

# Fail fast, with a clear message, if any required command is still
# missing after the apt-get install above (e.g. a custom/minimal image
# with restricted repositories) — instead of a confusing "No such file
# or directory" from whatever line happens to use it first.
for bin in rsync python3 useradd userdel chpasswd chage pkill ssh-keygen sshd ufw openssl visudo getent; do
  command -v "$bin" >/dev/null 2>&1 || fail "Required command '$bin' is still missing after package installation — check your APT sources/network and re-run."
done

id -u "$APP_USER" >/dev/null 2>&1 || useradd --system --create-home --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"

log "Deploying application code to $APP_DIR"
mkdir -p "$APP_DIR/config" "$APP_DIR/logs"
rsync -a --delete \
  --exclude 'venv' --exclude 'logs' --exclude 'config/.env' \
  "$APP_SRC/" "$APP_DIR/app/"

log "Installing the privileged helper (root-owned, not writable by $APP_USER)"
install -o root -g root -m 0750 "$APP_SRC/scripts/agentzone_helper.sh" /usr/local/sbin/agentzone-helper

log "Setting up Python virtualenv"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install -q --upgrade pip
"$APP_DIR/venv/bin/pip" install -q -r "$BUNDLE_DIR/requirements.txt"

log "Writing configuration"
cat > "$APP_DIR/config/.env" <<EOF
BOT_TOKEN=$BOT_TOKEN
ADMIN_ID=$ADMIN_ID
SERVER_IP=$SERVER_IP
AGENTZONE_PORT_RANGE_START=$PORT_RANGE_START
AGENTZONE_PORT_RANGE_END=$PORT_RANGE_END
AGENTZONE_HELPER_PATH=/usr/local/sbin/agentzone-helper
AGENTZONE_STATE_DIR=/var/lib/agentzone
EOF
chown "$APP_USER:$APP_USER" "$APP_DIR/config/.env"
chmod 0600 "$APP_DIR/config/.env"

log "Applying file permissions"
chown -R root:root "$APP_DIR/app"
find "$APP_DIR/app" -type d -exec chmod 0755 {} +
find "$APP_DIR/app" -type f -exec chmod 0644 {} +
chown -R "$APP_USER:$APP_USER" "$APP_DIR/logs"
chmod 0750 "$APP_DIR/logs"

install -d -m 0700 -o root -g root /var/lib/agentzone

log "Granting $APP_USER a narrow sudoers rule for the helper ONLY"
cat > /etc/sudoers.d/agentzone <<EOF
$APP_USER ALL=(root) NOPASSWD: /usr/local/sbin/agentzone-helper
EOF
chmod 440 /etc/sudoers.d/agentzone
visudo -cf /etc/sudoers.d/agentzone >/dev/null

# ---------------------------------------------------------------------------
# SSH baseline hardening.
#
# PasswordAuthentication is disabled GLOBALLY. This is safe to do
# immediately (rather than asking the admin to test a key login first, as
# some installers do) because:
#   - install.sh does not touch the admin's own key-based session;
#   - if the admin is currently using password auth to reach this box,
#     they were prompted above to confirm their current SSH port, and this
#     script does not close it — only newly-granted agent ports get their
#     own Match block.
# Per-grant blocks (see agentzone_helper.sh) add AllowUsers scoped to a
# single LocalPort, so agent accounts can never authenticate on the admin's
# port and vice versa.
# ---------------------------------------------------------------------------
log "Hardening sshd (key-only auth, no root login)"
# /run is tmpfs; sshd normally creates /run/sshd itself via its service's
# ExecStartPre on every boot, but a box where sshd has never been fully
# started yet (fresh install, or a provider image that only ships the
# package) can be missing it. Without it, `sshd -t` fails with "Missing
# privilege separation directory: /run/sshd" even for a perfectly valid
# config. Create it now, and make it survive reboots via systemd-tmpfiles
# so this is a one-time fix, not a recurring surprise.
mkdir -p /run/sshd
cat > /etc/tmpfiles.d/agentzone-sshd.conf <<'EOF'
d /run/sshd 0755 root root -
EOF
systemd-tmpfiles --create /etc/tmpfiles.d/agentzone-sshd.conf >/dev/null 2>&1 || true

mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-agentzone-hardening.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 4
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
if sshd -t 2>/dev/null; then
  # Ubuntu 24.04+ (and some newer Debian images) start sshd via systemd
  # socket activation (ssh.socket) instead of running the daemon
  # directly. When that is active, systemd itself owns the listening
  # socket for whatever port is baked into the .socket unit (normally
  # just 22) -- any additional `Port <n>` line written into
  # sshd_config.d by agentzone_helper.sh for a grant is syntactically
  # valid (sshd -t passes) but is NEVER actually listened on, because
  # sshd never binds its own sockets in this mode. The practical
  # symptom is exactly the one this project hit in testing: the
  # firewall lets the TCP handshake through (nothing is blocking it),
  # but no SSH banner ever arrives because nothing is really listening.
  # Disable socket activation and run the traditional standalone
  # service instead, so every `Port` directive in sshd_config.d is
  # actually honored.
  systemctl disable --now ssh.socket 2>/dev/null || true
  systemctl enable ssh.service 2>/dev/null || systemctl enable sshd.service 2>/dev/null || true
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
else
  rm -f /etc/ssh/sshd_config.d/00-agentzone-hardening.conf
  warn "sshd config test failed; skipped hardening this pass — check any existing custom sshd config."
fi

log "Configuring firewall (UFW)"
ufw allow "$SSH_ADMIN_PORT/tcp" comment "agentzone-admin-ssh" >/dev/null 2>&1 || true
ufw --force enable >/dev/null 2>&1 || true
# NOTE: per-grant ports are opened/closed dynamically by agentzone_helper.sh
# only while a grant is active — see cmd_grant/revoke_one_grant. No other
# inbound port is ever opened by this installer: there is no web panel, no
# webhook listener, nothing else exposed.

log "Installing systemd units"
cat > /etc/systemd/system/agentzone-bot.service <<EOF
[Unit]
Description=AgentZone Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
UMask=0007
WorkingDirectory=$APP_DIR/app
Environment=PYTHONPATH=$APP_DIR/app
EnvironmentFile=$APP_DIR/config/.env
ExecStart=$APP_DIR/venv/bin/python -m bot.main
Restart=always
RestartSec=5
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/agentzone-expire.service <<'EOF'
[Unit]
Description=AgentZone grant expiry sweep

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/agentzone-helper expire-check
EOF

cat > /etc/systemd/system/agentzone-expire.timer <<'EOF'
[Unit]
Description=Run AgentZone grant expiry sweep every minute

[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
AccuracySec=10s
Unit=agentzone-expire.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now agentzone-expire.timer >/dev/null 2>&1 || true
systemctl enable --now agentzone-bot.service

# Self-check: warn loudly, right now, if ssh.socket is still active. If it
# is, every future per-grant `Port <n>` directive will be silently
# ignored (see the comment above where we disable it) -- an agent's
# connection would pass the firewall but sshd would never answer it.
if systemctl is-active --quiet ssh.socket 2>/dev/null; then
  warn "ssh.socket is still active — per-grant SSH ports will NOT work."
  warn "Run: systemctl disable --now ssh.socket && systemctl enable --now ssh.service"
fi

echo
log "Done."
echo "  Bot service:    systemctl status agentzone-bot"
echo "  Expiry timer:   systemctl status agentzone-expire.timer"
echo "  Helper:         sudo -u $APP_USER sudo /usr/local/sbin/agentzone-helper status"
echo
echo "Open a chat with your bot in Telegram and send /start."
