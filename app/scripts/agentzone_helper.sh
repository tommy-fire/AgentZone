#!/usr/bin/env bash
# agentzone_helper.sh — root-only privileged operations for AgentZone.
#
# The Telegram bot never touches sshd/UFW/useradd directly. It shells out to
# this single, narrow, root-owned script through a dedicated sudoers rule
# (see install.sh). Keeping ALL privileged logic in one auditable file makes
# it easy to review exactly what the bot can do to the host.
#
# Security model
# ---------------
# - Every grant gets its OWN sshd port, opened in the firewall and bound to
#   exactly one Linux user via `Match LocalPort <port>` + `AllowUsers`, with
#   that user's authorized key stored in a ROOT-OWNED path that is enabled
#   only for the grant's port. A second `Match User <name>` block forces all
#   other ports (including the admin SSH port) to ignore the user's home
#   `~/.ssh/authorized_keys`, so an agent account cannot silently authenticate
#   on the admin port even if it later writes extra keys into its own home.
#   While no grant is active for a port, nothing listens there and nothing in
#   sshd_config references it — there is nothing for a port scanner to find.
#   This is stronger than one shared "agent" port with rotating users: a
#   leaked/rotated key on a shared port would still let an old holder probe
#   the port even after "revocation" broke only authentication, not
#   reachability.
# - Public-key authentication ONLY. PasswordAuthentication is disabled
#   globally in install.sh's baseline hardening; the per-grant password
#   this script sets is a LOCAL (su/sudo) secret, never usable over the
#   network. This means a leaked private key alone is useless without also
#   having a shell on the box already, and a brute-force campaign against
#   the port is a no-op against key auth.
# - `chage -E` (kernel-enforced account expiry) is set in addition to the
#   systemd timer that calls `revoke`, but Linux account expiry is only
#   day-granularity: on Ubuntu/Debian, the account is considered expired at
#   the START of the configured day. AgentZone therefore sets the kernel
#   expiry to the day AFTER the exact TTL deadline so it never locks a grant
#   out prematurely; the timer + bot monitor still enforce the precise
#   minute-level expiry, while `chage` remains a coarse fallback if they both
#   fail.
# - Revocation removes: the sshd Match block, the firewall rule, the
#   sudoers file, all active sessions (`pkill -KILL -u`), the Linux user
#   and its home directory, and every login trace for that user in
#   wtmp/btmp/lastlog. See revoke_one_grant() for exactly what is and is
#   not cleaned (journald is append-only and cannot be selectively edited
#   without corrupting it — see cmd_purge_journal for the explicit,
#   deliberate full-vacuum alternative).
# - A grant ALWAYS creates a brand-new Linux account and refuses to run if
#   the requested username already exists (see cmd_grant). This guarantees
#   a grant fully owns the account it manages: revoke can safely userdel
#   it, and an admin typo can never silently take over — and gain sudo
#   on — a pre-existing account.
# - Every state-mutating command (grant/revoke/expire-check) holds an
#   flock on the state file for its whole run, so the once-a-minute expiry
#   timer can never race a bot-triggered grant/revoke into corrupting or
#   silently losing a state change.
set -Eeuo pipefail

ENV_FILE="${AGENTZONE_ENV_FILE:-/opt/agentzone/config/.env}"
STATE_DIR="${AGENTZONE_STATE_DIR:-/var/lib/agentzone}"
STATE_FILE="$STATE_DIR/grants.json"
STATE_LOCK_FILE="$STATE_DIR/grants.lock"
SUDOERS_DIR="${AGENTZONE_SUDOERS_DIR:-/etc/sudoers.d}"
SSHD_DIR="${AGENTZONE_SSHD_DIR:-/etc/ssh/sshd_config.d}"
AUTHORIZED_KEYS_DIR="${AGENTZONE_AUTHORIZED_KEYS_DIR:-$STATE_DIR/authorized_keys}"
DISABLED_AUTHORIZED_KEYS_DIR="${AGENTZONE_DISABLED_AUTHORIZED_KEYS_DIR:-$STATE_DIR/authorized_keys-disabled}"
MANAGED_BEGIN="# AGENTZONE_BEGIN"
MANAGED_END="# AGENTZONE_END"
STATE_SCHEMA_VERSION=1

get_env() {
  local key="$1" default="$2"
  if [[ -r "$ENV_FILE" ]]; then
    local line
    line="$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -1 || true)"
    if [[ -n "$line" ]]; then
      printf '%s' "${line#*=}"
      return
    fi
  fi
  printf '%s' "$default"
}

PORT_RANGE_START="$(get_env AGENTZONE_PORT_RANGE_START 20000)"
PORT_RANGE_END="$(get_env AGENTZONE_PORT_RANGE_END 20100)"

fail(){ echo "error=$*" >&2; echo "ok=false"; exit 1; }
require_root(){
  if [[ "${AGENTZONE_HELPER_TEST:-0}" == "1" ]]; then return 0; fi
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "helper must run as root"
}
now_iso(){ date -u +%Y-%m-%dT%H:%M:%SZ; }
now_epoch(){ date -u +%s; }

# Linux account expiry (`chage -E`) is day-granularity and on Ubuntu/Debian
# the account becomes unusable at the START of the configured day. For an
# exact TTL like "+240 minutes", setting that same calendar date would lock
# the account immediately if the deadline is later today. So we program the
# kernel fallback to the DAY AFTER the intended deadline: this is never
# earlier than the real expiry, while the systemd timer + bot monitor remain
# responsible for exact minute-level revocation.
kernel_expire_date_from_ttl_minutes(){
  local ttl="$1"
  date -u -d "+${ttl} minutes +1 day" +%Y-%m-%d
}

# Serialize every command that reads-modifies-writes the state file.
# Without this, the once-a-minute expiry timer (cmd_expire_check) racing
# against a bot-triggered grant/revoke could both load the same snapshot,
# then one save_state() would silently clobber the other's change (e.g. a
# revoke "undone" by a concurrent grant's stale write, or two grants
# allocating the same port). Held for the lifetime of the helper process —
# it is released automatically when the process exits, so callers do not
# need to unlock explicitly.
acquire_state_lock(){
  if [[ "${AGENTZONE_HELPER_TEST:-0}" == "1" ]]; then return 0; fi
  mkdir -p "$STATE_DIR"
  exec 200>"$STATE_LOCK_FILE"
  flock -w 10 200 || fail "could not acquire state lock (another grant/revoke operation is in progress)"
}

validate_username(){
  [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || fail "invalid username: $1"
}

validate_port(){
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || fail "invalid port: $p"
  [[ "$p" -ge 1024 && "$p" -le 65535 ]] || fail "port out of range: $p"
}

sanitize_username() {
  local raw="$1" clean
  clean="$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9_-]+/-/g; s/^-+//; s/-+$//')"
  if [[ ! "$clean" =~ ^[a-z_] ]]; then
    clean="agent-${clean}"
  fi
  clean="${clean:0:32}"
  clean="$(printf '%s' "$clean" | sed -E 's/-+$//')"
  if [[ -z "$clean" || ! "$clean" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    clean="agent-$(head -c4 /dev/urandom | od -An -tx1 | tr -dc 0-9a-f)"
  fi
  printf '%s' "$clean"
}

new_grant_id(){
  head -c 8 /dev/urandom | od -An -tx1 | tr -dc "0-9a-f" | head -c 16
}

sudoers_path_for_grant(){ printf '%s/agentzone-grant-%s' "$SUDOERS_DIR" "$1"; }
sshd_path_for_grant(){ printf '%s/50-agentzone-grant-%s.conf' "$SSHD_DIR" "$1"; }
managed_authorized_keys_path(){ printf '%s/%s' "$AUTHORIZED_KEYS_DIR" "$1"; }

# ---------------------------------------------------------------------------
# State (JSON, atomic writes, 0600 root-only)
# ---------------------------------------------------------------------------
load_state() {
  GRANTS_JSON="{}"
  HISTORY_JSON="[]"
  [[ -r "$STATE_FILE" ]] || return 0
  local raw
  raw="$(cat "$STATE_FILE" 2>/dev/null || true)"
  [[ -n "$raw" ]] || return 0
  GRANTS_JSON="$(printf '%s' "$raw" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(json.dumps(d.get('grants') or {}, separators=(',', ':')))" 2>/dev/null || echo "{}")"
  HISTORY_JSON="$(printf '%s' "$raw" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(json.dumps(d.get('history') or [], separators=(',', ':')))" 2>/dev/null || echo "[]")"
}

save_state() {
  mkdir -p "$STATE_DIR"
  # sshd may need to traverse $STATE_DIR to read a root-owned
  # AuthorizedKeysFile from $AUTHORIZED_KEYS_DIR while authenticating a grant
  # user, but the state file itself stays 0600 root-only.
  chmod 711 "$STATE_DIR"
  GRANTS_JSON="$GRANTS_JSON" HISTORY_JSON="$HISTORY_JSON" python3 - "$STATE_FILE" <<'PYSAVE'
import json, sys, os
path = sys.argv[1]
grants = json.loads(os.environ.get("GRANTS_JSON", "{}") or "{}")
history = json.loads(os.environ.get("HISTORY_JSON", "[]") or "[]")
out = {"version": 1, "grants": grants, "history": history[-200:]}
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(out, f, separators=(",", ":"), sort_keys=True)
    f.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PYSAVE
}

upsert_grant(){
  local grant_id="$1" username="$2" port="$3" fingerprint="$4" expires_at="$5" granted_at="$6" admin_id="$7" ttl_minutes="$8"
  GRANTS_JSON="$(GRANTS_JSON="$GRANTS_JSON" GRANT_ID="$grant_id" USERNAME="$username" PORT="$port" \
    FINGERPRINT="$fingerprint" EXPIRES_AT="$expires_at" GRANTED_AT="$granted_at" \
    ADMIN_ID="$admin_id" TTL_MINUTES="$ttl_minutes" python3 -c '
import json, os
grants = json.loads(os.environ["GRANTS_JSON"])
grants[os.environ["GRANT_ID"]] = {
    "username": os.environ["USERNAME"],
    "port": int(os.environ["PORT"]),
    "fingerprint": os.environ["FINGERPRINT"],
    "expires_at": os.environ["EXPIRES_AT"] or None,
    "granted_at": os.environ["GRANTED_AT"],
    "admin_id": os.environ["ADMIN_ID"],
    "ttl_minutes": os.environ["TTL_MINUTES"] or None,
}
print(json.dumps(grants, separators=(",", ":")))
')"
}

remove_grant(){
  local grant_id="$1"
  GRANTS_JSON="$(GRANTS_JSON="$GRANTS_JSON" GRANT_ID="$grant_id" python3 -c '
import json, os
grants = json.loads(os.environ["GRANTS_JSON"])
grants.pop(os.environ["GRANT_ID"], None)
print(json.dumps(grants, separators=(",", ":")))
')"
}

append_history(){
  local grant_id="$1" action="$2" actor="$3" detail="$4"
  HISTORY_JSON="$(HISTORY_JSON="$HISTORY_JSON" GRANT_ID="$grant_id" ACTION="$action" ACTOR="$actor" DETAIL="$detail" python3 -c '
import json, os, datetime
hist = json.loads(os.environ["HISTORY_JSON"])
hist.append({
    "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "grant_id": os.environ["GRANT_ID"],
    "action": os.environ["ACTION"],
    "actor": os.environ["ACTOR"],
    "detail": os.environ["DETAIL"],
})
print(json.dumps(hist[-200:], separators=(",", ":")))
')"
}

grant_field(){
  local grant_id="$1" field="$2" default="${3:-}"
  GRANTS_JSON="$GRANTS_JSON" GRANT_ID="$grant_id" FIELD="$field" DEFAULT="$default" python3 -c '
import json, os, sys
try:
    grants = json.loads(os.environ["GRANTS_JSON"])
    g = grants.get(os.environ["GRANT_ID"]) or {}
    v = g.get(os.environ["FIELD"])
    print("" if v is None else str(v))
except Exception:
    print(os.environ["DEFAULT"], file=sys.stderr)
' 2>/dev/null || printf '%s' "$default"
}

used_ports(){
  GRANTS_JSON="$GRANTS_JSON" python3 -c '
import json, os
g = json.loads(os.environ["GRANTS_JSON"])
for v in g.values():
    print(v.get("port"))
' 2>/dev/null || true
}

port_listening_locally(){
  local port="$1"
  PORT="$port" python3 - <<'PY'
import os, sys
port = int(os.environ["PORT"])
port_hex = f"{port:04X}"
for path in ("/proc/net/tcp", "/proc/net/tcp6"):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) < 4:
                    continue
                state = parts[3]
                if state != "0A":
                    continue
                local_addr = parts[1]
                try:
                    _, local_port = local_addr.rsplit(":", 1)
                except ValueError:
                    continue
                if local_port.upper() == port_hex:
                    sys.exit(0)
    except FileNotFoundError:
        pass
sys.exit(1)
PY
}

allocate_port(){
  local used p
  used="$(used_ports)"
  for ((p = PORT_RANGE_START; p <= PORT_RANGE_END; p++)); do
    if ! grep -qxF "$p" <<<"$used" && ! port_listening_locally "$p"; then
      printf '%s' "$p"
      return 0
    fi
  done
  fail "no free port in range ${PORT_RANGE_START}-${PORT_RANGE_END} (all allocated or already in use by another local service)"
}

reload_sshd() {
  # sshd -t (config syntax check) requires /run/sshd to exist -- normally
  # created by the sshd service's own ExecStartPre, but /run is tmpfs and
  # this directory can be missing here if sshd has never been fully
  # started yet (fresh install, or a provider image that only ships the
  # package without starting the service). Create it defensively before
  # every syntax check so a missing tmpfs directory never masquerades as
  # "your new config is broken".
  mkdir -p /run/sshd
  if command -v sshd >/dev/null 2>&1 && sshd -t 2>/dev/null; then
    # `daemon-reload` before reloading the unit itself: on distros that
    # ship a systemd generator deriving ssh.socket's listening port(s)
    # from sshd_config (this is how Ubuntu 24.04+ implements socket
    # activation), a NEW `Port` line written by write_grant_sshd_block()
    # only takes effect after generators are re-run, which happens on
    # `daemon-reload`, not on a plain unit reload/restart. Skipping this
    # is exactly how a freshly granted port can pass every config check
    # yet never actually accept a connection. install.sh disables socket
    # activation outright during setup (see its sshd hardening step), but
    # this call is cheap, has no side effects otherwise, and closes the
    # gap defensively for any host where that could not be verified.
    systemctl daemon-reload 2>/dev/null || true
    systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || true
  fi
}

fingerprint_for_key() {
  local key_text="$1" tmp
  tmp="$(mktemp)"
  printf '%s\n' "$key_text" > "$tmp"
  ssh-keygen -lf "$tmp" 2>/dev/null | awk '{print $2}'
  rm -f "$tmp"
}

wait_for_local_ssh_banner(){
  local port="$1" timeout_sec="${2:-8}"
  PORT="$port" TIMEOUT_SEC="$timeout_sec" python3 - <<'PY'
import os, socket, sys, time
port = int(os.environ["PORT"])
timeout = float(os.environ["TIMEOUT_SEC"])
deadline = time.time() + timeout
last_error = "timeout waiting for SSH banner"
while time.time() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.5) as sock:
            sock.settimeout(1.5)
            data = sock.recv(64)
            if data.startswith(b"SSH-"):
                sys.exit(0)
            last_error = f"unexpected response on port {port}: {data!r}"
    except OSError as exc:
        last_error = str(exc)
    time.sleep(0.25)
print(last_error, file=sys.stderr)
sys.exit(1)
PY
}

ufw_rule_present(){ command -v ufw >/dev/null 2>&1 && ufw status numbered 2>/dev/null | grep -qF "$1/tcp"; }
ufw_open(){
  command -v ufw >/dev/null 2>&1 || return 1
  ufw allow "$1/tcp" comment "agentzone-$2" >/dev/null 2>&1 || return 1
  ufw_rule_present "$1"
}
ufw_close(){ command -v ufw >/dev/null 2>&1 && ufw delete allow "$1/tcp" >/dev/null 2>&1 || true; }

# Kill every process/session owned by a user (best-effort, both signals).
kill_user_sessions(){
  local user="$1"
  pkill -TERM -u "$user" >/dev/null 2>&1 || true
  sleep 1
  pkill -KILL -u "$user" >/dev/null 2>&1 || true
}

# Best-effort scrub of a specific username from login-trace databases.
# wtmp/btmp/lastlog are fixed-record binary files; `utmpdump` lets us
# filter+rebuild them without corrupting the format. If utmpdump is not
# installed this is skipped silently (not fatal — revocation still removes
# the account and its ability to log in, which is the actual security
# boundary; these logs are a forensic nicety, not an access-control gate).
scrub_login_traces(){
  local user="$1" f rebuilt
  command -v utmpdump >/dev/null 2>&1 || return 0
  for f in /var/log/wtmp /var/log/btmp; do
    [[ -f "$f" ]] || continue
    rebuilt="$(mktemp)"
    if utmpdump "$f" 2>/dev/null | grep -vF " ${user} " > "$rebuilt.txt" 2>/dev/null; then
      utmpdump -r "$rebuilt.txt" > "$rebuilt" 2>/dev/null && cat "$rebuilt" > "$f" || true
    fi
    rm -f "$rebuilt" "$rebuilt.txt"
  done
  if [[ -f /var/log/lastlog ]]; then
    python3 - "$user" <<'PYLL' || true
import struct, sys, pwd
user = sys.argv[1]
try:
    uid = pwd.getpwnam(user).pw_uid
except KeyError:
    sys.exit(0)
RECORD = 292  # sizeof(struct lastlog) on glibc x86_64: time(4/8)+32+256, padded
for size in (292, 296):
    try:
        with open("/var/log/lastlog", "r+b") as fh:
            fh.seek(uid * size)
            blank = b"\x00" * size
            fh.write(blank)
        break
    except Exception:
        continue
PYLL
  fi
}

# ---------------------------------------------------------------------------
# sshd: one Match block per grant, binding LocalPort -> AllowUsers.
# ---------------------------------------------------------------------------
write_grant_sshd_block(){
  local grant_id="$1" user="$2" port="$3" path key_path
  path="$(sshd_path_for_grant "$grant_id")"
  key_path="$(managed_authorized_keys_path "$user")"
  mkdir -p "$SSHD_DIR"
  cat > "$path" <<EOF
$MANAGED_BEGIN grant=$grant_id
Port $port
Match LocalPort $port User $user
    AllowUsers $user
    AuthorizedKeysFile $key_path
    PasswordAuthentication no
    PubkeyAuthentication yes
    AuthenticationMethods publickey
Match User $user
    AuthorizedKeysFile $DISABLED_AUTHORIZED_KEYS_DIR/%u
Match All
$MANAGED_END grant=$grant_id
EOF
  chmod 644 "$path"
  if command -v sshd >/dev/null 2>&1; then
    # See reload_sshd() for why /run/sshd must exist before "sshd -t" can
    # succeed at all -- without this, a perfectly valid config would be
    # rejected with "Missing privilege separation directory: /run/sshd"
    # on any box where sshd has not been fully started yet.
    mkdir -p /run/sshd
    sshd -t || { rm -f "$path"; fail "sshd config test failed for grant $grant_id"; }
  fi
  reload_sshd
}

remove_grant_sshd_block(){
  local grant_id="$1"
  rm -f "$(sshd_path_for_grant "$grant_id")"
  reload_sshd
}

rollback_uncommitted_grant(){
  local grant_id="$1" user="$2" port="$3"
  remove_grant_sshd_block "$grant_id"
  [[ -n "$port" ]] && ufw_close "$port" "$grant_id"
  rm -f "$(sudoers_path_for_grant "$grant_id")" "$(managed_authorized_keys_path "$user")"
  kill_user_sessions "$user"
  if id "$user" >/dev/null 2>&1; then
    userdel -r "$user" >/dev/null 2>&1 || {
      passwd -l "$user" >/dev/null 2>&1 || true
      usermod -s /usr/sbin/nologin "$user" >/dev/null 2>&1 || true
    }
  fi
}

# ---------------------------------------------------------------------------
# Revoke one grant end to end.
# ---------------------------------------------------------------------------
revoke_one_grant(){
  local grant_id="$1" reason="${2:-manual}"
  load_state
  local user port
  user="$(grant_field "$grant_id" username)"
  port="$(grant_field "$grant_id" port)"

  if [[ -z "$user" ]]; then
    rm -f "$(sudoers_path_for_grant "$grant_id")" "$(sshd_path_for_grant "$grant_id")"
    return 0
  fi

  remove_grant_sshd_block "$grant_id"
  [[ -n "$port" ]] && ufw_close "$port" "$grant_id"
  rm -f "$(sudoers_path_for_grant "$grant_id")" "$(managed_authorized_keys_path "$user")"

  kill_user_sessions "$user"
  if id "$user" >/dev/null 2>&1; then
    userdel -r "$user" >/dev/null 2>&1 || {
      passwd -l "$user" >/dev/null 2>&1 || true
      usermod -s /usr/sbin/nologin "$user" >/dev/null 2>&1 || true
    }
  fi
  scrub_login_traces "$user"

  remove_grant "$grant_id"
  append_history "$grant_id" "revoke" "$user" "reason=$reason port=$port"
  save_state
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
cmd_grant() {
  require_root
  acquire_state_lock
  local username="" ttl="" admin_id=""
  local arg
  while [[ $# -gt 0 ]]; do
    arg="$1"; shift
    case "$arg" in
      --username) username="${1:-}"; shift || true ;;
      --ttl) ttl="${1:-}"; shift || true ;;
      --admin-id) admin_id="${1:-}"; shift || true ;;
      *) ;;
    esac
  done
  [[ -n "$username" ]] || fail "missing --username"
  if [[ -n "$ttl" ]]; then
    [[ "$ttl" =~ ^[0-9]+$ ]] || fail "invalid ttl"
    [[ "$ttl" -ge 1 && "$ttl" -le 525600 ]] || fail "ttl out of range (max 1 year in minutes)"
  fi

  # Protocol on stdin: line 1 = public key, line 2 = plaintext password.
  # The password NEVER touches argv/ps or an on-disk temp file in plain
  # form — it is piped straight into openssl to produce a SHA-512 crypt
  # hash, and the plaintext variable is unset immediately after.
  local pub password
  IFS= read -r pub || fail "missing public key on stdin (line 1)"
  IFS= read -r password || fail "missing password on stdin (line 2)"
  printf '%s' "$pub" | grep -qE '^ssh-(ed25519|rsa) [A-Za-z0-9+/=]+( [^[:space:];&|`$]+)?$' \
    || fail "invalid public key (expected 'ssh-ed25519 <base64> [comment]' or 'ssh-rsa <base64> [comment]')"
  [[ -n "$password" && ${#password} -ge 12 ]] || fail "password must be at least 12 characters"
  local tmp_pub
  tmp_pub="$(mktemp)"
  printf '%s\n' "$pub" > "$tmp_pub"
  ssh-keygen -lf "$tmp_pub" >/dev/null 2>&1 || { rm -f "$tmp_pub"; fail "ssh-keygen rejected the public key"; }
  rm -f "$tmp_pub"
  local fp
  fp="$(fingerprint_for_key "$pub")"
  [[ -n "$fp" ]] || fail "could not compute key fingerprint"

  local password_hash
  password_hash="$(printf '%s' "$password" | openssl passwd -6 -stdin)"
  unset password
  [[ -n "$password_hash" ]] || fail "failed to hash password"

  local user
  user="$(sanitize_username "$username")"
  validate_username "$user"

  load_state
  local port grant_id
  port="$(allocate_port)"
  validate_port "$port"
  grant_id="$(new_grant_id)"

  # SECURITY: a grant may ONLY create a brand-new Linux account. Reusing an
  # existing username here would let an admin typo (or a malicious caller
  # with access to this command) silently take over an existing account —
  # this would overwrite its password, replace its authorized_keys, and
  # hand it sudo. Every grant must own the account it manages end to end,
  # so revoke can safely userdel it without risk of deleting something
  # that existed before AgentZone touched it.
  if id "$user" >/dev/null 2>&1; then
    fail "user '$user' already exists on this system — refusing to take over an existing account; choose a different username"
  fi
  useradd -m -s /bin/bash "$user"
  echo "${user}:${password_hash}" | chpasswd -e
  unset password_hash

  local ak
  chmod 711 "$STATE_DIR" 2>/dev/null || true
  install -d -m 0755 -o root -g root "$AUTHORIZED_KEYS_DIR"
  install -d -m 0755 -o root -g root "$DISABLED_AUTHORIZED_KEYS_DIR"
  ak="$(managed_authorized_keys_path "$user")"
  {
    echo "$MANAGED_BEGIN grant=$grant_id"
    echo "$pub"
    echo "$MANAGED_END grant=$grant_id"
  } > "$ak"
  chown root:root "$ak"
  chmod 0644 "$ak"

  # Least privilege by default: sudo requires the account password
  # (already hashed above), never NOPASSWD. This keeps a leaked SSH key
  # useless for privilege escalation without also knowing the password.
  local sudoers_path
  sudoers_path="$(sudoers_path_for_grant "$grant_id")"
  cat > "$sudoers_path" <<EOF
# agentzone grant $grant_id
$user ALL=(ALL:ALL) ALL
EOF
  chmod 440 "$sudoers_path"
  visudo -cf "$sudoers_path" >/dev/null || { rm -f "$sudoers_path"; fail "visudo rejected generated sudoers file"; }

  write_grant_sshd_block "$grant_id" "$user" "$port"
  if ! wait_for_local_ssh_banner "$port" 8; then
    rollback_uncommitted_grant "$grant_id" "$user" "$port"
    fail "grant port $port did not present an SSH banner after reload (likely ssh.socket/socket activation is still intercepting ports, sshd did not bind the new port, or the port is occupied by another local service)"
  fi
  if ! ufw_open "$port" "$grant_id"; then
    rollback_uncommitted_grant "$grant_id" "$user" "$port"
    fail "failed to open firewall rule for grant port $port"
  fi

  local expires=""
  if [[ -n "$ttl" ]]; then
    expires="$(date -u -d "+${ttl} minutes" +%Y-%m-%dT%H:%M:%SZ)"
    # Kernel-enforced account expiry as defense in depth. `chage -E` is only
    # day-granularity and expires the account at the START of the configured
    # day, so we intentionally set it to the day AFTER the intended exact
    # deadline. This avoids premature lockout; the systemd timer + bot
    # monitor still revoke at the real minute-level expiry.
    chage -E "$(kernel_expire_date_from_ttl_minutes "$ttl")" "$user" 2>/dev/null || true
  else
    chage -E -1 "$user" 2>/dev/null || true
  fi

  upsert_grant "$grant_id" "$user" "$port" "$fp" "$expires" "$(now_iso)" "${admin_id:-}" "${ttl:-}"
  append_history "$grant_id" "grant" "${admin_id:-system}" "user=$user port=$port ttl=${ttl:-forever}m"
  save_state

  echo "ok=true"
  echo "grant_id=$grant_id"
  echo "username=$user"
  echo "port=$port"
  echo "fingerprint=$fp"
  echo "expires_at=${expires:-never}"
  echo "granted_at=$(now_iso)"
  echo "created_user=true"
}


cmd_revoke() {
  require_root
  acquire_state_lock
  local grant_id="" reason="manual" all="false" arg
  while [[ $# -gt 0 ]]; do
    arg="$1"; shift
    case "$arg" in
      --grant-id) grant_id="${1:-}"; shift || true ;;
      --reason) reason="${1:-manual}"; shift || true ;;
      --all) all="true" ;;
      *) ;;
    esac
  done
  load_state

  if [[ "$all" == "true" ]]; then
    local gid
    for gid in $(GRANTS_JSON="$GRANTS_JSON" python3 -c 'import json,os; print("\n".join(json.loads(os.environ["GRANTS_JSON"]).keys()))' 2>/dev/null); do
      [[ -z "$gid" ]] && continue
      revoke_one_grant "$gid" "$reason"
      load_state
    done
    echo "ok=true"
    echo "revoked_all=true"
    return 0
  fi

  [[ -n "$grant_id" ]] || fail "missing --grant-id (or pass --all)"
  revoke_one_grant "$grant_id" "$reason"
  echo "ok=true"
  echo "revoked_grant_id=$grant_id"
}

cmd_status() {
  require_root
  load_state
  GRANTS_JSON="$GRANTS_JSON" NOW_EPOCH="$(now_epoch)" python3 -c '
import json, os
from datetime import datetime, timezone
g = json.loads(os.environ["GRANTS_JSON"])
now_epoch = float(os.environ["NOW_EPOCH"])
print(f"grant_count={len(g)}")
active = 0
for gid, v in g.items():
    exp = v.get("expires_at")
    is_active = True
    ttl = -1
    if exp:
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            ttl = int(exp_dt.timestamp() - now_epoch)
            is_active = ttl > 0
        except Exception:
            is_active = False
            ttl = 0
    if is_active:
        active += 1
    print("grant_id=" + gid)
    print("grant_username=" + str(v.get("username", "")))
    print("grant_port=" + str(v.get("port", "")))
    print("grant_fingerprint=" + str(v.get("fingerprint", "")))
    print("grant_active=" + str(is_active).lower())
    print("grant_expires_at=" + str(exp or "never"))
    print("grant_granted_at=" + str(v.get("granted_at", "")))
    print("grant_ttl_remaining_sec=" + str(ttl))
print(f"active_count={active}")
' 2>/dev/null
}

cmd_expire_check() {
  require_root
  acquire_state_lock
  load_state
  local gid
  for gid in $(GRANTS_JSON="$GRANTS_JSON" NOW_EPOCH="$(now_epoch)" python3 -c '
import json, os
from datetime import datetime
g = json.loads(os.environ["GRANTS_JSON"])
now_epoch = float(os.environ["NOW_EPOCH"])
for gid, v in g.items():
    exp = v.get("expires_at")
    if not exp:
        continue
    try:
        exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        if exp_dt.timestamp() <= now_epoch:
            print(gid)
    except Exception:
        pass
' 2>/dev/null); do
    [[ -z "$gid" ]] && continue
    revoke_one_grant "$gid" "expired"
    load_state
  done
  echo "ok=true"
}

# Explicit, deliberate full journald vacuum. journald is an append-only,
# tamper-evident log — there is no supported way to remove only the lines
# mentioning one user without breaking that guarantee. This command exists
# so an admin can consciously choose to drop ALL journal history (e.g.
# after offboarding an agent) instead of the helper silently doing
# selective (and fragile) edits on every revoke.
cmd_purge_journal() {
  require_root
  journalctl --rotate >/dev/null 2>&1 || true
  journalctl --vacuum-time=1s >/dev/null 2>&1 || true
  echo "ok=true"
}

case "${1:-status}" in
  grant) shift || true; cmd_grant "$@" ;;
  revoke) shift || true; cmd_revoke "$@" ;;
  status) shift || true; cmd_status "$@" ;;
  expire-check) shift || true; cmd_expire_check "$@" ;;
  purge-journal) shift || true; cmd_purge_journal "$@" ;;
  *) fail "unknown command: ${1:-}" ;;
esac
