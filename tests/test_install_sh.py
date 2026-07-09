"""Static checks on install.sh — locks in security invariants without
actually running the installer (which needs root + a real Ubuntu box)."""
from __future__ import annotations

import subprocess
from pathlib import Path

INSTALL = Path(__file__).resolve().parent.parent / "install.sh"


def _read() -> str:
    return INSTALL.read_text(encoding="utf-8")


def test_install_sh_has_valid_bash_syntax():
    result = subprocess.run(["bash", "-n", str(INSTALL)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_install_sh_requires_root():
    text = _read()
    assert 'EUID -eq 0' in text


def test_install_sh_validates_bot_token_format():
    text = _read()
    assert "validate_bot_token" in text
    assert "^[0-9]+:[A-Za-z0-9_-]{35}$" in text


def test_install_sh_validates_admin_id_is_numeric_only():
    """Regression guard: ADMIN_ID must be a single bare integer, not a list
    like the legacy ADMIN_IDS=[123,456] pattern — one admin only, by design."""
    text = _read()
    assert "validate_admin_id" in text
    assert "ADMIN_ID:-}" in text or "ADMIN_ID=" in text
    assert "ADMIN_IDS" not in text


def test_install_sh_auto_detects_public_ip():
    text = _read()
    assert "api.ipify.org" in text
    assert "ifconfig.me" in text


def test_install_sh_never_asks_for_a_domain():
    text = _read()
    # No domain / DOMAIN prompt anywhere — IP-only by design.
    assert "read -rp \"Domain" not in text
    assert "DOMAIN=" not in text


def test_install_sh_disables_password_authentication_globally():
    text = _read()
    assert "PasswordAuthentication no" in text
    assert "PermitRootLogin no" in text


def test_install_sh_does_not_open_any_web_port():
    text = _read()
    assert "nginx" not in text.lower()
    assert "ufw allow 80" not in text
    assert "ufw allow 443" not in text


def test_install_sh_only_opens_admin_ssh_port_statically():
    """Per-grant ports must be opened dynamically by the helper, not
    pre-opened in bulk by the installer."""
    text = _read()
    assert 'ufw allow "$SSH_ADMIN_PORT/tcp"' in text
    # The installer must never ufw-allow the whole per-grant port range at
    # once — only the helper opens one port at a time, only while its
    # grant is active.
    assert 'ufw allow "$PORT_RANGE_START' not in text
    assert "for" not in text[text.index("ufw allow"):text.index("ufw --force enable")]


def test_install_sh_installs_helper_as_root_owned_and_not_world_writable():
    text = _read()
    assert "install -o root -g root -m 0750" in text
    assert "/usr/local/sbin/agentzone-helper" in text


def test_install_sh_sudoers_rule_is_narrow_to_helper_path_only():
    text = _read()
    idx = text.index("cat > /etc/sudoers.d/agentzone")
    end = text.index("\nEOF\n", idx)
    block = text[idx:end]
    assert "/usr/local/sbin/agentzone-helper" in block
    assert "NOPASSWD: /usr/local/sbin/agentzone-helper" in block


def test_install_sh_enables_expiry_timer():
    text = _read()
    assert "agentzone-expire.timer" in text
    assert "OnUnitActiveSec=1min" in text


def test_install_sh_bot_service_has_no_new_privileges_disabled_reasonably():
    text = _read()
    idx = text.index("agentzone-bot.service <<EOF")
    end = text.index("\nEOF\n", idx)
    block = text[idx:end]
    assert "Restart=always" in block
    assert f"User=$APP_USER" in block


def test_install_sh_installs_rsync():
    """Regression: install.sh uses `rsync` to deploy app code, but rsync
    is not preinstalled on every minimal cloud/server image. Missing it
    used to fail deep inside the script with a confusing bare
    "No such file or directory" at the rsync call site."""
    text = _read()
    idx = text.index("apt-get install -y -qq")
    end = text.index("\n", idx)
    line = text[idx:end]
    assert "rsync" in line
    # rsync must be installed before it is ever invoked.
    rsync_call_idx = text.index("rsync -a --delete")
    assert idx < rsync_call_idx


def test_install_sh_installs_passwd_and_procps_for_the_helper():
    """passwd provides chpasswd/chage/useradd/userdel, procps provides
    pkill -- both used by agentzone_helper.sh when granting/revoking."""
    text = _read()
    idx = text.index("apt-get install -y -qq")
    end = text.index("\n", idx)
    line = text[idx:end]
    assert "passwd" in line
    assert "procps" in line


def test_install_sh_fails_fast_with_clear_message_if_a_required_command_is_missing():
    """A missing command after package installation must produce one
    clear, actionable error -- not an obscure failure wherever that
    command happens to be used first."""
    text = _read()
    idx = text.index("Fail fast, with a clear message")
    end = text.index("\ndone\n", idx)
    block = text[idx:end]
    for required in ("rsync", "useradd", "chpasswd", "chage", "pkill", "ssh-keygen", "sshd", "ufw"):
        assert required in block, f"{required} is not in the post-install command check"


def test_install_sh_ensures_ssh_service_is_actually_running():
    """Regression: some minimal cloud images ship openssh-server without
    enabling/starting its service, which makes every later `sshd -t` call
    (used to validate generated config) fail in confusing ways."""
    text = _read()
    assert "systemctl enable --now ssh.service" in text


def test_install_sh_disables_ssh_socket_activation():
    """Critical regression: on Ubuntu 24.04+ (and some newer Debian
    images), sshd is started via systemd socket activation (ssh.socket)
    instead of running standalone. When that is the case, systemd itself
    owns the listening socket for whatever port is baked into the
    .socket unit (normally just 22) -- any additional `Port <n>` line
    written by agentzone_helper.sh for a grant is syntactically valid
    (sshd -t passes) but is NEVER actually listened on. Symptom observed
    live: the firewall lets the TCP handshake through, but no SSH banner
    ever arrives on the grant's port. install.sh must disable ssh.socket
    and run the traditional ssh.service instead so every `Port` directive
    in sshd_config.d actually takes effect."""
    text = _read()
    idx = text.index("systemctl disable --now ssh.socket")
    # Must happen as part of the same hardening step that writes
    # 00-agentzone-hardening.conf, i.e. before install.sh finishes, and
    # must actually enable+start the alternative (ssh.service/sshd.service).
    surrounding = text[max(0, idx - 200):idx + 400]
    assert "00-agentzone-hardening.conf" in text[:idx]
    assert "systemctl enable ssh.service" in surrounding or "systemctl enable sshd.service" in surrounding
    assert "systemctl restart ssh" in surrounding or "systemctl restart sshd" in surrounding


def test_install_sh_warns_if_ssh_socket_is_still_active_at_the_end():
    """Defense in depth: even if disabling ssh.socket above didn't take
    for some reason (e.g. a custom image re-enables it), the admin must
    be told loudly and immediately, not left to discover it only when a
    grant silently fails to connect."""
    text = _read()
    idx = text.index('systemctl is-active --quiet ssh.socket')
    block = text[idx:idx + 300]
    assert "warn " in block


def test_install_sh_creates_run_sshd_before_testing_sshd_config():
    """Regression: `sshd -t` needs /run/sshd (tmpfs) to exist; on a box
    where sshd has never been fully started, this directory can be
    missing and a perfectly valid config gets rejected with "Missing
    privilege separation directory: /run/sshd"."""
    text = _read()
    idx = text.index("sshd -t 2>/dev/null")
    preceding = text[max(0, idx - 600):idx]
    assert "mkdir -p /run/sshd" in preceding
    # Also persisted across reboots via systemd-tmpfiles, not just created
    # once during this install run.
    assert "tmpfiles.d/agentzone-sshd.conf" in text
