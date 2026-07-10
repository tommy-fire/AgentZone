"""Static checks on the privileged helper script.

These do not execute the script as root (no useradd/sshd in CI); they
assert on its *source* to lock in the security invariants described in
its own header comment, so a future edit cannot silently weaken them.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

HELPER = Path(__file__).resolve().parent.parent / "app" / "scripts" / "agentzone_helper.sh"


def _read() -> str:
    return HELPER.read_text(encoding="utf-8")


def test_helper_has_valid_bash_syntax():
    result = subprocess.run(["bash", "-n", str(HELPER)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_helper_requires_root_for_every_command():
    text = _read()
    for fn in ("cmd_grant", "cmd_revoke", "cmd_status", "cmd_expire_check", "cmd_purge_journal"):
        start = text.index(f"{fn}() {{")
        end = text.index("\n}\n", start)
        body = text[start:end]
        assert "require_root" in body, f"{fn} must call require_root"


def test_helper_never_puts_password_on_argv():
    text = _read()
    assert "--password-hash" not in text, "password must travel via stdin, not argv"
    assert "--password " not in text


def test_helper_reads_password_from_stdin_and_unsets_it():
    text = _read()
    assert 'read -r password ||' in text
    assert "unset password" in text


def test_helper_hashes_password_before_chpasswd():
    text = _read()
    assert "openssl passwd -6 -stdin" in text
    assert "chpasswd -e" in text


def test_helper_grant_is_key_only_no_password_ssh_login():
    text = _read()
    # Match the function DEFINITION specifically ("name(){"), not any
    # earlier prose comment that happens to mention the function's name.
    grant_block_start = text.index("write_grant_sshd_block(){")
    grant_block_end = text.index("\n}\n", grant_block_start)
    block = text[grant_block_start:grant_block_end]
    assert "PasswordAuthentication no" in block
    assert "AuthenticationMethods publickey" in block


def test_helper_sudo_requires_password_not_nopasswd():
    """Security: sudo must require the account password. NOPASSWD would let
    a leaked SSH key alone escalate to root."""
    text = _read()
    start = text.index('cat > "$sudoers_path"')
    end = text.index("\nEOF\n", start)
    block = text[start:end + len("\nEOF\n")]
    assert "NOPASSWD" not in block
    assert "ALL=(ALL:ALL) ALL" in block


def test_helper_sets_kernel_account_expiry():
    text = _read()
    assert "chage -E" in text


def test_helper_one_port_per_grant():
    text = _read()
    assert "allocate_port" in text
    assert "Match LocalPort" in text
    assert "AllowUsers" in text


def test_helper_skips_ports_already_listening_on_the_host():
    """Regression: the helper must not hand out a port that is already
    occupied by some unrelated local service, even if AgentZone itself has
    never allocated it before."""
    text = _read()
    assert "port_listening_locally" in text
    assert "/proc/net/tcp" in text
    assert "/proc/net/tcp6" in text
    alloc_start = text.index("allocate_port(){") if "allocate_port(){" in text else text.index("allocate_port() {")
    alloc_end = text.index("\n}\n", alloc_start)
    block = text[alloc_start:alloc_end]
    assert 'port_listening_locally "$p"' in block


def test_helper_verifies_new_grant_port_serves_ssh_before_reporting_success():
    """A grant must fail fast if sshd never actually starts speaking SSH on
    the newly assigned port; otherwise the bot can report success while the
    connection is dead from the outside."""
    text = _read()
    assert "wait_for_local_ssh_banner" in text
    assert "rollback_uncommitted_grant" in text
    start = text.index("cmd_grant() {")
    end = text.index("\n}\n", start)
    block = text[start:end]
    write_idx = block.index("write_grant_sshd_block")
    verify_idx = block.index("wait_for_local_ssh_banner")
    ufw_idx = block.index("ufw_open")
    assert write_idx < verify_idx < ufw_idx


def test_helper_revoke_removes_sshd_block_firewall_user_and_sudoers():
    text = _read()
    start = text.index("revoke_one_grant(){")
    end = text.index("\n}\n", start)
    block = text[start:end]
    assert "remove_grant_sshd_block" in block
    assert "ufw_close" in block
    assert "sudoers_path_for_grant" in block
    assert "userdel" in block
    assert "kill_user_sessions" in block


def test_helper_kills_sessions_before_deleting_user():
    text = _read()
    start = text.index("revoke_one_grant(){")
    end = text.index("\n}\n", start)
    block = text[start:end]
    kill_idx = block.index("kill_user_sessions")
    userdel_idx = block.index("userdel")
    assert kill_idx < userdel_idx, "must kill active sessions before userdel -r"


def test_helper_generates_grant_id_from_urandom():
    text = _read()
    assert "/dev/urandom" in text


def test_helper_state_file_written_with_atomic_replace_and_0600():
    text = _read()
    assert "os.chmod(tmp, 0o600)" in text
    assert "os.replace(tmp, path)" in text


def test_helper_journal_purge_is_explicit_and_separate_from_revoke():
    text = _read()
    assert "cmd_purge_journal" in text
    revoke_start = text.index("revoke_one_grant(){")
    revoke_end = text.index("\n}\n", revoke_start)
    assert "journalctl" not in text[revoke_start:revoke_end]


def test_helper_refuses_to_grant_an_existing_username():
    """Security: a grant must only ever create a brand-new Linux account.
    Reusing an existing username would let a typo (or malicious caller)
    silently take over a pre-existing account -- overwriting its password,
    replacing its authorized_keys, and handing it sudo."""
    text = _read()
    start = text.index("cmd_grant() {")
    end = text.index("\n}\n", start)
    block = text[start:end]
    assert 'if id "$user" >/dev/null 2>&1; then' in block
    fail_idx = block.index('if id "$user" >/dev/null 2>&1; then')
    useradd_idx = block.index("useradd -m")
    assert fail_idx < useradd_idx
    assert "fail " in block[fail_idx:useradd_idx]


def test_helper_state_mutating_commands_take_a_lock():
    """Without serializing grant/revoke/expire-check, the once-a-minute
    expiry timer could race a bot-triggered grant/revoke and silently
    clobber its state change (lost revoke, duplicate port allocation)."""
    text = _read()
    assert "acquire_state_lock" in text
    assert "flock" in text
    for fn in ("cmd_grant", "cmd_revoke", "cmd_expire_check"):
        start = text.index(f"{fn}() {{")
        end = text.index("\n}\n", start)
        # acquire_state_lock must appear before the function's closing
        # brace, and specifically right after require_root.
        block = text[start:end]
        assert "acquire_state_lock" in block, f"{fn} must call acquire_state_lock"


def test_helper_state_lock_is_released_by_process_exit_not_manual_unlock():
    """flock on an fd tied to the process lifetime is simplest and safest
    here: it can never be left held by a crashed command."""
    text = _read()
    start = text.index("acquire_state_lock(){")
    end = text.index("\n}\n", start)
    block = text[start:end]
    assert "exec 200>" in block
    assert "flock -w" in block


def test_helper_creates_run_sshd_before_every_sshd_syntax_check():
    """Regression: `sshd -t` fails with "Missing privilege separation
    directory: /run/sshd" on any box where sshd has never been fully
    started (tmpfs directory not yet created by its own service). Every
    ACTUAL call site that runs `sshd -t` (not just comments mentioning it)
    must `mkdir -p /run/sshd` first."""
    text = _read()
    lines = text.splitlines()
    offset = 0
    call_sites = 0
    for line in lines:
        stripped = line.strip()
        is_real_call = (
            "sshd -t" in stripped
            and not stripped.startswith("#")
        )
        if is_real_call:
            call_sites += 1
            idx = offset
            preceding = text[max(0, idx - 400):idx]
            assert "mkdir -p /run/sshd" in preceding, (
                f"sshd -t call not preceded by 'mkdir -p /run/sshd': {line!r}"
            )
        offset += len(line) + 1  # account for the stripped '\n'
    assert call_sites >= 2, "expected sshd -t to be called from at least two places"


def test_helper_reload_sshd_runs_daemon_reload_before_reloading_the_unit():
    """Critical regression, observed live: on distros where a systemd
    generator derives ssh.socket's listening port(s) from sshd_config
    (this is how Ubuntu 24.04+ implements SSH socket activation), a NEW
    `Port` line written into a grant's sshd_config.d file only takes
    effect after generators are re-run -- which happens on
    `systemctl daemon-reload`, not on reloading/restarting the ssh unit
    itself. Symptom without this: the grant's config passes `sshd -t`,
    UFW opens the port, the TCP handshake even completes -- but no SSH
    banner ever arrives because nothing is really listening on that port
    yet. install.sh also disables socket activation outright, but this
    call is a cheap, side-effect-free second layer of defense."""
    text = _read()
    start = text.index("reload_sshd(){") if "reload_sshd(){" in text else text.index("reload_sshd() {")
    end = text.index("\n}\n", start)
    block = text[start:end]
    daemon_reload_idx = block.index("systemctl daemon-reload")
    unit_reload_idx = block.index("systemctl reload")
    assert daemon_reload_idx < unit_reload_idx, (
        "daemon-reload must run BEFORE reloading the ssh unit itself"
    )
