"""Low-level bridge to the privileged helper script."""
from __future__ import annotations

import asyncio
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from agentzone.config import Settings, settings


@dataclass(frozen=True)
class HelperResult:
    exit_code: int
    data: dict[str, str]
    raw: str


class HelperGateway:
    """Run the root-owned helper script and capture its structured output."""

    def __init__(self, runtime_settings: Settings) -> None:
        self.settings = runtime_settings

    async def run(self, *args: str, stdin: str | None = None) -> HelperResult:
        helper = Path(self.settings.AGENTZONE_HELPER_PATH)
        if not helper.exists():
            raw = f"Helper not installed at {helper}"
            return HelperResult(127, {"ok": "false", "error": raw}, raw)

        command = self._command_for(helper, args)
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out_b, err_b = await proc.communicate(
            stdin.encode("utf-8") if stdin is not None else None
        )
        stdout = out_b.decode("utf-8", "replace")
        stderr = err_b.decode("utf-8", "replace")
        raw = (stdout + (("\n" + stderr) if stderr else "")).strip()
        return HelperResult(proc.returncode or 0, parse_kv_output(stdout), raw)

    def _command_for(self, helper: Path, args: tuple[str, ...]) -> list[str]:
        if os.geteuid() == 0:
            if not os.access(helper, os.X_OK):
                return ["sh", "-c", f"echo 'Helper is not executable: {helper}' >&2; exit 126"]
            return [str(helper), *args]

        if shutil.which("sudo") is None:
            return ["sh", "-c", "echo 'sudo is not installed — cannot invoke the privileged helper' >&2; exit 127"]
        return ["sudo", "-n", str(helper), *args]



def parse_kv_output(raw: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


helper_gateway = HelperGateway(settings)
