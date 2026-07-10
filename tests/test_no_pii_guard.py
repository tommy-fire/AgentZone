from __future__ import annotations

import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_no_pii.sh"



def test_no_pii_guard_allows_pyproject_readme_filename(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        "[project]\n"
        'name = "agentzone"\n'
        'readme = "README.md"\n',
        encoding="utf-8",
    )
    result = subprocess.run(
        ["bash", str(SCRIPT), str(pyproject)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert result.returncode == 0, result.stderr
