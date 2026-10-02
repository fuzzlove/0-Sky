"""Select the pinned 0-Sky Python runtime for RemoteXPC operations."""

import os
import pathlib
import subprocess
import sys


PROJECT_PYTHON = pathlib.Path(__file__).resolve().parents[2] / ".venv/bin/python"
REQUIRED_PYMOBILEDEVICE3 = "11.3.1"
PROBE = (
    "import importlib.metadata, pymobiledevice3; "
    "from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel; "
    "from pymobiledevice3.services.cryptexd import CryptexdService; "
    "from pymobiledevice3.restore.tss import TSSRequest; "
    "print(importlib.metadata.version('pymobiledevice3'))"
)


def select_device_python(explicit: str | None = None) -> str:
    """Return a usable interpreter, keeping its venv path intact."""
    override = explicit or os.environ.get("SRD_PYTHON")
    candidates = [pathlib.Path(override).expanduser()] if override else [
        PROJECT_PYTHON, pathlib.Path(sys.executable)
    ]
    failures = []
    for candidate in candidates:
        if not candidate.is_file():
            failures.append(f"{candidate}: missing")
            continue
        result = subprocess.run(
            [str(candidate), "-c", PROBE], capture_output=True, text=True,
            timeout=30,
        )
        version = result.stdout.strip()
        if result.returncode == 0 and version == REQUIRED_PYMOBILEDEVICE3:
            return str(candidate.absolute())
        reason = result.stderr.strip().splitlines()[-1] if result.stderr.strip() else (
            f"pymobiledevice3 {version or 'unavailable'}"
        )
        failures.append(f"{candidate}: {reason}")
    raise ValueError(
        "No Python with pinned pymobiledevice3 11.3.1 is available. "
        "Set SRD_PYTHON to the 0-Sky runtime or install the project's pinned "
        "requirements into .venv. Checked: " + "; ".join(failures)
    )


def ensure_device_python() -> None:
    """Re-execute a direct device-tool invocation in the pinned environment."""
    selected = select_device_python()
    if pathlib.Path(sys.executable).absolute() != pathlib.Path(selected).absolute():
        os.execv(selected, [selected, *sys.argv])
