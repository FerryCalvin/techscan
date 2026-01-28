from __future__ import annotations

import logging
import subprocess  # nosec

# Reason: central wrapper validates executables against an allow list before invocation
from pathlib import Path
from typing import MutableMapping, Optional, Sequence

_LOG = logging.getLogger("techscan.subprocess")

_ALLOWED_EXECUTABLES = {
    "node",
    "node.exe",
    "npm",
    "npm.cmd",
    "pnpm",
    "pnpm.cmd",
    "yarn",
    "yarn.cmd",
    "bun",
    "bun.cmd",
    "npx",
    "npx.cmd",
    "git",
    "git.exe",
}


def register_allowed_executable(executable: str) -> None:
    """Allow an additional executable name (case-insensitive)."""
    if executable:
        _ALLOWED_EXECUTABLES.add(Path(executable).name.lower())


def is_allowed_executable(executable: str) -> bool:
    if not executable:
        return False
    return Path(executable).name.lower() in _ALLOWED_EXECUTABLES


def _ensure_allowed(cmd: Sequence[str]) -> Sequence[str]:
    if not cmd:
        raise ValueError("empty command passed to safe subprocess wrapper")
    executable = Path(cmd[0]).name.lower()
    if executable not in _ALLOWED_EXECUTABLES:
        raise ValueError(f"executable {cmd[0]!r} is not permitted by allow list")
    return cmd


def safe_run(
    cmd: Sequence[str],
    *,
    cwd: Optional[str] = None,
    env: Optional[MutableMapping[str, str]] = None,
    timeout: Optional[float] = None,
    capture_output: bool = False,
    text: bool = False,
    check: bool = False,
) -> subprocess.CompletedProcess:
    _ensure_allowed(cmd)
    _LOG.debug("safe_run executing cmd=%s cwd=%s timeout=%s", list(cmd), cwd, timeout)
    return subprocess.run(  # nosec
        list(cmd),
        cwd=cwd,
        env=env,
        timeout=timeout,
        capture_output=capture_output,
        text=text,
        check=check,
    )
    # Reason: _ensure_allowed enforces allow list, and shell is never enabled


def safe_popen(cmd: Sequence[str], **kwargs) -> subprocess.Popen:
    _ensure_allowed(cmd)
    _LOG.debug("safe_popen spawning cmd=%s cwd=%s", list(cmd), kwargs.get("cwd"))
    return subprocess.Popen(list(cmd), **kwargs)  # nosec
    # Reason: _ensure_allowed enforces allow list, and shell is never enabled


PopenType = subprocess.Popen
CompletedProcessType = subprocess.CompletedProcess
TimeoutExpired = subprocess.TimeoutExpired
PIPE = subprocess.PIPE
STDOUT = subprocess.STDOUT
DEVNULL = subprocess.DEVNULL
