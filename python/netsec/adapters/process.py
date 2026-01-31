"""Async subprocess execution helpers."""
from __future__ import annotations

import asyncio
import logging
import shlex
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ProcessResult:
    """Result of a subprocess execution."""
    returncode: int
    stdout: str
    stderr: str
    command: str
    timed_out: bool = False

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out


async def run_command(
    command: str | list[str],
    *,
    timeout: int = 300,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    stdin_data: str | None = None,
) -> ProcessResult:
    """Run a command asynchronously and capture output.

    Args:
        command: Command string or list of args
        timeout: Timeout in seconds
        cwd: Working directory
        env: Environment variables (merged with current)
        stdin_data: Data to send to stdin

    Returns:
        ProcessResult with stdout, stderr, returncode
    """
    if isinstance(command, str):
        cmd_str = command
        # Use shell=True on Windows for string commands
        import sys
        if sys.platform == "win32":
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
        else:
            args = shlex.split(command)
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
            )
    else:
        cmd_str = " ".join(command)
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )

    logger.debug("Running: %s", cmd_str)

    timed_out = False
    try:
        stdin_bytes = stdin_data.encode() if stdin_data else None
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_bytes),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        timed_out = True
        proc.kill()
        stdout, stderr = await proc.communicate()
        logger.warning("Command timed out after %ds: %s", timeout, cmd_str)

    result = ProcessResult(
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout=stdout.decode(errors="replace") if stdout else "",
        stderr=stderr.decode(errors="replace") if stderr else "",
        command=cmd_str,
        timed_out=timed_out,
    )

    if not result.success:
        logger.warning(
            "Command failed (rc=%d): %s\nstderr: %s",
            result.returncode,
            cmd_str,
            result.stderr[:500],
        )

    return result


async def check_binary(binary: str) -> str | None:
    """Check if a binary exists and return its path.

    Returns the full path or None if not found.
    """
    import sys
    if sys.platform == "win32":
        result = await run_command(f"where {binary}", timeout=10)
    else:
        result = await run_command(f"which {binary}", timeout=10)

    if result.success:
        return result.stdout.strip().split("\n")[0]
    return None


def quote_path(path: str) -> str:
    """Quote a path for shell commands if it contains spaces."""
    if " " in path and not (path.startswith('"') and path.endswith('"')):
        return f'"{path}"'
    return path


async def get_binary_version(binary: str, version_flag: str = "--version") -> str | None:
    """Get the version string from a binary."""
    quoted = quote_path(binary)
    result = await run_command(f"{quoted} {version_flag}", timeout=10)
    if result.success:
        return result.stdout.strip().split("\n")[0]
    return None
