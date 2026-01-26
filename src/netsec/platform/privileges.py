"""Privilege and permission checks."""
from __future__ import annotations

import logging
import os
import sys

logger = logging.getLogger(__name__)


def is_root() -> bool:
    """Check if running as root/admin."""
    if sys.platform == "win32":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def can_capture_packets() -> bool:
    """Check if the current user can capture packets."""
    if is_root():
        return True

    if sys.platform == "linux":
        # Check for CAP_NET_RAW capability
        try:
            with open(f"/proc/{os.getpid()}/status", "r") as f:
                for line in f:
                    if line.startswith("CapEff:"):
                        cap_hex = int(line.split(":")[1].strip(), 16)
                        CAP_NET_RAW = 1 << 13
                        return bool(cap_hex & CAP_NET_RAW)
        except OSError:
            pass

    return False


def check_sudo_available() -> bool:
    """Check if sudo is available (non-Windows)."""
    if sys.platform == "win32":
        return False
    import shutil
    return shutil.which("sudo") is not None
