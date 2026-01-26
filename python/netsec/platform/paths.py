"""Tool binary path resolution across platforms."""
from __future__ import annotations

import logging
from pathlib import Path

from netsec.platform.detect import OSType, detect_platform

logger = logging.getLogger(__name__)

# Known tool binary paths per platform
_TOOL_PATHS: dict[str, dict[OSType, list[str]]] = {
    "nmap": {
        OSType.LINUX: ["/usr/bin/nmap", "/usr/local/bin/nmap"],
        OSType.MACOS: ["/opt/homebrew/bin/nmap", "/usr/local/bin/nmap"],
        OSType.WINDOWS: [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
        ],
    },
    "suricata": {
        OSType.LINUX: ["/usr/bin/suricata", "/usr/local/bin/suricata"],
        OSType.MACOS: ["/opt/homebrew/bin/suricata", "/usr/local/bin/suricata"],
        OSType.WINDOWS: [],
    },
    "zeek": {
        OSType.LINUX: ["/usr/bin/zeek", "/usr/local/bin/zeek", "/opt/zeek/bin/zeek"],
        OSType.MACOS: ["/opt/homebrew/bin/zeek", "/usr/local/bin/zeek"],
        OSType.WINDOWS: [],
    },
    "openvas": {
        OSType.LINUX: ["/usr/bin/gvm-cli", "/usr/local/bin/gvm-cli"],
        OSType.MACOS: [],
        OSType.WINDOWS: [],
    },
    "tshark": {
        OSType.LINUX: ["/usr/bin/tshark", "/usr/local/bin/tshark"],
        OSType.MACOS: ["/opt/homebrew/bin/tshark", "/usr/local/bin/tshark"],
        OSType.WINDOWS: [
            r"C:\Program Files\Wireshark\tshark.exe",
        ],
    },
    "clamscan": {
        OSType.LINUX: ["/usr/bin/clamscan", "/usr/local/bin/clamscan"],
        OSType.MACOS: ["/opt/homebrew/bin/clamscan", "/usr/local/bin/clamscan"],
        OSType.WINDOWS: [
            r"C:\Program Files\ClamAV\clamscan.exe",
        ],
    },
    "ossec": {
        OSType.LINUX: ["/var/ossec/bin/ossec-control"],
        OSType.MACOS: ["/var/ossec/bin/ossec-control"],
        OSType.WINDOWS: [],
    },
    "fail2ban-client": {
        OSType.LINUX: ["/usr/bin/fail2ban-client", "/usr/local/bin/fail2ban-client"],
        OSType.MACOS: ["/opt/homebrew/bin/fail2ban-client"],
        OSType.WINDOWS: [],
    },
}


def find_tool_binary(tool_name: str) -> str | None:
    """Find the binary path for a tool on the current platform.

    Checks known paths first, then falls back to PATH lookup.
    """
    platform_info = detect_platform()
    paths = _TOOL_PATHS.get(tool_name, {}).get(platform_info.os_type, [])

    for path_str in paths:
        path = Path(path_str)
        if path.exists() and path.is_file():
            logger.debug("Found %s at known path: %s", tool_name, path)
            return str(path)

    # Fallback: check PATH
    import shutil
    which_result = shutil.which(tool_name)
    if which_result:
        logger.debug("Found %s in PATH: %s", tool_name, which_result)
        return which_result

    return None
