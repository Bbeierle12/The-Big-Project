"""OS and platform detection."""
from __future__ import annotations

import platform
import sys
from dataclasses import dataclass
from enum import StrEnum


class OSType(StrEnum):
    LINUX = "linux"
    MACOS = "macos"
    WINDOWS = "windows"
    UNKNOWN = "unknown"


class LinuxDistro(StrEnum):
    DEBIAN = "debian"
    UBUNTU = "ubuntu"
    FEDORA = "fedora"
    CENTOS = "centos"
    RHEL = "rhel"
    ARCH = "arch"
    ALPINE = "alpine"
    UNKNOWN = "unknown"


@dataclass
class PlatformInfo:
    os_type: OSType
    distro: LinuxDistro
    version: str
    arch: str
    is_wsl: bool
    is_container: bool


def detect_platform() -> PlatformInfo:
    """Detect the current platform."""
    system = platform.system().lower()

    if system == "linux":
        os_type = OSType.LINUX
    elif system == "darwin":
        os_type = OSType.MACOS
    elif system == "windows":
        os_type = OSType.WINDOWS
    else:
        os_type = OSType.UNKNOWN

    distro = LinuxDistro.UNKNOWN
    if os_type == OSType.LINUX:
        distro = _detect_linux_distro()

    is_wsl = False
    if os_type == OSType.LINUX:
        try:
            with open("/proc/version", "r") as f:
                is_wsl = "microsoft" in f.read().lower()
        except OSError:
            pass

    is_container = False
    try:
        with open("/proc/1/cgroup", "r") as f:
            content = f.read()
            is_container = "docker" in content or "containerd" in content
    except OSError:
        pass

    return PlatformInfo(
        os_type=os_type,
        distro=distro,
        version=platform.version(),
        arch=platform.machine(),
        is_wsl=is_wsl,
        is_container=is_container,
    )


def _detect_linux_distro() -> LinuxDistro:
    """Detect Linux distribution."""
    try:
        with open("/etc/os-release", "r") as f:
            content = f.read().lower()
            if "ubuntu" in content:
                return LinuxDistro.UBUNTU
            elif "debian" in content:
                return LinuxDistro.DEBIAN
            elif "fedora" in content:
                return LinuxDistro.FEDORA
            elif "centos" in content:
                return LinuxDistro.CENTOS
            elif "rhel" in content or "red hat" in content:
                return LinuxDistro.RHEL
            elif "arch" in content:
                return LinuxDistro.ARCH
            elif "alpine" in content:
                return LinuxDistro.ALPINE
    except OSError:
        pass
    return LinuxDistro.UNKNOWN
