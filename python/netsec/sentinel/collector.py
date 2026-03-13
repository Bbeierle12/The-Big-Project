"""Minimal local collectors for Sentinel snapshot tables."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import socket
import stat
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from netsec.core.config import get_settings
from netsec.sentinel import connect, ensure_schema, utcnow

STATE_MAP = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

PROC_NET_FILES = [
    ("tcp", Path("/proc/net/tcp"), socket.AF_INET),
    ("tcp6", Path("/proc/net/tcp6"), socket.AF_INET6),
    ("udp", Path("/proc/net/udp"), socket.AF_INET),
    ("udp6", Path("/proc/net/udp6"), socket.AF_INET6),
]

TEMP_DIRECTORIES = (Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"))
IGNORED_TEMP_PREFIXES = (
    "/tmp/.mount_",
    "/tmp/.X11-unix",
    "/tmp/.font-unix",
    "/tmp/.ICE-unix",
    "/tmp/.Test-unix",
    "/tmp/.XIM-unix",
)

RETENTION_TABLES = (
    ("sentinel_network_snapshots", "timestamp"),
    ("sentinel_system_metrics", "timestamp"),
    ("sentinel_file_hashes", "timestamp"),
    ("sentinel_process_snapshots", "timestamp"),
    ("sentinel_auth_events", "timestamp"),
    ("sentinel_persistence_entries", "timestamp"),
    ("sentinel_vuln_matches", "timestamp"),
    ("sentinel_reputation_cache", "queried_at"),
)


def _decode_address(raw_address: str, family: int) -> tuple[str, int]:
    hex_ip, hex_port = raw_address.split(":")
    port = int(hex_port, 16)

    if family == socket.AF_INET:
        packed = bytes.fromhex(hex_ip)[::-1]
        return socket.inet_ntop(socket.AF_INET, packed), port

    packed = bytes.fromhex(hex_ip)
    normalized = b"".join(packed[index:index + 4][::-1] for index in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, normalized), port


def _build_inode_pid_map() -> dict[str, int]:
    inode_map: dict[str, int] = {}
    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.name.isdigit():
            continue
        fd_dir = proc_dir / "fd"
        if not fd_dir.exists():
            continue
        try:
            for fd in fd_dir.iterdir():
                try:
                    target = os.readlink(fd)
                except OSError:
                    continue
                if target.startswith("socket:[") and target.endswith("]"):
                    inode = target[8:-1]
                    inode_map.setdefault(inode, int(proc_dir.name))
        except PermissionError:
            continue
    return inode_map


def _read_process_name(pid: int, cache: dict[int, str]) -> str:
    if pid <= 0:
        return ""
    cached = cache.get(pid)
    if cached is not None:
        return cached
    try:
        cache[pid] = (Path("/proc") / str(pid) / "comm").read_text(encoding="utf-8").strip()
    except OSError:
        cache[pid] = ""
    return cache[pid]


def _collect_network(connection: Any, timestamp: str) -> tuple[int, list[str]]:
    warnings: list[str] = []
    rows: list[tuple[Any, ...]] = []
    inode_pid_map = _build_inode_pid_map()
    process_names: dict[int, str] = {}
    unresolved = 0

    for proto, proc_file, family in PROC_NET_FILES:
        if not proc_file.exists():
            continue
        try:
            lines = proc_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except PermissionError:
            warnings.append(f"network collector cannot read {proc_file}")
            continue

        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 10:
                continue
            try:
                local_addr, local_port = _decode_address(fields[1], family)
                remote_addr, remote_port = _decode_address(fields[2], family)
            except (OSError, ValueError):
                continue

            state = STATE_MAP.get(fields[3], fields[3])
            if proto.startswith("udp") and remote_port == 0 and remote_addr in {"0.0.0.0", "::"}:
                state = "LISTEN"

            pid = inode_pid_map.get(fields[9], 0)
            if pid == 0:
                unresolved += 1

            rows.append(
                (
                    uuid4().hex,
                    timestamp,
                    proto,
                    local_addr,
                    local_port,
                    remote_addr,
                    remote_port,
                    state,
                    pid,
                    _read_process_name(pid, process_names),
                )
            )

    if rows:
        connection.executemany(
            """
            INSERT INTO sentinel_network_snapshots (
                id, timestamp, proto, local_addr, local_port, remote_addr, remote_port,
                state, pid, process_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    if unresolved:
        warnings.append(f"network collector could not attribute pid for {unresolved} sockets")
    return len(rows), warnings


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _record_file(path: Path, timestamp: str) -> tuple[tuple[Any, ...] | None, str]:
    try:
        stat_result = path.stat()
        if not stat.S_ISREG(stat_result.st_mode):
            return None, "not_regular"
        return (
            (
                uuid4().hex,
                timestamp,
                str(path),
                _hash_file(path),
                int(stat_result.st_size),
                float(stat_result.st_mtime),
                float(stat_result.st_ctime),
                int(stat_result.st_uid),
                int(stat_result.st_gid),
                int(stat_result.st_mode & 0o7777),
            ),
            "",
        )
    except FileNotFoundError:
        return None, "missing"
    except PermissionError:
        return None, "unreadable"
    except OSError as exc:
        return None, f"error:{exc}"


def _temp_file_suspicious(path: Path) -> bool:
    try:
        path_str = str(path)
        if any(path_str.startswith(prefix) for prefix in IGNORED_TEMP_PREFIXES):
            return False
        stat_result = path.stat()
        if not stat.S_ISREG(stat_result.st_mode):
            return False
        with path.open("rb") as handle:
            head = handle.read(64)
        executable = bool(stat_result.st_mode & 0o111)
        elf = head.startswith(b"\x7fELF")
        shebang = head.startswith(b"#!")
        hidden = path.name.startswith(".")
        return executable or elf or shebang or (hidden and (executable or elf or shebang))
    except OSError:
        return False


def _collect_file_hashes(connection: Any, settings: Any, timestamp: str) -> tuple[int, list[str]]:
    warnings: list[str] = []
    rows: list[tuple[Any, ...]] = []
    seen_paths: set[str] = set()
    unreadable_watch_paths: list[str] = []

    for path_str in settings.sentinel.files.watch_paths:
        path = Path(path_str).expanduser()
        if str(path) in seen_paths:
            continue
        seen_paths.add(str(path))
        row, issue = _record_file(path, timestamp)
        if row is not None:
            rows.append(row)
        elif issue == "unreadable":
            unreadable_watch_paths.append(str(path))
        elif issue.startswith("error:"):
            warnings.append(f"file collector error {path}: {issue[6:]}")

    for directory in TEMP_DIRECTORIES:
        if directory == Path("/dev/shm") and not settings.sentinel.files.scan_dev_shm:
            continue
        if directory in {Path("/tmp"), Path("/var/tmp")} and not settings.sentinel.files.scan_tmp:
            continue
        if not directory.exists():
            continue
        for root, _, filenames in os.walk(directory, followlinks=False):
            for filename in filenames:
                path = Path(root) / filename
                if str(path) in seen_paths or not _temp_file_suspicious(path):
                    continue
                seen_paths.add(str(path))
                row, _ = _record_file(path, timestamp)
                if row is not None:
                    rows.append(row)

    if rows:
        connection.executemany(
            """
            INSERT INTO sentinel_file_hashes (
                id, timestamp, path, sha256, size_bytes, mtime, ctime, uid, gid, mode
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    if unreadable_watch_paths:
        warnings.append(
            "file collector cannot read watch paths: "
            + ", ".join(sorted(unreadable_watch_paths))
        )
    return len(rows), warnings


def _read_cpu_times() -> tuple[int, int]:
    cpu_line = Path("/proc/stat").read_text(encoding="utf-8").splitlines()[0]
    values = [int(part) for part in cpu_line.split()[1:]]
    total = sum(values)
    idle = values[3] + (values[4] if len(values) > 4 else 0)
    return total, idle


def _cpu_percent() -> float:
    try:
        total_1, idle_1 = _read_cpu_times()
        time.sleep(0.15)
        total_2, idle_2 = _read_cpu_times()
    except (IndexError, OSError, ValueError):
        return 0.0

    total_delta = total_2 - total_1
    idle_delta = idle_2 - idle_1
    if total_delta <= 0:
        return 0.0
    busy = total_delta - idle_delta
    return round(max(0.0, min(100.0, busy * 100.0 / total_delta)), 2)


def _read_meminfo() -> tuple[int, int]:
    total_kb = 0
    available_kb = 0
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        if line.startswith("MemTotal:"):
            total_kb = int(line.split()[1])
        elif line.startswith("MemAvailable:"):
            available_kb = int(line.split()[1])
    return total_kb, available_kb


def _read_net_bytes() -> tuple[int, int]:
    recv = 0
    sent = 0
    for line in Path("/proc/net/dev").read_text(encoding="utf-8").splitlines()[2:]:
        interface, values = line.split(":", 1)
        if interface.strip() == "lo":
            continue
        counters = values.split()
        recv += int(counters[0])
        sent += int(counters[8])
    return sent, recv


def _collect_metrics(connection: Any, timestamp: str) -> tuple[int, list[str]]:
    warnings: list[str] = []
    try:
        mem_total_kb, mem_available_kb = _read_meminfo()
        mem_used_kb = max(mem_total_kb - mem_available_kb, 0)
        mem_pct = (mem_used_kb * 100.0 / mem_total_kb) if mem_total_kb else 0.0
        disk = shutil.disk_usage("/")
        disk_used_gb = (disk.used / (1024 ** 3)) if disk.total else 0.0
        disk_pct = (disk.used * 100.0 / disk.total) if disk.total else 0.0
        net_sent, net_recv = _read_net_bytes()
        load_1m = os.getloadavg()[0]
        row = (
            uuid4().hex,
            timestamp,
            _cpu_percent(),
            round(mem_pct, 2),
            round(mem_used_kb / 1024.0, 2),
            round(disk_pct, 2),
            round(disk_used_gb, 2),
            net_sent,
            net_recv,
            round(load_1m, 2),
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        warnings.append(f"metrics collector error: {exc}")
        return 0, warnings

    connection.execute(
        """
        INSERT INTO sentinel_system_metrics (
            id, timestamp, cpu_pct, mem_pct, mem_used_mb, disk_pct, disk_used_gb,
            net_bytes_sent, net_bytes_recv, load_1m
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        row,
    )
    return 1, warnings


def _collect_processes(connection: Any, settings: Any, timestamp: str) -> tuple[int, list[str]]:
    warnings: list[str] = []
    rows: list[tuple[Any, ...]] = []
    clk_tck = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096

    for proc_dir in Path("/proc").iterdir():
        if not proc_dir.name.isdigit():
            continue
        pid = int(proc_dir.name)
        try:
            stat_path = proc_dir / "stat"
            stat_text = stat_path.read_text(encoding="utf-8", errors="replace")
        except (PermissionError, OSError):
            continue

        # Parse /proc/[pid]/stat — process name is in parens, may contain spaces
        paren_open = stat_text.index("(")
        paren_close = stat_text.rindex(")")
        name = stat_text[paren_open + 1 : paren_close]
        fields_after = stat_text[paren_close + 2 :].split()
        if len(fields_after) < 22:
            continue

        ppid = int(fields_after[1])
        utime = int(fields_after[11])
        stime = int(fields_after[12])
        rss_pages = int(fields_after[21])
        rss_bytes = rss_pages * page_size

        # CPU % approximation: (utime + stime) / uptime — rough snapshot
        try:
            uptime = float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0])
            total_ticks = utime + stime
            cpu_pct = round((total_ticks / clk_tck / uptime) * 100.0, 2) if uptime > 0 else 0.0
        except (OSError, ValueError, ZeroDivisionError):
            cpu_pct = 0.0

        # Read username from /proc/[pid]/status
        user = ""
        try:
            status_text = (proc_dir / "status").read_text(encoding="utf-8", errors="replace")
            for line in status_text.splitlines():
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    try:
                        import pwd
                        user = pwd.getpwuid(uid).pw_name
                    except (KeyError, ImportError):
                        user = str(uid)
                    break
        except (PermissionError, OSError):
            pass

        # Read exe path
        exe_path = ""
        try:
            exe_path = os.readlink(proc_dir / "exe")
        except OSError:
            pass

        # Read cmdline
        cmdline = ""
        try:
            raw = (proc_dir / "cmdline").read_bytes()
            if raw:
                cmdline = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        except (PermissionError, OSError):
            pass

        # Parent name
        parent_name = _read_process_name(ppid, {}) if ppid > 0 else ""

        rows.append(
            (
                uuid4().hex,
                timestamp,
                pid,
                name,
                user,
                ppid,
                parent_name,
                exe_path,
                cmdline[:2000],
                cpu_pct,
                rss_bytes,
            )
        )

    if rows:
        connection.executemany(
            """
            INSERT INTO sentinel_process_snapshots (
                id, timestamp, pid, name, user, ppid, parent_name, exe_path,
                cmdline, cpu_pct, rss_bytes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    return len(rows), warnings


# Auth log patterns
_AUTH_LOG_PATHS = [
    Path("/var/log/auth.log"),       # Debian/Ubuntu
    Path("/var/log/secure"),          # RHEL/CentOS
]

_AUTH_PATTERNS = [
    # sshd accepted
    (
        re.compile(r"sshd\[\d+\]: Accepted (\S+) for (\S+) from ([\d.]+)"),
        "ssh_accept",
        lambda m: {"method": m.group(1), "user": m.group(2), "source_ip": m.group(3), "severity": "info"},
    ),
    # sshd failed
    (
        re.compile(r"sshd\[\d+\]: Failed (\S+) for (?:invalid user )?(\S+) from ([\d.]+)"),
        "ssh_fail",
        lambda m: {"method": m.group(1), "user": m.group(2), "source_ip": m.group(3), "severity": "warning"},
    ),
    # sudo
    (
        re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.+)"),
        "sudo",
        lambda m: {"user": m.group(1), "detail": m.group(2).strip()[:500], "severity": "info"},
    ),
    # su session opened
    (
        re.compile(r"su\[\d+\]: .*session opened for user (\S+)"),
        "su_open",
        lambda m: {"user": m.group(1), "severity": "info"},
    ),
    # login failure
    (
        re.compile(r"pam_unix\(.*:auth\): authentication failure;.*user=(\S+)"),
        "auth_fail",
        lambda m: {"user": m.group(1), "severity": "warning"},
    ),
]


def _collect_auth(connection: Any, timestamp: str) -> tuple[int, list[str]]:
    warnings: list[str] = []
    rows: list[tuple[Any, ...]] = []

    # Find the most recent watermark
    cursor = connection.execute(
        "SELECT MAX(timestamp) AS ts FROM sentinel_auth_events"
    )
    last_ts = cursor.fetchone()["ts"]

    log_path = None
    for candidate in _AUTH_LOG_PATHS:
        if candidate.exists():
            log_path = candidate
            break

    if log_path is None:
        warnings.append("auth collector: no auth log found")
        return 0, warnings

    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except PermissionError:
        warnings.append(f"auth collector: cannot read {log_path}")
        return 0, warnings

    for line in lines:
        for pattern, event_type, extractor in _AUTH_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            fields = extractor(match)
            rows.append(
                (
                    uuid4().hex,
                    timestamp,
                    event_type,
                    fields.get("user", ""),
                    fields.get("source_ip", ""),
                    fields.get("method", ""),
                    fields.get("detail", ""),
                    fields.get("severity", "info"),
                )
            )
            break  # one match per line

    if rows:
        connection.executemany(
            """
            INSERT INTO sentinel_auth_events (
                id, timestamp, event_type, user, source_ip, method, detail, severity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    return len(rows), warnings


# Persistence mechanisms to check
_CRON_DIRS = [
    Path("/etc/cron.d"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
    Path("/var/spool/cron/crontabs"),
]

_SYSTEMD_DIRS = [
    Path("/etc/systemd/system"),
    Path("/usr/lib/systemd/system"),
]


def _collect_persistence(connection: Any, timestamp: str) -> tuple[int, list[str]]:
    warnings: list[str] = []
    rows: list[tuple[Any, ...]] = []
    seen_paths: set[str] = set()

    def _add_entry(mechanism: str, path: Path, detail: str = "") -> None:
        path_str = str(path)
        if path_str in seen_paths:
            return
        seen_paths.add(path_str)
        content_hash = ""
        try:
            if path.is_file():
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                content_hash = digest.hexdigest()
        except (PermissionError, OSError):
            pass
        rows.append((uuid4().hex, timestamp, mechanism, path_str, content_hash, detail))

    # 1. Crontabs
    for cron_dir in _CRON_DIRS:
        if not cron_dir.is_dir():
            continue
        try:
            for entry in cron_dir.iterdir():
                if entry.is_file():
                    _add_entry("cron", entry)
        except PermissionError:
            warnings.append(f"persistence collector: cannot read {cron_dir}")

    # /etc/crontab
    crontab = Path("/etc/crontab")
    if crontab.is_file():
        _add_entry("cron", crontab)

    # 2. Systemd unit files (user-created / overrides)
    for systemd_dir in _SYSTEMD_DIRS:
        if not systemd_dir.is_dir():
            continue
        try:
            for entry in systemd_dir.iterdir():
                if entry.is_file() and entry.suffix in (".service", ".timer"):
                    _add_entry("systemd", entry)
        except PermissionError:
            warnings.append(f"persistence collector: cannot read {systemd_dir}")

    # 3. rc.local
    rc_local = Path("/etc/rc.local")
    if rc_local.is_file():
        _add_entry("rc_local", rc_local)

    # 4. LD_PRELOAD
    ld_preload = Path("/etc/ld.so.preload")
    if ld_preload.is_file():
        try:
            content = ld_preload.read_text(encoding="utf-8", errors="replace").strip()
            detail = content[:500] if content else ""
            _add_entry("ld_preload", ld_preload, detail)
        except (PermissionError, OSError):
            _add_entry("ld_preload", ld_preload)

    # 5. /etc/environment
    env_file = Path("/etc/environment")
    if env_file.is_file():
        _add_entry("environment", env_file)

    # 6. Shell profiles
    for profile in [
        Path("/etc/profile"),
        Path("/etc/bash.bashrc"),
        Path("/etc/profile.d"),
    ]:
        if profile.is_file():
            _add_entry("shell_profile", profile)
        elif profile.is_dir():
            try:
                for entry in profile.iterdir():
                    if entry.is_file():
                        _add_entry("shell_profile", entry)
            except PermissionError:
                pass

    # 7. XDG autostart
    autostart_dirs = [
        Path("/etc/xdg/autostart"),
    ]
    # Also check user-level autostart
    xdg_config = os.environ.get("XDG_CONFIG_HOME", "")
    if xdg_config:
        autostart_dirs.append(Path(xdg_config) / "autostart")
    else:
        home = os.environ.get("HOME", "")
        if home:
            autostart_dirs.append(Path(home) / ".config" / "autostart")

    for autostart_dir in autostart_dirs:
        if not autostart_dir.is_dir():
            continue
        try:
            for entry in autostart_dir.iterdir():
                if entry.is_file() and entry.suffix == ".desktop":
                    _add_entry("xdg_autostart", entry)
        except PermissionError:
            pass

    if rows:
        connection.executemany(
            """
            INSERT INTO sentinel_persistence_entries (
                id, timestamp, mechanism, path, content_hash, detail
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    return len(rows), warnings


def _prune_retention(connection: Any, settings: Any) -> dict[str, int]:
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=max(int(settings.sentinel.retention_days), 1))
    ).replace(microsecond=0).isoformat()
    deleted: dict[str, int] = {}
    for table, column in RETENTION_TABLES:
        cursor = connection.execute(f"DELETE FROM {table} WHERE {column} < ?", (cutoff,))
        deleted[table] = int(cursor.rowcount or 0)
    return deleted


def collect(settings: Any | None = None) -> dict[str, Any]:
    resolved_settings = settings or get_settings()
    ensure_schema(resolved_settings)
    timestamp = utcnow()
    counts: dict[str, int] = {}
    warnings: list[str] = []

    with connect(resolved_settings) as connection:
        network_count, network_warnings = _collect_network(connection, timestamp)
        file_count, file_warnings = _collect_file_hashes(connection, resolved_settings, timestamp)
        metrics_count, metrics_warnings = _collect_metrics(connection, timestamp)
        process_count, process_warnings = _collect_processes(connection, resolved_settings, timestamp)
        auth_count, auth_warnings = _collect_auth(connection, timestamp)
        persistence_count, persistence_warnings = _collect_persistence(connection, timestamp)
        pruned = _prune_retention(connection, resolved_settings)
        connection.commit()

    counts["network"] = network_count
    counts["file_hashes"] = file_count
    counts["metrics"] = metrics_count
    counts["processes"] = process_count
    counts["auth"] = auth_count
    counts["persistence"] = persistence_count
    warnings.extend(network_warnings)
    warnings.extend(file_warnings)
    warnings.extend(metrics_warnings)
    warnings.extend(process_warnings)
    warnings.extend(auth_warnings)
    warnings.extend(persistence_warnings)

    return {
        "timestamp": timestamp,
        "counts": counts,
        "warnings": warnings,
        "pruned": pruned,
    }
