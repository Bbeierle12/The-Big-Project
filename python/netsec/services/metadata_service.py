"""Metadata extraction service.

Provides file metadata extraction and security analysis, mirroring the
Rust netsec-metadata engine.  When PyO3 bindings are available the service
will delegate to the compiled Rust engine; until then it uses Python-native
extraction with hashlib + mimetypes.
"""
from __future__ import annotations

import hashlib
import logging
import mimetypes
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Supported MIME types (mirrors the Rust image handler).
SUPPORTED_MIMES: list[str] = [
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/tiff",
    "image/bmp",
    "image/webp",
]

SUPPORTED_EXTENSIONS: list[str] = [
    ".jpg", ".jpeg", ".png", ".gif", ".tiff", ".tif", ".bmp", ".webp",
]

# Maximum file size default: 500 MB.
DEFAULT_MAX_FILE_SIZE: int = 500 * 1024 * 1024


@dataclass
class FileIdentity:
    """Basic file identity information."""
    path: str
    name: str
    extension: str
    size: int
    sha256: str
    modified_at: str


@dataclass
class SecurityFlags:
    """Security flags detected during analysis."""
    has_gps: bool = False
    has_software_id: bool = False
    has_author_info: bool = False
    has_timestamp_anomaly: bool = False
    has_mime_mismatch: bool = False
    details: list[str] = field(default_factory=list)

    @property
    def flag_count(self) -> int:
        return sum([
            self.has_gps,
            self.has_software_id,
            self.has_author_info,
            self.has_timestamp_anomaly,
            self.has_mime_mismatch,
        ])


@dataclass
class MetadataResult:
    """Result of metadata extraction."""
    file: FileIdentity
    mime: str
    detected_mime: str | None
    metadata: dict[str, Any]
    flags: SecurityFlags
    risk_score: float
    severity: str
    alert_generated: bool = False


def _compute_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_mime(path: Path) -> str | None:
    """Detect MIME type from extension."""
    mime, _ = mimetypes.guess_type(str(path))
    return mime


def _risk_to_severity(score: float) -> str:
    if score >= 0.8:
        return "critical"
    elif score >= 0.6:
        return "high"
    elif score >= 0.4:
        return "medium"
    elif score >= 0.2:
        return "low"
    return "info"


class MetadataService:
    """File metadata extraction and security analysis service."""

    def __init__(self, max_file_size: int = DEFAULT_MAX_FILE_SIZE) -> None:
        self._max_file_size = max_file_size

    def extract(self, file_path: str) -> MetadataResult:
        """Extract metadata from a file.

        Args:
            file_path: Absolute path to the file.

        Returns:
            MetadataResult with file identity, detected MIME, and raw metadata.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file exceeds the size limit.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        stat = path.stat()
        if stat.st_size > self._max_file_size:
            raise ValueError(
                f"File too large: {stat.st_size} bytes (max {self._max_file_size})"
            )

        sha256 = _compute_sha256(path)
        detected_mime = _detect_mime(path)
        ext = path.suffix.lower()

        identity = FileIdentity(
            path=str(path.resolve()),
            name=path.name,
            extension=ext,
            size=stat.st_size,
            sha256=sha256,
            modified_at=datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc
            ).isoformat(),
        )

        metadata: dict[str, Any] = {
            "file_size": stat.st_size,
            "extension": ext,
            "detected_mime": detected_mime,
        }

        # EXIF extraction for images (best-effort, requires Pillow).
        exif_data: dict[str, Any] = {}
        if detected_mime and detected_mime.startswith("image/"):
            try:
                from PIL import Image
                from PIL.ExifTags import TAGS

                with Image.open(path) as img:
                    metadata["width"] = img.width
                    metadata["height"] = img.height
                    metadata["mode"] = img.mode

                    raw_exif = img.getexif()
                    if raw_exif:
                        for tag_id, value in raw_exif.items():
                            tag_name = TAGS.get(tag_id, str(tag_id))
                            try:
                                exif_data[tag_name] = str(value)
                            except Exception:
                                exif_data[tag_name] = repr(value)
                        metadata["exif"] = exif_data
            except ImportError:
                logger.debug("Pillow not installed; skipping EXIF extraction")
            except Exception as exc:
                logger.debug("EXIF extraction failed: %s", exc)

        # Security analysis.
        flags = self._analyze_security(identity, metadata, exif_data, detected_mime, ext)
        risk_score = self._compute_risk_score(flags)
        severity = _risk_to_severity(risk_score)

        return MetadataResult(
            file=identity,
            mime=detected_mime or "application/octet-stream",
            detected_mime=detected_mime,
            metadata=metadata,
            flags=flags,
            risk_score=risk_score,
            severity=severity,
        )

    def _analyze_security(
        self,
        identity: FileIdentity,
        metadata: dict[str, Any],
        exif_data: dict[str, Any],
        detected_mime: str | None,
        extension: str,
    ) -> SecurityFlags:
        """Compute security flags from extracted metadata."""
        flags = SecurityFlags()

        # GPS check.
        gps_keys = {"GPSInfo", "GPSLatitude", "GPSLongitude"}
        if gps_keys & set(exif_data.keys()):
            flags.has_gps = True
            flags.details.append("GPS data found in EXIF")

        # Software check.
        if "Software" in exif_data:
            flags.has_software_id = True
            flags.details.append(f"Software identified: {exif_data['Software']}")

        # Author/creator check.
        author_keys = {"Artist", "Author", "Creator", "Make", "Model"}
        found_author_keys = author_keys & set(exif_data.keys())
        if found_author_keys:
            flags.has_author_info = True
            for key in found_author_keys:
                flags.details.append(f"{key}: {exif_data[key]}")

        # MIME mismatch check.
        if detected_mime:
            guessed = mimetypes.guess_type(f"file{extension}")[0]
            if guessed and guessed != detected_mime:
                flags.has_mime_mismatch = True
                flags.details.append(
                    f"MIME mismatch: detected={detected_mime}, extension says {guessed}"
                )

        return flags

    def _compute_risk_score(self, flags: SecurityFlags) -> float:
        """Compute risk score from security flags (mirrors Rust implementation)."""
        score = 0.0
        if flags.has_gps:
            score += 0.35
        if flags.has_software_id:
            score += 0.10
        if flags.has_author_info:
            score += 0.15
        if flags.has_timestamp_anomaly:
            score += 0.25
        if flags.has_mime_mismatch:
            score += 0.30
        return min(score, 1.0)

    def is_supported(self, mime: str | None = None, extension: str | None = None) -> bool:
        """Check if a MIME type or extension is supported."""
        if mime and mime in SUPPORTED_MIMES:
            return True
        if extension:
            ext = extension if extension.startswith(".") else f".{extension}"
            if ext.lower() in SUPPORTED_EXTENSIONS:
                return True
        return False

    def supported_types(self) -> dict[str, list[str]]:
        """Return supported MIME types and extensions."""
        return {
            "mime_types": list(SUPPORTED_MIMES),
            "extensions": list(SUPPORTED_EXTENSIONS),
        }
