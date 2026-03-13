"""Metadata extraction router.

Endpoints for file metadata extraction, security analysis, and
supported-type queries.  Mirrors the Rust netsec-metadata engine
behavior.
"""
from __future__ import annotations

import logging
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request, UploadFile, File
from pydantic import BaseModel

from netsec.core.events import Event, EventType
from netsec.services.metadata_service import MetadataService

logger = logging.getLogger(__name__)

router = APIRouter()

# Shared service instance.
_service = MetadataService()


# ---------- Response models ----------


class FileIdentityOut(BaseModel):
    path: str
    name: str
    extension: str
    size: int
    sha256: str
    modified_at: str


class SecurityFlagsOut(BaseModel):
    has_gps: bool
    has_software_id: bool
    has_author_info: bool
    has_timestamp_anomaly: bool
    has_mime_mismatch: bool
    flag_count: int
    details: list[str]


class MetadataExtractOut(BaseModel):
    file: FileIdentityOut
    mime: str
    detected_mime: str | None
    metadata: dict[str, Any]


class MetadataAnalyzeOut(BaseModel):
    file: FileIdentityOut
    mime: str
    detected_mime: str | None
    metadata: dict[str, Any]
    flags: SecurityFlagsOut
    risk_score: float
    severity: str
    alert_generated: bool


class SupportedTypesOut(BaseModel):
    mime_types: list[str]
    extensions: list[str]


# ---------- Helpers ----------


async def _save_upload(upload: UploadFile) -> Path:
    """Save an uploaded file to a temp location and return the path."""
    suffix = Path(upload.filename or "upload").suffix or ""
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        contents = await upload.read()
        tmp.write(contents)
        return Path(tmp.name)


def _get_event_bus(request: Request):
    """Get event bus from app state (may be None during tests)."""
    return getattr(request.app.state, "event_bus", None)


# ---------- Endpoints ----------


@router.post("/extract", response_model=MetadataExtractOut)
async def extract_metadata(
    request: Request,
    file: UploadFile = File(...),
) -> MetadataExtractOut:
    """Extract metadata from an uploaded file.

    Returns file identity, detected MIME type, and raw metadata
    without security analysis.
    """
    tmp_path = await _save_upload(file)
    try:
        result = _service.extract(str(tmp_path))
        return MetadataExtractOut(
            file=FileIdentityOut(
                path=result.file.path,
                name=file.filename or result.file.name,
                extension=result.file.extension,
                size=result.file.size,
                sha256=result.file.sha256,
                modified_at=result.file.modified_at,
            ),
            mime=result.mime,
            detected_mime=result.detected_mime,
            metadata=result.metadata,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except Exception as exc:
        logger.exception("Metadata extraction failed")
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        tmp_path.unlink(missing_ok=True)


@router.post("/analyze", response_model=MetadataAnalyzeOut)
async def analyze_metadata(
    request: Request,
    file: UploadFile = File(...),
) -> MetadataAnalyzeOut:
    """Extract metadata and run security analysis on an uploaded file.

    Returns file identity, metadata, security flags, risk score,
    and severity classification.  Publishes a ``metadata.extracted``
    event on the event bus.
    """
    tmp_path = await _save_upload(file)
    try:
        result = _service.extract(str(tmp_path))

        # Publish event.
        event_bus = _get_event_bus(request)
        if event_bus is not None:
            await event_bus.publish(Event(
                type=EventType.METADATA_EXTRACTED,
                source="metadata_router",
                data={
                    "file": file.filename or result.file.name,
                    "mime": result.mime,
                    "risk_score": result.risk_score,
                    "severity": result.severity,
                    "flags": result.flags.flag_count,
                    "alert_generated": result.alert_generated,
                },
            ))

        return MetadataAnalyzeOut(
            file=FileIdentityOut(
                path=result.file.path,
                name=file.filename or result.file.name,
                extension=result.file.extension,
                size=result.file.size,
                sha256=result.file.sha256,
                modified_at=result.file.modified_at,
            ),
            mime=result.mime,
            detected_mime=result.detected_mime,
            metadata=result.metadata,
            flags=SecurityFlagsOut(
                has_gps=result.flags.has_gps,
                has_software_id=result.flags.has_software_id,
                has_author_info=result.flags.has_author_info,
                has_timestamp_anomaly=result.flags.has_timestamp_anomaly,
                has_mime_mismatch=result.flags.has_mime_mismatch,
                flag_count=result.flags.flag_count,
                details=result.flags.details,
            ),
            risk_score=result.risk_score,
            severity=result.severity,
            alert_generated=result.alert_generated,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    except Exception as exc:
        logger.exception("Metadata analysis failed")
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        tmp_path.unlink(missing_ok=True)


@router.get("/supported", response_model=SupportedTypesOut)
async def supported_types() -> SupportedTypesOut:
    """List supported MIME types and file extensions."""
    types = _service.supported_types()
    return SupportedTypesOut(**types)
