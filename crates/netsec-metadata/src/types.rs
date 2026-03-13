//! Core type definitions for the metadata extraction engine.
//!
//! Ported from MetaExtract `core/types.rs` with all original types preserved,
//! plus new `SecurityFlags` and `MetadataAnalysis` types in the `security` module.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// File identity
// ---------------------------------------------------------------------------

/// File identity information (hash, size, timestamps).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileIdentity {
    pub path: PathBuf,
    pub name: String,
    pub extension: String,
    pub size: u64,
    pub hash: FileHash,
    pub timestamps: FileTimestamps,
}

/// File hash information.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileHash {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// File timestamp information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTimestamps {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
    pub modified: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessed: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Format detection
// ---------------------------------------------------------------------------

/// Format detection information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatInfo {
    pub mime: String,
    pub extension: String,
    pub detected: DetectedFormat,
    pub confidence: Confidence,
}

/// Detected format from different sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedFormat {
    pub by_magic_bytes: Option<String>,
    pub by_extension: Option<String>,
}

/// Confidence level for format detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

// ---------------------------------------------------------------------------
// EXIF / Camera
// ---------------------------------------------------------------------------

/// EXIF metadata from images.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExifData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub camera: Option<CameraInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<CameraSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datetime: Option<ExifDatetime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gps: Option<GpsInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orientation: Option<u16>,
}

/// Camera information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CameraInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub make: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens: Option<String>,
}

/// Camera settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CameraSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub focal_length: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aperture: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shutter_speed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iso: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flash: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exposure_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metering_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub white_balance: Option<String>,
}

/// EXIF datetime fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExifDatetime {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digitized: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified: Option<DateTime<Utc>>,
}

/// GPS information.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GpsInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub altitude: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// IPTC
// ---------------------------------------------------------------------------

/// IPTC metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IptcData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keywords: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub copyright: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_created: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

// ---------------------------------------------------------------------------
// XMP
// ---------------------------------------------------------------------------

/// XMP metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct XmpData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rights: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rating: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<HashMap<String, serde_json::Value>>,
}

// ---------------------------------------------------------------------------
// Image technical details
// ---------------------------------------------------------------------------

/// Image-specific technical details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageTechnicalDetails {
    pub width: u32,
    pub height: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_depth: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color_space: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_alpha: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_animated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression: Option<String>,
}

// ---------------------------------------------------------------------------
// Content metadata (aggregate)
// ---------------------------------------------------------------------------

/// Content metadata extracted from the file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContentMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exif: Option<ExifData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iptc: Option<IptcData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xmp: Option<XmpData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technical: Option<ImageTechnicalDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<HashMap<String, serde_json::Value>>,
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Provenance information about the extraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceInfo {
    pub extracted_at: DateTime<Utc>,
    pub extractor_version: String,
    pub handler_name: String,
    pub handler_version: String,
    pub extraction_mode: ExtractionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<String>>,
}

/// Extraction mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtractionMode {
    Shallow,
    Deep,
}

// ---------------------------------------------------------------------------
// Complete extraction result
// ---------------------------------------------------------------------------

/// Complete extracted metadata result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedMetadata {
    pub file: FileIdentity,
    pub format: FormatInfo,
    pub content: ContentMetadata,
    pub provenance: ProvenanceInfo,
}

// ---------------------------------------------------------------------------
// Handler manifest
// ---------------------------------------------------------------------------

/// Handler manifest describing capabilities.
#[derive(Debug, Clone)]
pub struct HandlerManifest {
    pub name: &'static str,
    pub version: &'static str,
    pub description: &'static str,
    pub supported_mimes: &'static [&'static str],
    pub supported_extensions: &'static [&'static str],
    pub priority: u32,
}

/// File context passed to handlers.
pub struct FileContext {
    pub path: PathBuf,
    pub data: Vec<u8>,
    pub identity: FileIdentity,
    pub format: FormatInfo,
}

// ---------------------------------------------------------------------------
// Extraction options
// ---------------------------------------------------------------------------

/// Extraction options.
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    pub deep: bool,
    pub compute_hash: HashAlgorithm,
    pub include_raw: bool,
}

/// Hash algorithm selection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    None,
    Md5,
    #[default]
    Sha256,
    Both,
}

/// Extraction configuration (runtime).
#[derive(Debug, Clone)]
pub struct ExtractionConfig {
    pub default_hash_algorithm: HashAlgorithm,
    pub deep_extraction_by_default: bool,
    pub include_raw_by_default: bool,
    pub max_file_size_bytes: u64,
    pub timeout_ms: u64,
}

impl Default for ExtractionConfig {
    fn default() -> Self {
        Self {
            default_hash_algorithm: HashAlgorithm::Sha256,
            deep_extraction_by_default: false,
            include_raw_by_default: false,
            max_file_size_bytes: 500 * 1024 * 1024, // 500 MB
            timeout_ms: 30_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_hash_serde_roundtrip() {
        let h = FileHash {
            md5: Some("abc123".into()),
            sha256: None,
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: FileHash = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
        // sha256 was None, so it should be absent from JSON
        assert!(!json.contains("sha256"));
    }

    #[test]
    fn confidence_serde() {
        let c = Confidence::High;
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, "\"high\"");
        let back: Confidence = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Confidence::High);
    }

    #[test]
    fn extraction_mode_serde() {
        let m = ExtractionMode::Deep;
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(json, "\"deep\"");
        let back: ExtractionMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ExtractionMode::Deep);
    }

    #[test]
    fn hash_algorithm_default() {
        assert_eq!(HashAlgorithm::default(), HashAlgorithm::Sha256);
    }

    #[test]
    fn extraction_config_defaults() {
        let cfg = ExtractionConfig::default();
        assert_eq!(cfg.default_hash_algorithm, HashAlgorithm::Sha256);
        assert!(!cfg.deep_extraction_by_default);
        assert!(!cfg.include_raw_by_default);
        assert_eq!(cfg.max_file_size_bytes, 500 * 1024 * 1024);
    }

    #[test]
    fn exif_data_default_empty() {
        let e = ExifData::default();
        assert!(e.camera.is_none());
        assert!(e.settings.is_none());
        assert!(e.datetime.is_none());
        assert!(e.gps.is_none());
        assert!(e.software.is_none());
        assert!(e.orientation.is_none());
    }

    #[test]
    fn gps_info_serde_roundtrip() {
        let gps = GpsInfo {
            latitude: Some(37.7749),
            longitude: Some(-122.4194),
            altitude: Some(10.0),
            timestamp: None,
        };
        let json = serde_json::to_string(&gps).unwrap();
        let back: GpsInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.latitude, Some(37.7749));
        assert_eq!(back.longitude, Some(-122.4194));
    }

    #[test]
    fn content_metadata_default_empty() {
        let cm = ContentMetadata::default();
        assert!(cm.exif.is_none());
        assert!(cm.iptc.is_none());
        assert!(cm.xmp.is_none());
        assert!(cm.technical.is_none());
        assert!(cm.raw.is_none());
    }

    #[test]
    fn xmp_data_serde_roundtrip() {
        let xmp = XmpData {
            creator: Some(vec!["Alice".into()]),
            title: Some("Test".into()),
            rating: Some(5),
            ..Default::default()
        };
        let json = serde_json::to_string(&xmp).unwrap();
        let back: XmpData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.creator.as_ref().unwrap()[0], "Alice");
        assert_eq!(back.rating, Some(5));
    }

    #[test]
    fn iptc_data_serde_roundtrip() {
        let iptc = IptcData {
            title: Some("Photo".into()),
            keywords: Some(vec!["nature".into(), "sunset".into()]),
            ..Default::default()
        };
        let json = serde_json::to_string(&iptc).unwrap();
        let back: IptcData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title, Some("Photo".into()));
        assert_eq!(back.keywords.as_ref().unwrap().len(), 2);
    }
}
