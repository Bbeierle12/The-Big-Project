//! Security analysis of extracted metadata.
//!
//! Computes `SecurityFlags` from an `ExtractedMetadata` result, assigns a
//! risk score, and optionally bridges to `NormalizedAlert` for the netsec pipeline.

use crate::config::SecurityAnalysisConfig;
use crate::types::ExtractedMetadata;
use chrono::Utc;
use netsec_models::alert::{AlertCategory, NormalizedAlert, Severity};
use serde::{Deserialize, Serialize};

/// Security flags detected in file metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityFlags {
    /// File contains GPS coordinates.
    pub has_gps: bool,

    /// File contains software/tool identification.
    pub has_software_id: bool,

    /// File contains author or creator information.
    pub has_author_info: bool,

    /// File has timestamp anomalies (future dates or large gaps).
    pub has_timestamp_anomaly: bool,

    /// File has a MIME / extension mismatch.
    pub has_mime_mismatch: bool,

    /// Human-readable details about each flag.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

/// Complete security analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataAnalysis {
    /// The computed security flags.
    pub flags: SecurityFlags,

    /// Risk score (0.0 = clean, 1.0 = maximum risk).
    pub risk_score: f64,

    /// Suggested severity based on risk score.
    pub severity: String,
}

impl SecurityFlags {
    /// Compute security flags from extracted metadata.
    pub fn from_metadata(meta: &ExtractedMetadata, cfg: &SecurityAnalysisConfig) -> Self {
        let mut flags = SecurityFlags::default();

        // GPS check.
        if cfg.flag_gps {
            if let Some(ref exif) = meta.content.exif {
                if let Some(ref gps) = exif.gps {
                    if gps.latitude.is_some() || gps.longitude.is_some() {
                        flags.has_gps = true;
                        let lat = gps.latitude.unwrap_or(0.0);
                        let lon = gps.longitude.unwrap_or(0.0);
                        flags
                            .details
                            .push(format!("GPS coordinates found: {:.4}, {:.4}", lat, lon));
                    }
                }
            }
        }

        // Software fingerprint check.
        if cfg.flag_software {
            if let Some(ref exif) = meta.content.exif {
                if let Some(ref sw) = exif.software {
                    flags.has_software_id = true;
                    flags
                        .details
                        .push(format!("Software identified: {}", sw));
                }
            }
        }

        // Author / creator leak check.
        if cfg.flag_author_leaks {
            // Check EXIF camera make/model.
            if let Some(ref exif) = meta.content.exif {
                if let Some(ref cam) = exif.camera {
                    if cam.make.is_some() || cam.model.is_some() {
                        flags.has_author_info = true;
                        let make = cam.make.as_deref().unwrap_or("?");
                        let model = cam.model.as_deref().unwrap_or("?");
                        flags
                            .details
                            .push(format!("Camera: {} {}", make, model));
                    }
                }
            }
            // Check IPTC creator.
            if let Some(ref iptc) = meta.content.iptc {
                if let Some(ref creator) = iptc.creator {
                    flags.has_author_info = true;
                    flags
                        .details
                        .push(format!("IPTC creator: {}", creator));
                }
            }
            // Check XMP creator.
            if let Some(ref xmp) = meta.content.xmp {
                if let Some(ref creators) = xmp.creator {
                    if !creators.is_empty() {
                        flags.has_author_info = true;
                        flags
                            .details
                            .push(format!("XMP creators: {}", creators.join(", ")));
                    }
                }
            }
        }

        // Timestamp anomaly check.
        if cfg.flag_timestamps {
            let now = Utc::now();
            if let Some(ref exif) = meta.content.exif {
                if let Some(ref dt) = exif.datetime {
                    // Future date check.
                    if let Some(ref orig) = dt.original {
                        if *orig > now {
                            flags.has_timestamp_anomaly = true;
                            flags
                                .details
                                .push("EXIF original date is in the future".into());
                        }
                    }
                    // Large gap between original and modified.
                    if let Some(ref orig) = dt.original {
                        if let Some(ref modified) = dt.modified {
                            let gap = (*modified - *orig).num_days().unsigned_abs();
                            if gap > 365 * 5 {
                                flags.has_timestamp_anomaly = true;
                                flags.details.push(format!(
                                    "Large EXIF date gap: {} days between original and modified",
                                    gap
                                ));
                            }
                        }
                    }
                }
            }
        }

        // MIME / extension mismatch.
        if let Some(ref by_magic) = meta.format.detected.by_magic_bytes {
            if let Some(ref by_ext) = meta.format.detected.by_extension {
                if by_magic != by_ext {
                    flags.has_mime_mismatch = true;
                    flags.details.push(format!(
                        "MIME mismatch: magic says {}, extension says {}",
                        by_magic, by_ext
                    ));
                }
            }
        }

        flags
    }

    /// Count how many flags are set.
    pub fn flag_count(&self) -> u32 {
        let mut count = 0;
        if self.has_gps {
            count += 1;
        }
        if self.has_software_id {
            count += 1;
        }
        if self.has_author_info {
            count += 1;
        }
        if self.has_timestamp_anomaly {
            count += 1;
        }
        if self.has_mime_mismatch {
            count += 1;
        }
        count
    }
}

impl MetadataAnalysis {
    /// Perform a full security analysis of extracted metadata.
    pub fn analyze(meta: &ExtractedMetadata, cfg: &SecurityAnalysisConfig) -> Self {
        let flags = SecurityFlags::from_metadata(meta, cfg);
        let risk_score = compute_risk_score(&flags);
        let severity = risk_to_severity(risk_score);

        Self {
            flags,
            risk_score,
            severity: severity.as_str().to_string(),
        }
    }

    /// Convert to a `NormalizedAlert` if the risk score exceeds the threshold.
    pub fn to_alert(
        &self,
        meta: &ExtractedMetadata,
        threshold: f64,
    ) -> Option<NormalizedAlert> {
        if self.risk_score < threshold {
            return None;
        }

        let severity = risk_to_severity(self.risk_score);
        let title = format!(
            "Metadata risk detected: {} (score {:.2})",
            meta.file.name, self.risk_score
        );
        let description = if self.flags.details.is_empty() {
            "No details".to_string()
        } else {
            self.flags.details.join("; ")
        };

        let fingerprint = format!(
            "metadata-risk:{}:{}",
            meta.file
                .hash
                .sha256
                .as_deref()
                .or(meta.file.hash.md5.as_deref())
                .unwrap_or(&meta.file.name),
            self.flags.flag_count()
        );

        let raw_data =
            serde_json::to_value(&self.flags).unwrap_or(serde_json::Value::Null);

        Some(NormalizedAlert {
            source_tool: "netsec-metadata".into(),
            severity,
            category: AlertCategory::Anomaly,
            title,
            description,
            device_ip: None,
            fingerprint,
            raw_data,
            timestamp: Utc::now(),
        })
    }
}

/// Compute a risk score from security flags.
fn compute_risk_score(flags: &SecurityFlags) -> f64 {
    let mut score = 0.0_f64;

    // Weights for each flag type.
    if flags.has_gps {
        score += 0.35;
    }
    if flags.has_software_id {
        score += 0.10;
    }
    if flags.has_author_info {
        score += 0.15;
    }
    if flags.has_timestamp_anomaly {
        score += 0.25;
    }
    if flags.has_mime_mismatch {
        score += 0.30;
    }

    score.min(1.0)
}

/// Map a risk score to a Severity.
fn risk_to_severity(score: f64) -> Severity {
    if score >= 0.8 {
        Severity::Critical
    } else if score >= 0.6 {
        Severity::High
    } else if score >= 0.4 {
        Severity::Medium
    } else if score >= 0.2 {
        Severity::Low
    } else {
        Severity::Info
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    /// Build a minimal ExtractedMetadata for testing.
    fn make_test_metadata() -> ExtractedMetadata {
        ExtractedMetadata {
            file: FileIdentity {
                path: "/tmp/test.jpg".into(),
                name: "test.jpg".into(),
                extension: ".jpg".into(),
                size: 1024,
                hash: FileHash {
                    sha256: Some("abc123".into()),
                    md5: None,
                },
                timestamps: FileTimestamps {
                    created: None,
                    modified: Utc::now(),
                    accessed: None,
                },
            },
            format: FormatInfo {
                mime: "image/jpeg".into(),
                extension: ".jpg".into(),
                detected: DetectedFormat {
                    by_magic_bytes: Some("image/jpeg".into()),
                    by_extension: Some("image/jpeg".into()),
                },
                confidence: Confidence::High,
            },
            content: ContentMetadata::default(),
            provenance: ProvenanceInfo {
                extracted_at: Utc::now(),
                extractor_version: "0.1.0".into(),
                handler_name: "image".into(),
                handler_version: "1.0.0".into(),
                extraction_mode: ExtractionMode::Shallow,
                warnings: None,
                errors: None,
            },
        }
    }

    #[test]
    fn flags_clean_file() {
        let meta = make_test_metadata();
        let cfg = SecurityAnalysisConfig::default();
        let flags = SecurityFlags::from_metadata(&meta, &cfg);
        assert!(!flags.has_gps);
        assert!(!flags.has_software_id);
        assert!(!flags.has_author_info);
        assert!(!flags.has_timestamp_anomaly);
        assert!(!flags.has_mime_mismatch);
        assert_eq!(flags.flag_count(), 0);
        assert!(flags.details.is_empty());
    }

    #[test]
    fn flags_gps_detected() {
        let mut meta = make_test_metadata();
        meta.content.exif = Some(ExifData {
            gps: Some(GpsInfo {
                latitude: Some(37.7749),
                longitude: Some(-122.4194),
                ..Default::default()
            }),
            ..Default::default()
        });

        let cfg = SecurityAnalysisConfig::default();
        let flags = SecurityFlags::from_metadata(&meta, &cfg);
        assert!(flags.has_gps);
        assert_eq!(flags.flag_count(), 1);
        assert!(flags.details[0].contains("GPS"));
    }

    #[test]
    fn flags_gps_disabled() {
        let mut meta = make_test_metadata();
        meta.content.exif = Some(ExifData {
            gps: Some(GpsInfo {
                latitude: Some(37.7749),
                longitude: Some(-122.4194),
                ..Default::default()
            }),
            ..Default::default()
        });

        let cfg = SecurityAnalysisConfig {
            flag_gps: false,
            ..Default::default()
        };
        let flags = SecurityFlags::from_metadata(&meta, &cfg);
        assert!(!flags.has_gps);
    }

    #[test]
    fn flags_software_and_author() {
        let mut meta = make_test_metadata();
        meta.content.exif = Some(ExifData {
            software: Some("Adobe Photoshop CC".into()),
            camera: Some(CameraInfo {
                make: Some("Canon".into()),
                model: Some("EOS R5".into()),
                lens: None,
            }),
            ..Default::default()
        });

        let cfg = SecurityAnalysisConfig::default();
        let flags = SecurityFlags::from_metadata(&meta, &cfg);
        assert!(flags.has_software_id);
        assert!(flags.has_author_info);
        assert_eq!(flags.flag_count(), 2);
    }

    #[test]
    fn flags_mime_mismatch() {
        let mut meta = make_test_metadata();
        meta.format.detected.by_magic_bytes = Some("image/png".into());
        meta.format.detected.by_extension = Some("image/jpeg".into());

        let cfg = SecurityAnalysisConfig::default();
        let flags = SecurityFlags::from_metadata(&meta, &cfg);
        assert!(flags.has_mime_mismatch);
        assert!(flags.details.iter().any(|d| d.contains("mismatch")));
    }

    #[test]
    fn analysis_clean_file() {
        let meta = make_test_metadata();
        let cfg = SecurityAnalysisConfig::default();
        let analysis = MetadataAnalysis::analyze(&meta, &cfg);
        assert_eq!(analysis.risk_score, 0.0);
        assert_eq!(analysis.severity, "info");
    }

    #[test]
    fn analysis_high_risk() {
        let mut meta = make_test_metadata();
        meta.content.exif = Some(ExifData {
            gps: Some(GpsInfo {
                latitude: Some(37.7749),
                longitude: Some(-122.4194),
                ..Default::default()
            }),
            software: Some("GIMP 2.10".into()),
            camera: Some(CameraInfo {
                make: Some("Nikon".into()),
                model: None,
                lens: None,
            }),
            ..Default::default()
        });
        // Also add MIME mismatch.
        meta.format.detected.by_magic_bytes = Some("image/png".into());
        meta.format.detected.by_extension = Some("image/jpeg".into());

        let cfg = SecurityAnalysisConfig::default();
        let analysis = MetadataAnalysis::analyze(&meta, &cfg);
        // GPS(0.35) + software(0.10) + author(0.15) + mismatch(0.30) = 0.90
        assert!(analysis.risk_score >= 0.8);
        assert_eq!(analysis.severity, "critical");
    }

    #[test]
    fn alert_below_threshold() {
        let meta = make_test_metadata();
        let cfg = SecurityAnalysisConfig::default();
        let analysis = MetadataAnalysis::analyze(&meta, &cfg);
        let alert = analysis.to_alert(&meta, 0.3);
        assert!(alert.is_none());
    }

    #[test]
    fn alert_above_threshold() {
        let mut meta = make_test_metadata();
        meta.content.exif = Some(ExifData {
            gps: Some(GpsInfo {
                latitude: Some(37.7749),
                longitude: Some(-122.4194),
                ..Default::default()
            }),
            ..Default::default()
        });

        let cfg = SecurityAnalysisConfig::default();
        let analysis = MetadataAnalysis::analyze(&meta, &cfg);
        let alert = analysis.to_alert(&meta, 0.3);
        assert!(alert.is_some());
        let alert = alert.unwrap();
        assert_eq!(alert.source_tool, "netsec-metadata");
        assert_eq!(alert.category, AlertCategory::Anomaly);
        assert!(alert.title.contains("test.jpg"));
    }

    #[test]
    fn risk_score_clamped() {
        let flags = SecurityFlags {
            has_gps: true,
            has_software_id: true,
            has_author_info: true,
            has_timestamp_anomaly: true,
            has_mime_mismatch: true,
            details: vec![],
        };
        let score = compute_risk_score(&flags);
        assert!(score <= 1.0);
    }

    #[test]
    fn iptc_creator_flagged() {
        let mut meta = make_test_metadata();
        meta.content.iptc = Some(IptcData {
            creator: Some("John Doe".into()),
            ..Default::default()
        });

        let cfg = SecurityAnalysisConfig::default();
        let flags = SecurityFlags::from_metadata(&meta, &cfg);
        assert!(flags.has_author_info);
        assert!(flags.details.iter().any(|d| d.contains("IPTC creator")));
    }

    #[test]
    fn xmp_creator_flagged() {
        let mut meta = make_test_metadata();
        meta.content.xmp = Some(XmpData {
            creator: Some(vec!["Jane Smith".into()]),
            ..Default::default()
        });

        let cfg = SecurityAnalysisConfig::default();
        let flags = SecurityFlags::from_metadata(&meta, &cfg);
        assert!(flags.has_author_info);
        assert!(flags.details.iter().any(|d| d.contains("XMP creators")));
    }
}
