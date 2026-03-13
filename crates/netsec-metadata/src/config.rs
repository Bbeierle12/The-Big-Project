//! Serde-friendly configuration for the metadata extraction engine.

use crate::types::HashAlgorithm;
use serde::{Deserialize, Serialize};

/// Top-level metadata extraction configuration (serde-friendly).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetadataConfig {
    /// Default hash algorithm for file identity.
    #[serde(default)]
    pub hash_algorithm: HashAlgorithm,

    /// Whether to perform deep extraction by default.
    #[serde(default)]
    pub deep_by_default: bool,

    /// Include raw metadata fields in output.
    #[serde(default)]
    pub include_raw: bool,

    /// Maximum file size in bytes (0 = unlimited).
    #[serde(default = "default_max_file_size")]
    pub max_file_size_bytes: u64,

    /// Extraction timeout in milliseconds.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,

    /// Security analysis settings.
    #[serde(default)]
    pub security: SecurityAnalysisConfig,
}

/// Security analysis sub-configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAnalysisConfig {
    /// Flag GPS coordinates in metadata.
    #[serde(default = "default_true")]
    pub flag_gps: bool,

    /// Flag software/tool fingerprints.
    #[serde(default = "default_true")]
    pub flag_software: bool,

    /// Flag timestamp anomalies (future dates, large gaps).
    #[serde(default = "default_true")]
    pub flag_timestamps: bool,

    /// Flag embedded author/creator identifiers.
    #[serde(default = "default_true")]
    pub flag_author_leaks: bool,

    /// Minimum risk score to generate a NormalizedAlert (0.0 - 1.0).
    #[serde(default = "default_alert_threshold")]
    pub alert_threshold: f64,
}

impl Default for MetadataConfig {
    fn default() -> Self {
        Self {
            hash_algorithm: HashAlgorithm::Sha256,
            deep_by_default: false,
            include_raw: false,
            max_file_size_bytes: default_max_file_size(),
            timeout_ms: default_timeout_ms(),
            security: SecurityAnalysisConfig::default(),
        }
    }
}

impl Default for SecurityAnalysisConfig {
    fn default() -> Self {
        Self {
            flag_gps: true,
            flag_software: true,
            flag_timestamps: true,
            flag_author_leaks: true,
            alert_threshold: default_alert_threshold(),
        }
    }
}

fn default_max_file_size() -> u64 {
    500 * 1024 * 1024 // 500 MB
}

fn default_timeout_ms() -> u64 {
    30_000
}

fn default_true() -> bool {
    true
}

fn default_alert_threshold() -> f64 {
    0.3
}

impl MetadataConfig {
    /// Convert to the runtime ExtractionConfig.
    pub fn to_extraction_config(&self) -> crate::types::ExtractionConfig {
        crate::types::ExtractionConfig {
            default_hash_algorithm: self.hash_algorithm,
            deep_extraction_by_default: self.deep_by_default,
            include_raw_by_default: self.include_raw,
            max_file_size_bytes: self.max_file_size_bytes,
            timeout_ms: self.timeout_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_serde_roundtrip() {
        let cfg = MetadataConfig::default();
        let json = serde_json::to_string_pretty(&cfg).unwrap();
        let back: MetadataConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hash_algorithm, HashAlgorithm::Sha256);
        assert!(!back.deep_by_default);
        assert!(back.security.flag_gps);
    }

    #[test]
    fn config_from_empty_json() {
        let cfg: MetadataConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.hash_algorithm, HashAlgorithm::Sha256);
        assert_eq!(cfg.max_file_size_bytes, 500 * 1024 * 1024);
        assert!(cfg.security.flag_gps);
        assert_eq!(cfg.security.alert_threshold, 0.3);
    }

    #[test]
    fn config_custom_values() {
        let json = r#"{
            "hash_algorithm": "both",
            "deep_by_default": true,
            "max_file_size_bytes": 1048576,
            "security": {
                "flag_gps": false,
                "alert_threshold": 0.5
            }
        }"#;
        let cfg: MetadataConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.hash_algorithm, HashAlgorithm::Both);
        assert!(cfg.deep_by_default);
        assert_eq!(cfg.max_file_size_bytes, 1_048_576);
        assert!(!cfg.security.flag_gps);
        assert_eq!(cfg.security.alert_threshold, 0.5);
    }

    #[test]
    fn to_extraction_config() {
        let cfg = MetadataConfig {
            hash_algorithm: HashAlgorithm::Md5,
            deep_by_default: true,
            include_raw: true,
            max_file_size_bytes: 1024,
            timeout_ms: 5000,
            security: SecurityAnalysisConfig::default(),
        };
        let ec = cfg.to_extraction_config();
        assert_eq!(ec.default_hash_algorithm, HashAlgorithm::Md5);
        assert!(ec.deep_extraction_by_default);
        assert!(ec.include_raw_by_default);
        assert_eq!(ec.max_file_size_bytes, 1024);
        assert_eq!(ec.timeout_ms, 5000);
    }
}
