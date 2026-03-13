//! MetadataEngine -- orchestrates extraction and optional security analysis.

use crate::config::MetadataConfig;
use crate::handler::HandlerRegistry;
use crate::handlers::ImageHandler;
use crate::security::MetadataAnalysis;
use crate::types::{
    ContentMetadata, ExtractionConfig, ExtractionMode, ExtractOptions, ExtractedMetadata,
    FileContext, HashAlgorithm, ProvenanceInfo,
};
use crate::utils::{get_file_identity, get_format_info};
use crate::{MetadataError, MetadataResult};
use chrono::Utc;
use netsec_models::alert::NormalizedAlert;
use std::path::Path;
use std::sync::Arc;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Metadata extraction engine.
pub struct MetadataEngine {
    registry: HandlerRegistry,
    config: ExtractionConfig,
    metadata_config: MetadataConfig,
}

impl MetadataEngine {
    /// Create an engine from a full `MetadataConfig`.
    pub fn from_config(config: MetadataConfig) -> Self {
        let extraction_config = config.to_extraction_config();
        let mut registry = HandlerRegistry::new();
        registry.register(Arc::new(ImageHandler::new()));
        Self {
            registry,
            config: extraction_config,
            metadata_config: config,
        }
    }

    /// Create an engine with the given registry and extraction config.
    pub fn new(registry: HandlerRegistry, config: ExtractionConfig) -> Self {
        Self {
            registry,
            config,
            metadata_config: MetadataConfig::default(),
        }
    }

    /// Create with default configuration and the image handler pre-registered.
    pub fn with_defaults() -> Self {
        Self::from_config(MetadataConfig::default())
    }

    /// Extract metadata from a single file.
    pub fn extract<P: AsRef<Path>>(
        &self,
        path: P,
        options: &ExtractOptions,
    ) -> MetadataResult<ExtractedMetadata> {
        let path = path.as_ref();
        let warnings: Vec<String> = Vec::new();
        let mut errors = Vec::new();

        // Determine hash algorithm.
        let hash_algo = if options.compute_hash != HashAlgorithm::None {
            options.compute_hash
        } else {
            self.config.default_hash_algorithm
        };

        // Pass 1: File identity (hash, size, timestamps).
        let (identity, data) = get_file_identity(path, hash_algo)?;

        // Check file size.
        if identity.size > self.config.max_file_size_bytes {
            return Err(MetadataError::FileTooLarge {
                size: identity.size,
                max: self.config.max_file_size_bytes,
            });
        }

        // Pass 2: Format detection (magic bytes, MIME).
        let format = get_format_info(&data, &identity.extension);

        // Find handler.
        let handler = self
            .registry
            .get_handler(&format.mime, &identity.extension)
            .ok_or_else(|| MetadataError::NoHandler {
                mime: format.mime.clone(),
                extension: identity.extension.clone(),
            })?;

        // Create file context.
        let context = FileContext {
            path: path.to_path_buf(),
            data,
            identity: identity.clone(),
            format: format.clone(),
        };

        // Validate file.
        handler.validate(&context)?;

        // Determine extraction mode.
        let deep = options.deep || self.config.deep_extraction_by_default;

        // Pass 3/4: Metadata extraction.
        let content = if deep {
            match handler.extract_deep(&context) {
                Ok(c) => c,
                Err(e) => {
                    errors.push(format!("Deep extraction failed: {}", e));
                    ContentMetadata::default()
                }
            }
        } else {
            match handler.extract_shallow(&context) {
                Ok(c) => c,
                Err(e) => {
                    errors.push(format!("Shallow extraction failed: {}", e));
                    ContentMetadata::default()
                }
            }
        };

        // Build provenance.
        let manifest = handler.manifest();
        let provenance = ProvenanceInfo {
            extracted_at: Utc::now(),
            extractor_version: VERSION.to_string(),
            handler_name: manifest.name.to_string(),
            handler_version: manifest.version.to_string(),
            extraction_mode: if deep {
                ExtractionMode::Deep
            } else {
                ExtractionMode::Shallow
            },
            warnings: if warnings.is_empty() {
                None
            } else {
                Some(warnings)
            },
            errors: if errors.is_empty() {
                None
            } else {
                Some(errors)
            },
        };

        Ok(ExtractedMetadata {
            file: identity,
            format,
            content,
            provenance,
        })
    }

    /// Extract metadata and run security analysis in one call.
    ///
    /// Returns the metadata plus an optional `NormalizedAlert` if the risk
    /// score exceeds the configured threshold.
    pub fn analyze<P: AsRef<Path>>(
        &self,
        path: P,
        options: &ExtractOptions,
    ) -> MetadataResult<(ExtractedMetadata, MetadataAnalysis, Option<NormalizedAlert>)> {
        let meta = self.extract(path, options)?;
        let analysis =
            MetadataAnalysis::analyze(&meta, &self.metadata_config.security);
        let alert =
            analysis.to_alert(&meta, self.metadata_config.security.alert_threshold);
        Ok((meta, analysis, alert))
    }

    /// Extract metadata from multiple files.
    #[allow(clippy::type_complexity)]
    pub fn extract_batch<P: AsRef<Path>>(
        &self,
        paths: &[P],
        options: &ExtractOptions,
        mut on_progress: Option<&mut dyn FnMut(usize, usize, &Path)>,
        mut on_error: Option<&mut dyn FnMut(&MetadataError, &Path)>,
    ) -> Vec<ExtractedMetadata> {
        let total = paths.len();
        let mut results = Vec::with_capacity(total);

        for (i, path) in paths.iter().enumerate() {
            let path = path.as_ref();

            match self.extract(path, options) {
                Ok(metadata) => {
                    results.push(metadata);
                }
                Err(e) => {
                    if let Some(ref mut callback) = on_error {
                        callback(&e, path);
                    }
                }
            }

            if let Some(ref mut callback) = on_progress {
                callback(i + 1, total, path);
            }
        }

        results
    }

    /// Check if a file type is supported.
    pub fn is_supported(&self, mime: &str, extension: &str) -> bool {
        self.registry.has_handler(mime, extension)
    }

    /// Get the current extraction configuration.
    pub fn config(&self) -> &ExtractionConfig {
        &self.config
    }

    /// Update extraction configuration.
    pub fn set_config(&mut self, config: ExtractionConfig) {
        self.config = config;
    }

    /// Get the full metadata configuration.
    pub fn metadata_config(&self) -> &MetadataConfig {
        &self.metadata_config
    }

    /// Get a reference to the registry.
    pub fn registry(&self) -> &HandlerRegistry {
        &self.registry
    }

    /// Get a mutable reference to the registry (to add custom handlers).
    pub fn registry_mut(&mut self) -> &mut HandlerRegistry {
        &mut self.registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_with_defaults() {
        let engine = MetadataEngine::with_defaults();
        assert!(engine.is_supported("image/jpeg", ".jpg"));
        assert!(engine.is_supported("image/png", ".png"));
        assert!(!engine.is_supported("application/pdf", ".pdf"));
    }

    #[test]
    fn engine_from_config() {
        let cfg = MetadataConfig::default();
        let engine = MetadataEngine::from_config(cfg);
        assert_eq!(engine.registry().handler_count(), 1);
        assert!(engine.registry().list_handlers().contains(&"image"));
    }

    #[test]
    fn engine_extract_nonexistent() {
        let engine = MetadataEngine::with_defaults();
        let opts = ExtractOptions::default();
        let result = engine.extract("/tmp/does_not_exist_netsec_test.jpg", &opts);
        assert!(result.is_err());
    }

    #[test]
    fn engine_extract_real_png() {
        // Create a minimal valid 1x1 PNG in a temp file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.png");

        let img = image::RgbImage::new(1, 1);
        img.save(&path).unwrap();

        let engine = MetadataEngine::with_defaults();
        let opts = ExtractOptions::default();
        let meta = engine.extract(&path, &opts).unwrap();

        assert_eq!(meta.file.name, "test.png");
        assert_eq!(meta.format.mime, "image/png");
        assert!(meta.content.technical.is_some());
        let tech = meta.content.technical.unwrap();
        assert_eq!(tech.width, 1);
        assert_eq!(tech.height, 1);
    }

    #[test]
    fn engine_analyze_clean_png() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clean.png");

        let img = image::RgbImage::new(2, 2);
        img.save(&path).unwrap();

        let engine = MetadataEngine::with_defaults();
        let opts = ExtractOptions::default();
        let (meta, analysis, alert) = engine.analyze(&path, &opts).unwrap();

        assert_eq!(meta.file.name, "clean.png");
        assert_eq!(analysis.risk_score, 0.0);
        assert!(alert.is_none());
    }

    #[test]
    fn engine_file_too_large() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.png");

        let img = image::RgbImage::new(1, 1);
        img.save(&path).unwrap();

        let cfg = MetadataConfig {
            max_file_size_bytes: 1, // 1 byte limit
            ..Default::default()
        };
        let engine = MetadataEngine::from_config(cfg);
        let opts = ExtractOptions::default();
        let result = engine.extract(&path, &opts);
        assert!(matches!(result, Err(MetadataError::FileTooLarge { .. })));
    }

    #[test]
    fn engine_batch_extract() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = dir.path().join("a.png");
        let p2 = dir.path().join("b.png");
        image::RgbImage::new(1, 1).save(&p1).unwrap();
        image::RgbImage::new(2, 2).save(&p2).unwrap();

        let engine = MetadataEngine::with_defaults();
        let opts = ExtractOptions::default();
        let results = engine.extract_batch(&[&p1, &p2], &opts, None, None);
        assert_eq!(results.len(), 2);
    }
}
