//! The main NetsecEngine that orchestrates all subsystems.
//!
//! Provides a single entry point for initializing the database, event bus,
//! pipeline, scanner, scheduler, and plugin registry.

use std::path::Path;
use std::time::Duration;

use netsec_events::EventBus;
use netsec_models::alert::NormalizedAlert;
use netsec_models::device::Device;
use netsec_models::event::{EventType, NetsecEvent};
use netsec_models::plugin::TriggerType;
use netsec_pipeline::{Pipeline, PipelineConfig};
use netsec_scanner::active::{ActiveScanner, ScanConfig};
use netsec_scheduler::Scheduler;
use sqlx::SqlitePool;
use thiserror::Error;
use tokio::task::JoinHandle;

use crate::config::{load_config, NetsecConfig};
use crate::plugin_registry::PluginRegistry;

/// Normalize a SQLite URL from Python-style to sqlx-compatible format.
///
/// Strips dialect suffixes like `+aiosqlite` from `sqlite+aiosqlite:///./db`
/// to produce `sqlite:./db` that sqlx can parse.
fn normalize_sqlite_url(url: &str) -> String {
    // Strip dialect suffix: "sqlite+aiosqlite:" -> "sqlite:"
    let url = if let Some(rest) = url.strip_prefix("sqlite+") {
        if let Some(pos) = rest.find(':') {
            format!("sqlite:{}", &rest[pos + 1..])
        } else {
            url.to_string()
        }
    } else {
        url.to_string()
    };

    // Normalize triple-slash relative path: "sqlite:///./db" -> "sqlite:./db"
    url.replace("sqlite:///./", "sqlite:./")
}

/// Errors produced by the engine.
#[derive(Debug, Error)]
pub enum EngineError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("scanner error: {0}")]
    Scanner(#[from] netsec_scanner::ScannerError),
    #[error("pipeline error: {0}")]
    Pipeline(#[from] netsec_pipeline::PipelineError),
    #[error("scheduler error: {0}")]
    Scheduler(#[from] netsec_scheduler::SchedulerError),
    #[error("{0}")]
    Other(String),
}

pub type EngineResult<T> = Result<T, EngineError>;

/// Central orchestration engine for the netsec platform.
///
/// Holds references to all subsystems and provides high-level operations
/// (scan, process alert, schedule job, etc.).
pub struct NetsecEngine {
    config: NetsecConfig,
    pool: SqlitePool,
    event_bus: EventBus,
    pipeline: Pipeline,
    scanner: ActiveScanner,
    scheduler: Scheduler,
    plugin_registry: PluginRegistry,
    metadata_engine: netsec_metadata::MetadataEngine,
    scheduler_handle: Option<JoinHandle<()>>,
}

impl NetsecEngine {
    /// Create a new engine instance, loading config from `config_dir`.
    ///
    /// 1. Loads layered TOML config.
    /// 2. Creates SQLite pool and runs migrations.
    /// 3. Initializes EventBus, Pipeline, ActiveScanner, Scheduler, PluginRegistry.
    pub async fn new(config_dir: Option<&Path>) -> EngineResult<Self> {
        let config = load_config(config_dir).map_err(|e| EngineError::Config(e.to_string()))?;

        let db_url = normalize_sqlite_url(&config.database.url);
        let pool = netsec_db::create_pool(&db_url).await?;
        netsec_db::run_migrations(&pool).await?;

        let event_bus = EventBus::new();

        let pipeline_config = PipelineConfig {
            correlation_window_secs: config.alerts.dedup_window_seconds as i64,
            ..PipelineConfig::default()
        };
        let pipeline = Pipeline::with_config(pool.clone(), event_bus.clone(), pipeline_config)?;

        let scanner = ActiveScanner::new(pool.clone(), event_bus.clone());

        let scheduler = Scheduler::new(
            pool.clone(),
            event_bus.clone(),
            Duration::from_secs(60),
        );

        let plugin_registry = PluginRegistry::new();

        let metadata_engine = netsec_metadata::MetadataEngine::with_defaults();

        Ok(Self {
            config,
            pool,
            event_bus,
            pipeline,
            scanner,
            scheduler,
            plugin_registry,
            metadata_engine,
            scheduler_handle: None,
        })
    }

    /// Create an engine with a pre-existing pool (useful for tests with in-memory SQLite).
    pub async fn new_with_pool(
        config_dir: Option<&Path>,
        pool: SqlitePool,
    ) -> EngineResult<Self> {
        let config = load_config(config_dir).map_err(|e| EngineError::Config(e.to_string()))?;

        netsec_db::run_migrations(&pool).await?;

        let event_bus = EventBus::new();

        let pipeline_config = PipelineConfig {
            correlation_window_secs: config.alerts.dedup_window_seconds as i64,
            ..PipelineConfig::default()
        };
        let pipeline = Pipeline::with_config(pool.clone(), event_bus.clone(), pipeline_config)?;

        let scanner = ActiveScanner::new(pool.clone(), event_bus.clone());

        let scheduler = Scheduler::new(
            pool.clone(),
            event_bus.clone(),
            Duration::from_secs(60),
        );

        let plugin_registry = PluginRegistry::new();

        let metadata_engine = netsec_metadata::MetadataEngine::with_defaults();

        Ok(Self {
            config,
            pool,
            event_bus,
            pipeline,
            scanner,
            scheduler,
            plugin_registry,
            metadata_engine,
            scheduler_handle: None,
        })
    }

    /// Start the engine: launches the scheduler tick loop and publishes
    /// a startup event on the event bus.
    pub async fn start(&mut self) -> EngineResult<()> {
        if self.config.scheduler.enabled {
            let handle = self.scheduler.start();
            self.scheduler_handle = Some(handle);
        }

        let event = NetsecEvent::new(
            EventType::ScanStarted, // reuse as "engine started" event
            serde_json::json!({"action": "engine_started"}),
        );
        let _ = self.event_bus.publish(event);

        Ok(())
    }

    /// Gracefully shut down the engine: stop scheduler, close pool.
    pub async fn shutdown(&mut self) -> EngineResult<()> {
        self.scheduler.shutdown();

        if let Some(handle) = self.scheduler_handle.take() {
            let _ = handle.await;
        }

        self.pool.close().await;

        Ok(())
    }

    /// Run a scan after validating the configuration.
    pub async fn scan(&self, config: &ScanConfig) -> EngineResult<Vec<Device>> {
        config.validate()?;
        let devices = self.scanner.run_scan(config).await?;
        Ok(devices)
    }

    /// Push a normalized alert through the pipeline.
    pub async fn process_alert(
        &self,
        normalized: NormalizedAlert,
    ) -> EngineResult<netsec_models::alert::Alert> {
        let alert = self.pipeline.process(normalized).await?;
        Ok(alert)
    }

    /// Insert a scheduled job into the database.
    pub async fn schedule_job(
        &self,
        trigger_type: TriggerType,
        trigger_args: &str,
        task_type: &str,
        task_params: &str,
    ) -> EngineResult<netsec_models::plugin::ScheduledJob> {
        let mut job =
            netsec_models::plugin::ScheduledJob::new(trigger_type, task_type.to_string());
        job.trigger_args = trigger_args.to_string();
        job.task_params = task_params.to_string();

        netsec_db::repo::scheduled_jobs::insert(&self.pool, &job).await?;
        Ok(job)
    }

    // --- Accessors ---

    /// Reference to the event bus.
    pub fn event_bus(&self) -> &EventBus {
        &self.event_bus
    }

    /// Reference to the SQLite pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Reference to the loaded configuration.
    pub fn config(&self) -> &NetsecConfig {
        &self.config
    }

    /// Immutable reference to the plugin registry.
    pub fn plugin_registry(&self) -> &PluginRegistry {
        &self.plugin_registry
    }

    /// Mutable reference to the plugin registry.
    pub fn plugin_registry_mut(&mut self) -> &mut PluginRegistry {
        &mut self.plugin_registry
    }

    /// Reference to the metadata extraction engine.
    pub fn metadata_engine(&self) -> &netsec_metadata::MetadataEngine {
        &self.metadata_engine
    }

    /// Extract metadata from a file, run security analysis, and publish a
    /// `MetadataExtracted` event on the event bus.
    ///
    /// Returns the full analysis tuple: (metadata, analysis, optional alert).
    pub fn extract_metadata(
        &self,
        path: &str,
    ) -> netsec_metadata::MetadataResult<(
        netsec_metadata::ExtractedMetadata,
        netsec_metadata::MetadataAnalysis,
        Option<NormalizedAlert>,
    )> {
        let opts = netsec_metadata::types::ExtractOptions::default();
        let result = self.metadata_engine.analyze(path, &opts)?;

        // Publish MetadataExtracted event with summary payload.
        let (ref meta, ref analysis, ref alert) = result;
        let event = NetsecEvent::new(
            EventType::MetadataExtracted,
            serde_json::json!({
                "file": meta.file.name,
                "mime": meta.format.mime,
                "risk_score": analysis.risk_score,
                "severity": analysis.severity,
                "flags": analysis.flags.flag_count(),
                "alert_generated": alert.is_some(),
            }),
        );
        let _ = self.event_bus.publish(event);

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn config_dir() -> PathBuf {
        let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        dir.pop(); // crates/
        dir.pop(); // workspace root
        dir.join("config")
    }

    async fn test_engine() -> NetsecEngine {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        NetsecEngine::new_with_pool(Some(&config_dir()), pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_engine_new() {
        let engine = test_engine().await;
        assert!(!engine.config().server.host.is_empty());
        assert_eq!(engine.plugin_registry().count(), 0);
    }

    #[tokio::test]
    async fn test_engine_start_and_shutdown() {
        let mut engine = test_engine().await;
        engine.start().await.unwrap();

        // Verify event bus has a subscriber (the scheduler created one internally)
        // Just ensure no panic on start/shutdown cycle
        engine.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_engine_scan_validates_config() {
        let engine = test_engine().await;

        // Invalid config should fail validation
        let bad_config = ScanConfig {
            target: "".to_string(),
            scan_type: netsec_models::scan::ScanType::Discovery,
            timing: 4,
            ports: None,
        };
        let result = engine.scan(&bad_config).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("target must not be empty"));
    }

    #[tokio::test]
    async fn test_engine_accessors() {
        let mut engine = test_engine().await;

        // pool is accessible
        let _pool = engine.pool();

        // event_bus is accessible
        let _bus = engine.event_bus();

        // plugin_registry is accessible
        assert_eq!(engine.plugin_registry().count(), 0);

        // plugin_registry_mut is accessible
        let registry = engine.plugin_registry_mut();
        assert_eq!(registry.count(), 0);
    }

    #[tokio::test]
    async fn test_engine_schedule_job() {
        let engine = test_engine().await;

        let job = engine
            .schedule_job(
                TriggerType::Interval,
                r#"{"interval_secs": 3600}"#,
                "discovery_scan",
                r#"{"target": "192.168.1.0/24"}"#,
            )
            .await
            .unwrap();

        assert_eq!(job.task_type, "discovery_scan");
        assert_eq!(job.trigger_type, "interval");
        assert!(job.enabled);

        // Verify it's in the database
        let from_db =
            netsec_db::repo::scheduled_jobs::get_by_id(engine.pool(), &job.id)
                .await
                .unwrap();
        assert!(from_db.is_some());
    }

    #[tokio::test]
    async fn test_engine_invalid_config_dir() {
        let result = NetsecEngine::new(Some(Path::new("/nonexistent/config/dir"))).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_engine_metadata_engine_accessor() {
        let engine = test_engine().await;

        // metadata_engine is accessible and supports expected types
        let me = engine.metadata_engine();
        assert!(me.is_supported("image/jpeg", ".jpg"));
        assert!(me.is_supported("image/png", ".png"));
        assert!(!me.is_supported("application/pdf", ".pdf"));
    }

    #[tokio::test]
    async fn test_engine_extract_metadata_real_png() {
        let engine = test_engine().await;

        // Subscribe to capture the MetadataExtracted event
        let mut rx = engine.event_bus().subscribe();

        // Create a minimal PNG
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine_test.png");
        image::RgbImage::new(1, 1).save(&path).unwrap();

        let (meta, analysis, alert) = engine
            .extract_metadata(path.to_str().unwrap())
            .unwrap();

        assert_eq!(meta.file.name, "engine_test.png");
        assert_eq!(meta.format.mime, "image/png");
        assert_eq!(analysis.risk_score, 0.0);
        assert!(alert.is_none());

        // Verify a MetadataExtracted event was published
        let event = rx.recv().await.unwrap();
        assert_eq!(event.event_type, EventType::MetadataExtracted);
        assert_eq!(event.payload["file"], "engine_test.png");
        assert_eq!(event.payload["mime"], "image/png");
        assert_eq!(event.payload["alert_generated"], false);
    }

    #[tokio::test]
    async fn test_engine_extract_metadata_nonexistent() {
        let engine = test_engine().await;
        let result = engine.extract_metadata("/tmp/does_not_exist_netsec.jpg");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_sqlite_url() {
        // Python-style aiosqlite URL
        assert_eq!(
            normalize_sqlite_url("sqlite+aiosqlite:///./netsec.db"),
            "sqlite:./netsec.db"
        );
        // Already valid sqlx URL
        assert_eq!(
            normalize_sqlite_url("sqlite:netsec.db"),
            "sqlite:netsec.db"
        );
        // In-memory
        assert_eq!(
            normalize_sqlite_url("sqlite::memory:"),
            "sqlite::memory:"
        );
        // Other dialect suffix
        assert_eq!(
            normalize_sqlite_url("sqlite+pysqlite:///./test.db"),
            "sqlite:./test.db"
        );
    }
}
