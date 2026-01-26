//! Alert processing pipeline: normalize -> dedup -> correlate -> score -> dispatch.

pub mod normalization;
pub mod deduplication;
pub mod correlation;
pub mod scoring;
pub mod dispatch;

use netsec_events::EventBus;
use netsec_models::alert::{Alert, NormalizedAlert};
use sqlx::SqlitePool;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("normalization error: {0}")]
    Normalization(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("correlation error: {0}")]
    Correlation(String),
    #[error("dispatch error: {0}")]
    Dispatch(String),
    #[error("event bus error: {0}")]
    EventBus(String),
}

pub type PipelineResult<T> = Result<T, PipelineError>;

/// Configuration for the alert processing pipeline.
pub struct PipelineConfig {
    /// Window in seconds for correlating alerts from the same device.
    pub correlation_window_secs: i64,
    /// Ports that trigger a severity boost when targeted.
    pub critical_ports: Vec<u16>,
    /// Threshold for high-count deduplication (reserved for future use).
    pub high_count_threshold: i64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            correlation_window_secs: 300,
            critical_ports: vec![22, 23, 3389, 445, 1433, 3306, 5432, 6379, 27017],
            high_count_threshold: 5,
        }
    }
}

/// The 5-stage alert processing pipeline.
pub struct Pipeline {
    pool: SqlitePool,
    #[allow(dead_code)]
    event_bus: EventBus,
    config: PipelineConfig,
    dispatch_targets: Vec<Box<dyn dispatch::DispatchTarget>>,
}

impl Pipeline {
    /// Create a pipeline with default config and DB + EventBus dispatch targets.
    pub fn new(pool: SqlitePool, event_bus: EventBus) -> Self {
        let db_target = dispatch::DatabaseTarget::new(pool.clone());
        let bus_target = dispatch::EventBusTarget::new(event_bus.clone());
        Self {
            pool,
            event_bus,
            config: PipelineConfig::default(),
            dispatch_targets: vec![Box::new(db_target), Box::new(bus_target)],
        }
    }

    /// Create a pipeline with a custom config and DB + EventBus dispatch targets.
    pub fn with_config(pool: SqlitePool, event_bus: EventBus, config: PipelineConfig) -> Self {
        let db_target = dispatch::DatabaseTarget::new(pool.clone());
        let bus_target = dispatch::EventBusTarget::new(event_bus.clone());
        Self {
            pool,
            event_bus,
            config,
            dispatch_targets: vec![Box::new(db_target), Box::new(bus_target)],
        }
    }

    /// Add an additional dispatch target.
    pub fn add_dispatch_target(&mut self, target: Box<dyn dispatch::DispatchTarget>) {
        self.dispatch_targets.push(target);
    }

    /// Process a normalized alert through the pipeline stages:
    /// deduplicate -> correlate -> score -> dispatch.
    pub async fn process(&self, normalized: NormalizedAlert) -> PipelineResult<Alert> {
        // Stage 2: Deduplicate
        let dedup_result = deduplication::deduplicate(&self.pool, &normalized).await?;
        if let deduplication::DeduplicationResult::Duplicate(existing) = dedup_result {
            return Ok(existing);
        }

        // Stage 3: Correlate
        let correlation_id = correlation::correlate(
            &self.pool,
            &normalized,
            self.config.correlation_window_secs,
        )
        .await?;

        // Stage 4: Score
        let final_severity = scoring::score(&normalized, &self.config).await;

        // Stage 5: Dispatch
        let alert = dispatch::dispatch(
            &normalized,
            final_severity,
            correlation_id,
            &self.dispatch_targets,
        )
        .await?;

        Ok(alert)
    }
}
