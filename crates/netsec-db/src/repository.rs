//! Repository trait and implementations for all tables.
//!
//! Stub — full implementation in Phase 1.

use netsec_models::error::Result;

/// Generic async repository trait.
#[allow(async_fn_in_trait)]
pub trait Repository<T> {
    async fn get_by_id(&self, id: uuid::Uuid) -> Result<Option<T>>;
    async fn list(&self, limit: i64, offset: i64) -> Result<Vec<T>>;
    async fn create(&self, entity: &T) -> Result<T>;
    async fn delete(&self, id: uuid::Uuid) -> Result<bool>;
}
