//! Alert processing pipeline: normalize → dedup → correlate → score → dispatch.
//!
//! Stub — full implementation in Phase 2.

pub mod normalization;
pub mod deduplication;
pub mod correlation;
pub mod scoring;
pub mod dispatch;
