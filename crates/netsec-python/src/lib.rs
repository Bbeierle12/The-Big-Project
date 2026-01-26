//! PyO3 bindings exposing the Rust netsec engine to Python.
//!
//! This crate produces a `netsec_core` Python module that FastAPI routers
//! call into for all core engine operations.
//!
//! Phase 0: Re-exports existing parser functions for backward compatibility.
//! Phase 5: Full engine, services, event bus, scheduler bindings.

use pyo3::prelude::*;

// Re-export existing parser functions for backward compatibility
mod parsers;

/// The netsec_core Python module.
#[pymodule]
fn netsec_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Parser sub-module (backward compat with netsec_nmap + netsec_stream)
    let parsers_mod = PyModule::new_bound(m.py(), "parsers")?;
    parsers::register(&parsers_mod)?;
    m.add_submodule(&parsers_mod)?;

    Ok(())
}
