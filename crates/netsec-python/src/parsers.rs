//! PyO3 parser bindings — wraps netsec-parsers for Python consumption.
//!
//! Provides backward-compatible functions matching the old netsec_nmap and
//! netsec_stream Python modules.
//!
//! Stub — parser functions will be wired in Task #3 (move existing parsers).

use pyo3::prelude::*;

pub fn register(_m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Parser functions will be registered here after migration
    Ok(())
}
