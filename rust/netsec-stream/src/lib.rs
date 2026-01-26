use pyo3::prelude::*;

mod suri_parser;
mod zeek_parser;
mod pcap_parser;

/// High-performance parsers for security tool output.
#[pymodule]
fn netsec_stream(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(suri_parser::parse_eve_batch, m)?)?;
    m.add_function(wrap_pyfunction!(zeek_parser::parse_zeek_log, m)?)?;
    m.add_function(wrap_pyfunction!(pcap_parser::extract_flows, m)?)?;
    Ok(())
}
