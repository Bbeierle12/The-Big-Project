use pyo3::prelude::*;

mod xml_parser;

#[pymodule]
fn netsec_nmap(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(xml_parser::parse_nmap_xml, m)?)?;
    Ok(())
}
