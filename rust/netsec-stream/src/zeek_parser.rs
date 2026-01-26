//! Fast parser for Zeek tab-separated log files.

use pyo3::prelude::*;
use pyo3::types::PyList;

/// Parse Zeek tab-separated log data into a list of dicts.
///
/// Args:
///     data: Raw Zeek log content (with #fields header)
///
/// Returns:
///     List of dicts with field names as keys
#[pyfunction]
fn parse_zeek_log(py: Python<'_>, data: &str) -> PyResult<Py<PyList>> {
    let list = PyList::empty(py);
    let mut headers: Vec<&str> = Vec::new();

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with("#fields") {
            headers = line.split('\t').skip(1).collect();
            continue;
        }

        if line.starts_with('#') {
            continue;
        }

        if headers.is_empty() {
            continue;
        }

        let values: Vec<&str> = line.split('\t').collect();
        let dict = pyo3::types::PyDict::new(py);

        for (i, header) in headers.iter().enumerate() {
            let value = values.get(i).unwrap_or(&"-");
            if *value != "-" && *value != "(empty)" {
                dict.set_item(*header, *value)?;
            }
        }

        list.append(dict)?;
    }

    Ok(list.into())
}
