//! Fast batch parser for Suricata EVE JSON logs.

use pyo3::prelude::*;
use pyo3::types::PyList;
use serde::Deserialize;

#[derive(Deserialize)]
struct EveEvent {
    timestamp: Option<String>,
    event_type: Option<String>,
    src_ip: Option<String>,
    src_port: Option<u16>,
    dest_ip: Option<String>,
    dest_port: Option<u16>,
    proto: Option<String>,
    alert: Option<EveAlert>,
}

#[derive(Deserialize)]
struct EveAlert {
    action: Option<String>,
    signature: Option<String>,
    signature_id: Option<u64>,
    severity: Option<u8>,
    category: Option<String>,
}

/// Parse a batch of EVE JSON lines and return alert events as Python dicts.
///
/// Args:
///     data: Raw string containing newline-delimited EVE JSON
///     alerts_only: If True, only return alert events (default True)
///
/// Returns:
///     List of parsed event dicts
#[pyfunction]
#[pyo3(signature = (data, alerts_only=true))]
fn parse_eve_batch(py: Python<'_>, data: &str, alerts_only: bool) -> PyResult<Py<PyList>> {
    let list = PyList::empty(py);

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let event: EveEvent = match serde_json::from_str(line) {
            Ok(e) => e,
            Err(_) => continue,
        };

        if alerts_only {
            if event.event_type.as_deref() != Some("alert") {
                continue;
            }
        }

        let dict = pyo3::types::PyDict::new(py);
        if let Some(ref ts) = event.timestamp {
            dict.set_item("timestamp", ts)?;
        }
        if let Some(ref et) = event.event_type {
            dict.set_item("event_type", et)?;
        }
        if let Some(ref ip) = event.src_ip {
            dict.set_item("src_ip", ip)?;
        }
        if let Some(port) = event.src_port {
            dict.set_item("src_port", port)?;
        }
        if let Some(ref ip) = event.dest_ip {
            dict.set_item("dest_ip", ip)?;
        }
        if let Some(port) = event.dest_port {
            dict.set_item("dest_port", port)?;
        }
        if let Some(ref proto) = event.proto {
            dict.set_item("proto", proto)?;
        }

        if let Some(ref alert) = event.alert {
            let alert_dict = pyo3::types::PyDict::new(py);
            if let Some(ref action) = alert.action {
                alert_dict.set_item("action", action)?;
            }
            if let Some(ref sig) = alert.signature {
                alert_dict.set_item("signature", sig)?;
            }
            if let Some(sid) = alert.signature_id {
                alert_dict.set_item("signature_id", sid)?;
            }
            if let Some(sev) = alert.severity {
                alert_dict.set_item("severity", sev)?;
            }
            if let Some(ref cat) = alert.category {
                alert_dict.set_item("category", cat)?;
            }
            dict.set_item("alert", alert_dict)?;
        }

        list.append(dict)?;
    }

    Ok(list.into())
}
