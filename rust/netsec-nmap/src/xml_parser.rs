//! Fast Nmap XML output parser using quick-xml.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use quick_xml::events::Event;
use quick_xml::reader::Reader;

/// Parse Nmap XML output into structured Python dicts.
///
/// Args:
///     xml_data: Raw XML string from Nmap (-oX output)
///
/// Returns:
///     Dict with 'hosts' list and 'scan_info' metadata
#[pyfunction]
fn parse_nmap_xml(py: Python<'_>, xml_data: &str) -> PyResult<PyObject> {
    let result = PyDict::new(py);
    let hosts = PyList::empty(py);
    let scan_info = PyDict::new(py);

    let mut reader = Reader::from_str(xml_data);
    reader.config_mut().trim_text(true);

    let mut current_host: Option<Py<PyDict>> = None;
    let mut current_ports: Option<Py<PyList>> = None;
    let mut in_host = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                match name.as_str() {
                    "nmaprun" => {
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = String::from_utf8_lossy(&attr.value).to_string();
                            scan_info.set_item(&key, &val)?;
                        }
                    }
                    "host" => {
                        in_host = true;
                        let host = PyDict::new(py);
                        host.set_item("addresses", PyDict::new(py))?;
                        host.set_item("hostnames", PyList::empty(py))?;
                        host.set_item("ports", PyList::empty(py))?;
                        host.set_item("os", PyDict::new(py))?;
                        host.set_item("status", "unknown")?;
                        current_ports = Some(PyList::empty(py).into());
                        current_host = Some(host.into());
                    }
                    "status" if in_host => {
                        if let Some(ref host) = current_host {
                            let host = host.bind(py);
                            for attr in e.attributes().flatten() {
                                if attr.key.as_ref() == b"state" {
                                    let val = String::from_utf8_lossy(&attr.value).to_string();
                                    host.set_item("status", &val)?;
                                }
                            }
                        }
                    }
                    "address" if in_host => {
                        if let Some(ref host) = current_host {
                            let host = host.bind(py);
                            let addrs: Bound<'_, PyDict> = host.get_item("addresses")?.unwrap().downcast_into()?;
                            let mut addr_type = String::new();
                            let mut addr_val = String::new();
                            let mut vendor = String::new();
                            for attr in e.attributes().flatten() {
                                match attr.key.as_ref() {
                                    b"addrtype" => addr_type = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"addr" => addr_val = String::from_utf8_lossy(&attr.value).to_string(),
                                    b"vendor" => vendor = String::from_utf8_lossy(&attr.value).to_string(),
                                    _ => {}
                                }
                            }
                            addrs.set_item(&addr_type, &addr_val)?;
                            if !vendor.is_empty() {
                                addrs.set_item("vendor", &vendor)?;
                            }
                        }
                    }
                    "hostname" if in_host => {
                        if let Some(ref host) = current_host {
                            let host = host.bind(py);
                            let hostnames: Bound<'_, PyList> = host.get_item("hostnames")?.unwrap().downcast_into()?;
                            let hn = PyDict::new(py);
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let val = String::from_utf8_lossy(&attr.value).to_string();
                                hn.set_item(&key, &val)?;
                            }
                            hostnames.append(hn)?;
                        }
                    }
                    "port" if in_host => {
                        let port_dict = PyDict::new(py);
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"portid" => {
                                    let val = String::from_utf8_lossy(&attr.value).to_string();
                                    port_dict.set_item("port", val.parse::<u16>().unwrap_or(0))?;
                                }
                                b"protocol" => {
                                    let val = String::from_utf8_lossy(&attr.value).to_string();
                                    port_dict.set_item("protocol", &val)?;
                                }
                                _ => {}
                            }
                        }
                        if let Some(ref ports) = current_ports {
                            ports.bind(py).append(port_dict)?;
                        }
                    }
                    "state" if in_host => {
                        if let Some(ref ports) = current_ports {
                            let ports = ports.bind(py);
                            if ports.len() > 0 {
                                let last: Bound<'_, PyDict> = ports.get_item(ports.len() - 1)?.downcast_into()?;
                                for attr in e.attributes().flatten() {
                                    if attr.key.as_ref() == b"state" {
                                        let val = String::from_utf8_lossy(&attr.value).to_string();
                                        last.set_item("state", &val)?;
                                    }
                                }
                            }
                        }
                    }
                    "service" if in_host => {
                        if let Some(ref ports) = current_ports {
                            let ports = ports.bind(py);
                            if ports.len() > 0 {
                                let last: Bound<'_, PyDict> = ports.get_item(ports.len() - 1)?.downcast_into()?;
                                for attr in e.attributes().flatten() {
                                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                    let val = String::from_utf8_lossy(&attr.value).to_string();
                                    last.set_item(&key, &val)?;
                                }
                            }
                        }
                    }
                    "osmatch" if in_host => {
                        if let Some(ref host) = current_host {
                            let host = host.bind(py);
                            let os: Bound<'_, PyDict> = host.get_item("os")?.unwrap().downcast_into()?;
                            for attr in e.attributes().flatten() {
                                let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                let val = String::from_utf8_lossy(&attr.value).to_string();
                                os.set_item(&key, &val)?;
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if name == "host" {
                    if let Some(host) = current_host.take() {
                        let host = host.bind(py);
                        if let Some(ref ports) = current_ports {
                            host.set_item("ports", ports.bind(py))?;
                        }
                        hosts.append(host)?;
                    }
                    current_ports = None;
                    in_host = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    result.set_item("hosts", hosts)?;
    result.set_item("scan_info", scan_info)?;

    Ok(result.into())
}
