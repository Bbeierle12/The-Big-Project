# Test Fixtures

Shared test data consumed by both Rust and Python test suites.

## Nmap XML Fixtures

| File | Description | Consumers |
|------|-------------|-----------|
| `nmap_single_host.xml` | Single host (192.168.1.1) with ports 22/80, OS Linux 5.x, MAC AA:BB:CC:DD:EE:FF | `tests/python/unit/test_nmap_adapter.py`, `crates/netsec-scanner/tests/integration.rs` |
| `nmap_empty.xml` | Valid nmap output with zero hosts | `tests/python/unit/test_nmap_adapter.py`, `crates/netsec-parsers/src/nmap.rs` |
| `nmap_ipv6_host.xml` | Single host with IPv6 address | `crates/netsec-parsers/src/nmap.rs` |
| `nmap_malformed.xml` | Truncated/invalid XML for error handling tests | `crates/netsec-parsers/src/nmap.rs` |

## Suricata EVE Fixtures

| File | Description | Consumers |
|------|-------------|-----------|
| `eve_alert.json` | Single Suricata alert event (JSONL) | `crates/netsec-parsers/src/suricata.rs` |
| `eve_mixed.json` | Alert + flow events (JSONL) | `crates/netsec-parsers/src/suricata.rs` |
| `eve_malformed.json` | Mix of valid and invalid JSONL for error handling | `crates/netsec-parsers/src/suricata.rs` |
