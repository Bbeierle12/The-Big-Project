//! High-performance parsers for security tool output.
//!
//! Consolidates nmap XML, Suricata EVE JSON, Zeek log, and PCAP flow parsers
//! that were previously in separate crates (netsec-nmap, netsec-stream).

pub mod nmap;
pub mod suricata;
pub mod pcap;
pub mod zeek;
