//! Passive network discovery: mDNS and SSDP multicast listeners.
//!
//! Uses `socket2` to create multicast UDP sockets, then converts them
//! to `tokio::net::UdpSocket` for async I/O.

use netsec_events::EventBus;
use sqlx::SqlitePool;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::passive::{self, MdnsRecord};
use crate::ScannerResult;

/// MDNS multicast group address.
const MDNS_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// MDNS port.
const MDNS_PORT: u16 = 5353;

/// SSDP multicast group address.
const SSDP_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
/// SSDP port.
const SSDP_PORT: u16 = 1900;

/// Passive scanner that listens for mDNS and SSDP multicast traffic.
pub struct PassiveScanner {
    pool: SqlitePool,
    event_bus: EventBus,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl PassiveScanner {
    /// Create a new passive scanner.
    pub fn new(pool: SqlitePool, event_bus: EventBus) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            pool,
            event_bus,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Start the mDNS listener in a background task.
    ///
    /// Joins the 224.0.0.251:5353 multicast group, receives DNS responses,
    /// parses them, and upserts discovered devices.
    pub async fn start_mdns(&self) -> ScannerResult<JoinHandle<()>> {
        let socket = create_multicast_socket(MDNS_MULTICAST_ADDR, MDNS_PORT)?;
        let pool = self.pool.clone();
        let _event_bus = self.event_bus.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            tracing::info!("mDNS listener shutting down");
                            break;
                        }
                    }
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, addr)) => {
                                let source_ip = addr.ip().to_string();
                                if let Some(record) = parse_mdns_response(&buf[..len], &source_ip) {
                                    if let Err(e) = passive::process_mdns_discovery(&pool, &record, &source_ip).await {
                                        tracing::warn!("Failed to process mDNS discovery: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("mDNS recv error: {e}");
                            }
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Start the SSDP listener in a background task.
    ///
    /// Sends an M-SEARCH discovery request to 239.255.255.250:1900,
    /// then listens for responses and upserts discovered devices.
    pub async fn start_ssdp(&self) -> ScannerResult<JoinHandle<()>> {
        let socket = create_multicast_socket(SSDP_MULTICAST_ADDR, SSDP_PORT)?;
        let pool = self.pool.clone();
        let _event_bus = self.event_bus.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();

        // Send M-SEARCH
        let msearch = build_ssdp_msearch();
        let target = SocketAddrV4::new(SSDP_MULTICAST_ADDR, SSDP_PORT);
        if let Err(e) = socket.send_to(msearch.as_bytes(), target).await {
            tracing::warn!("Failed to send SSDP M-SEARCH: {e}");
        }

        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                tokio::select! {
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            tracing::info!("SSDP listener shutting down");
                            break;
                        }
                    }
                    result = socket.recv_from(&mut buf) => {
                        match result {
                            Ok((len, addr)) => {
                                let source_ip = addr.ip().to_string();
                                let response = String::from_utf8_lossy(&buf[..len]);
                                if let Some(ssdp_device) = passive::parse_ssdp_response(&response) {
                                    if let Err(e) = passive::process_ssdp_discovery(&pool, &ssdp_device, &source_ip).await {
                                        tracing::warn!("Failed to process SSDP discovery: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!("SSDP recv error: {e}");
                            }
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    /// Signal all listener tasks to shut down.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

/// Create a multicast UDP socket bound to the given group and port.
///
/// Uses `socket2::Socket` with `SO_REUSEADDR` and `IP_ADD_MEMBERSHIP`,
/// then converts to `tokio::net::UdpSocket`.
fn create_multicast_socket(
    multicast_addr: Ipv4Addr,
    port: u16,
) -> ScannerResult<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|e| crate::ScannerError::PassiveParse(format!("socket creation failed: {e}")))?;

    socket
        .set_reuse_address(true)
        .map_err(|e| crate::ScannerError::PassiveParse(format!("set_reuse_address failed: {e}")))?;

    let bind_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    socket
        .bind(&bind_addr.into())
        .map_err(|e| crate::ScannerError::PassiveParse(format!("bind failed: {e}")))?;

    socket
        .join_multicast_v4(&multicast_addr, &Ipv4Addr::UNSPECIFIED)
        .map_err(|e| {
            crate::ScannerError::PassiveParse(format!("join_multicast_v4 failed: {e}"))
        })?;

    socket.set_nonblocking(true).map_err(|e| {
        crate::ScannerError::PassiveParse(format!("set_nonblocking failed: {e}"))
    })?;

    let std_socket: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_socket)
        .map_err(|e| crate::ScannerError::PassiveParse(format!("from_std failed: {e}")))
}

/// Extract mDNS record fields from raw DNS response bytes.
///
/// Performs basic DNS packet parsing: checks minimum length, extracts the
/// first question domain name as the service type, and associates it with
/// the source IP.
pub fn parse_mdns_response(data: &[u8], source_ip: &str) -> Option<MdnsRecord> {
    // DNS header is 12 bytes minimum
    if data.len() < 12 {
        return None;
    }

    // Try to extract the question/answer domain name
    // DNS names are encoded as length-prefixed labels
    let mut pos = 12; // skip header
    let mut labels = Vec::new();

    while pos < data.len() {
        let label_len = data[pos] as usize;
        if label_len == 0 {
            break;
        }
        // Pointer compression (top 2 bits set)
        if label_len & 0xC0 == 0xC0 {
            break;
        }
        pos += 1;
        if pos + label_len > data.len() {
            break;
        }
        if let Ok(label) = std::str::from_utf8(&data[pos..pos + label_len]) {
            labels.push(label.to_string());
        }
        pos += label_len;
    }

    if labels.is_empty() {
        return None;
    }

    let service_type = labels.join(".");

    // Try to parse as mDNS service name
    let hostname = if let Some((service, _proto)) = passive::parse_mdns_name(&service_type) {
        Some(format!("{}.{}", service, source_ip))
    } else {
        Some(service_type.clone())
    };

    Some(MdnsRecord {
        hostname,
        service_type,
        ip: Some(source_ip.to_string()),
        port: None,
    })
}

/// Build an SSDP M-SEARCH discovery request string.
///
/// The request is sent to 239.255.255.250:1900 to discover UPnP devices.
pub fn build_ssdp_msearch() -> String {
    "M-SEARCH * HTTP/1.1\r\n\
     HOST: 239.255.255.250:1900\r\n\
     MAN: \"ssdp:discover\"\r\n\
     MX: 3\r\n\
     ST: ssdp:all\r\n\
     \r\n"
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_ssdp_msearch() {
        let msearch = build_ssdp_msearch();
        assert!(msearch.contains("M-SEARCH"));
        assert!(msearch.contains("MAN:"));
        assert!(msearch.contains("ST:"));
        assert!(msearch.contains("MX:"));
    }

    #[test]
    fn test_build_ssdp_msearch_host() {
        let msearch = build_ssdp_msearch();
        assert!(msearch.contains("HOST: 239.255.255.250:1900"));
    }

    #[test]
    fn test_parse_mdns_response_empty() {
        assert!(parse_mdns_response(&[], "192.168.1.1").is_none());
        assert!(parse_mdns_response(&[0u8; 5], "192.168.1.1").is_none());
    }

    #[tokio::test]
    async fn test_passive_scanner_new() {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        netsec_db::run_migrations(&pool).await.unwrap();
        let bus = EventBus::new();
        let scanner = PassiveScanner::new(pool, bus);
        // Should create without panicking
        assert!(!*scanner.shutdown_rx.borrow());
    }

    #[tokio::test]
    async fn test_passive_scanner_shutdown() {
        let pool = netsec_db::pool::create_test_pool().await.unwrap();
        netsec_db::run_migrations(&pool).await.unwrap();
        let bus = EventBus::new();
        let scanner = PassiveScanner::new(pool, bus);
        scanner.shutdown();
        assert!(*scanner.shutdown_rx.borrow());
    }

    #[test]
    fn test_ssdp_response_integration() {
        let msearch = build_ssdp_msearch();
        assert!(msearch.starts_with("M-SEARCH"));

        // Simulate an SSDP response
        let response = "HTTP/1.1 200 OK\r\n\
                         LOCATION: http://192.168.1.1:80/desc.xml\r\n\
                         SERVER: Linux/3.0 UPnP/1.0\r\n\
                         ST: upnp:rootdevice\r\n\r\n";
        let device = passive::parse_ssdp_response(response).unwrap();
        assert_eq!(device.location, "http://192.168.1.1:80/desc.xml");
    }
}
