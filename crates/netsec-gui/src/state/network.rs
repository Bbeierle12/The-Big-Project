//! Network state management - nodes, connections, and vulnerabilities.

use crate::message::{
    ConnectionId, ConnectionType, NodeId, NodeStatus, NodeType, Severity,
};
use rand::Rng;

/// Layout configuration for radial positioning
pub mod layout {
    pub const CENTER_X: f32 = 400.0;
    pub const CENTER_Y: f32 = 200.0;
    pub const SPOKE_Y_OFFSET: f32 = 150.0;
    pub const BASE_RADIUS: f32 = 180.0;
    pub const RADIUS_VARIATION: f32 = 60.0;
}

/// A vulnerability detected on a node.
#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub cve: String,
    pub cvss: f32,
    pub severity: Severity,
    pub description: String,
    pub references: Vec<String>,
}

/// An open port on a node.
#[derive(Debug, Clone)]
pub struct Port {
    pub number: u16,
    pub protocol: String,
    pub state: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
}

/// A node on the network canvas.
#[derive(Debug, Clone)]
pub struct Node {
    pub id: NodeId,
    pub node_type: NodeType,
    pub x: f32,
    pub y: f32,
    pub label: String,
    pub status: NodeStatus,
    pub ip: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub oui: Option<String>,
    pub hostname: Option<String>,
    pub os_family: Option<String>,
    pub signal_strength: Option<u8>,
    pub ssids: Vec<String>,
    pub ports: Vec<Port>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub parent_id: Option<NodeId>,
    /// For group nodes
    pub width: Option<f32>,
    pub height: Option<f32>,
}

impl Node {
    pub fn new(node_type: NodeType, x: f32, y: f32, label: String, ip: String) -> Self {
        Self {
            id: NodeId::new(),
            node_type,
            x,
            y,
            label,
            status: NodeStatus::Online,
            ip,
            mac: None,
            vendor: None,
            oui: None,
            hostname: None,
            os_family: None,
            signal_strength: None,
            ssids: Vec::new(),
            ports: Vec::new(),
            vulnerabilities: Vec::new(),
            parent_id: None,
            width: None,
            height: None,
        }
    }

    pub fn has_vulnerabilities(&self) -> bool {
        !self.vulnerabilities.is_empty()
    }

    pub fn critical_vulns(&self) -> usize {
        self.vulnerabilities
            .iter()
            .filter(|v| matches!(v.severity, Severity::Critical))
            .count()
    }

    pub fn high_vulns(&self) -> usize {
        self.vulnerabilities
            .iter()
            .filter(|v| matches!(v.severity, Severity::High))
            .count()
    }
}

/// A connection between two nodes.
#[derive(Debug, Clone)]
pub struct Connection {
    pub id: ConnectionId,
    pub from: NodeId,
    pub to: NodeId,
    pub connection_type: ConnectionType,
    pub traffic: f32,
    pub ssid: Option<String>,
    pub speed: Option<String>,
}

impl Connection {
    pub fn new(from: NodeId, to: NodeId, connection_type: ConnectionType) -> Self {
        Self {
            id: ConnectionId::new(),
            from,
            to,
            connection_type,
            traffic: 0.0,
            ssid: None,
            speed: None,
        }
    }
}

/// Network canvas state.
#[derive(Debug, Default)]
pub struct NetworkState {
    pub nodes: Vec<Node>,
    pub connections: Vec<Connection>,
    pub selected_ids: Vec<NodeId>,
    pub hovered_connection: Option<ConnectionId>,
    pub pan: (f32, f32),
    pub zoom: f32,
    pub connecting_from: Option<NodeId>,
    pub is_scanning: bool,
    pub scan_progress: u8,
}

impl NetworkState {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            connections: Vec::new(),
            selected_ids: Vec::new(),
            hovered_connection: None,
            pan: (0.0, 0.0),
            zoom: 1.0,
            connecting_from: None,
            is_scanning: false,
            scan_progress: 0,
        }
    }

    /// Add a new node to the network.
    pub fn add_node(&mut self, node: Node) {
        self.nodes.push(node);
    }

    /// Remove a node and its connections.
    pub fn remove_node(&mut self, id: NodeId) {
        self.nodes.retain(|n| n.id != id);
        self.connections.retain(|c| c.from != id && c.to != id);
        self.selected_ids.retain(|&sid| sid != id);
    }

    /// Get a node by ID.
    pub fn get_node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }

    /// Get a mutable node by ID.
    pub fn get_node_mut(&mut self, id: NodeId) -> Option<&mut Node> {
        self.nodes.iter_mut().find(|n| n.id == id)
    }

    /// Select a single node.
    pub fn select_node(&mut self, id: NodeId) {
        self.selected_ids.clear();
        self.selected_ids.push(id);
    }

    /// Add nodes to selection.
    pub fn add_to_selection(&mut self, ids: &[NodeId]) {
        for id in ids {
            if !self.selected_ids.contains(id) {
                self.selected_ids.push(*id);
            }
        }
    }

    /// Clear selection.
    pub fn clear_selection(&mut self) {
        self.selected_ids.clear();
    }

    /// Get the first selected node.
    pub fn selected_node(&self) -> Option<&Node> {
        self.selected_ids.first().and_then(|&id| self.get_node(id))
    }

    /// Delete all selected nodes.
    pub fn delete_selected(&mut self) {
        let ids: Vec<_> = self.selected_ids.clone();
        for id in ids {
            self.remove_node(id);
        }
    }

    /// Add a connection between two nodes.
    pub fn add_connection(&mut self, from: NodeId, to: NodeId, connection_type: ConnectionType) {
        // Don't add duplicate connections
        if !self.connections.iter().any(|c|
            (c.from == from && c.to == to) || (c.from == to && c.to == from)
        ) {
            self.connections.push(Connection::new(from, to, connection_type));
        }
    }

    /// Get connections involving a specific node.
    pub fn connections_for_node(&self, id: NodeId) -> Vec<&Connection> {
        self.connections
            .iter()
            .filter(|c| c.from == id || c.to == id)
            .collect()
    }

    /// Get all vulnerabilities across all nodes.
    pub fn all_vulnerabilities(&self) -> Vec<(&Node, &Vulnerability)> {
        self.nodes
            .iter()
            .flat_map(|node| node.vulnerabilities.iter().map(move |v| (node, v)))
            .collect()
    }

    /// Count total vulnerabilities by severity.
    pub fn vuln_counts(&self) -> (usize, usize, usize, usize) {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;

        for node in &self.nodes {
            for vuln in &node.vulnerabilities {
                match vuln.severity {
                    Severity::Critical => critical += 1,
                    Severity::High => high += 1,
                    Severity::Medium => medium += 1,
                    Severity::Low => low += 1,
                }
            }
        }

        (critical, high, medium, low)
    }

    /// Move a node to a new position.
    pub fn move_node(&mut self, id: NodeId, x: f32, y: f32) {
        if let Some(node) = self.get_node_mut(id) {
            node.x = x;
            node.y = y;
        }
    }

    /// Pan the canvas.
    pub fn pan(&mut self, dx: f32, dy: f32) {
        self.pan.0 += dx;
        self.pan.1 += dy;
    }

    /// Set zoom level.
    pub fn set_zoom(&mut self, zoom: f32) {
        self.zoom = zoom.clamp(0.25, 4.0);
    }

    /// Find the hub node (Router > Firewall > first node).
    pub fn find_hub_node(&self) -> Option<NodeId> {
        // Priority 1: Router
        if let Some(node) = self.nodes.iter().find(|n| matches!(n.node_type, NodeType::Router)) {
            return Some(node.id);
        }
        // Priority 2: Firewall
        if let Some(node) = self.nodes.iter().find(|n| matches!(n.node_type, NodeType::Firewall)) {
            return Some(node.id);
        }
        // Fallback: first node
        self.nodes.first().map(|n| n.id)
    }

    /// Apply radial hub-and-spoke layout to all nodes.
    pub fn apply_radial_layout(&mut self) {
        use std::f32::consts::PI;

        if self.nodes.is_empty() {
            return;
        }

        let hub_id = match self.find_hub_node() {
            Some(id) => id,
            None => return,
        };

        // Position hub at center
        if let Some(hub) = self.get_node_mut(hub_id) {
            hub.x = layout::CENTER_X;
            hub.y = layout::CENTER_Y;
        }

        // Collect spoke node IDs (all nodes except hub)
        let spoke_ids: Vec<NodeId> = self.nodes
            .iter()
            .filter(|n| n.id != hub_id)
            .map(|n| n.id)
            .collect();

        let spoke_count = spoke_ids.len();
        if spoke_count == 0 {
            return;
        }

        // Position spokes in a circle around hub
        let mut rng = rand::thread_rng();
        for (index, node_id) in spoke_ids.iter().enumerate() {
            let angle = (2.0 * PI * index as f32) / spoke_count as f32;
            let radius = layout::BASE_RADIUS + rng.gen_range(0.0..layout::RADIUS_VARIATION);
            let x = layout::CENTER_X + angle.cos() * radius;
            let y = layout::CENTER_Y + layout::SPOKE_Y_OFFSET + angle.sin() * radius;

            if let Some(node) = self.get_node_mut(*node_id) {
                node.x = x;
                node.y = y;
            }
        }
    }

    /// Create connections from hub to all spoke nodes.
    pub fn create_hub_connections(&mut self) {
        let hub_id = match self.find_hub_node() {
            Some(id) => id,
            None => return,
        };

        // Collect spoke IDs and their types
        let spokes: Vec<(NodeId, NodeType)> = self.nodes
            .iter()
            .filter(|n| n.id != hub_id)
            .map(|n| (n.id, n.node_type.clone()))
            .collect();

        for (spoke_id, node_type) in spokes {
            // Determine connection type based on device type
            let conn_type = match node_type {
                NodeType::Server | NodeType::Database | NodeType::Firewall | NodeType::Workstation => {
                    ConnectionType::Wired
                }
                NodeType::Mobile | NodeType::IoT | NodeType::Extender => {
                    ConnectionType::Wireless
                }
                _ => ConnectionType::Wired,
            };

            self.add_connection(hub_id, spoke_id, conn_type);
        }
    }

    /// Create a sample network for testing.
    pub fn create_sample_network(&mut self) {
        // Router
        let mut router = Node::new(
            NodeType::Router,
            400.0,
            100.0,
            "Main Router".to_string(),
            "192.168.1.1".to_string(),
        );
        router.vendor = Some("Cisco Systems".to_string());
        router.status = NodeStatus::Online;
        let router_id = router.id;
        self.add_node(router);

        // Server
        let mut server = Node::new(
            NodeType::Server,
            200.0,
            250.0,
            "File Server".to_string(),
            "192.168.1.10".to_string(),
        );
        server.vendor = Some("Dell Inc.".to_string());
        server.os_family = Some("Ubuntu Linux".to_string());
        server.ports = vec![
            Port {
                number: 22,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service_name: Some("ssh".to_string()),
                service_version: Some("OpenSSH 8.9".to_string()),
            },
            Port {
                number: 445,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service_name: Some("smb".to_string()),
                service_version: None,
            },
        ];
        let server_id = server.id;
        self.add_node(server);

        // Workstation
        let mut workstation = Node::new(
            NodeType::Workstation,
            400.0,
            300.0,
            "Dev Laptop".to_string(),
            "192.168.1.50".to_string(),
        );
        workstation.vendor = Some("Apple Inc.".to_string());
        workstation.os_family = Some("macOS".to_string());
        let workstation_id = workstation.id;
        self.add_node(workstation);

        // IoT device with vulnerabilities
        let mut iot = Node::new(
            NodeType::IoT,
            600.0,
            250.0,
            "Smart Camera".to_string(),
            "192.168.1.100".to_string(),
        );
        iot.vendor = Some("Generic IoT".to_string());
        iot.status = NodeStatus::Warning;
        iot.vulnerabilities = vec![
            Vulnerability {
                cve: "CVE-2023-12345".to_string(),
                cvss: 8.5,
                severity: Severity::High,
                description: "Remote code execution via buffer overflow".to_string(),
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2023-12345".to_string()],
            },
        ];
        let iot_id = iot.id;
        self.add_node(iot);

        // Connections
        self.add_connection(router_id, server_id, ConnectionType::Wired);
        self.add_connection(router_id, workstation_id, ConnectionType::Wireless);
        self.add_connection(router_id, iot_id, ConnectionType::Wireless);
    }
}
