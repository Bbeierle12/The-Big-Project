//! Network canvas view for displaying nodes and connections.

use iced::widget::{canvas, column, container, text, Space};
use iced::{Element, Length, Point, Rectangle, Size, mouse, Renderer, Theme, Color};
use iced::widget::canvas::{Cache, Geometry, Path, Stroke, Frame, Program, Text};
use iced::{Alignment, Background, Border};

use crate::message::{Message, NodeId, NodeStatus, NodeType};
use crate::state::network::{NetworkState, Node, Connection};
use crate::theme::colors;

/// Get node color based on type.
fn node_color(node_type: NodeType) -> Color {
    match node_type {
        NodeType::Router => colors::CYAN,
        NodeType::Server => colors::GREEN,
        NodeType::Firewall => colors::ORANGE,
        NodeType::Workstation => Color::from_rgb(0.53, 0.55, 0.97), // Purple
        NodeType::Mobile => Color::from_rgb(0.98, 0.47, 0.64), // Pink
        NodeType::IoT => colors::YELLOW,
        NodeType::Extender => colors::CYAN,
        NodeType::Database => Color::from_rgb(0.58, 0.78, 0.24), // Lime
        NodeType::Cloud => Color::from_rgb(0.45, 0.72, 0.95), // Sky blue
        NodeType::Group => colors::TEXT_MUTED,
    }
}

/// Get node icon character.
fn node_icon(node_type: NodeType) -> char {
    match node_type {
        NodeType::Router => '\u{25CE}',     // ◎
        NodeType::Server => '\u{25A0}',     // ■
        NodeType::Firewall => '\u{25B2}',   // ▲
        NodeType::Workstation => '\u{25A1}', // □
        NodeType::Mobile => '\u{25C6}',     // ◆
        NodeType::IoT => '\u{25CB}',        // ○
        NodeType::Extender => '\u{25C9}',   // ◉
        NodeType::Database => '\u{25A3}',   // ▣
        NodeType::Cloud => '\u{2601}',      // ☁
        NodeType::Group => '\u{2B1A}',      // ⬚
    }
}

/// Get status indicator color.
fn status_color(status: NodeStatus) -> Color {
    match status {
        NodeStatus::Online => colors::GREEN,
        NodeStatus::Offline => colors::TEXT_MUTED,
        NodeStatus::Warning => colors::YELLOW,
        NodeStatus::Compromised => colors::RED,
    }
}

/// Network canvas drawing program.
pub struct NetworkCanvasProgram<'a> {
    network: &'a NetworkState,
}

impl<'a> NetworkCanvasProgram<'a> {
    pub fn new(network: &'a NetworkState) -> Self {
        Self { network }
    }
}

impl<'a> Program<Message> for NetworkCanvasProgram<'a> {
    type State = ();

    fn draw(
        &self,
        _state: &Self::State,
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());

        // Apply pan and zoom transforms
        let (pan_x, pan_y) = self.network.pan;
        let zoom = self.network.zoom;

        // Draw background grid
        draw_grid(&mut frame, bounds.size(), pan_x, pan_y, zoom);

        // Draw connections first (behind nodes)
        for conn in &self.network.connections {
            if let (Some(from_node), Some(to_node)) = (
                self.network.get_node(conn.from),
                self.network.get_node(conn.to),
            ) {
                draw_connection(&mut frame, from_node, to_node, conn, pan_x, pan_y, zoom);
            }
        }

        // Draw nodes
        for node in &self.network.nodes {
            let is_selected = self.network.selected_ids.contains(&node.id);
            draw_node(&mut frame, node, is_selected, pan_x, pan_y, zoom);
        }

        // Draw "connecting" line if in connection mode
        if let Some(from_id) = self.network.connecting_from {
            if let Some(from_node) = self.network.get_node(from_id) {
                // Draw a dashed line from the node to cursor position
                // For now, just highlight the node
                let x = (from_node.x + pan_x) * zoom;
                let y = (from_node.y + pan_y) * zoom;
                let highlight = Path::circle(Point::new(x, y), 45.0 * zoom);
                frame.stroke(&highlight, Stroke::default()
                    .with_color(colors::CYAN)
                    .with_width(2.0));
            }
        }

        vec![frame.into_geometry()]
    }
}

fn draw_grid(frame: &mut Frame, size: Size, pan_x: f32, pan_y: f32, zoom: f32) {
    let grid_size = 50.0 * zoom;
    let stroke = Stroke::default()
        .with_color(Color::from_rgba(1.0, 1.0, 1.0, 0.05))
        .with_width(1.0);

    // Offset grid based on pan
    let offset_x = (pan_x * zoom) % grid_size;
    let offset_y = (pan_y * zoom) % grid_size;

    // Vertical lines
    let mut x = offset_x;
    while x < size.width {
        if x >= 0.0 {
            let path = Path::line(Point::new(x, 0.0), Point::new(x, size.height));
            frame.stroke(&path, stroke.clone());
        }
        x += grid_size;
    }

    // Horizontal lines
    let mut y = offset_y;
    while y < size.height {
        if y >= 0.0 {
            let path = Path::line(Point::new(0.0, y), Point::new(size.width, y));
            frame.stroke(&path, stroke.clone());
        }
        y += grid_size;
    }
}

fn draw_connection(
    frame: &mut Frame,
    from: &Node,
    to: &Node,
    conn: &Connection,
    pan_x: f32,
    pan_y: f32,
    zoom: f32,
) {
    let from_x = (from.x + pan_x) * zoom;
    let from_y = (from.y + pan_y) * zoom;
    let to_x = (to.x + pan_x) * zoom;
    let to_y = (to.y + pan_y) * zoom;

    // Determine line color based on connection type
    let line_color = match conn.connection_type {
        crate::message::ConnectionType::Wired => Color::from_rgba(0.13, 0.83, 0.93, 0.6),
        crate::message::ConnectionType::Wireless => Color::from_rgba(0.13, 0.83, 0.93, 0.4),
    };

    let path = Path::line(Point::new(from_x, from_y), Point::new(to_x, to_y));

    let stroke = Stroke::default()
        .with_color(line_color)
        .with_width(2.0 * zoom);

    frame.stroke(&path, stroke);

    // Draw small circles at connection points
    let dot_radius = 4.0 * zoom;
    frame.fill(&Path::circle(Point::new(from_x, from_y), dot_radius), line_color);
    frame.fill(&Path::circle(Point::new(to_x, to_y), dot_radius), line_color);
}

fn draw_node(
    frame: &mut Frame,
    node: &Node,
    is_selected: bool,
    pan_x: f32,
    pan_y: f32,
    zoom: f32,
) {
    let x = (node.x + pan_x) * zoom;
    let y = (node.y + pan_y) * zoom;
    let radius = 30.0 * zoom;

    let color = node_color(node.node_type);
    let center = Point::new(x, y);

    // Selection highlight
    if is_selected {
        let selection_ring = Path::circle(center, radius + 8.0 * zoom);
        frame.stroke(&selection_ring, Stroke::default()
            .with_color(colors::CYAN)
            .with_width(3.0 * zoom));
    }

    // Node background
    let bg_circle = Path::circle(center, radius);
    frame.fill(&bg_circle, Color::from_rgba(color.r * 0.2, color.g * 0.2, color.b * 0.2, 0.9));

    // Node border
    frame.stroke(&bg_circle, Stroke::default()
        .with_color(color)
        .with_width(2.0 * zoom));

    // Status indicator
    let status_pos = Point::new(x + radius * 0.6, y - radius * 0.6);
    let status_circle = Path::circle(status_pos, 6.0 * zoom);
    frame.fill(&status_circle, status_color(node.status));
    frame.stroke(&status_circle, Stroke::default()
        .with_color(colors::BG_PRIMARY)
        .with_width(1.5 * zoom));

    // Vulnerability indicator
    if !node.vulnerabilities.is_empty() {
        let vuln_pos = Point::new(x - radius * 0.6, y - radius * 0.6);
        let vuln_circle = Path::circle(vuln_pos, 8.0 * zoom);
        frame.fill(&vuln_circle, colors::RED);

        // Draw warning icon or count
        let count_text = Text {
            content: node.vulnerabilities.len().to_string(),
            position: vuln_pos,
            color: Color::WHITE,
            size: iced::Pixels(10.0 * zoom),
            ..Default::default()
        };
        frame.fill_text(count_text);
    }

    // Node icon
    let icon_text = Text {
        content: node_icon(node.node_type).to_string(),
        position: Point::new(x, y - 4.0 * zoom),
        color,
        size: iced::Pixels(20.0 * zoom),
        horizontal_alignment: iced::alignment::Horizontal::Center,
        vertical_alignment: iced::alignment::Vertical::Center,
        ..Default::default()
    };
    frame.fill_text(icon_text);

    // Node label
    let label_text = Text {
        content: node.label.clone(),
        position: Point::new(x, y + radius + 12.0 * zoom),
        color: colors::TEXT_PRIMARY,
        size: iced::Pixels(11.0 * zoom),
        horizontal_alignment: iced::alignment::Horizontal::Center,
        vertical_alignment: iced::alignment::Vertical::Top,
        ..Default::default()
    };
    frame.fill_text(label_text);

    // IP address
    let ip_text = Text {
        content: node.ip.clone(),
        position: Point::new(x, y + radius + 24.0 * zoom),
        color: colors::TEXT_MUTED,
        size: iced::Pixels(9.0 * zoom),
        horizontal_alignment: iced::alignment::Horizontal::Center,
        vertical_alignment: iced::alignment::Vertical::Top,
        ..Default::default()
    };
    frame.fill_text(ip_text);
}

/// Render the network canvas view.
pub fn view<'a>(network: &'a NetworkState) -> Element<'a, Message> {
    let title_row = container(
        text("Network Canvas")
            .size(12)
            .color(colors::TEXT_MUTED)
    )
    .padding([8, 12]);

    let canvas_program = NetworkCanvasProgram::new(network);

    let canvas_widget = canvas(canvas_program)
        .width(Length::Fill)
        .height(Length::Fill);

    container(
        column![
            title_row,
            canvas_widget,
        ]
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(crate::theme::panel_style)
    .into()
}
