//! Traffic flows dashboard view.

use iced::widget::{button, column, container, horizontal_rule, row, scrollable, text, Space};
use iced::{Alignment, Background, Border, Color, Element, Length};

use crate::api::TrafficFlow;
use crate::message::Message;
use crate::theme::colors;

/// Traffic direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficDirection {
    Inbound,
    Outbound,
    Internal,
}

/// Format bytes to human-readable string.
fn format_bytes(bytes: i64) -> String {
    const KB: i64 = 1024;
    const MB: i64 = KB * 1024;
    const GB: i64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Protocol color.
fn protocol_color(protocol: &str) -> Color {
    match protocol.to_uppercase().as_str() {
        "TCP" => colors::CYAN,
        "UDP" => colors::PURPLE,
        "ICMP" => colors::YELLOW,
        "HTTP" | "HTTPS" => colors::GREEN,
        "DNS" => colors::ORANGE,
        "SSH" => colors::RED,
        _ => colors::TEXT_MUTED,
    }
}

/// Render a traffic flow card.
fn traffic_card<'a>(flow: &'a TrafficFlow, is_selected: bool) -> Element<'a, Message> {
    let flow_id = flow.id.clone();
    let bg_color = if is_selected {
        Color::from_rgba(0.13, 0.83, 0.93, 0.15)
    } else {
        colors::BG_SECONDARY
    };

    let border_color = if is_selected {
        colors::CYAN
    } else {
        Color::TRANSPARENT
    };

    let total_bytes = flow.bytes_sent + flow.bytes_received;
    let total_packets = flow.packets_sent + flow.packets_received;

    let content = column![
        // Header: Protocol and Application
        row![
            container(
                text(flow.protocol.clone())
                    .size(10)
                    .color(Color::WHITE)
            )
            .padding([2, 8])
            .style(move |_| {
                let proto = flow.protocol.clone();
                container::Style {
                    background: Some(Background::Color(protocol_color(&proto))),
                    border: Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            }),
            Space::with_width(8),
            text(flow.application.clone().unwrap_or_else(|| "Unknown".to_string()))
                .size(12)
                .color(colors::TEXT_PRIMARY),
            Space::with_width(Length::Fill),
            text(format_bytes(total_bytes))
                .size(11)
                .color(colors::CYAN),
        ]
        .align_y(Alignment::Center),
        Space::with_height(8),
        // Source and destination
        row![
            column![
                text("Source").size(9).color(colors::TEXT_MUTED),
                text(format!("{}:{}", flow.src_ip, flow.src_port.unwrap_or(0)))
                    .size(11)
                    .color(colors::TEXT_PRIMARY),
            ],
            Space::with_width(16),
            text("\u{2192}") // →
                .size(14)
                .color(colors::TEXT_MUTED),
            Space::with_width(16),
            column![
                text("Destination").size(9).color(colors::TEXT_MUTED),
                text(format!("{}:{}", flow.dst_ip, flow.dst_port.unwrap_or(0)))
                    .size(11)
                    .color(colors::TEXT_PRIMARY),
            ],
        ]
        .align_y(Alignment::Center),
        Space::with_height(8),
        // Stats
        row![
            text(format!("{} packets", total_packets))
                .size(10)
                .color(colors::TEXT_MUTED),
            Space::with_width(Length::Fill),
            text(format!("\u{2191}{} \u{2193}{}",
                format_bytes(flow.bytes_sent),
                format_bytes(flow.bytes_received)))
                .size(10)
                .color(colors::TEXT_MUTED),
        ],
    ]
    .padding(12)
    .spacing(4);

    button(content)
        .on_press(Message::TrafficFlowSelected(flow_id))
        .padding(0)
        .style(move |_theme, status| {
            let hover_bg = match status {
                iced::widget::button::Status::Hovered => {
                    Color::from_rgba(0.13, 0.83, 0.93, 0.1)
                }
                _ => bg_color,
            };
            iced::widget::button::Style {
                background: Some(Background::Color(hover_bg)),
                text_color: colors::TEXT_PRIMARY,
                border: Border {
                    color: border_color,
                    width: if is_selected { 1.0 } else { 0.0 },
                    radius: 8.0.into(),
                },
                ..Default::default()
            }
        })
        .width(Length::Fill)
        .into()
}

/// Render traffic flow detail panel.
fn traffic_detail<'a>(flow: &TrafficFlow) -> Element<'a, Message> {
    let proto_color = protocol_color(&flow.protocol);

    let started = flow.started_at.format("%Y-%m-%d %H:%M:%S").to_string();
    let ended = flow.ended_at
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "Active".to_string());

    column![
        // Header
        row![
            container(
                text(flow.protocol.clone())
                    .size(12)
                    .color(Color::WHITE)
            )
            .padding([4, 12])
            .style(move |_| container::Style {
                background: Some(Background::Color(proto_color)),
                border: Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
            Space::with_width(12),
            column![
                text(flow.application.clone().unwrap_or_else(|| "Unknown Application".to_string()))
                    .size(14)
                    .color(colors::TEXT_PRIMARY),
                text(format!("Flow ID: {}", &flow.id[..8]))
                    .size(10)
                    .color(colors::TEXT_MUTED),
            ],
        ]
        .align_y(Alignment::Center),
        Space::with_height(16),
        horizontal_rule(1),
        Space::with_height(16),
        // Connection info
        text("Connection").size(12).color(colors::CYAN),
        Space::with_height(8),
        row![
            column![
                text("Source IP").size(10).color(colors::TEXT_MUTED),
                text(flow.src_ip.clone()).size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
            column![
                text("Source Port").size(10).color(colors::TEXT_MUTED),
                text(flow.src_port.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()))
                    .size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
        ],
        Space::with_height(8),
        row![
            column![
                text("Destination IP").size(10).color(colors::TEXT_MUTED),
                text(flow.dst_ip.clone()).size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
            column![
                text("Destination Port").size(10).color(colors::TEXT_MUTED),
                text(flow.dst_port.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()))
                    .size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
        ],
        Space::with_height(16),
        horizontal_rule(1),
        Space::with_height(16),
        // Transfer stats
        text("Transfer Statistics").size(12).color(colors::CYAN),
        Space::with_height(8),
        row![
            column![
                text("Bytes Sent").size(10).color(colors::TEXT_MUTED),
                text(format_bytes(flow.bytes_sent)).size(14).color(colors::GREEN),
            ]
            .width(Length::Fill),
            column![
                text("Bytes Received").size(10).color(colors::TEXT_MUTED),
                text(format_bytes(flow.bytes_received)).size(14).color(colors::ORANGE),
            ]
            .width(Length::Fill),
        ],
        Space::with_height(8),
        row![
            column![
                text("Packets Sent").size(10).color(colors::TEXT_MUTED),
                text(flow.packets_sent.to_string()).size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
            column![
                text("Packets Received").size(10).color(colors::TEXT_MUTED),
                text(flow.packets_received.to_string()).size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
        ],
        Space::with_height(16),
        horizontal_rule(1),
        Space::with_height(16),
        // Timing
        text("Timing").size(12).color(colors::CYAN),
        Space::with_height(8),
        row![
            column![
                text("Started").size(10).color(colors::TEXT_MUTED),
                text(started).size(11).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
            column![
                text("Ended").size(10).color(colors::TEXT_MUTED),
                text(ended).size(11).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
        ],
        Space::with_height(16),
        horizontal_rule(1),
        Space::with_height(16),
        // Geo info
        text("Geolocation").size(12).color(colors::CYAN),
        Space::with_height(8),
        row![
            column![
                text("Source Country").size(10).color(colors::TEXT_MUTED),
                text(flow.country_src.clone().unwrap_or_else(|| "Unknown".to_string()))
                    .size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
            column![
                text("Destination Country").size(10).color(colors::TEXT_MUTED),
                text(flow.country_dst.clone().unwrap_or_else(|| "Unknown".to_string()))
                    .size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
        ],
    ]
    .padding(16)
    .into()
}

/// Stats bar showing traffic summary.
fn stats_bar<'a>(flows: &[TrafficFlow]) -> Element<'a, Message> {
    let total_flows = flows.len();
    let total_bytes: i64 = flows.iter().map(|f| f.bytes_sent + f.bytes_received).sum();
    let total_packets: i64 = flows.iter().map(|f| f.packets_sent + f.packets_received).sum();

    // Count by protocol
    let tcp_count = flows.iter().filter(|f| f.protocol.to_uppercase() == "TCP").count();
    let udp_count = flows.iter().filter(|f| f.protocol.to_uppercase() == "UDP").count();
    let other_count = total_flows - tcp_count - udp_count;

    row![
        // Total flows
        container(
            row![
                text("\u{1F4CA}").size(12), // 📊
                Space::with_width(6),
                text(format!("{} flows", total_flows)).size(11).color(colors::TEXT_PRIMARY),
            ]
            .align_y(Alignment::Center)
        )
        .padding([6, 12])
        .style(|_| container::Style {
            background: Some(Background::Color(colors::BG_SECONDARY)),
            border: Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }),
        Space::with_width(8),
        // Total bandwidth
        container(
            row![
                text("\u{21C5}").size(12), // ⇅
                Space::with_width(6),
                text(format_bytes(total_bytes)).size(11).color(colors::CYAN),
            ]
            .align_y(Alignment::Center)
        )
        .padding([6, 12])
        .style(|_| container::Style {
            background: Some(Background::Color(colors::BG_SECONDARY)),
            border: Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }),
        Space::with_width(8),
        // Total packets
        container(
            row![
                text("\u{1F4E6}").size(12), // 📦
                Space::with_width(6),
                text(format!("{} pkts", total_packets)).size(11).color(colors::TEXT_PRIMARY),
            ]
            .align_y(Alignment::Center)
        )
        .padding([6, 12])
        .style(|_| container::Style {
            background: Some(Background::Color(colors::BG_SECONDARY)),
            border: Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }),
        Space::with_width(Length::Fill),
        // Protocol breakdown
        container(
            row![
                text(format!("TCP: {}", tcp_count)).size(10).color(colors::CYAN),
                Space::with_width(12),
                text(format!("UDP: {}", udp_count)).size(10).color(colors::PURPLE),
                Space::with_width(12),
                text(format!("Other: {}", other_count)).size(10).color(colors::TEXT_MUTED),
            ]
            .align_y(Alignment::Center)
        )
        .padding([6, 12])
        .style(|_| container::Style {
            background: Some(Background::Color(colors::BG_SECONDARY)),
            border: Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }),
    ]
    .padding([8, 16])
    .align_y(Alignment::Center)
    .into()
}

/// Main traffic dashboard view.
pub fn view<'a>(
    flows: &'a [TrafficFlow],
    selected_flow_id: &'a Option<String>,
    filter_protocol: &'a Option<String>,
) -> Element<'a, Message> {
    // Filter flows
    let filtered_flows: Vec<&TrafficFlow> = flows
        .iter()
        .filter(|f| {
            filter_protocol.as_ref().map_or(true, |proto| {
                f.protocol.to_uppercase() == proto.to_uppercase()
            })
        })
        .collect();

    // Find selected flow
    let selected_flow = selected_flow_id
        .as_ref()
        .and_then(|id| flows.iter().find(|f| &f.id == id));

    // Header
    let header = row![
        text("Network Traffic")
            .size(18)
            .color(colors::TEXT_PRIMARY),
        Space::with_width(Length::Fill),
        // Protocol filter buttons
        button(text("All").size(10))
            .on_press(Message::TrafficFilterProtocol(None))
            .padding([4, 12])
            .style(move |_theme, _status| {
                let is_active = filter_protocol.is_none();
                iced::widget::button::Style {
                    background: Some(Background::Color(if is_active {
                        colors::CYAN
                    } else {
                        colors::BG_SECONDARY
                    })),
                    text_color: if is_active { Color::WHITE } else { colors::TEXT_MUTED },
                    border: Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            }),
        Space::with_width(4),
        button(text("TCP").size(10))
            .on_press(Message::TrafficFilterProtocol(Some("TCP".to_string())))
            .padding([4, 12])
            .style(move |_theme, _status| {
                let is_active = filter_protocol.as_ref().map_or(false, |p| p == "TCP");
                iced::widget::button::Style {
                    background: Some(Background::Color(if is_active {
                        colors::CYAN
                    } else {
                        colors::BG_SECONDARY
                    })),
                    text_color: if is_active { Color::WHITE } else { colors::TEXT_MUTED },
                    border: Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            }),
        Space::with_width(4),
        button(text("UDP").size(10))
            .on_press(Message::TrafficFilterProtocol(Some("UDP".to_string())))
            .padding([4, 12])
            .style(move |_theme, _status| {
                let is_active = filter_protocol.as_ref().map_or(false, |p| p == "UDP");
                iced::widget::button::Style {
                    background: Some(Background::Color(if is_active {
                        colors::PURPLE
                    } else {
                        colors::BG_SECONDARY
                    })),
                    text_color: if is_active { Color::WHITE } else { colors::TEXT_MUTED },
                    border: Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            }),
        Space::with_width(16),
        button(text("\u{2715}").size(14)) // ✕
            .on_press(Message::HideTrafficDashboard)
            .padding([4, 8])
            .style(|_theme, status| {
                let bg = match status {
                    iced::widget::button::Status::Hovered => colors::RED,
                    _ => Color::TRANSPARENT,
                };
                iced::widget::button::Style {
                    background: Some(Background::Color(bg)),
                    text_color: colors::TEXT_MUTED,
                    border: Border::default(),
                    ..Default::default()
                }
            }),
    ]
    .padding([12, 16])
    .align_y(Alignment::Center);

    // Stats bar
    let stats = stats_bar(flows);

    // Flow list
    let flow_list: Element<'a, Message> = if filtered_flows.is_empty() {
        container(
            column![
                text("\u{1F4CA}").size(48), // 📊
                Space::with_height(16),
                text("No traffic flows")
                    .size(14)
                    .color(colors::TEXT_MUTED),
                Space::with_height(8),
                text("Traffic will appear here when detected")
                    .size(11)
                    .color(colors::TEXT_MUTED),
            ]
            .align_x(Alignment::Center)
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
    } else {
        let cards: Vec<Element<'a, Message>> = filtered_flows
            .iter()
            .map(|flow| {
                let is_selected = selected_flow_id.as_ref().map_or(false, |id| id == &flow.id);
                traffic_card(flow, is_selected)
            })
            .collect();

        scrollable(
            column(cards)
                .spacing(8)
                .padding([8, 16])
        )
        .height(Length::Fill)
        .into()
    };

    // Detail panel
    let detail_panel: Element<'a, Message> = if let Some(flow) = selected_flow {
        container(
            scrollable(traffic_detail(flow))
                .height(Length::Fill)
        )
        .width(Length::Fixed(350.0))
        .height(Length::Fill)
        .style(|_| container::Style {
            background: Some(Background::Color(colors::BG_SECONDARY)),
            border: Border {
                color: colors::BORDER,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
    } else {
        container(
            column![
                text("\u{1F4CA}").size(32).color(colors::TEXT_MUTED), // 📊
                Space::with_height(8),
                text("Select a flow")
                    .size(12)
                    .color(colors::TEXT_MUTED),
            ]
            .align_x(Alignment::Center)
        )
        .width(Length::Fixed(350.0))
        .height(Length::Fill)
        .center_x(Length::Fixed(350.0))
        .center_y(Length::Fill)
        .style(|_| container::Style {
            background: Some(Background::Color(colors::BG_SECONDARY)),
            border: Border {
                color: colors::BORDER,
                width: 1.0,
                radius: 0.0.into(),
            },
            ..Default::default()
        })
        .into()
    };

    // Main layout
    let main_content = row![
        // Flow list
        container(flow_list)
            .width(Length::Fill)
            .height(Length::Fill),
        // Detail panel
        detail_panel,
    ];

    let content = column![
        header,
        horizontal_rule(1),
        stats,
        horizontal_rule(1),
        main_content,
    ];

    // Modal overlay
    container(
        container(content)
            .width(Length::Fixed(1000.0))
            .height(Length::Fixed(700.0))
            .style(|_| container::Style {
                background: Some(Background::Color(colors::BG_PRIMARY)),
                border: Border {
                    color: colors::BORDER,
                    width: 1.0,
                    radius: 8.0.into(),
                },
                ..Default::default()
            })
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .style(|_| container::Style {
        background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.7))),
        ..Default::default()
    })
    .into()
}
