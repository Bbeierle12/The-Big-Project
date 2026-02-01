//! Scans dashboard view with history and progress tracking.

use iced::widget::{button, column, container, progress_bar, row, scrollable, text, Space};
use iced::{Alignment, Background, Border, Color, Element, Length};

use crate::api::Scan;
use crate::message::Message;
use crate::theme::colors;

/// Scan status for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl ScanStatus {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pending" | "queued" => Self::Pending,
            "running" | "in_progress" | "active" => Self::Running,
            "completed" | "done" | "success" => Self::Completed,
            "failed" | "error" => Self::Failed,
            "cancelled" | "canceled" | "aborted" => Self::Cancelled,
            _ => Self::Pending,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Running => "RUNNING",
            Self::Completed => "COMPLETED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
        }
    }

    pub fn color(&self) -> Color {
        match self {
            Self::Pending => colors::YELLOW,
            Self::Running => colors::CYAN,
            Self::Completed => colors::GREEN,
            Self::Failed => colors::RED,
            Self::Cancelled => colors::TEXT_MUTED,
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            Self::Pending => "\u{23F3}",    // ⏳
            Self::Running => "\u{27F3}",    // ⟳
            Self::Completed => "\u{2714}",  // ✔
            Self::Failed => "\u{2716}",     // ✖
            Self::Cancelled => "\u{23F9}",  // ⏹
        }
    }
}

/// Render a status badge.
fn status_badge(status: ScanStatus) -> Element<'static, Message> {
    container(
        row![
            text(status.icon()).size(9).color(status.color()),
            Space::with_width(4),
            text(status.label()).size(8).color(status.color()),
        ]
        .align_y(Alignment::Center)
    )
    .padding([3, 8])
    .style(move |_| container::Style {
        background: Some(Background::Color(Color::from_rgba(
            status.color().r,
            status.color().g,
            status.color().b,
            0.15,
        ))),
        border: Border {
            color: Color::from_rgba(
                status.color().r,
                status.color().g,
                status.color().b,
                0.3,
            ),
            width: 1.0,
            radius: 4.0.into(),
        },
        ..Default::default()
    })
    .into()
}

/// Render a scan type badge.
fn scan_type_badge(scan_type: &str) -> Element<'_, Message> {
    let color = match scan_type.to_lowercase().as_str() {
        "network" | "discovery" => colors::CYAN,
        "vulnerability" | "vuln" => colors::ORANGE,
        "service" => colors::GREEN,
        "os" => Color::from_rgb(0.6, 0.4, 0.8),
        "full" => colors::RED,
        _ => colors::TEXT_SECONDARY,
    };

    container(
        text(scan_type.to_uppercase())
            .size(7)
            .color(color)
    )
    .padding([2, 6])
    .style(move |_| container::Style {
        background: Some(Background::Color(Color::from_rgba(color.r, color.g, color.b, 0.1))),
        border: Border {
            color: Color::from_rgba(color.r, color.g, color.b, 0.3),
            width: 1.0,
            radius: 3.0.into(),
        },
        ..Default::default()
    })
    .into()
}

/// Render a scan card.
fn scan_card(scan: &Scan, is_selected: bool) -> Element<'_, Message> {
    let status = ScanStatus::from_str(&scan.status);
    let is_running = matches!(status, ScanStatus::Running);

    // Time display
    let time_display = if let Some(ref started) = scan.started_at {
        if let Some(ref completed) = scan.completed_at {
            // Completed - show duration
            let duration = completed.signed_duration_since(*started);
            if duration.num_minutes() > 0 {
                format!("{}m {}s", duration.num_minutes(), duration.num_seconds() % 60)
            } else {
                format!("{}s", duration.num_seconds())
            }
        } else {
            // Still running - show elapsed
            let now = chrono::Utc::now();
            let elapsed = now.signed_duration_since(*started);
            if elapsed.num_minutes() > 0 {
                format!("{}m {}s", elapsed.num_minutes(), elapsed.num_seconds() % 60)
            } else {
                format!("{}s", elapsed.num_seconds())
            }
        }
    } else {
        "Pending".to_string()
    };

    // Header row
    let header = row![
        text(scan.tool.to_uppercase())
            .size(12)
            .color(colors::TEXT_PRIMARY),
        Space::with_width(8),
        scan_type_badge(&scan.scan_type),
        Space::with_width(Length::Fill),
        status_badge(status),
    ]
    .align_y(Alignment::Center);

    // Target row
    let target_row = row![
        text("\u{1F3AF}").size(10).color(colors::TEXT_MUTED), // 🎯
        Space::with_width(6),
        text(scan.target.clone())
            .size(10)
            .color(colors::CYAN),
    ]
    .align_y(Alignment::Center);

    // Progress bar (only for running scans)
    let progress_section: Element<'_, Message> = if is_running {
        column![
            Space::with_height(8),
            progress_bar(0.0..=100.0, scan.progress as f32)
                .height(4)
                .style(|_| progress_bar::Style {
                    background: Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.1)),
                    bar: Background::Color(colors::CYAN),
                    border: Border {
                        radius: 2.0.into(),
                        ..Default::default()
                    },
                }),
            Space::with_height(4),
            row![
                text(format!("{}%", scan.progress))
                    .size(9)
                    .color(colors::CYAN),
                Space::with_width(Length::Fill),
                text(time_display)
                    .size(9)
                    .color(colors::TEXT_MUTED),
            ],
        ]
        .into()
    } else {
        // Stats row for completed scans
        row![
            if scan.devices_found > 0 {
                row![
                    text("\u{1F4BB}").size(9).color(colors::TEXT_MUTED),
                    Space::with_width(4),
                    text(format!("{} devices", scan.devices_found))
                        .size(9)
                        .color(colors::GREEN),
                ]
                .align_y(Alignment::Center)
            } else {
                row![]
            },
            Space::with_width(12),
            if scan.alerts_generated > 0 {
                row![
                    text("\u{26A0}").size(9).color(colors::TEXT_MUTED),
                    Space::with_width(4),
                    text(format!("{} alerts", scan.alerts_generated))
                        .size(9)
                        .color(colors::ORANGE),
                ]
                .align_y(Alignment::Center)
            } else {
                row![]
            },
            Space::with_width(Length::Fill),
            text(time_display)
                .size(9)
                .color(colors::TEXT_MUTED),
        ]
        .align_y(Alignment::Center)
        .into()
    };

    // Error message if failed
    let error_section: Element<'_, Message> = if let Some(ref error) = scan.error_message {
        container(
            row![
                text("\u{26A0}").size(10).color(colors::RED),
                Space::with_width(6),
                text(error.clone())
                    .size(9)
                    .color(colors::RED),
            ]
            .align_y(Alignment::Center)
        )
        .padding([6, 8])
        .width(Length::Fill)
        .style(|_| container::Style {
            background: Some(Background::Color(Color::from_rgba(0.94, 0.27, 0.27, 0.1))),
            border: Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .into()
    } else {
        Space::with_height(0).into()
    };

    // Card content
    let content = column![
        header,
        Space::with_height(8),
        target_row,
        progress_section,
        error_section,
    ];

    // Card styling
    let bg_color = if is_selected {
        Color::from_rgba(0.13, 0.83, 0.93, 0.1)
    } else {
        Color::from_rgba(1.0, 1.0, 1.0, 0.02)
    };

    let border_color = if is_selected {
        colors::CYAN
    } else if is_running {
        Color::from_rgba(0.13, 0.83, 0.93, 0.3)
    } else {
        colors::BORDER
    };

    button(
        container(content)
            .padding(12)
            .width(Length::Fill)
    )
    .on_press(Message::ScanSelected(scan.id.clone()))
    .padding(0)
    .width(Length::Fill)
    .style(move |_, btn_status| {
        let bg = if matches!(btn_status, iced::widget::button::Status::Hovered) && !is_selected {
            Color::from_rgba(1.0, 1.0, 1.0, 0.05)
        } else {
            bg_color
        };
        iced::widget::button::Style {
            background: Some(Background::Color(bg)),
            text_color: colors::TEXT_PRIMARY,
            border: Border {
                color: border_color,
                width: if is_running { 2.0 } else { 1.0 },
                radius: 6.0.into(),
            },
            ..Default::default()
        }
    })
    .into()
}

/// Render the scan detail panel.
fn scan_detail(scan: &Scan) -> Element<'_, Message> {
    let status = ScanStatus::from_str(&scan.status);
    let is_running = matches!(status, ScanStatus::Running);

    // Header
    let header = column![
        row![
            status_badge(status),
            Space::with_width(8),
            scan_type_badge(&scan.scan_type),
        ],
        Space::with_height(12),
        text(format!("{} Scan", scan.tool.to_uppercase()))
            .size(16)
            .color(colors::TEXT_PRIMARY),
        Space::with_height(4),
        text(scan.target.clone())
            .size(12)
            .color(colors::CYAN),
    ];

    // Progress section
    let progress_section: Element<'_, Message> = if is_running {
        column![
            Space::with_height(16),
            text("Progress")
                .size(9)
                .color(colors::TEXT_MUTED),
            Space::with_height(8),
            progress_bar(0.0..=100.0, scan.progress as f32)
                .height(8)
                .style(|_| progress_bar::Style {
                    background: Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.1)),
                    bar: Background::Color(colors::CYAN),
                    border: Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                }),
            Space::with_height(8),
            text(format!("{}% complete", scan.progress))
                .size(11)
                .color(colors::CYAN),
        ]
        .into()
    } else {
        Space::with_height(0).into()
    };

    // Info section
    let info_row = |label: &'static str, value: String, value_color: Color| -> Element<'_, Message> {
        row![
            text(label)
                .size(9)
                .color(colors::TEXT_MUTED)
                .width(Length::Fixed(100.0)),
            text(value)
                .size(10)
                .color(value_color),
        ]
        .into()
    };

    let mut info_section = column![].spacing(8);

    info_section = info_section.push(info_row("Tool", scan.tool.clone(), colors::TEXT_PRIMARY));
    info_section = info_section.push(info_row("Type", scan.scan_type.clone(), colors::TEXT_SECONDARY));

    if let Some(ref started) = scan.started_at {
        info_section = info_section.push(info_row(
            "Started",
            started.format("%Y-%m-%d %H:%M:%S").to_string(),
            colors::TEXT_SECONDARY,
        ));
    }

    if let Some(ref completed) = scan.completed_at {
        info_section = info_section.push(info_row(
            "Completed",
            completed.format("%Y-%m-%d %H:%M:%S").to_string(),
            colors::TEXT_SECONDARY,
        ));

        // Duration
        if let Some(ref started) = scan.started_at {
            let duration = completed.signed_duration_since(*started);
            let duration_str = if duration.num_minutes() > 0 {
                format!("{}m {}s", duration.num_minutes(), duration.num_seconds() % 60)
            } else {
                format!("{}s", duration.num_seconds())
            };
            info_section = info_section.push(info_row("Duration", duration_str, colors::TEXT_SECONDARY));
        }
    }

    info_section = info_section.push(info_row(
        "Devices Found",
        scan.devices_found.to_string(),
        if scan.devices_found > 0 { colors::GREEN } else { colors::TEXT_MUTED },
    ));

    info_section = info_section.push(info_row(
        "Alerts",
        scan.alerts_generated.to_string(),
        if scan.alerts_generated > 0 { colors::ORANGE } else { colors::TEXT_MUTED },
    ));

    // Result summary
    let result_section: Element<'_, Message> = if let Some(ref summary) = scan.result_summary {
        column![
            Space::with_height(16),
            text("Summary")
                .size(9)
                .color(colors::TEXT_MUTED),
            Space::with_height(8),
            container(
                text(summary.clone())
                    .size(10)
                    .color(colors::TEXT_SECONDARY)
            )
            .padding(12)
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.2))),
                border: Border {
                    color: colors::BORDER,
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            }),
        ]
        .into()
    } else {
        Space::with_height(0).into()
    };

    // Error section
    let error_section: Element<'_, Message> = if let Some(ref error) = scan.error_message {
        column![
            Space::with_height(16),
            text("Error")
                .size(9)
                .color(colors::RED),
            Space::with_height(8),
            container(
                text(error.clone())
                    .size(10)
                    .color(colors::RED)
            )
            .padding(12)
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.94, 0.27, 0.27, 0.1))),
                border: Border {
                    color: Color::from_rgba(0.94, 0.27, 0.27, 0.3),
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            }),
        ]
        .into()
    } else {
        Space::with_height(0).into()
    };

    // Action buttons
    let action_buttons: Element<'_, Message> = if is_running {
        button(
            row![
                text("\u{23F9}").size(10), // ⏹
                Space::with_width(6),
                text("Cancel Scan").size(10),
            ]
            .align_y(Alignment::Center)
        )
        .on_press(Message::CancelScan(scan.id.clone()))
        .padding([10, 20])
        .width(Length::Fill)
        .style(|_, btn_status| {
            let bg = if matches!(btn_status, iced::widget::button::Status::Hovered) {
                Color::from_rgba(0.94, 0.27, 0.27, 0.2)
            } else {
                Color::from_rgba(0.94, 0.27, 0.27, 0.1)
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: colors::RED,
                border: Border {
                    color: Color::from_rgba(0.94, 0.27, 0.27, 0.3),
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            }
        })
        .into()
    } else {
        // Rescan button for completed scans
        button(
            row![
                text("\u{21BB}").size(10), // ↻
                Space::with_width(6),
                text("Run Again").size(10),
            ]
            .align_y(Alignment::Center)
        )
        .on_press(Message::RescanTarget(scan.target.clone(), scan.scan_type.clone(), scan.tool.clone()))
        .padding([10, 20])
        .width(Length::Fill)
        .style(|_, btn_status| {
            let bg = if matches!(btn_status, iced::widget::button::Status::Hovered) {
                Color::from_rgba(0.13, 0.83, 0.93, 0.2)
            } else {
                Color::from_rgba(0.13, 0.83, 0.93, 0.1)
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: colors::CYAN,
                border: Border {
                    color: Color::from_rgba(0.13, 0.83, 0.93, 0.3),
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            }
        })
        .into()
    };

    container(
        scrollable(
            column![
                header,
                progress_section,
                Space::with_height(16),
                container(info_section)
                    .padding(12)
                    .width(Length::Fill)
                    .style(|_| container::Style {
                        background: Some(Background::Color(Color::from_rgba(1.0, 1.0, 1.0, 0.02))),
                        border: Border {
                            color: colors::BORDER,
                            width: 1.0,
                            radius: 4.0.into(),
                        },
                        ..Default::default()
                    }),
                result_section,
                error_section,
                Space::with_height(16),
                action_buttons,
            ]
            .padding(16)
        )
        .height(Length::Fill)
    )
    .width(Length::Fixed(350.0))
    .height(Length::Fill)
    .style(|_| container::Style {
        background: Some(Background::Color(colors::BG_SECONDARY)),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            ..Default::default()
        },
        ..Default::default()
    })
    .into()
}

/// Render stats bar showing scan counts by status.
fn stats_bar(scans: &[Scan]) -> Element<'_, Message> {
    let running = scans.iter().filter(|s| ScanStatus::from_str(&s.status) == ScanStatus::Running).count();
    let completed = scans.iter().filter(|s| ScanStatus::from_str(&s.status) == ScanStatus::Completed).count();
    let failed = scans.iter().filter(|s| ScanStatus::from_str(&s.status) == ScanStatus::Failed).count();
    let pending = scans.iter().filter(|s| ScanStatus::from_str(&s.status) == ScanStatus::Pending).count();

    let stat_box = |label: &'static str, count: usize, color: Color| -> Element<'_, Message> {
        container(
            column![
                text(count.to_string())
                    .size(18)
                    .color(color),
                text(label)
                    .size(8)
                    .color(colors::TEXT_MUTED),
            ]
            .align_x(Alignment::Center)
        )
        .padding([8, 16])
        .style(move |_| container::Style {
            background: Some(Background::Color(Color::from_rgba(color.r, color.g, color.b, 0.1))),
            border: Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        })
        .into()
    };

    row![
        stat_box("RUNNING", running, colors::CYAN),
        Space::with_width(8),
        stat_box("PENDING", pending, colors::YELLOW),
        Space::with_width(8),
        stat_box("COMPLETED", completed, colors::GREEN),
        Space::with_width(8),
        stat_box("FAILED", failed, colors::RED),
        Space::with_width(Length::Fill),
        text(format!("{} total scans", scans.len()))
            .size(10)
            .color(colors::TEXT_MUTED),
    ]
    .align_y(Alignment::Center)
    .into()
}

/// Render the scans dashboard.
pub fn view<'a>(
    scans: &'a [Scan],
    selected_id: Option<&'a str>,
    filter_status: Option<&'a str>,
) -> Element<'a, Message> {
    // Header
    let header = row![
        container(
            text("\u{1F50D}")  // 🔍
                .size(20)
                .color(colors::CYAN)
        )
        .padding([8, 12])
        .style(|_| container::Style {
            background: Some(Background::Color(Color::from_rgba(0.13, 0.83, 0.93, 0.2))),
            border: Border {
                radius: 8.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }),
        Space::with_width(16),
        column![
            text("SCAN HISTORY")
                .size(18)
                .color(colors::TEXT_PRIMARY),
            text("View and manage network scans")
                .size(10)
                .color(colors::TEXT_MUTED),
        ],
        Space::with_width(Length::Fill),
        button(
            text("\u{21BB}").size(14).color(colors::TEXT_MUTED) // ↻
        )
        .on_press(Message::FetchScans)
        .padding([8, 12])
        .style(|_, status| {
            let bg = if matches!(status, iced::widget::button::Status::Hovered) {
                Color::from_rgba(1.0, 1.0, 1.0, 0.1)
            } else {
                Color::TRANSPARENT
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: colors::TEXT_MUTED,
                border: Border::default(),
                ..Default::default()
            }
        }),
        Space::with_width(8),
        button(
            text("\u{2716}").size(18).color(colors::TEXT_MUTED) // ✖
        )
        .on_press(Message::HideScansDashboard)
        .padding([8, 12])
        .style(|_, status| {
            let bg = if matches!(status, iced::widget::button::Status::Hovered) {
                Color::from_rgba(1.0, 1.0, 1.0, 0.1)
            } else {
                Color::TRANSPARENT
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: colors::TEXT_MUTED,
                border: Border::default(),
                ..Default::default()
            }
        }),
    ]
    .align_y(Alignment::Center)
    .padding([16, 24]);

    // Filter toolbar
    let filter_btn = |label: &'static str, is_active: bool, color: Color, status_filter: Option<&'static str>| -> Element<'_, Message> {
        button(
            text(label).size(9).color(if is_active { Color::WHITE } else { color })
        )
        .on_press(Message::ScanFilterStatus(status_filter.map(String::from)))
        .padding([6, 12])
        .style(move |_, btn_status| {
            let bg = if is_active {
                color
            } else if matches!(btn_status, iced::widget::button::Status::Hovered) {
                Color::from_rgba(color.r, color.g, color.b, 0.2)
            } else {
                Color::TRANSPARENT
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: if is_active { Color::WHITE } else { color },
                border: Border {
                    color: Color::from_rgba(color.r, color.g, color.b, 0.3),
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            }
        })
        .into()
    };

    let filters = row![
        text("Filter:").size(9).color(colors::TEXT_MUTED),
        Space::with_width(8),
        filter_btn("ALL", filter_status.is_none(), colors::CYAN, None),
        Space::with_width(4),
        filter_btn("RUNNING", filter_status == Some("running"), colors::CYAN, Some("running")),
        Space::with_width(4),
        filter_btn("COMPLETED", filter_status == Some("completed"), colors::GREEN, Some("completed")),
        Space::with_width(4),
        filter_btn("FAILED", filter_status == Some("failed"), colors::RED, Some("failed")),
        Space::with_width(4),
        filter_btn("PENDING", filter_status == Some("pending"), colors::YELLOW, Some("pending")),
    ]
    .align_y(Alignment::Center)
    .padding([12, 24]);

    // Filter scans
    let filtered_scans: Vec<&Scan> = scans
        .iter()
        .filter(|scan| {
            if let Some(status) = filter_status {
                let scan_status = ScanStatus::from_str(&scan.status);
                match status {
                    "running" => scan_status == ScanStatus::Running,
                    "completed" => scan_status == ScanStatus::Completed,
                    "failed" => scan_status == ScanStatus::Failed,
                    "pending" => scan_status == ScanStatus::Pending,
                    _ => true,
                }
            } else {
                true
            }
        })
        .collect();

    // Sort scans: running first, then by created_at desc
    let mut sorted_scans = filtered_scans;
    sorted_scans.sort_by(|a, b| {
        let a_running = ScanStatus::from_str(&a.status) == ScanStatus::Running;
        let b_running = ScanStatus::from_str(&b.status) == ScanStatus::Running;

        match (a_running, b_running) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => b.created_at.cmp(&a.created_at),
        }
    });

    // Scan list
    let scan_list: Element<'a, Message> = if sorted_scans.is_empty() {
        container(
            column![
                text("\u{1F50D}").size(48).color(Color::from_rgba(1.0, 1.0, 1.0, 0.1)),
                Space::with_height(16),
                text("No scans found")
                    .size(12)
                    .color(colors::TEXT_MUTED),
                Space::with_height(8),
                text("Start a scan from the toolbar")
                    .size(10)
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
        let mut cards = column![].spacing(8);
        for scan in &sorted_scans {
            let is_selected = selected_id == Some(&scan.id);
            cards = cards.push(scan_card(scan, is_selected));
        }
        scrollable(
            container(cards)
                .padding([0, 24])
                .width(Length::Fill)
        )
        .height(Length::Fill)
        .into()
    };

    // Detail panel (if a scan is selected)
    let selected_scan = selected_id.and_then(|id| scans.iter().find(|s| s.id == id));

    // Main content with optional detail panel
    let main_content: Element<'a, Message> = if let Some(scan) = selected_scan {
        row![
            container(scan_list)
                .width(Length::Fill)
                .height(Length::Fill),
            scan_detail(scan),
        ]
        .into()
    } else {
        scan_list
    };

    // Stats bar
    let stats_section = stats_bar(scans);

    // Full layout
    let content = column![
        header,
        container(Space::with_height(1))
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(colors::BORDER)),
                ..Default::default()
            }),
        container(stats_section)
            .padding([12, 24])
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.2))),
                ..Default::default()
            }),
        container(Space::with_height(1))
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(colors::BORDER)),
                ..Default::default()
            }),
        filters,
        container(Space::with_height(1))
            .width(Length::Fill)
            .style(|_| container::Style {
                background: Some(Background::Color(colors::BORDER)),
                ..Default::default()
            }),
        container(main_content)
            .width(Length::Fill)
            .height(Length::Fill)
            .padding([12, 0]),
    ];

    // Modal overlay
    container(
        container(content)
            .width(Length::Fixed(1000.0))
            .height(Length::Fixed(650.0))
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
        background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.8))),
        ..Default::default()
    })
    .into()
}
