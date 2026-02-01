//! Tools dashboard view.

use iced::widget::{button, column, container, horizontal_rule, row, scrollable, text, Space};
use iced::{Alignment, Background, Border, Color, Element, Length};

use crate::api::{Tool, ToolHealth};
use crate::message::Message;
use crate::theme::colors;

/// Tool status color.
fn status_color(status: &str) -> Color {
    match status.to_lowercase().as_str() {
        "available" | "healthy" | "ok" => colors::GREEN,
        "busy" | "running" => colors::CYAN,
        "warning" | "degraded" => colors::YELLOW,
        "error" | "unavailable" | "failed" => colors::RED,
        "unknown" => colors::TEXT_MUTED,
        _ => colors::TEXT_MUTED,
    }
}

/// Category icon.
fn category_icon(category: &str) -> &'static str {
    match category.to_lowercase().as_str() {
        "scanner" | "scanning" => "\u{1F50D}", // 🔍
        "exploit" | "exploitation" => "\u{1F4A3}", // 💣
        "recon" | "reconnaissance" => "\u{1F441}", // 👁
        "analysis" | "analyzer" => "\u{1F4CA}", // 📊
        "network" => "\u{1F310}", // 🌐
        "password" | "cracker" => "\u{1F511}", // 🔑
        "wireless" => "\u{1F4F6}", // 📶
        "web" => "\u{1F578}", // 🕸
        _ => "\u{1F527}", // 🔧
    }
}

/// Render a tool card.
fn tool_card<'a>(tool: &Tool, health: Option<&ToolHealth>, is_selected: bool) -> Element<'a, Message> {
    let tool_name = tool.name.clone();
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

    let status = health
        .map(|h| h.status.clone())
        .unwrap_or_else(|| tool.status.clone());
    let status_col = status_color(&status);

    let content = column![
        // Header row
        row![
            text(category_icon(&tool.category)).size(20),
            Space::with_width(12),
            column![
                text(tool.display_name.clone())
                    .size(13)
                    .color(colors::TEXT_PRIMARY),
                text(tool.name.clone())
                    .size(10)
                    .color(colors::TEXT_MUTED),
            ],
            Space::with_width(Length::Fill),
            // Status indicator
            container(
                row![
                    container(Space::with_width(8).height(8))
                        .style(move |_| container::Style {
                            background: Some(Background::Color(status_col)),
                            border: Border {
                                radius: 4.0.into(),
                                ..Default::default()
                            },
                            ..Default::default()
                        }),
                    Space::with_width(6),
                    text(status.clone())
                        .size(10)
                        .color(status_col),
                ]
                .align_y(Alignment::Center)
            ),
        ]
        .align_y(Alignment::Center),
        Space::with_height(8),
        // Description
        text(tool.description.clone().unwrap_or_else(|| "No description available".to_string()))
            .size(11)
            .color(colors::TEXT_MUTED),
        Space::with_height(8),
        // Tags/tasks
        row![
            container(
                text(tool.category.clone())
                    .size(9)
                    .color(colors::CYAN)
            )
            .padding([2, 8])
            .style(|_| container::Style {
                background: Some(Background::Color(Color::from_rgba(0.13, 0.83, 0.93, 0.1))),
                border: Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }),
            Space::with_width(8),
            text(tool.version.clone().unwrap_or_else(|| "unknown".to_string()))
                .size(10)
                .color(colors::TEXT_MUTED),
        ],
    ]
    .padding(12)
    .spacing(4);

    button(content)
        .on_press(Message::ToolSelected(tool_name))
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

/// Render tool detail panel.
fn tool_detail<'a>(tool: &Tool, health: Option<&ToolHealth>) -> Element<'a, Message> {
    let status = health
        .map(|h| h.status.clone())
        .unwrap_or_else(|| tool.status.clone());
    let status_col = status_color(&status);
    let tool_name = tool.name.clone();

    let health_message = health
        .and_then(|h| h.message.clone())
        .unwrap_or_else(|| "No health information available".to_string());

    column![
        // Header
        row![
            text(category_icon(&tool.category)).size(32),
            Space::with_width(12),
            column![
                text(tool.display_name.clone())
                    .size(16)
                    .color(colors::TEXT_PRIMARY),
                text(tool.name.clone())
                    .size(11)
                    .color(colors::TEXT_MUTED),
            ],
        ]
        .align_y(Alignment::Center),
        Space::with_height(16),
        horizontal_rule(1),
        Space::with_height(16),
        // Status
        text("Status").size(12).color(colors::CYAN),
        Space::with_height(8),
        row![
            container(Space::with_width(12).height(12))
                .style(move |_| container::Style {
                    background: Some(Background::Color(status_col)),
                    border: Border {
                        radius: 6.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
            Space::with_width(12),
            column![
                text(status.clone())
                    .size(14)
                    .color(status_col),
                text(health_message)
                    .size(10)
                    .color(colors::TEXT_MUTED),
            ],
        ]
        .align_y(Alignment::Center),
        Space::with_height(16),
        horizontal_rule(1),
        Space::with_height(16),
        // Info
        text("Information").size(12).color(colors::CYAN),
        Space::with_height(8),
        row![
            column![
                text("Category").size(10).color(colors::TEXT_MUTED),
                text(tool.category.clone()).size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
            column![
                text("Version").size(10).color(colors::TEXT_MUTED),
                text(tool.version.clone().unwrap_or_else(|| "Unknown".to_string()))
                    .size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
        ],
        Space::with_height(16),
        horizontal_rule(1),
        Space::with_height(16),
        // Description
        text("Description").size(12).color(colors::CYAN),
        Space::with_height(8),
        text(tool.description.clone().unwrap_or_else(|| "No description available".to_string()))
            .size(11)
            .color(colors::TEXT_PRIMARY),
        Space::with_height(16),
        horizontal_rule(1),
        Space::with_height(16),
        // Supported tasks
        text("Supported Tasks").size(12).color(colors::CYAN),
        Space::with_height(8),
        {
            let tasks: Vec<Element<'a, Message>> = tool.supported_tasks
                .iter()
                .map(|task| {
                    container(
                        text(task.clone())
                            .size(10)
                            .color(colors::TEXT_PRIMARY)
                    )
                    .padding([4, 8])
                    .style(|_| container::Style {
                        background: Some(Background::Color(colors::BG_PRIMARY)),
                        border: Border {
                            color: colors::BORDER,
                            width: 1.0,
                            radius: 4.0.into(),
                        },
                        ..Default::default()
                    })
                    .into()
                })
                .collect();

            if tasks.is_empty() {
                let empty: Element<'a, Message> = container(text("No tasks defined").size(10).color(colors::TEXT_MUTED))
                    .into();
                empty
            } else {
                scrollable(row(tasks).spacing(8))
                    .direction(iced::widget::scrollable::Direction::Horizontal(
                        iced::widget::scrollable::Scrollbar::default()
                    ))
                    .into()
            }
        },
        Space::with_height(24),
        // Actions
        button(
            row![
                text("\u{2764}").size(12), // ❤
                Space::with_width(8),
                text("Run Health Check").size(11),
            ]
            .align_y(Alignment::Center)
        )
        .on_press(Message::RunToolHealthCheck(tool_name))
        .padding([8, 16])
        .width(Length::Fill)
        .style(|_theme, status| {
            let bg = match status {
                iced::widget::button::Status::Hovered => colors::CYAN,
                _ => Color::from_rgba(0.13, 0.83, 0.93, 0.2),
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: if matches!(status, iced::widget::button::Status::Hovered) {
                    Color::WHITE
                } else {
                    colors::CYAN
                },
                border: Border {
                    color: colors::CYAN,
                    width: 1.0,
                    radius: 4.0.into(),
                },
                ..Default::default()
            }
        }),
    ]
    .padding(16)
    .into()
}

/// Stats bar showing tool summary.
fn stats_bar<'a>(tools: &[Tool], health: &[ToolHealth]) -> Element<'a, Message> {
    let total_tools = tools.len();

    // Count by status from health data
    let healthy_count = health.iter()
        .filter(|h| h.status.to_lowercase() == "healthy" || h.status.to_lowercase() == "ok")
        .count();
    let warning_count = health.iter()
        .filter(|h| h.status.to_lowercase() == "warning" || h.status.to_lowercase() == "degraded")
        .count();
    let error_count = health.iter()
        .filter(|h| h.status.to_lowercase() == "error" || h.status.to_lowercase() == "failed")
        .count();

    row![
        // Total tools
        container(
            row![
                text("\u{1F527}").size(12), // 🔧
                Space::with_width(6),
                text(format!("{} tools", total_tools)).size(11).color(colors::TEXT_PRIMARY),
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
        // Healthy
        container(
            row![
                text("\u{2705}").size(12), // ✅
                Space::with_width(6),
                text(format!("{} healthy", healthy_count)).size(11).color(colors::GREEN),
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
        // Warnings
        container(
            row![
                text("\u{26A0}").size(12), // ⚠
                Space::with_width(6),
                text(format!("{} warning", warning_count)).size(11).color(colors::YELLOW),
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
        // Errors
        container(
            row![
                text("\u{274C}").size(12), // ❌
                Space::with_width(6),
                text(format!("{} error", error_count)).size(11).color(colors::RED),
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
        // Refresh button
        button(
            row![
                text("\u{21BB}").size(12), // ↻
                Space::with_width(6),
                text("Check All").size(10),
            ]
            .align_y(Alignment::Center)
        )
        .on_press(Message::FetchToolsHealth)
        .padding([6, 12])
        .style(|_theme, status| {
            let bg = match status {
                iced::widget::button::Status::Hovered => colors::CYAN,
                _ => colors::BG_SECONDARY,
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                text_color: if matches!(status, iced::widget::button::Status::Hovered) {
                    Color::WHITE
                } else {
                    colors::TEXT_PRIMARY
                },
                border: Border {
                    radius: 4.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }
        }),
    ]
    .padding([8, 16])
    .align_y(Alignment::Center)
    .into()
}

/// Main tools dashboard view.
pub fn view<'a>(
    tools: &'a [Tool],
    tools_health: &'a [ToolHealth],
    selected_tool: &'a Option<String>,
) -> Element<'a, Message> {
    // Find selected tool
    let selected = selected_tool
        .as_ref()
        .and_then(|name| tools.iter().find(|t| &t.name == name));

    // Header
    let header = row![
        text("Security Tools")
            .size(18)
            .color(colors::TEXT_PRIMARY),
        Space::with_width(Length::Fill),
        button(text("\u{2715}").size(14)) // ✕
            .on_press(Message::HideToolsDashboard)
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
    let stats = stats_bar(tools, tools_health);

    // Tool list
    let tool_list: Element<'a, Message> = if tools.is_empty() {
        container(
            column![
                text("\u{1F527}").size(48), // 🔧
                Space::with_height(16),
                text("No tools available")
                    .size(14)
                    .color(colors::TEXT_MUTED),
                Space::with_height(8),
                text("Configure tools in the backend")
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
        let cards: Vec<Element<'a, Message>> = tools
            .iter()
            .map(|tool| {
                let is_selected = selected_tool.as_ref().map_or(false, |name| name == &tool.name);
                let health = tools_health.iter().find(|h| h.name == tool.name);
                tool_card(tool, health, is_selected)
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
    let detail_panel: Element<'a, Message> = if let Some(tool) = selected {
        let health = tools_health.iter().find(|h| h.name == tool.name);
        container(
            scrollable(tool_detail(tool, health))
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
                text("\u{1F527}").size(32).color(colors::TEXT_MUTED), // 🔧
                Space::with_height(8),
                text("Select a tool")
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
        container(tool_list)
            .width(Length::Fill)
            .height(Length::Fill),
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
            .width(Length::Fixed(900.0))
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
        background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.7))),
        ..Default::default()
    })
    .into()
}
