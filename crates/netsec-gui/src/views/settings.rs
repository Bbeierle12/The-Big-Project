//! Settings panel view.

use iced::widget::{button, column, container, horizontal_rule, row, scrollable, text, text_input, toggler, Space};
use iced::{Alignment, Background, Border, Color, Element, Length};

use crate::message::Message;
use crate::theme::colors;

/// Application settings state.
#[derive(Debug, Clone)]
pub struct Settings {
    pub api_url: String,
    pub ws_url: String,
    pub dark_mode: bool,
    pub notifications_enabled: bool,
    pub auto_refresh: bool,
    pub refresh_interval_secs: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            api_url: "http://127.0.0.1:8420".to_string(),
            ws_url: "ws://127.0.0.1:8420/ws".to_string(),
            dark_mode: true,
            notifications_enabled: true,
            auto_refresh: true,
            refresh_interval_secs: 30,
        }
    }
}

/// Settings section component.
fn settings_section<'a>(
    title: &'a str,
    description: &'a str,
    content: Element<'a, Message>,
) -> Element<'a, Message> {
    column![
        text(title).size(14).color(colors::CYAN),
        Space::with_height(4),
        text(description).size(10).color(colors::TEXT_MUTED),
        Space::with_height(12),
        content,
    ]
    .spacing(4)
    .into()
}

/// Toggle row component.
fn toggle_row<'a>(
    label: &'a str,
    description: &'a str,
    value: bool,
    on_toggle: impl Fn(bool) -> Message + 'a,
) -> Element<'a, Message> {
    row![
        column![
            text(label).size(12).color(colors::TEXT_PRIMARY),
            text(description).size(10).color(colors::TEXT_MUTED),
        ]
        .width(Length::Fill),
        toggler(value)
            .on_toggle(on_toggle)
            .size(20)
            .style(|_theme, status| {
                let (bg, fg) = match status {
                    iced::widget::toggler::Status::Active { is_toggled } |
                    iced::widget::toggler::Status::Hovered { is_toggled } => {
                        if is_toggled {
                            (colors::CYAN, Color::WHITE)
                        } else {
                            (colors::BG_SECONDARY, colors::TEXT_MUTED)
                        }
                    }
                    iced::widget::toggler::Status::Disabled => {
                        (colors::BG_SECONDARY, colors::TEXT_MUTED)
                    }
                };
                iced::widget::toggler::Style {
                    background: bg,
                    background_border_width: 1.0,
                    background_border_color: colors::BORDER,
                    foreground: fg,
                    foreground_border_width: 0.0,
                    foreground_border_color: Color::TRANSPARENT,
                }
            }),
    ]
    .align_y(Alignment::Center)
    .padding([8, 0])
    .into()
}

/// Input field component.
fn input_field<'a>(
    label: &'a str,
    value: &'a str,
    placeholder: &'a str,
    on_change: impl Fn(String) -> Message + 'a,
) -> Element<'a, Message> {
    column![
        text(label).size(11).color(colors::TEXT_MUTED),
        Space::with_height(4),
        text_input(placeholder, value)
            .on_input(on_change)
            .padding([8, 12])
            .size(12)
            .style(|_theme, status| {
                let border_color = match status {
                    iced::widget::text_input::Status::Focused => colors::CYAN,
                    iced::widget::text_input::Status::Hovered => colors::BORDER,
                    _ => colors::BORDER,
                };
                iced::widget::text_input::Style {
                    background: Background::Color(colors::BG_SECONDARY),
                    border: Border {
                        color: border_color,
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    icon: colors::TEXT_MUTED,
                    placeholder: colors::TEXT_MUTED,
                    value: colors::TEXT_PRIMARY,
                    selection: colors::CYAN,
                }
            }),
    ]
    .spacing(4)
    .into()
}

/// Main settings view.
pub fn view<'a>(settings: &'a Settings) -> Element<'a, Message> {
    // Header
    let header = row![
        text("Settings")
            .size(18)
            .color(colors::TEXT_PRIMARY),
        Space::with_width(Length::Fill),
        button(text("\u{2715}").size(14)) // ✕
            .on_press(Message::HideSettings)
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

    // API Configuration section
    let api_section = settings_section(
        "API Configuration",
        "Configure the backend API connection",
        column![
            input_field(
                "API URL",
                &settings.api_url,
                "http://127.0.0.1:8420",
                Message::SettingsUpdateApiUrl,
            ),
            Space::with_height(12),
            input_field(
                "WebSocket URL",
                &settings.ws_url,
                "ws://127.0.0.1:8420/ws",
                Message::SettingsUpdateWsUrl,
            ),
        ]
        .into(),
    );

    // Appearance section
    let appearance_section = settings_section(
        "Appearance",
        "Customize the look and feel",
        column![
            toggle_row(
                "Dark Mode",
                "Use dark color scheme",
                settings.dark_mode,
                |_| Message::SettingsToggleDarkMode,
            ),
        ]
        .into(),
    );

    // Notifications section
    let notifications_section = settings_section(
        "Notifications",
        "Configure alerts and notifications",
        column![
            toggle_row(
                "Enable Notifications",
                "Show desktop notifications for alerts",
                settings.notifications_enabled,
                |_| Message::SettingsToggleNotifications,
            ),
        ]
        .into(),
    );

    // Data refresh section
    let refresh_section = settings_section(
        "Data Refresh",
        "Configure automatic data updates",
        column![
            toggle_row(
                "Auto Refresh",
                "Automatically refresh data from API",
                settings.auto_refresh,
                |_| Message::SettingsToggleAutoRefresh,
            ),
            Space::with_height(8),
            row![
                text("Refresh Interval").size(11).color(colors::TEXT_MUTED),
                Space::with_width(Length::Fill),
                button(text("-").size(12))
                    .on_press(Message::SettingsUpdateRefreshInterval(
                        settings.refresh_interval_secs.saturating_sub(5).max(5)
                    ))
                    .padding([4, 12])
                    .style(|_theme, status| {
                        let bg = match status {
                            iced::widget::button::Status::Hovered => colors::BG_SECONDARY,
                            _ => colors::BG_PRIMARY,
                        };
                        iced::widget::button::Style {
                            background: Some(Background::Color(bg)),
                            text_color: colors::TEXT_PRIMARY,
                            border: Border {
                                color: colors::BORDER,
                                width: 1.0,
                                radius: 4.0.into(),
                            },
                            ..Default::default()
                        }
                    }),
                Space::with_width(8),
                container(
                    text(format!("{}s", settings.refresh_interval_secs))
                        .size(12)
                        .color(colors::TEXT_PRIMARY)
                )
                .padding([4, 12])
                .style(|_| container::Style {
                    background: Some(Background::Color(colors::BG_SECONDARY)),
                    border: Border {
                        radius: 4.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                Space::with_width(8),
                button(text("+").size(12))
                    .on_press(Message::SettingsUpdateRefreshInterval(
                        settings.refresh_interval_secs.saturating_add(5).min(300)
                    ))
                    .padding([4, 12])
                    .style(|_theme, status| {
                        let bg = match status {
                            iced::widget::button::Status::Hovered => colors::BG_SECONDARY,
                            _ => colors::BG_PRIMARY,
                        };
                        iced::widget::button::Style {
                            background: Some(Background::Color(bg)),
                            text_color: colors::TEXT_PRIMARY,
                            border: Border {
                                color: colors::BORDER,
                                width: 1.0,
                                radius: 4.0.into(),
                            },
                            ..Default::default()
                        }
                    }),
            ]
            .align_y(Alignment::Center),
        ]
        .into(),
    );

    // About section
    let about_section = settings_section(
        "About",
        "Application information",
        column![
            row![
                text("Version").size(11).color(colors::TEXT_MUTED),
                Space::with_width(Length::Fill),
                text("0.1.0").size(11).color(colors::TEXT_PRIMARY),
            ],
            Space::with_height(8),
            row![
                text("Build").size(11).color(colors::TEXT_MUTED),
                Space::with_width(Length::Fill),
                text("Development").size(11).color(colors::TEXT_PRIMARY),
            ],
        ]
        .into(),
    );

    // Main content
    let content = column![
        header,
        horizontal_rule(1),
        scrollable(
            column![
                Space::with_height(16),
                api_section,
                Space::with_height(24),
                horizontal_rule(1),
                Space::with_height(24),
                appearance_section,
                Space::with_height(24),
                horizontal_rule(1),
                Space::with_height(24),
                notifications_section,
                Space::with_height(24),
                horizontal_rule(1),
                Space::with_height(24),
                refresh_section,
                Space::with_height(24),
                horizontal_rule(1),
                Space::with_height(24),
                about_section,
                Space::with_height(24),
            ]
            .padding([0, 16])
        )
        .height(Length::Fill),
        horizontal_rule(1),
        // Footer with save button
        container(
            row![
                Space::with_width(Length::Fill),
                button(
                    row![
                        text("\u{1F4BE}").size(12), // 💾
                        Space::with_width(8),
                        text("Save Settings").size(11),
                    ]
                    .align_y(Alignment::Center)
                )
                .on_press(Message::SettingsSave)
                .padding([10, 24])
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
        ),
    ];

    // Modal overlay
    container(
        container(content)
            .width(Length::Fixed(500.0))
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
