//! Shared UI components: toast notifications, confirmation dialogs, loading spinners.

use iced::widget::{button, column, container, row, text, Space};
use iced::{Alignment, Background, Border, Color, Element, Length};

use crate::message::{Message, ToastLevel};
use crate::theme::colors;

/// Toast notification data.
#[derive(Debug, Clone)]
pub struct Toast {
    pub id: usize,
    pub message: String,
    pub level: ToastLevel,
    pub created_at: std::time::Instant,
}

impl Toast {
    pub fn new(id: usize, message: String, level: ToastLevel) -> Self {
        Self {
            id,
            message,
            level,
            created_at: std::time::Instant::now(),
        }
    }

    /// Check if toast should be auto-dismissed (after 5 seconds).
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed().as_secs() >= 5
    }
}

/// Get color for toast level.
fn toast_color(level: &ToastLevel) -> Color {
    match level {
        ToastLevel::Info => colors::CYAN,
        ToastLevel::Success => colors::GREEN,
        ToastLevel::Warning => colors::YELLOW,
        ToastLevel::Error => colors::RED,
    }
}

/// Get icon for toast level.
fn toast_icon(level: &ToastLevel) -> &'static str {
    match level {
        ToastLevel::Info => "\u{2139}", // ℹ
        ToastLevel::Success => "\u{2705}", // ✅
        ToastLevel::Warning => "\u{26A0}", // ⚠
        ToastLevel::Error => "\u{274C}", // ❌
    }
}

/// Render a single toast notification.
fn toast_view<'a>(toast: &Toast) -> Element<'a, Message> {
    let color = toast_color(&toast.level);
    let icon = toast_icon(&toast.level);
    let toast_id = toast.id;

    container(
        row![
            // Icon
            container(
                text(icon).size(14).color(color)
            )
            .padding([0, 8]),
            // Message
            text(toast.message.clone())
                .size(12)
                .color(colors::TEXT_PRIMARY)
                .width(Length::Fill),
            // Dismiss button
            button(text("\u{2715}").size(10)) // ✕
                .on_press(Message::DismissToast(toast_id))
                .padding([2, 6])
                .style(move |_theme, status| {
                    let bg = match status {
                        iced::widget::button::Status::Hovered => Color::from_rgba(1.0, 1.0, 1.0, 0.1),
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
        .align_y(Alignment::Center)
        .padding(12)
    )
    .style(move |_| container::Style {
        background: Some(Background::Color(colors::BG_SECONDARY)),
        border: Border {
            color,
            width: 1.0,
            radius: 6.0.into(),
        },
        ..Default::default()
    })
    .width(Length::Fixed(350.0))
    .into()
}

/// Render toast container (positioned in bottom-right).
pub fn toast_container<'a>(toasts: &[Toast]) -> Element<'a, Message> {
    if toasts.is_empty() {
        return Space::with_width(0).into();
    }

    let toast_elements: Vec<Element<'a, Message>> = toasts
        .iter()
        .rev() // Show newest at bottom
        .take(5) // Max 5 visible
        .map(toast_view)
        .collect();

    container(
        column(toast_elements)
            .spacing(8)
            .align_x(Alignment::End)
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .align_x(iced::alignment::Horizontal::Right)
    .align_y(iced::alignment::Vertical::Bottom)
    .padding([16, 16])
    .into()
}

/// Confirmation dialog data.
#[derive(Debug, Clone)]
pub struct ConfirmDialog {
    pub message: String,
    pub confirm_action: Box<Message>,
}

impl ConfirmDialog {
    pub fn new(message: String, confirm_action: Message) -> Self {
        Self {
            message,
            confirm_action: Box::new(confirm_action),
        }
    }
}

/// Render confirmation dialog.
pub fn confirm_dialog_view<'a>(dialog: &ConfirmDialog) -> Element<'a, Message> {
    let content = column![
        // Icon
        text("\u{2753}").size(36).color(colors::YELLOW), // ❓
        Space::with_height(16),
        // Message
        text(dialog.message.clone())
            .size(14)
            .color(colors::TEXT_PRIMARY),
        Space::with_height(24),
        // Buttons
        row![
            button(
                text("Cancel")
                    .size(12)
            )
            .on_press(Message::ConfirmDialogCancel)
            .padding([10, 24])
            .style(|_theme, status| {
                let bg = match status {
                    iced::widget::button::Status::Hovered => colors::BG_SECONDARY,
                    _ => colors::BG_PRIMARY,
                };
                iced::widget::button::Style {
                    background: Some(Background::Color(bg)),
                    text_color: colors::TEXT_MUTED,
                    border: Border {
                        color: colors::BORDER,
                        width: 1.0,
                        radius: 4.0.into(),
                    },
                    ..Default::default()
                }
            }),
            Space::with_width(12),
            button(
                text("Confirm")
                    .size(12)
            )
            .on_press(Message::ConfirmDialogAccept)
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
        .align_y(Alignment::Center),
    ]
    .align_x(Alignment::Center)
    .padding(32);

    // Modal overlay
    container(
        container(content)
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

/// Loading spinner component.
pub fn loading_spinner<'a>(message: &'a str) -> Element<'a, Message> {
    container(
        column![
            // Animated spinner (using text characters)
            text("\u{27F3}") // ⟳
                .size(32)
                .color(colors::CYAN),
            Space::with_height(12),
            text(message)
                .size(12)
                .color(colors::TEXT_MUTED),
        ]
        .align_x(Alignment::Center)
    )
    .padding(24)
    .style(|_| container::Style {
        background: Some(Background::Color(colors::BG_SECONDARY)),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 8.0.into(),
        },
        ..Default::default()
    })
    .into()
}

/// Full-screen loading overlay.
pub fn loading_overlay<'a>(message: &'a str) -> Element<'a, Message> {
    container(
        loading_spinner(message)
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .style(|_| container::Style {
        background: Some(Background::Color(Color::from_rgba(0.0, 0.0, 0.0, 0.5))),
        ..Default::default()
    })
    .into()
}

/// Empty state component.
pub fn empty_state<'a>(icon: &'a str, title: &'a str, description: &'a str) -> Element<'a, Message> {
    container(
        column![
            text(icon).size(48),
            Space::with_height(16),
            text(title)
                .size(14)
                .color(colors::TEXT_PRIMARY),
            Space::with_height(8),
            text(description)
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
}

/// Error state component.
pub fn error_state<'a>(error_message: &'a str) -> Element<'a, Message> {
    container(
        column![
            text("\u{274C}").size(48), // ❌
            Space::with_height(16),
            text("An error occurred")
                .size(14)
                .color(colors::RED),
            Space::with_height(8),
            text(error_message)
                .size(11)
                .color(colors::TEXT_MUTED),
            Space::with_height(16),
            button(
                row![
                    text("\u{21BB}").size(12), // ↻
                    Space::with_width(8),
                    text("Retry").size(11),
                ]
                .align_y(Alignment::Center)
            )
            .on_press(Message::RefreshAll)
            .padding([8, 16])
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
        .align_x(Alignment::Center)
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .center_x(Length::Fill)
    .center_y(Length::Fill)
    .into()
}

/// Badge component.
pub fn badge<'a>(label: &'a str, color: Color) -> Element<'a, Message> {
    container(
        text(label)
            .size(9)
            .color(Color::WHITE)
    )
    .padding([2, 8])
    .style(move |_| container::Style {
        background: Some(Background::Color(color)),
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    })
    .into()
}

/// Count badge component (for header buttons).
pub fn count_badge<'a>(count: usize, color: Color) -> Element<'a, Message> {
    if count == 0 {
        return Space::with_width(0).into();
    }

    container(
        text(count.to_string())
            .size(9)
            .color(Color::WHITE)
    )
    .padding([2, 6])
    .style(move |_| container::Style {
        background: Some(Background::Color(color)),
        border: Border {
            radius: 8.0.into(),
            ..Default::default()
        },
        ..Default::default()
    })
    .into()
}
