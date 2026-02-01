//! Dark theme styling for NetWatch.

use iced::widget::{button, container};
use iced::{Background, Border, Color, Theme};

/// Color palette for the dark theme.
pub mod colors {
    use iced::Color;

    // Base colors
    pub const BG_PRIMARY: Color = Color::from_rgb(0.04, 0.04, 0.05); // #0a0a0d
    pub const BG_SECONDARY: Color = Color::from_rgb(0.07, 0.09, 0.11); // #121719
    pub const BG_TERTIARY: Color = Color::from_rgb(0.10, 0.12, 0.14); // #1a1f24

    // Surface colors
    pub const SURFACE: Color = Color::from_rgb(0.12, 0.14, 0.16); // #1e2429
    pub const SURFACE_HOVER: Color = Color::from_rgb(0.16, 0.18, 0.20); // #292e33

    // Border colors
    pub const BORDER: Color = Color::from_rgba(1.0, 1.0, 1.0, 0.1);
    pub const BORDER_FOCUS: Color = Color::from_rgb(0.13, 0.83, 0.93); // #22d3ee (cyan)

    // Text colors
    pub const TEXT_PRIMARY: Color = Color::from_rgb(0.89, 0.91, 0.94); // #e2e8f0
    pub const TEXT_SECONDARY: Color = Color::from_rgb(0.58, 0.64, 0.69); // #94a3b0
    pub const TEXT_MUTED: Color = Color::from_rgb(0.39, 0.45, 0.51); // #647282

    // Accent colors
    pub const CYAN: Color = Color::from_rgb(0.13, 0.83, 0.93); // #22d3ee
    pub const GREEN: Color = Color::from_rgb(0.13, 0.77, 0.37); // #22c55e
    pub const YELLOW: Color = Color::from_rgb(0.92, 0.70, 0.03); // #eab308
    pub const RED: Color = Color::from_rgb(0.94, 0.27, 0.27); // #ef4444
    pub const ORANGE: Color = Color::from_rgb(0.97, 0.53, 0.15); // #f88725
    pub const PURPLE: Color = Color::from_rgb(0.57, 0.36, 0.90); // #9158e5

    // Status colors
    pub const STATUS_ONLINE: Color = GREEN;
    pub const STATUS_OFFLINE: Color = Color::from_rgb(0.39, 0.45, 0.51);
    pub const STATUS_WARNING: Color = YELLOW;
    pub const STATUS_CRITICAL: Color = RED;
}

/// Get the application theme.
pub fn get_theme() -> Theme {
    Theme::Dark
}

/// Container style for panels.
pub fn panel_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(colors::BG_SECONDARY)),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 4.0.into(),
        },
        ..Default::default()
    }
}

/// Container style for the main content area.
pub fn content_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(colors::BG_PRIMARY)),
        ..Default::default()
    }
}

/// Container style for the terminal area.
pub fn terminal_style(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgb(0.04, 0.04, 0.04))),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 0.0.into(),
        },
        ..Default::default()
    }
}

/// Button style for primary actions.
pub fn primary_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(Background::Color(colors::CYAN)),
        text_color: colors::BG_PRIMARY,
        border: Border {
            radius: 4.0.into(),
            ..Default::default()
        },
        ..Default::default()
    };

    match status {
        button::Status::Active => base,
        button::Status::Hovered => button::Style {
            background: Some(Background::Color(Color::from_rgb(0.26, 0.91, 0.97))),
            ..base
        },
        button::Status::Pressed => button::Style {
            background: Some(Background::Color(Color::from_rgb(0.10, 0.70, 0.80))),
            ..base
        },
        button::Status::Disabled => button::Style {
            background: Some(Background::Color(colors::SURFACE)),
            text_color: colors::TEXT_MUTED,
            ..base
        },
    }
}

/// Button style for secondary/subtle actions.
pub fn secondary_button_style(_theme: &Theme, status: button::Status) -> button::Style {
    let base = button::Style {
        background: Some(Background::Color(colors::SURFACE)),
        text_color: colors::TEXT_PRIMARY,
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 4.0.into(),
        },
        ..Default::default()
    };

    match status {
        button::Status::Active => base,
        button::Status::Hovered => button::Style {
            background: Some(Background::Color(colors::SURFACE_HOVER)),
            border: Border {
                color: colors::CYAN,
                ..base.border
            },
            ..base
        },
        button::Status::Pressed => button::Style {
            background: Some(Background::Color(colors::BG_TERTIARY)),
            ..base
        },
        button::Status::Disabled => button::Style {
            text_color: colors::TEXT_MUTED,
            ..base
        },
    }
}

/// Tab button style.
pub fn tab_button_style(_theme: &Theme, status: button::Status, active: bool) -> button::Style {
    let base = if active {
        button::Style {
            background: Some(Background::Color(colors::BG_TERTIARY)),
            text_color: colors::TEXT_PRIMARY,
            border: Border {
                color: colors::CYAN,
                width: 0.0,
                radius: 4.0.into(),
            },
            ..Default::default()
        }
    } else {
        button::Style {
            background: Some(Background::Color(Color::TRANSPARENT)),
            text_color: colors::TEXT_SECONDARY,
            border: Border {
                radius: 4.0.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    };

    match status {
        button::Status::Hovered if !active => button::Style {
            background: Some(Background::Color(colors::SURFACE)),
            text_color: colors::TEXT_PRIMARY,
            ..base
        },
        _ => base,
    }
}
