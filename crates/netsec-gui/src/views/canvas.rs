//! Network canvas view - placeholder for embedded React webview.
//!
//! This view renders a placeholder region where the Wry webview
//! displaying the React NetworkCanvas component will be overlaid.
//! The actual canvas rendering is done by React in the webview.

use iced::widget::{column, container, text, Space};
use iced::{Element, Length, Color, Background, Border};

use crate::message::Message;
use crate::state::network::NetworkState;
use crate::theme::colors;

/// Render the canvas placeholder view.
///
/// This creates a container that serves as the placeholder region
/// for the webview. The webview will be positioned to overlay this
/// exact region, creating a seamless integration.
pub fn view<'a>(network: &'a NetworkState) -> Element<'a, Message> {
    let title_row = container(
        text("Network Canvas")
            .size(12)
            .color(colors::TEXT_MUTED)
    )
    .padding([8, 12]);

    // Status indicator
    let status_text = if network.is_scanning {
        format!("Scanning... {}%", network.scan_progress)
    } else {
        format!("{} nodes, {} connections", network.nodes.len(), network.connections.len())
    };

    let status_row = container(
        text(status_text)
            .size(10)
            .color(colors::TEXT_MUTED)
    )
    .padding([4, 12]);

    // Placeholder content - this will be hidden when webview is active
    // but provides visual feedback during loading or if webview fails
    let placeholder = container(
        column![
            Space::with_height(Length::FillPortion(1)),
            container(
                column![
                    text("React NetworkCanvas")
                        .size(18)
                        .color(colors::CYAN),
                    Space::with_height(8),
                    text("Loading embedded webview...")
                        .size(12)
                        .color(colors::TEXT_MUTED),
                ]
                .align_x(iced::Alignment::Center)
            )
            .width(Length::Fill)
            .align_x(iced::Alignment::Center),
            Space::with_height(Length::FillPortion(1)),
        ]
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(canvas_placeholder_style);

    container(
        column![
            title_row,
            status_row,
            placeholder,
        ]
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .style(crate::theme::panel_style)
    .into()
}

/// Style for the canvas placeholder region.
fn canvas_placeholder_style(theme: &iced::Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(Color::from_rgba(0.02, 0.02, 0.03, 1.0))),
        border: Border {
            color: colors::BORDER,
            width: 1.0,
            radius: 4.0.into(),
        },
        ..Default::default()
    }
}
