//! Terminal panel view.

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Alignment, Element, Length};

use crate::message::Message;
use crate::state::terminal::{TerminalState, TerminalStatus};
use crate::theme::{self, colors};

/// Render the terminal panel.
pub fn view<'a>(state: &'a TerminalState) -> Element<'a, Message> {
    // Tab bar
    let tab_bar = view_tab_bar(state);

    // Terminal content
    let content: Element<'_, Message> = if let Some(tab) = state.active_tab() {
        let screen_content = tab.screen_content();

        scrollable(
            container(
                text(screen_content)
                    .size(13)
                    .font(iced::Font::MONOSPACE)
                    .color(colors::TEXT_PRIMARY)
            )
            .padding(8)
            .width(Length::Fill)
        )
        .height(Length::Fill)
        .into()
    } else {
        container(
            text("No terminal open. Click + to create one.")
                .size(14)
                .color(colors::TEXT_MUTED)
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .into()
    };

    let terminal_container = container(content)
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::terminal_style);

    column![
        tab_bar,
        terminal_container,
    ]
    .spacing(0)
    .into()
}

/// Render the tab bar.
fn view_tab_bar<'a>(state: &'a TerminalState) -> Element<'a, Message> {
    let mut tabs = row![].spacing(2).align_y(Alignment::Center);

    // Existing tabs
    for (idx, tab) in state.tabs.iter().enumerate() {
        let is_active = state.active_index == Some(idx);

        let status_indicator = match tab.status {
            TerminalStatus::Connected => text("●").size(8).color(colors::GREEN),
            TerminalStatus::Connecting => text("●").size(8).color(colors::YELLOW),
            TerminalStatus::Disconnected => text("●").size(8).color(colors::TEXT_MUTED),
            TerminalStatus::Error => text("●").size(8).color(colors::RED),
        };

        let tab_title = text(&tab.title).size(12);

        let close_btn = button(text("×").size(12))
            .on_press(Message::TerminalCloseTab(tab.id))
            .padding([2, 6])
            .style(move |theme, status| theme::secondary_button_style(theme, status));

        let tab_content = row![
            status_indicator,
            Space::with_width(4),
            tab_title,
            Space::with_width(8),
            close_btn,
        ]
        .align_y(Alignment::Center);

        let tab_btn = button(tab_content)
            .on_press(Message::TerminalSelectTab(tab.id))
            .padding([6, 12])
            .style(move |theme, status| theme::tab_button_style(theme, status, is_active));

        tabs = tabs.push(tab_btn);
    }

    // Add new terminal button with shell picker
    // For now, use a simple + button
    // In a full implementation, this would be a dropdown
    let add_btn = if let Some(default_shell) = state.available_shells.first() {
        let shell_clone = default_shell.clone();
        button(text("+").size(14))
            .on_press(Message::TerminalNewTab(shell_clone))
            .padding([6, 12])
            .style(theme::secondary_button_style)
    } else {
        button(text("+").size(14))
            .padding([6, 12])
            .style(theme::secondary_button_style)
    };

    tabs = tabs.push(Space::with_width(4));
    tabs = tabs.push(add_btn);

    container(tabs)
        .width(Length::Fill)
        .padding([4, 8])
        .style(theme::panel_style)
        .into()
}
