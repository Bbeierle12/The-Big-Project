//! Left toolbar view with tools and actions.

use iced::widget::{button, column, container, row, text, Space, vertical_rule};
use iced::{Alignment, Element, Length};

use crate::message::{AttackTool, Message, NmapScanType, NodeType, ToolMode};
use crate::theme::{self, colors};

/// Render a tool button.
fn tool_button<'a>(
    label: &'a str,
    icon_char: char,
    active: bool,
    on_press: Message,
) -> Element<'a, Message> {
    let icon = text(icon_char.to_string())
        .size(16);

    let label_text = text(label)
        .size(8);

    let content = column![icon, label_text]
        .spacing(2)
        .align_x(Alignment::Center);

    let btn = button(content)
        .on_press(on_press)
        .padding([8, 4])
        .width(Length::Fixed(56.0));

    if active {
        btn.style(theme::primary_button_style).into()
    } else {
        btn.style(theme::secondary_button_style).into()
    }
}

/// Render a scan button (nmap style).
fn scan_button<'a>(
    label: &'a str,
    icon_char: char,
    scan_type: NmapScanType,
) -> Element<'a, Message> {
    let icon = text(icon_char.to_string())
        .size(14);

    let label_text = text(label)
        .size(7);

    let content = column![icon, label_text]
        .spacing(2)
        .align_x(Alignment::Center);

    button(content)
        .on_press(Message::RunNmapScan(scan_type))
        .padding([6, 4])
        .width(Length::Fixed(56.0))
        .style(theme::secondary_button_style)
        .into()
}

/// Render an attack tool button.
fn attack_button<'a>(
    label: &'a str,
    icon_char: char,
    tool: AttackTool,
) -> Element<'a, Message> {
    let icon = text(icon_char.to_string())
        .size(14);

    let label_text = text(label)
        .size(7);

    let content = column![icon, label_text]
        .spacing(2)
        .align_x(Alignment::Center);

    button(content)
        .on_press(Message::RunAttackTool(tool))
        .padding([6, 4])
        .width(Length::Fixed(56.0))
        .style(theme::secondary_button_style)
        .into()
}

/// Section label.
fn section_label<'a>(label: &'a str) -> Element<'a, Message> {
    text(label)
        .size(8)
        .color(colors::TEXT_MUTED)
        .into()
}

/// Render the toolbar.
pub fn view<'a>(current_mode: ToolMode) -> Element<'a, Message> {
    let mode_section = column![
        tool_button(
            "Select",
            '\u{25A1}', // □
            matches!(current_mode, ToolMode::Select),
            Message::SetToolMode(ToolMode::Select),
        ),
        tool_button(
            "Link",
            '\u{2194}', // ↔
            matches!(current_mode, ToolMode::Connect),
            Message::SetToolMode(ToolMode::Connect),
        ),
    ]
    .spacing(4)
    .align_x(Alignment::Center);

    let add_section = column![
        section_label("ADD"),
        Space::with_height(4),
        tool_button("Router", '\u{25CE}', false, Message::AddNode(NodeType::Router)),
        tool_button("AP", '\u{25C9}', false, Message::AddNode(NodeType::Extender)),
        tool_button("IoT", '\u{25CB}', false, Message::AddNode(NodeType::IoT)),
        tool_button("Mobile", '\u{25A0}', false, Message::AddNode(NodeType::Mobile)),
        tool_button("Laptop", '\u{25A1}', false, Message::AddNode(NodeType::Workstation)),
    ]
    .spacing(4)
    .align_x(Alignment::Center);

    let nmap_section = column![
        section_label("NMAP"),
        Space::with_height(4),
        scan_button("Quick", '\u{26A1}', NmapScanType::Quick),
        scan_button("Ports", '\u{2261}', NmapScanType::Ports),
        scan_button("Service", '\u{2630}', NmapScanType::Service),
        scan_button("OS", '\u{2318}', NmapScanType::OS),
        scan_button("Vuln", '\u{26A0}', NmapScanType::Vuln),
        scan_button("Full", '\u{25CF}', NmapScanType::Full),
    ]
    .spacing(4)
    .align_x(Alignment::Center);

    let attack_section = column![
        section_label("ATTACK"),
        Space::with_height(4),
        attack_button("Hydra", '\u{26A1}', AttackTool::Hydra),
        attack_button("Msf", '\u{2620}', AttackTool::Metasploit),
    ]
    .spacing(4)
    .align_x(Alignment::Center);

    let actions_section = column![
        tool_button("Group", '\u{2B1A}', false, Message::GroupSelected),
        tool_button("Delete", '\u{2716}', false, Message::DeleteSelected),
    ]
    .spacing(4)
    .align_x(Alignment::Center);

    let divider = || {
        container(Space::with_height(1))
            .width(Length::Fixed(48.0))
            .style(|_| container::Style {
                background: Some(iced::Background::Color(colors::BORDER)),
                ..Default::default()
            })
    };

    let content = column![
        mode_section,
        divider(),
        add_section,
        divider(),
        nmap_section,
        divider(),
        attack_section,
        Space::with_height(Length::Fill),
        actions_section,
    ]
    .spacing(8)
    .padding([12, 8])
    .align_x(Alignment::Center);

    container(content)
        .width(Length::Fixed(72.0))
        .height(Length::Fill)
        .style(theme::panel_style)
        .into()
}
