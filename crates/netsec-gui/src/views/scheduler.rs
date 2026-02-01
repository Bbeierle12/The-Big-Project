//! Scheduler dashboard view.

use iced::widget::{button, column, container, horizontal_rule, row, scrollable, text, Space};
use iced::{Alignment, Background, Border, Color, Element, Length};

use crate::api::ScheduledJob;
use crate::message::Message;
use crate::theme::colors;

/// Format cron expression to human-readable.
fn format_trigger(trigger_type: &str, _trigger_args: &std::collections::HashMap<String, String>) -> String {
    match trigger_type {
        "cron" => "Scheduled (cron)".to_string(),
        "interval" => "Interval".to_string(),
        "once" => "One-time".to_string(),
        _ => trigger_type.to_string(),
    }
}

/// Render a job card.
fn job_card<'a>(job: &ScheduledJob, is_selected: bool) -> Element<'a, Message> {
    let job_id = job.id.clone();
    let job_id_toggle = job.id.clone();
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

    let enabled = job.enabled;
    let status_color = if enabled { colors::GREEN } else { colors::TEXT_MUTED };
    let status_text = if enabled { "Active" } else { "Paused" };

    let next_run = job.next_run
        .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_else(|| "Not scheduled".to_string());

    let content = row![
        // Enable/disable toggle
        button(
            container(Space::with_width(12).height(12))
                .style(move |_| container::Style {
                    background: Some(Background::Color(if enabled {
                        colors::GREEN
                    } else {
                        colors::TEXT_MUTED
                    })),
                    border: Border {
                        radius: 6.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                })
        )
        .on_press(Message::ToggleJobEnabled(job_id_toggle))
        .padding(4)
        .style(|_theme, status| {
            let bg = match status {
                iced::widget::button::Status::Hovered => Color::from_rgba(1.0, 1.0, 1.0, 0.1),
                _ => Color::TRANSPARENT,
            };
            iced::widget::button::Style {
                background: Some(Background::Color(bg)),
                border: Border {
                    radius: 8.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }
        }),
        Space::with_width(12),
        // Job info
        column![
            row![
                text(job.name.clone())
                    .size(13)
                    .color(colors::TEXT_PRIMARY),
                Space::with_width(Length::Fill),
                text(status_text)
                    .size(10)
                    .color(status_color),
            ],
            Space::with_height(4),
            row![
                container(
                    text(job.task_type.clone())
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
                text(format_trigger(&job.trigger_type, &job.trigger_args))
                    .size(10)
                    .color(colors::TEXT_MUTED),
            ],
            Space::with_height(4),
            text(format!("Next run: {}", next_run))
                .size(10)
                .color(colors::TEXT_MUTED),
        ]
        .width(Length::Fill),
    ]
    .padding(12)
    .align_y(Alignment::Center);

    button(content)
        .on_press(Message::JobSelected(job_id))
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

/// Render job detail panel.
fn job_detail<'a>(job: &ScheduledJob) -> Element<'a, Message> {
    let job_id_pause = job.id.clone();
    let job_id_resume = job.id.clone();
    let job_id_delete = job.id.clone();

    let enabled = job.enabled;
    let status_color = if enabled { colors::GREEN } else { colors::TEXT_MUTED };
    let status_text = if enabled { "Active" } else { "Paused" };

    let next_run = job.next_run
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "Not scheduled".to_string());

    let last_run = job.last_run
        .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "Never".to_string());

    let created = job.created_at.format("%Y-%m-%d %H:%M:%S").to_string();

    // Build params display
    let params_count = job.task_params.len();

    column![
        // Header
        row![
            column![
                text(job.name.clone())
                    .size(16)
                    .color(colors::TEXT_PRIMARY),
                text(format!("ID: {}", &job.id[..8]))
                    .size(10)
                    .color(colors::TEXT_MUTED),
            ],
            Space::with_width(Length::Fill),
            container(
                row![
                    container(Space::with_width(8).height(8))
                        .style(move |_| container::Style {
                            background: Some(Background::Color(status_color)),
                            border: Border {
                                radius: 4.0.into(),
                                ..Default::default()
                            },
                            ..Default::default()
                        }),
                    Space::with_width(6),
                    text(status_text)
                        .size(11)
                        .color(status_color),
                ]
                .align_y(Alignment::Center)
            ),
        ]
        .align_y(Alignment::Center),
        Space::with_height(16),
        horizontal_rule(1),
        Space::with_height(16),
        // Schedule info
        text("Schedule").size(12).color(colors::CYAN),
        Space::with_height(8),
        row![
            column![
                text("Trigger Type").size(10).color(colors::TEXT_MUTED),
                text(job.trigger_type.clone()).size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
            column![
                text("Next Run").size(10).color(colors::TEXT_MUTED),
                text(next_run).size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
        ],
        Space::with_height(8),
        row![
            column![
                text("Last Run").size(10).color(colors::TEXT_MUTED),
                text(last_run).size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
            column![
                text("Created").size(10).color(colors::TEXT_MUTED),
                text(created).size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
        ],
        Space::with_height(16),
        horizontal_rule(1),
        Space::with_height(16),
        // Task info
        text("Task Configuration").size(12).color(colors::CYAN),
        Space::with_height(8),
        row![
            column![
                text("Task Type").size(10).color(colors::TEXT_MUTED),
                text(job.task_type.clone()).size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
            column![
                text("Parameters").size(10).color(colors::TEXT_MUTED),
                text(format!("{} configured", params_count)).size(12).color(colors::TEXT_PRIMARY),
            ]
            .width(Length::Fill),
        ],
        Space::with_height(24),
        // Actions
        {
            let toggle_btn: Element<'a, Message> = if enabled {
                button(
                    row![
                        text("\u{23F8}").size(12), // ⏸
                        Space::with_width(8),
                        text("Pause").size(11),
                    ]
                    .align_y(Alignment::Center)
                )
                .on_press(Message::PauseJob(job_id_pause))
                .padding([8, 16])
                .style(|_theme, status| {
                    let bg = match status {
                        iced::widget::button::Status::Hovered => colors::YELLOW,
                        _ => Color::from_rgba(1.0, 0.8, 0.0, 0.2),
                    };
                    iced::widget::button::Style {
                        background: Some(Background::Color(bg)),
                        text_color: if matches!(status, iced::widget::button::Status::Hovered) {
                            Color::WHITE
                        } else {
                            colors::YELLOW
                        },
                        border: Border {
                            color: colors::YELLOW,
                            width: 1.0,
                            radius: 4.0.into(),
                        },
                        ..Default::default()
                    }
                })
                .into()
            } else {
                button(
                    row![
                        text("\u{25B6}").size(12), // ▶
                        Space::with_width(8),
                        text("Resume").size(11),
                    ]
                    .align_y(Alignment::Center)
                )
                .on_press(Message::ResumeJob(job_id_resume))
                .padding([8, 16])
                .style(|_theme, status| {
                    let bg = match status {
                        iced::widget::button::Status::Hovered => colors::GREEN,
                        _ => Color::from_rgba(0.34, 0.84, 0.44, 0.2),
                    };
                    iced::widget::button::Style {
                        background: Some(Background::Color(bg)),
                        text_color: if matches!(status, iced::widget::button::Status::Hovered) {
                            Color::WHITE
                        } else {
                            colors::GREEN
                        },
                        border: Border {
                            color: colors::GREEN,
                            width: 1.0,
                            radius: 4.0.into(),
                        },
                        ..Default::default()
                    }
                })
                .into()
            };
            row![
                toggle_btn,
                Space::with_width(8),
                button(
                    row![
                        text("\u{1F5D1}").size(12), // 🗑
                        Space::with_width(8),
                        text("Delete").size(11),
                    ]
                    .align_y(Alignment::Center)
                )
                .on_press(Message::DeleteJob(job_id_delete))
                .padding([8, 16])
                .style(|_theme, status| {
                    let bg = match status {
                        iced::widget::button::Status::Hovered => colors::RED,
                        _ => Color::from_rgba(0.94, 0.27, 0.27, 0.2),
                    };
                    iced::widget::button::Style {
                        background: Some(Background::Color(bg)),
                        text_color: if matches!(status, iced::widget::button::Status::Hovered) {
                            Color::WHITE
                        } else {
                            colors::RED
                        },
                        border: Border {
                            color: colors::RED,
                            width: 1.0,
                            radius: 4.0.into(),
                        },
                        ..Default::default()
                    }
                }),
            ]
        },
    ]
    .padding(16)
    .into()
}

/// Stats bar showing job summary.
fn stats_bar<'a>(jobs: &[ScheduledJob]) -> Element<'a, Message> {
    let total_jobs = jobs.len();
    let active_count = jobs.iter().filter(|j| j.enabled).count();
    let paused_count = total_jobs - active_count;

    row![
        // Total jobs
        container(
            row![
                text("\u{1F4C5}").size(12), // 📅
                Space::with_width(6),
                text(format!("{} jobs", total_jobs)).size(11).color(colors::TEXT_PRIMARY),
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
        // Active
        container(
            row![
                text("\u{25B6}").size(12), // ▶
                Space::with_width(6),
                text(format!("{} active", active_count)).size(11).color(colors::GREEN),
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
        // Paused
        container(
            row![
                text("\u{23F8}").size(12), // ⏸
                Space::with_width(6),
                text(format!("{} paused", paused_count)).size(11).color(colors::TEXT_MUTED),
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
                text("Refresh").size(10),
            ]
            .align_y(Alignment::Center)
        )
        .on_press(Message::FetchJobs)
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

/// Main scheduler dashboard view.
pub fn view<'a>(
    jobs: &'a [ScheduledJob],
    selected_job_id: &'a Option<String>,
) -> Element<'a, Message> {
    // Find selected job
    let selected_job = selected_job_id
        .as_ref()
        .and_then(|id| jobs.iter().find(|j| &j.id == id));

    // Header
    let header = row![
        text("Scheduled Jobs")
            .size(18)
            .color(colors::TEXT_PRIMARY),
        Space::with_width(Length::Fill),
        button(text("\u{2715}").size(14)) // ✕
            .on_press(Message::HideSchedulerDashboard)
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
    let stats = stats_bar(jobs);

    // Job list
    let job_list: Element<'a, Message> = if jobs.is_empty() {
        container(
            column![
                text("\u{1F4C5}").size(48), // 📅
                Space::with_height(16),
                text("No scheduled jobs")
                    .size(14)
                    .color(colors::TEXT_MUTED),
                Space::with_height(8),
                text("Create a job to automate tasks")
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
        let cards: Vec<Element<'a, Message>> = jobs
            .iter()
            .map(|job| {
                let is_selected = selected_job_id.as_ref().map_or(false, |id| id == &job.id);
                job_card(job, is_selected)
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
    let detail_panel: Element<'a, Message> = if let Some(job) = selected_job {
        container(
            scrollable(job_detail(job))
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
                text("\u{1F4C5}").size(32).color(colors::TEXT_MUTED), // 📅
                Space::with_height(8),
                text("Select a job")
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
        container(job_list)
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
            .width(Length::Fixed(850.0))
            .height(Length::Fixed(600.0))
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
