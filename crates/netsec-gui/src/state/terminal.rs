//! Terminal state management.

use iced::{Subscription, Task};
use netsec_pty::{detect_available_shells, PtySession, ShellInfo};

use crate::message::{Message, TabId};

/// State for a single terminal tab.
pub struct TerminalTab {
    /// Unique identifier
    pub id: TabId,
    /// Shell information
    pub shell: ShellInfo,
    /// Display title
    pub title: String,
    /// PTY session (None if not yet created or closed)
    pub session: Option<PtySession>,
    /// Terminal state parser
    pub parser: vt100::Parser,
    /// Connection status
    pub status: TerminalStatus,
}

/// Terminal connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalStatus {
    Connecting,
    Connected,
    Disconnected,
    Error,
}

impl TerminalTab {
    /// Create a new terminal tab.
    pub fn new(shell: ShellInfo) -> Self {
        let id = TabId::new();
        let title = shell.name.clone();

        Self {
            id,
            shell,
            title,
            session: None,
            parser: vt100::Parser::new(24, 80, 1000), // rows, cols, scrollback
            status: TerminalStatus::Connecting,
        }
    }

    /// Get the rendered terminal content.
    pub fn screen_content(&self) -> String {
        let screen = self.parser.screen();
        let mut content = String::new();

        for row in 0..screen.size().0 {
            let row_content = screen.contents_between(
                row, 0,
                row, screen.size().1,
            );
            content.push_str(&row_content);
            content.push('\n');
        }

        content
    }

    /// Get the cursor position.
    pub fn cursor_position(&self) -> (u16, u16) {
        self.parser.screen().cursor_position()
    }
}

/// State for all terminals.
pub struct TerminalState {
    /// All terminal tabs
    pub tabs: Vec<TerminalTab>,
    /// Currently active tab index
    pub active_index: Option<usize>,
    /// Available shells on this system
    pub available_shells: Vec<ShellInfo>,
}

impl TerminalState {
    /// Create new terminal state.
    pub fn new() -> Self {
        Self {
            tabs: Vec::new(),
            active_index: None,
            available_shells: detect_available_shells(),
        }
    }

    /// Create a tab with the default shell.
    pub fn create_default_tab(&mut self) -> Task<Message> {
        if let Some(shell) = self.available_shells.first().cloned() {
            self.create_tab(shell)
        } else {
            Task::none()
        }
    }

    /// Create a new terminal tab with the given shell.
    pub fn create_tab(&mut self, shell: ShellInfo) -> Task<Message> {
        let mut tab = TerminalTab::new(shell.clone());

        // Try to create PTY session
        match PtySession::new(&shell, 80, 24) {
            Ok(session) => {
                tab.session = Some(session);
                tab.status = TerminalStatus::Connected;
                tracing::info!("Created terminal session for {}", shell.name);
            }
            Err(e) => {
                tracing::error!("Failed to create PTY session: {}", e);
                tab.status = TerminalStatus::Error;
            }
        }

        let _tab_id = tab.id;
        self.tabs.push(tab);
        self.active_index = Some(self.tabs.len() - 1);

        Task::none()
    }

    /// Close a terminal tab.
    pub fn close_tab(&mut self, tab_id: TabId) {
        if let Some(pos) = self.tabs.iter().position(|t| t.id == tab_id) {
            self.tabs.remove(pos);

            // Adjust active index
            if self.tabs.is_empty() {
                self.active_index = None;
            } else if let Some(idx) = self.active_index {
                if idx >= self.tabs.len() {
                    self.active_index = Some(self.tabs.len() - 1);
                } else if pos <= idx && idx > 0 {
                    self.active_index = Some(idx - 1);
                }
            }
        }
    }

    /// Select a terminal tab.
    pub fn select_tab(&mut self, tab_id: TabId) {
        if let Some(pos) = self.tabs.iter().position(|t| t.id == tab_id) {
            self.active_index = Some(pos);
        }
    }

    /// Get the active tab.
    pub fn active_tab(&self) -> Option<&TerminalTab> {
        self.active_index.and_then(|idx| self.tabs.get(idx))
    }

    /// Get the active tab mutably.
    pub fn active_tab_mut(&mut self) -> Option<&mut TerminalTab> {
        self.active_index.and_then(|idx| self.tabs.get_mut(idx))
    }

    /// Write input to a terminal.
    pub fn write_input(&mut self, tab_id: TabId, input: &str) -> Task<Message> {
        if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == tab_id) {
            if let Some(ref session) = tab.session {
                let _session_clone = session.reader();
                let input_bytes = input.as_bytes().to_vec();
                let _tab_id = tab_id;

                // We need to write to the PTY - this would be async
                // For now, we'll use a blocking write wrapped in spawn_blocking
                return Task::perform(
                    async move {
                        // This is a simplified approach - in production we'd use proper async
                        input_bytes
                    },
                    move |_| Message::Tick, // Placeholder
                );
            }
        }
        Task::none()
    }

    /// Handle output from a terminal.
    pub fn handle_output(&mut self, tab_id: TabId, data: &[u8]) {
        if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == tab_id) {
            tab.parser.process(data);
        }
    }

    /// Handle terminal closed.
    pub fn handle_closed(&mut self, tab_id: TabId) {
        if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == tab_id) {
            tab.session = None;
            tab.status = TerminalStatus::Disconnected;
        }
    }

    /// Resize a terminal.
    pub fn resize_tab(&mut self, tab_id: TabId, cols: u16, rows: u16) {
        if let Some(tab) = self.tabs.iter_mut().find(|t| t.id == tab_id) {
            tab.parser.set_size(rows, cols);
            if let Some(ref mut session) = tab.session {
                let _ = session.resize(cols, rows);
            }
        }
    }

    /// Get subscriptions for terminal output.
    pub fn subscription(&self) -> Subscription<Message> {
        // For now, return empty subscription
        // In a full implementation, this would create subscriptions for each PTY reader
        Subscription::none()
    }
}

impl Default for TerminalState {
    fn default() -> Self {
        Self::new()
    }
}
