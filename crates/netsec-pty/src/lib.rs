//! Cross-platform PTY abstraction for terminal emulation.
//!
//! This crate provides a unified interface for creating and managing
//! pseudo-terminal sessions across Windows and Unix platforms.

mod session;
mod shell;

pub use session::{PtySession, PtyError};
pub use shell::{ShellInfo, detect_available_shells};
