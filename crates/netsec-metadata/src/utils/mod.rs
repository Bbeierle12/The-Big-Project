//! File identity utilities and MIME detection.

mod file_identity;
mod mime_detect;

pub use file_identity::{compute_hashes, compute_md5, compute_sha256, get_file_identity};
pub use mime_detect::{detect_by_extension, detect_by_magic_bytes, get_format_info};
