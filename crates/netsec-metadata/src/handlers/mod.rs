//! Built-in metadata extraction handlers.
//!
//! Currently supports image formats (JPEG, PNG, TIFF, WebP, GIF, BMP).

pub mod image_handler;

pub use image_handler::ImageHandler;
