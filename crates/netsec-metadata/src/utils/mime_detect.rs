//! MIME type detection using magic bytes and file extension.

use crate::types::{Confidence, DetectedFormat, FormatInfo};

/// Magic byte signatures for common file formats.
const MAGIC_SIGNATURES: &[(&[u8], &str)] = &[
    // JPEG
    (&[0xFF, 0xD8, 0xFF], "image/jpeg"),
    // PNG
    (
        &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        "image/png",
    ),
    // GIF87a
    (&[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], "image/gif"),
    // GIF89a
    (&[0x47, 0x49, 0x46, 0x38, 0x39, 0x61], "image/gif"),
    // TIFF (little-endian)
    (&[0x49, 0x49, 0x2A, 0x00], "image/tiff"),
    // TIFF (big-endian)
    (&[0x4D, 0x4D, 0x00, 0x2A], "image/tiff"),
    // BMP
    (&[0x42, 0x4D], "image/bmp"),
    // PDF
    (&[0x25, 0x50, 0x44, 0x46], "application/pdf"),
    // ICO
    (&[0x00, 0x00, 0x01, 0x00], "image/x-icon"),
];

/// Check for WebP format (RIFF....WEBP).
fn is_webp(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    data[0..4] == [0x52, 0x49, 0x46, 0x46] && data[8..12] == [0x57, 0x45, 0x42, 0x50]
}

/// Check for HEIC/HEIF format (ftyp box with heic/heif brand).
fn is_heic(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    if data[4..8] == [0x66, 0x74, 0x79, 0x70] {
        let brand = &data[8..12];
        let heic_brands: &[&[u8]] = &[b"heic", b"heif", b"heix", b"mif1"];
        return heic_brands.contains(&brand);
    }
    false
}

/// Check for AVIF format.
fn is_avif(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    if data[4..8] == [0x66, 0x74, 0x79, 0x70] {
        let brand = &data[8..12];
        return brand == b"avif" || brand == b"avis";
    }
    false
}

/// Detect MIME type from magic bytes.
pub fn detect_by_magic_bytes(data: &[u8]) -> Option<String> {
    if is_webp(data) {
        return Some("image/webp".to_string());
    }
    if is_heic(data) {
        return Some("image/heic".to_string());
    }
    if is_avif(data) {
        return Some("image/avif".to_string());
    }

    for (signature, mime) in MAGIC_SIGNATURES {
        if data.len() >= signature.len() && &data[..signature.len()] == *signature {
            return Some(mime.to_string());
        }
    }

    None
}

/// Detect MIME type from file extension.
pub fn detect_by_extension(extension: &str) -> Option<String> {
    let ext = extension.trim_start_matches('.').to_lowercase();
    mime_guess::from_ext(&ext).first().map(|m| m.to_string())
}

/// Get format info for a file.
pub fn get_format_info(data: &[u8], extension: &str) -> FormatInfo {
    let by_magic_bytes = detect_by_magic_bytes(data);
    let by_extension = detect_by_extension(extension);

    let (mime, confidence) = match (&by_magic_bytes, &by_extension) {
        (Some(magic), Some(ext)) if magic == ext => (magic.clone(), Confidence::High),
        (Some(magic), Some(_)) => (magic.clone(), Confidence::Medium),
        (Some(magic), None) => (magic.clone(), Confidence::High),
        (None, Some(ext)) => (ext.clone(), Confidence::Low),
        (None, None) => ("application/octet-stream".to_string(), Confidence::Low),
    };

    let normalized_ext = if extension.starts_with('.') {
        extension.to_string()
    } else {
        format!(".{}", extension)
    };

    FormatInfo {
        mime,
        extension: normalized_ext,
        detected: DetectedFormat {
            by_magic_bytes,
            by_extension,
        },
        confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_jpeg_magic() {
        let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert_eq!(detect_by_magic_bytes(&data), Some("image/jpeg".into()));
    }

    #[test]
    fn detect_png_magic() {
        let data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00];
        assert_eq!(detect_by_magic_bytes(&data), Some("image/png".into()));
    }

    #[test]
    fn detect_webp_magic() {
        let mut data = [0u8; 12];
        data[0..4].copy_from_slice(b"RIFF");
        data[8..12].copy_from_slice(b"WEBP");
        assert_eq!(detect_by_magic_bytes(&data), Some("image/webp".into()));
    }

    #[test]
    fn detect_unknown_magic() {
        let data = [0x00, 0x01, 0x02, 0x03];
        assert_eq!(detect_by_magic_bytes(&data), None);
    }

    #[test]
    fn detect_by_ext_jpg() {
        let mime = detect_by_extension(".jpg");
        assert_eq!(mime, Some("image/jpeg".into()));
    }

    #[test]
    fn detect_by_ext_no_dot() {
        let mime = detect_by_extension("png");
        assert_eq!(mime, Some("image/png".into()));
    }

    #[test]
    fn format_info_high_confidence() {
        let jpeg_data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let info = get_format_info(&jpeg_data, ".jpg");
        assert_eq!(info.mime, "image/jpeg");
        assert_eq!(info.confidence, Confidence::High);
    }

    #[test]
    fn format_info_mismatch() {
        let jpeg_data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        let info = get_format_info(&jpeg_data, ".png");
        assert_eq!(info.mime, "image/jpeg"); // magic wins
        assert_eq!(info.confidence, Confidence::Medium);
    }

    #[test]
    fn format_info_unknown() {
        let data = [0x00, 0x01, 0x02, 0x03];
        let info = get_format_info(&data, ".zzzzunknown");
        assert_eq!(info.mime, "application/octet-stream");
        assert_eq!(info.confidence, Confidence::Low);
    }

    #[test]
    fn format_info_ext_only() {
        let data = [0x00, 0x01, 0x02, 0x03];
        let info = get_format_info(&data, ".jpg");
        assert_eq!(info.mime, "image/jpeg");
        assert_eq!(info.confidence, Confidence::Low);
    }
}
