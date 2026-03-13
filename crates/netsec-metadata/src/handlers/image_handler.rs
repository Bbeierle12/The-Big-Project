//! Image metadata handler.
//!
//! Supports: JPEG, PNG, TIFF, WebP, GIF, BMP, AVIF, HEIC/HEIF.
//! Extracts EXIF, IPTC, XMP, and image technical details.

mod exif_parser;

use crate::handler::Handler;
use crate::types::{ContentMetadata, FileContext, HandlerManifest, ImageTechnicalDetails};
use crate::{MetadataError, MetadataResult};
use image::GenericImageView;
use tracing::{debug, info};

/// Image handler manifest.
const IMAGE_HANDLER_MANIFEST: HandlerManifest = HandlerManifest {
    name: "image",
    version: "1.0.0",
    description: "Extracts metadata from image files (EXIF, IPTC, XMP)",
    supported_mimes: &[
        "image/jpeg",
        "image/png",
        "image/tiff",
        "image/webp",
        "image/heic",
        "image/heif",
        "image/gif",
        "image/bmp",
        "image/avif",
    ],
    supported_extensions: &[
        ".jpg", ".jpeg", ".png", ".tiff", ".tif", ".webp", ".heic", ".heif", ".gif", ".bmp",
        ".avif",
    ],
    priority: 100,
};

/// Image metadata handler.
#[derive(Debug, Default)]
pub struct ImageHandler;

impl ImageHandler {
    /// Create a new image handler.
    pub fn new() -> Self {
        Self
    }

    /// Extract technical details from image data.
    fn extract_technical(&self, data: &[u8]) -> MetadataResult<ImageTechnicalDetails> {
        let img = image::load_from_memory(data)?;
        let (width, height) = img.dimensions();

        let color_type = img.color();
        let has_alpha = matches!(
            color_type,
            image::ColorType::La8
                | image::ColorType::Rgba8
                | image::ColorType::La16
                | image::ColorType::Rgba16
                | image::ColorType::Rgba32F
        );

        let bit_depth = match color_type {
            image::ColorType::L8
            | image::ColorType::La8
            | image::ColorType::Rgb8
            | image::ColorType::Rgba8 => Some(8),
            image::ColorType::L16
            | image::ColorType::La16
            | image::ColorType::Rgb16
            | image::ColorType::Rgba16 => Some(16),
            image::ColorType::Rgb32F | image::ColorType::Rgba32F => Some(32),
            _ => None,
        };

        let color_space = match color_type {
            image::ColorType::L8 | image::ColorType::L16 => Some("grayscale".to_string()),
            image::ColorType::La8 | image::ColorType::La16 => {
                Some("grayscale+alpha".to_string())
            }
            image::ColorType::Rgb8 | image::ColorType::Rgb16 | image::ColorType::Rgb32F => {
                Some("rgb".to_string())
            }
            image::ColorType::Rgba8 | image::ColorType::Rgba16 | image::ColorType::Rgba32F => {
                Some("rgba".to_string())
            }
            _ => None,
        };

        Ok(ImageTechnicalDetails {
            width,
            height,
            bit_depth,
            color_space,
            color_profile: None,
            has_alpha: Some(has_alpha),
            is_animated: None,
            frame_count: None,
            compression: None,
        })
    }
}

impl Handler for ImageHandler {
    fn manifest(&self) -> &HandlerManifest {
        &IMAGE_HANDLER_MANIFEST
    }

    fn validate(&self, context: &FileContext) -> MetadataResult<()> {
        if context.data.is_empty() {
            return Err(MetadataError::ValidationFailed(
                "File is empty".to_string(),
            ));
        }

        image::load_from_memory(&context.data).map_err(|e| {
            MetadataError::InvalidFormat(format!("Invalid image format: {}", e))
        })?;

        Ok(())
    }

    fn extract_shallow(&self, context: &FileContext) -> MetadataResult<ContentMetadata> {
        let technical = self.extract_technical(&context.data)?;

        Ok(ContentMetadata {
            technical: Some(technical),
            ..Default::default()
        })
    }

    fn extract_deep(&self, context: &FileContext) -> MetadataResult<ContentMetadata> {
        let mut content = self.extract_shallow(context)?;

        info!("Deep extraction for {}", context.path.display());

        // Extract EXIF data for JPEG and TIFF.
        if context.format.mime == "image/jpeg" || context.format.mime == "image/tiff" {
            debug!("Extracting EXIF data");
            if let Ok(exif) = exif_parser::extract_exif(&context.data) {
                content.exif = Some(exif);
            }
        }

        // Extract IPTC data (JPEG only).
        if context.format.mime == "image/jpeg" {
            debug!("Extracting IPTC data");
            if let Some(iptc) = exif_parser::extract_iptc(&context.data) {
                content.iptc = Some(iptc);
            }
        }

        // Extract XMP data.
        debug!("Extracting XMP data");
        if let Some(xmp) = exif_parser::extract_xmp(&context.data) {
            content.xmp = Some(xmp);
        }

        Ok(content)
    }
}
