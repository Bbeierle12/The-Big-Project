//! Handler trait and HandlerRegistry for pluggable format support.

use crate::types::{ContentMetadata, FileContext, HandlerManifest};
use crate::MetadataResult;
use std::collections::HashMap;
use std::sync::Arc;

/// Trait that all metadata handlers must implement.
///
/// Handlers are `Send + Sync` so they can be shared across threads.
pub trait Handler: Send + Sync {
    /// Get the handler manifest describing capabilities.
    fn manifest(&self) -> &HandlerManifest;

    /// Check if this handler can process the given file.
    fn can_handle(&self, mime: &str, extension: &str) -> bool {
        let manifest = self.manifest();
        let normalized_ext = if extension.starts_with('.') {
            extension.to_lowercase()
        } else {
            format!(".{}", extension.to_lowercase())
        };

        manifest.supported_mimes.contains(&mime)
            || manifest
                .supported_extensions
                .iter()
                .any(|e| *e == normalized_ext)
    }

    /// Validate that the file is processable.
    fn validate(&self, context: &FileContext) -> MetadataResult<()>;

    /// Quick metadata extraction (fast, basic info).
    fn extract_shallow(&self, context: &FileContext) -> MetadataResult<ContentMetadata>;

    /// Full metadata extraction (slower, comprehensive).
    fn extract_deep(&self, context: &FileContext) -> MetadataResult<ContentMetadata>;
}

/// Registry for metadata extraction handlers.
///
/// Handlers are indexed by MIME type and extension for fast lookup,
/// sorted by priority (higher priority first).
pub struct HandlerRegistry {
    handlers: Vec<Arc<dyn Handler>>,
    mime_index: HashMap<String, Vec<usize>>,
    ext_index: HashMap<String, Vec<usize>>,
}

impl Default for HandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HandlerRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            mime_index: HashMap::new(),
            ext_index: HashMap::new(),
        }
    }

    /// Register a handler.
    pub fn register(&mut self, handler: Arc<dyn Handler>) {
        let idx = self.handlers.len();
        let manifest = handler.manifest();

        // Index by MIME types.
        for mime in manifest.supported_mimes {
            self.mime_index
                .entry(mime.to_string())
                .or_default()
                .push(idx);
        }

        // Index by extensions.
        for ext in manifest.supported_extensions {
            let normalized = if ext.starts_with('.') {
                ext.to_string()
            } else {
                format!(".{}", ext)
            };
            self.ext_index.entry(normalized).or_default().push(idx);
        }

        self.handlers.push(handler);

        // Sort indices by priority (higher first).
        for indices in self.mime_index.values_mut() {
            indices.sort_by(|a, b| {
                let pa = self.handlers[*a].manifest().priority;
                let pb = self.handlers[*b].manifest().priority;
                pb.cmp(&pa)
            });
        }
        for indices in self.ext_index.values_mut() {
            indices.sort_by(|a, b| {
                let pa = self.handlers[*a].manifest().priority;
                let pb = self.handlers[*b].manifest().priority;
                pb.cmp(&pa)
            });
        }
    }

    /// Get the best handler for a given file.
    pub fn get_handler(&self, mime: &str, extension: &str) -> Option<Arc<dyn Handler>> {
        // Try MIME type first.
        if let Some(indices) = self.mime_index.get(mime) {
            if let Some(&idx) = indices.first() {
                let handler = &self.handlers[idx];
                if handler.can_handle(mime, extension) {
                    return Some(Arc::clone(handler));
                }
            }
        }

        // Try extension.
        let normalized_ext = if extension.starts_with('.') {
            extension.to_lowercase()
        } else {
            format!(".{}", extension.to_lowercase())
        };

        if let Some(indices) = self.ext_index.get(&normalized_ext) {
            if let Some(&idx) = indices.first() {
                let handler = &self.handlers[idx];
                if handler.can_handle(mime, extension) {
                    return Some(Arc::clone(handler));
                }
            }
        }

        // Try all handlers as fallback.
        for handler in &self.handlers {
            if handler.can_handle(mime, extension) {
                return Some(Arc::clone(handler));
            }
        }

        None
    }

    /// Get all handlers that can process a file.
    pub fn get_handlers(&self, mime: &str, extension: &str) -> Vec<Arc<dyn Handler>> {
        let mut result = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for handler in &self.handlers {
            let name = handler.manifest().name;
            if handler.can_handle(mime, extension) && !seen.contains(name) {
                result.push(Arc::clone(handler));
                seen.insert(name);
            }
        }

        result.sort_by(|a, b| b.manifest().priority.cmp(&a.manifest().priority));
        result
    }

    /// Check if a handler exists for the given type.
    pub fn has_handler(&self, mime: &str, extension: &str) -> bool {
        self.get_handler(mime, extension).is_some()
    }

    /// List all registered handler names.
    pub fn list_handlers(&self) -> Vec<&'static str> {
        self.handlers.iter().map(|h| h.manifest().name).collect()
    }

    /// Number of registered handlers.
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// Clear all registered handlers.
    pub fn clear(&mut self) {
        self.handlers.clear();
        self.mime_index.clear();
        self.ext_index.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FileContext;

    // A trivial test handler for registry tests.
    struct DummyHandler;

    static DUMMY_MANIFEST: HandlerManifest = HandlerManifest {
        name: "dummy",
        version: "0.0.1",
        description: "Test handler",
        supported_mimes: &["text/plain"],
        supported_extensions: &[".txt", ".text"],
        priority: 50,
    };

    impl Handler for DummyHandler {
        fn manifest(&self) -> &HandlerManifest {
            &DUMMY_MANIFEST
        }
        fn validate(&self, _ctx: &FileContext) -> MetadataResult<()> {
            Ok(())
        }
        fn extract_shallow(&self, _ctx: &FileContext) -> MetadataResult<ContentMetadata> {
            Ok(ContentMetadata::default())
        }
        fn extract_deep(&self, _ctx: &FileContext) -> MetadataResult<ContentMetadata> {
            Ok(ContentMetadata::default())
        }
    }

    #[test]
    fn registry_empty() {
        let reg = HandlerRegistry::new();
        assert_eq!(reg.handler_count(), 0);
        assert!(reg.list_handlers().is_empty());
        assert!(!reg.has_handler("text/plain", ".txt"));
    }

    #[test]
    fn registry_register_and_lookup() {
        let mut reg = HandlerRegistry::new();
        reg.register(Arc::new(DummyHandler));

        assert_eq!(reg.handler_count(), 1);
        assert!(reg.has_handler("text/plain", ".txt"));
        assert!(reg.has_handler("text/plain", "txt"));
        assert!(!reg.has_handler("image/jpeg", ".jpg"));

        let names = reg.list_handlers();
        assert_eq!(names, vec!["dummy"]);
    }

    #[test]
    fn registry_get_handler_by_mime() {
        let mut reg = HandlerRegistry::new();
        reg.register(Arc::new(DummyHandler));

        let h = reg.get_handler("text/plain", ".unknown").unwrap();
        assert_eq!(h.manifest().name, "dummy");
    }

    #[test]
    fn registry_get_handler_by_ext() {
        let mut reg = HandlerRegistry::new();
        reg.register(Arc::new(DummyHandler));

        let h = reg.get_handler("application/octet-stream", ".txt").unwrap();
        assert_eq!(h.manifest().name, "dummy");
    }

    #[test]
    fn registry_clear() {
        let mut reg = HandlerRegistry::new();
        reg.register(Arc::new(DummyHandler));
        assert_eq!(reg.handler_count(), 1);
        reg.clear();
        assert_eq!(reg.handler_count(), 0);
        assert!(!reg.has_handler("text/plain", ".txt"));
    }

    #[test]
    fn handler_can_handle_default() {
        let h = DummyHandler;
        assert!(h.can_handle("text/plain", ".txt"));
        assert!(h.can_handle("text/plain", "txt"));
        assert!(h.can_handle("application/unknown", ".text"));
        assert!(!h.can_handle("image/png", ".png"));
    }

    #[test]
    fn registry_default() {
        let reg = HandlerRegistry::default();
        assert_eq!(reg.handler_count(), 0);
    }
}
