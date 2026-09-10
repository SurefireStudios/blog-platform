pub fn generate_slug(title: &str) -> String {
    let mut slug = String::with_capacity(title.len());
    for c in title.to_lowercase().chars() {
        if c.is_alphanumeric() {
            slug.push(c);
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }

    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "untitled".to_string()
    } else {
        slug.to_string()
    }
}

pub fn is_valid_url(url: &str) -> bool {
    let url = url.trim();
    if url.is_empty() {
        return true; // Empty is allowed (optional field)
    }

    let lower = url.to_lowercase();

    // Reject dangerous URL schemes
    if lower.starts_with("javascript:")
        || lower.starts_with("data:")
        || lower.starts_with("vbscript:")
        || lower.starts_with("file:")
    {
        return false;
    }

    // Allow http, https, or relative URLs
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || (!lower.contains("://") && !lower.starts_with("javascript"))
}

pub fn validate_file_content(content: &[u8], filename: &str) -> Result<(), String> {
    let lower = filename.to_lowercase();

    // Check magic bytes for common file types
    if lower.ends_with(".png") {
        if content.len() < 8 || &content[0..8] != b"\x89PNG\r\n\x1a\n" {
            return Err("Invalid PNG file".to_string());
        }
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        if content.len() < 3 || &content[0..3] != b"\xff\xd8\xff" {
            return Err("Invalid JPEG file".to_string());
        }
    } else if lower.ends_with(".gif") {
        if content.len() < 6 || (&content[0..6] != b"GIF87a" && &content[0..6] != b"GIF89a") {
            return Err("Invalid GIF file".to_string());
        }
    } else if lower.ends_with(".svg") {
        // SVG is XML, just check it starts with <svg
        let content_str = String::from_utf8_lossy(content);
        if !content_str.trim_start().starts_with("<svg") {
            return Err("Invalid SVG file".to_string());
        }
    } else if lower.ends_with(".webp") {
        if content.len() < 12 || &content[0..4] != b"RIFF" || &content[8..12] != b"WEBP" {
            return Err("Invalid WebP file".to_string());
        }
    } else if lower.ends_with(".pdf") && (content.len() < 5 || &content[0..5] != b"%PDF-") {
        return Err("Invalid PDF file".to_string());
    }

    Ok(())
}

/// Resolve a request path against a base directory, refusing anything that
/// would escape it.
///
/// Axum percent-decodes path parameters and does not normalise `..`, so a
/// request path must never be joined onto a directory without being checked
/// first.
pub fn resolve_within(base: &str, requested: &str) -> Option<std::path::PathBuf> {
    use std::path::{Component, Path, PathBuf};

    let requested = requested.trim_start_matches('/');

    let mut safe = PathBuf::new();
    for component in Path::new(requested).components() {
        match component {
            Component::Normal(part) => safe.push(part),
            // `.` contributes nothing and is harmless.
            Component::CurDir => {}
            // Anything that walks upwards or re-roots the path is rejected
            // outright rather than silently clamped.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }

    if safe.as_os_str().is_empty() {
        return None;
    }

    Some(Path::new(base).join(safe))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_collapses_separators_and_trims() {
        assert_eq!(generate_slug("Hello, World!"), "hello-world");
        assert_eq!(generate_slug("  spaced   out  "), "spaced-out");
        assert_eq!(generate_slug("already-a-slug"), "already-a-slug");
    }

    #[test]
    fn slug_never_returns_empty() {
        assert_eq!(generate_slug("!!!"), "untitled");
        assert_eq!(generate_slug(""), "untitled");
    }

    #[test]
    fn rejects_dangerous_url_schemes_regardless_of_case() {
        assert!(!is_valid_url("javascript:alert(1)"));
        assert!(!is_valid_url("JavaScript:alert(1)"));
        assert!(!is_valid_url("  JAVASCRIPT:alert(1)  "));
        assert!(!is_valid_url("data:text/html;base64,PHN2Zy8+"));
    }

    #[test]
    fn allows_ordinary_urls() {
        assert!(is_valid_url(""));
        assert!(is_valid_url("https://example.com/a.png"));
        assert!(is_valid_url("/media/a.png"));
    }

    #[test]
    fn resolve_within_allows_ordinary_paths() {
        assert_eq!(
            resolve_within("output", "blog/post.html"),
            Some(
                std::path::Path::new("output")
                    .join("blog")
                    .join("post.html")
            )
        );
        assert_eq!(
            resolve_within("output", "/sitemap.xml"),
            Some(std::path::Path::new("output").join("sitemap.xml"))
        );
    }

    #[test]
    fn resolve_within_rejects_traversal() {
        assert_eq!(resolve_within("output", "../.env"), None);
        assert_eq!(resolve_within("output", "../../etc/passwd"), None);
        assert_eq!(resolve_within("output", "blog/../../.env"), None);
        assert_eq!(resolve_within("output", ""), None);
    }
}
