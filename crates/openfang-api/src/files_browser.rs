//! Read-only file browser API for agent workspaces and hands install dirs.
//!
//! Exposes `/api/files/{roots,list,read,download}` for the dashboard "Files"
//! tab. Two server-enumerated roots only: `workspaces` and `hands`. Path
//! safety delegated to `openfang_runtime::workspace_sandbox::resolve_sandbox_path`.

use crate::routes::AppState;
use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use openfang_runtime::workspace_sandbox::resolve_sandbox_path;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Maximum bytes returned by the inline `/read` endpoint.
const MAX_INLINE_BYTES: u64 = 1024 * 1024; // 1 MiB

/// File extensions treated as text for the inline reader.
/// Anything not in this list gets 415; client should fall back to /download.
const TEXT_EXTENSIONS: &[&str] = &[
    "md", "markdown", "txt", "text", "json", "yaml", "yml", "toml", "rs", "py",
    "js", "mjs", "cjs", "ts", "tsx", "jsx", "html", "htm", "css", "scss", "log",
    "sh", "bash", "zsh", "fish", "env", "ini", "cfg", "conf", "csv", "tsv",
    "xml", "svg", "rst", "lock", "gitignore", "dockerignore",
];

/// Named filenames (case-insensitive) accepted as text even without extension.
const TEXT_FILENAMES: &[&str] = &[
    "dockerfile", "makefile", "license", "readme", "changelog", "notice",
    "authors", "contributors", "soul", "user", "agent", "hand",
];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Root {
    Workspaces,
    Hands,
}

impl Root {
    fn name(self) -> &'static str {
        match self {
            Root::Workspaces => "workspaces",
            Root::Hands => "hands",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Root::Workspaces => "Agent Workspaces",
            Root::Hands => "Hands",
        }
    }
}

fn parse_root(name: &str) -> Option<Root> {
    match name {
        "workspaces" => Some(Root::Workspaces),
        "hands" => Some(Root::Hands),
        _ => None,
    }
}

fn root_dir(state: &AppState, root: Root) -> PathBuf {
    match root {
        Root::Workspaces => state.kernel.config.effective_workspaces_dir(),
        Root::Hands => state.kernel.config.home_dir.join("hands"),
    }
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

fn is_text_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lc = ext.to_ascii_lowercase();
        if TEXT_EXTENSIONS.iter().any(|e| *e == ext_lc) {
            return true;
        }
    }
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let lc = name.to_ascii_lowercase();
        if TEXT_FILENAMES.iter().any(|n| lc.starts_with(n)) {
            return true;
        }
    }
    false
}

fn mime_for(path: &Path) -> &'static str {
    match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("md") | Some("markdown") => "text/markdown",
        Some("json") => "application/json",
        Some("yaml") | Some("yml") => "application/yaml",
        Some("toml") => "application/toml",
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") | Some("mjs") | Some("cjs") => "application/javascript",
        Some("ts") | Some("tsx") => "application/typescript",
        Some("py") => "text/x-python",
        Some("rs") => "text/x-rust",
        Some("svg") => "image/svg+xml",
        Some("csv") => "text/csv",
        Some("log") => "text/plain",
        _ => "text/plain",
    }
}

/// Sanitize a filename for use in `Content-Disposition`.
fn safe_disposition_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control() && *c != '"' && *c != '\\')
        .take(255)
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct FsQuery {
    pub root: String,
    #[serde(default)]
    pub path: String,
}

/// GET /api/files/roots — Enumerate the two browseable roots.
pub async fn list_roots(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let roots: Vec<serde_json::Value> = [Root::Workspaces, Root::Hands]
        .iter()
        .map(|r| {
            let dir = root_dir(&state, *r);
            serde_json::json!({
                "name": r.name(),
                "label": r.label(),
                "path": dir.display().to_string(),
                "exists": dir.exists(),
            })
        })
        .collect();
    Json(serde_json::json!({ "roots": roots })).into_response()
}

/// GET /api/files/list?root=<n>&path=<rel> — Directory listing.
pub async fn list_dir(
    State(state): State<Arc<AppState>>,
    Query(q): Query<FsQuery>,
) -> Response {
    let Some(root) = parse_root(&q.root) else {
        return err(StatusCode::BAD_REQUEST, "Unknown root");
    };
    let root_path = root_dir(&state, root);

    // Ensure root exists so resolve_sandbox_path can canonicalize.
    if !root_path.exists() {
        if let Err(e) = std::fs::create_dir_all(&root_path) {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to access root: {e}"),
            );
        }
    }

    // Empty path = root listing.
    let user_path = if q.path.is_empty() { "." } else { q.path.as_str() };
    let target = match resolve_sandbox_path(user_path, &root_path) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::FORBIDDEN, "Path denied"),
    };

    let md = match std::fs::metadata(&target) {
        Ok(m) => m,
        Err(_) => return err(StatusCode::NOT_FOUND, "Path not found"),
    };
    if !md.is_dir() {
        return err(StatusCode::BAD_REQUEST, "Not a directory");
    }

    let mut entries: Vec<serde_json::Value> = Vec::new();
    let iter = match std::fs::read_dir(&target) {
        Ok(it) => it,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to read dir: {e}"),
            );
        }
    };
    for ent in iter.flatten() {
        let name = match ent.file_name().to_str() {
            Some(n) => n.to_string(),
            None => continue, // skip non-UTF8 names
        };
        let meta = match ent.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| {
                chrono::DateTime::<chrono::Utc>::from_timestamp(d.as_secs() as i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        entries.push(serde_json::json!({
            "name": name,
            "is_dir": meta.is_dir(),
            "is_symlink": meta.file_type().is_symlink(),
            "size_bytes": if meta.is_file() { meta.len() } else { 0 },
            "modified": modified,
        }));
    }

    // Stable order: directories first, then by name.
    entries.sort_by(|a, b| {
        let ad = a.get("is_dir").and_then(|v| v.as_bool()).unwrap_or(false);
        let bd = b.get("is_dir").and_then(|v| v.as_bool()).unwrap_or(false);
        match (ad, bd) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase()
                .cmp(
                    &b.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_ascii_lowercase(),
                ),
        }
    });

    // Normalize echoed path (always relative, forward-slashes, no leading `./`).
    let echoed_path = q.path.trim_matches('/').to_string();
    Json(serde_json::json!({
        "root": root.name(),
        "path": echoed_path,
        "entries": entries,
    }))
    .into_response()
}

/// GET /api/files/read?root=<n>&path=<rel> — Inline file content (text only).
pub async fn read_file(
    State(state): State<Arc<AppState>>,
    Query(q): Query<FsQuery>,
) -> Response {
    let Some(root) = parse_root(&q.root) else {
        return err(StatusCode::BAD_REQUEST, "Unknown root");
    };
    if q.path.is_empty() {
        return err(StatusCode::BAD_REQUEST, "Missing path");
    }
    let root_path = root_dir(&state, root);
    let target = match resolve_sandbox_path(&q.path, &root_path) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::FORBIDDEN, "Path denied"),
    };

    let md = match std::fs::metadata(&target) {
        Ok(m) => m,
        Err(_) => return err(StatusCode::NOT_FOUND, "File not found"),
    };
    if !md.is_file() {
        return err(StatusCode::BAD_REQUEST, "Not a file");
    }
    if md.len() > MAX_INLINE_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "error": "File too large for inline read; use /api/files/download",
                "size_bytes": md.len(),
                "max_inline_bytes": MAX_INLINE_BYTES,
            })),
        )
            .into_response();
    }
    if !is_text_file(&target) {
        return (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Json(serde_json::json!({
                "error": "Binary file; use /api/files/download",
            })),
        )
            .into_response();
    }

    let content = match std::fs::read(&target) {
        Ok(b) => b,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to read file: {e}"),
            );
        }
    };
    // Reject if content is not valid UTF-8 (treat as binary).
    let text = match String::from_utf8(content) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(serde_json::json!({
                    "error": "Non-UTF8 content; use /api/files/download",
                })),
            )
                .into_response();
        }
    };

    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string();
    Json(serde_json::json!({
        "name": name,
        "content": text,
        "size_bytes": md.len(),
        "mime": mime_for(&target),
        "truncated": false,
    }))
    .into_response()
}

/// GET /api/files/download?root=<n>&path=<rel> — Stream file as attachment.
pub async fn download_file(
    State(state): State<Arc<AppState>>,
    Query(q): Query<FsQuery>,
) -> Response {
    let Some(root) = parse_root(&q.root) else {
        return err(StatusCode::BAD_REQUEST, "Unknown root");
    };
    if q.path.is_empty() {
        return err(StatusCode::BAD_REQUEST, "Missing path");
    }
    let root_path = root_dir(&state, root);
    let target = match resolve_sandbox_path(&q.path, &root_path) {
        Ok(p) => p,
        Err(_) => return err(StatusCode::FORBIDDEN, "Path denied"),
    };
    let md = match std::fs::metadata(&target) {
        Ok(m) => m,
        Err(_) => return err(StatusCode::NOT_FOUND, "File not found"),
    };
    if !md.is_file() {
        return err(StatusCode::BAD_REQUEST, "Not a file");
    }
    let bytes = match std::fs::read(&target) {
        Ok(b) => b,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Failed to read file: {e}"),
            );
        }
    };
    let filename = safe_disposition_name(
        target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("download"),
    );
    let disposition = format!("attachment; filename=\"{filename}\"");
    let mime = mime_for(&target);
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(Body::from(bytes))
        .unwrap_or_else(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "Response build failed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_root_known() {
        assert_eq!(parse_root("workspaces"), Some(Root::Workspaces));
        assert_eq!(parse_root("hands"), Some(Root::Hands));
    }

    #[test]
    fn parse_root_unknown_returns_none() {
        assert_eq!(parse_root("evil"), None);
        assert_eq!(parse_root(""), None);
        assert_eq!(parse_root("Workspaces"), None);
    }

    #[test]
    fn is_text_file_extensions() {
        assert!(is_text_file(Path::new("foo.md")));
        assert!(is_text_file(Path::new("a/b/notes.txt")));
        assert!(is_text_file(Path::new("config.TOML")));
        assert!(is_text_file(Path::new("Dockerfile")));
        assert!(is_text_file(Path::new("README")));
        assert!(!is_text_file(Path::new("image.png")));
        assert!(!is_text_file(Path::new("archive.tar.gz")));
        assert!(!is_text_file(Path::new("binary")));
    }

    #[test]
    fn safe_disposition_strips_quotes_and_controls() {
        assert_eq!(safe_disposition_name("foo\"bar.txt"), "foobar.txt");
        assert_eq!(safe_disposition_name("a\nb.md"), "ab.md");
        assert_eq!(safe_disposition_name("ok-name.json"), "ok-name.json");
    }

    #[test]
    fn mime_for_known() {
        assert_eq!(mime_for(Path::new("x.md")), "text/markdown");
        assert_eq!(mime_for(Path::new("x.json")), "application/json");
        assert_eq!(mime_for(Path::new("x.unknown")), "text/plain");
    }

    /// Confirms that the sandbox helper we delegate to actually rejects `..`.
    /// Smoke-test our integration — the heavy lifting is in workspace_sandbox.
    #[test]
    fn sandbox_blocks_traversal() {
        let dir = tempfile::TempDir::new().unwrap();
        let r = resolve_sandbox_path("../etc/passwd", dir.path());
        assert!(r.is_err());
    }
}
