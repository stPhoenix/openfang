//! Workspace filesystem sandboxing.
//!
//! Confines agent file operations to their workspace directory.
//! Prevents path traversal, symlink escapes, and access outside the sandbox.

use std::path::{Path, PathBuf};

/// Resolve a user-supplied path within a workspace sandbox.
///
/// - Rejects `..` components outright.
/// - Relative paths are joined with `workspace_root`.
/// - Absolute paths are checked against the workspace root after canonicalization.
/// - For new files in not-yet-existing directories: walks up to the deepest
///   existing ancestor, canonicalizes that, then re-appends the missing tail
///   so callers (e.g. `tool_file_write`) can `create_dir_all` afterwards.
/// - The final canonical path must start with the canonical workspace root.
pub fn resolve_sandbox_path(user_path: &str, workspace_root: &Path) -> Result<PathBuf, String> {
    let path = Path::new(user_path);

    // Reject any `..` components
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err("Path traversal denied: '..' components are forbidden".to_string());
        }
    }

    // Build the candidate path
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace_root.join(path)
    };

    // Canonicalize the workspace root
    let canon_root = workspace_root
        .canonicalize()
        .map_err(|e| format!("Failed to resolve workspace root: {e}"))?;

    // Canonicalize the candidate (or its deepest existing ancestor for new paths)
    let canon_candidate = if candidate.exists() {
        candidate
            .canonicalize()
            .map_err(|e| format!("Failed to resolve path: {e}"))?
    } else {
        // Walk up to the deepest existing ancestor. This lets callers create
        // a file in a not-yet-existing nested directory (the caller is
        // responsible for `create_dir_all` after sandbox approval).
        let existing = candidate
            .ancestors()
            .find(|p| p.exists())
            .ok_or_else(|| "Invalid path: no existing ancestor".to_string())?;
        let canon_existing = existing
            .canonicalize()
            .map_err(|e| format!("Failed to resolve ancestor: {e}"))?;
        let tail = candidate
            .strip_prefix(existing)
            .map_err(|_| "Failed to compute path tail".to_string())?;
        canon_existing.join(tail)
    };

    // Verify the canonical path is inside the workspace
    if !canon_candidate.starts_with(&canon_root) {
        return Err(format!(
            "Access denied: path '{}' resolves outside workspace. \
             If you have an MCP filesystem server configured, use the \
             mcp_filesystem_* tools (e.g. mcp_filesystem_read_file, \
             mcp_filesystem_list_directory) to access files outside \
             the workspace.",
            user_path
        ));
    }

    Ok(canon_candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_relative_path_inside_workspace() {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join("test.txt"), "hello").unwrap();

        let result = resolve_sandbox_path("data/test.txt", dir.path());
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.starts_with(dir.path().canonicalize().unwrap()));
    }

    #[test]
    fn test_absolute_path_inside_workspace() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("file.txt"), "ok").unwrap();
        let abs_path = dir.path().join("file.txt");

        let result = resolve_sandbox_path(abs_path.to_str().unwrap(), dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_absolute_path_outside_workspace_blocked() {
        let dir = TempDir::new().unwrap();
        let outside = std::env::temp_dir().join("outside_test.txt");
        std::fs::write(&outside, "nope").unwrap();

        let result = resolve_sandbox_path(outside.to_str().unwrap(), dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Access denied"));

        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn test_dotdot_component_blocked() {
        let dir = TempDir::new().unwrap();
        let result = resolve_sandbox_path("../../../etc/passwd", dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Path traversal denied"));
    }

    #[test]
    fn test_nonexistent_file_with_valid_parent() {
        let dir = TempDir::new().unwrap();
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).unwrap();

        let result = resolve_sandbox_path("data/new_file.txt", dir.path());
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.starts_with(dir.path().canonicalize().unwrap()));
        assert!(resolved.ends_with("new_file.txt"));
    }

    #[test]
    fn test_nonexistent_nested_dir_resolves() {
        // file_write to a/b/c/d.md where only the workspace root exists
        let dir = TempDir::new().unwrap();
        let result = resolve_sandbox_path("a/b/c/d.md", dir.path());
        assert!(result.is_ok(), "got error: {:?}", result.err());
        let resolved = result.unwrap();
        assert!(resolved.starts_with(dir.path().canonicalize().unwrap()));
        assert!(resolved.ends_with("a/b/c/d.md"));
    }

    #[test]
    fn test_partial_existing_ancestor_resolves() {
        // data/ exists, data/x/y/z.md does not — must still resolve under root
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("data")).unwrap();
        let result = resolve_sandbox_path("data/x/y/z.md", dir.path());
        assert!(result.is_ok(), "got error: {:?}", result.err());
        let resolved = result.unwrap();
        assert!(resolved.starts_with(dir.path().canonicalize().unwrap()));
        assert!(resolved.ends_with("data/x/y/z.md"));
    }

    #[cfg(unix)]
    #[test]
    fn test_nonexistent_path_with_symlinked_existing_ancestor_blocked() {
        // workspace contains a symlink `escape` → /tmp/<somewhere outside>.
        // Asking to write to escape/foo/bar.md must reject because the
        // deepest existing ancestor (escape) canonicalizes outside root.
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let link_path = dir.path().join("escape");
        std::os::unix::fs::symlink(outside.path(), &link_path).unwrap();

        let result = resolve_sandbox_path("escape/foo/bar.md", dir.path());
        assert!(result.is_err(), "should reject; got: {:?}", result);
        assert!(result.unwrap_err().contains("Access denied"));
    }

    #[cfg(unix)]
    #[test]
    fn test_symlink_escape_blocked() {
        let dir = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        std::fs::write(outside.path().join("secret.txt"), "secret").unwrap();

        // Create a symlink inside the workspace pointing outside
        let link_path = dir.path().join("escape");
        std::os::unix::fs::symlink(outside.path(), &link_path).unwrap();

        let result = resolve_sandbox_path("escape/secret.txt", dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Access denied"));
    }
}
