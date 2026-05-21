//! Patch parser and file operations for skill evolution.
//!
//! Supports three LLM output formats:
//! - Format A: `*** Begin Patch` / `*** End Patch` (surgical edits)
//! - Format B: `*** Begin Files` / `*** End Files` (full content)
//! - Format C: `<<<<<<< SEARCH` / `>>>>>>> REPLACE` (search/replace)

use std::collections::HashMap;
use std::path::Path;

/// Detected patch format from LLM output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchFormat {
    /// `*** Begin Patch ... *** End Patch`
    Patch,
    /// `*** Begin Files ... *** End Files`
    FullContent,
    /// `<<<<<<< SEARCH ... >>>>>>> REPLACE`
    SearchReplace,
}

/// Result of applying a patch to a skill directory.
#[derive(Debug, Clone)]
pub struct PatchResult {
    /// Unified diff of changes made.
    pub content_diff: String,
    /// Full snapshot of the skill directory after patching: {relative_path: content}.
    pub content_snapshot: HashMap<String, String>,
}

/// Detect which patch format the LLM used.
pub fn detect_format(content: &str) -> PatchFormat {
    if content.contains("*** Begin Patch") {
        PatchFormat::Patch
    } else if content.contains("*** Begin Files") {
        PatchFormat::FullContent
    } else if content.contains("<<<<<<< SEARCH") {
        PatchFormat::SearchReplace
    } else {
        // Default: treat as full content for a single SKILL.md
        PatchFormat::FullContent
    }
}

/// Apply a patch-format edit to a skill directory.
///
/// Format A: `*** Begin Patch ... *** End Patch`
pub fn apply_patch(skill_dir: &Path, content: &str) -> Result<PatchResult, String> {
    let begin = content
        .find("*** Begin Patch")
        .ok_or("missing *** Begin Patch marker")?;
    let end = content
        .find("*** End Patch")
        .ok_or("missing *** End Patch marker")?;
    let patch_body = &content[begin..end + "*** End Patch".len()];

    // Parse operations from the patch body
    let mut operations: Vec<PatchOp> = Vec::new();
    let mut current_file: Option<String> = None;
    let mut current_op: Option<PatchOpKind> = None;
    let mut hunks: Vec<String> = Vec::new();

    for line in patch_body.lines().skip(1) {
        // skip "*** Begin Patch" line
        if line == "*** End Patch" {
            break;
        }

        if let Some(path) = line.strip_prefix("*** Update File: ") {
            if let (Some(file), Some(op)) = (current_file.take(), current_op.take()) {
                operations.push(PatchOp {
                    file,
                    kind: op,
                    content: hunks.join("\n"),
                });
                hunks.clear();
            }
            current_file = Some(path.trim().to_string());
            current_op = Some(PatchOpKind::Update);
        } else if let Some(path) = line.strip_prefix("*** Add File: ") {
            if let (Some(file), Some(op)) = (current_file.take(), current_op.take()) {
                operations.push(PatchOp {
                    file,
                    kind: op,
                    content: hunks.join("\n"),
                });
                hunks.clear();
            }
            current_file = Some(path.trim().to_string());
            current_op = Some(PatchOpKind::Add);
        } else if let Some(path) = line.strip_prefix("*** Delete File: ") {
            if let (Some(file), Some(op)) = (current_file.take(), current_op.take()) {
                operations.push(PatchOp {
                    file,
                    kind: op,
                    content: hunks.join("\n"),
                });
                hunks.clear();
            }
            current_file = Some(path.trim().to_string());
            current_op = Some(PatchOpKind::Delete);
        } else {
            hunks.push(line.to_string());
        }
    }

    // Flush last operation
    if let (Some(file), Some(op)) = (current_file, current_op) {
        operations.push(PatchOp {
            file,
            kind: op,
            content: hunks.join("\n"),
        });
    }

    if operations.is_empty() {
        return Err("no patch operations found".into());
    }

    // Apply each operation
    for op in &operations {
        let file_path = skill_dir.join(&op.file);
        match op.kind {
            PatchOpKind::Delete => {
                if file_path.exists() {
                    std::fs::remove_file(&file_path)
                        .map_err(|e| format!("failed to delete {}: {e}", op.file))?;
                }
            }
            PatchOpKind::Add => {
                if let Some(parent) = file_path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("failed to create dir for {}: {e}", op.file))?;
                }
                let content = extract_added_lines(&op.content);
                std::fs::write(&file_path, &content)
                    .map_err(|e| format!("failed to write {}: {e}", op.file))?;
            }
            PatchOpKind::Update => {
                let original = std::fs::read_to_string(&file_path)
                    .map_err(|e| format!("failed to read {}: {e}", op.file))?;
                let patched = apply_hunk_to_content(&original, &op.content)?;
                std::fs::write(&file_path, &patched)
                    .map_err(|e| format!("failed to write {}: {e}", op.file))?;
            }
        }
    }

    build_patch_result(skill_dir)
}

/// Apply full-content format to a skill directory.
///
/// Format B: `*** Begin Files ... *** End Files`
pub fn apply_full_content(skill_dir: &Path, content: &str) -> Result<PatchResult, String> {
    let files = parse_full_content_files(content)?;

    std::fs::create_dir_all(skill_dir)
        .map_err(|e| format!("failed to create skill dir: {e}"))?;

    for (file_path, file_content) in &files {
        let full_path = skill_dir.join(file_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create dir for {file_path}: {e}"))?;
        }
        std::fs::write(&full_path, file_content)
            .map_err(|e| format!("failed to write {file_path}: {e}"))?;
    }

    build_patch_result(skill_dir)
}

/// Apply search/replace format to a skill directory.
///
/// Format C: `<<<<<<< SEARCH ... ======= ... >>>>>>> REPLACE`
pub fn apply_search_replace(skill_dir: &Path, content: &str) -> Result<PatchResult, String> {
    let skill_md = skill_dir.join("SKILL.md");
    let original = std::fs::read_to_string(&skill_md)
        .map_err(|e| format!("failed to read SKILL.md: {e}"))?;

    let mut result = original.clone();

    let mut pos = 0;
    while let Some(search_start) = content[pos..].find("<<<<<<< SEARCH") {
        let abs_start = pos + search_start;
        let separator = content[abs_start..]
            .find("=======")
            .ok_or("missing ======= separator in search/replace block")?;
        let replace_end = content[abs_start..]
            .find(">>>>>>> REPLACE")
            .ok_or("missing >>>>>>> REPLACE marker")?;

        let search_text = content[abs_start + "<<<<<<< SEARCH".len()..abs_start + separator]
            .trim_start_matches('\n')
            .trim_end_matches('\n');
        let replace_text = content[abs_start + separator + "=======".len()..abs_start + replace_end]
            .trim_start_matches('\n')
            .trim_end_matches('\n');

        if !result.contains(search_text) {
            return Err(format!(
                "search text not found in SKILL.md: {:?}",
                &search_text[..search_text.len().min(80)]
            ));
        }

        result = result.replacen(search_text, replace_text, 1);
        pos = abs_start + replace_end + ">>>>>>> REPLACE".len();
    }

    if result == original {
        return Err("no search/replace blocks found or no changes made".into());
    }

    std::fs::write(&skill_md, &result)
        .map_err(|e| format!("failed to write SKILL.md: {e}"))?;

    build_patch_result(skill_dir)
}

/// Fix a skill in-place (FIX evolution type).
pub fn fix_skill(skill_dir: &Path, content: &str) -> Result<PatchResult, String> {
    match detect_format(content) {
        PatchFormat::Patch => apply_patch(skill_dir, content),
        PatchFormat::FullContent => apply_full_content(skill_dir, content),
        PatchFormat::SearchReplace => apply_search_replace(skill_dir, content),
    }
}

/// Derive a new skill from parent(s) (DERIVED evolution type).
///
/// For single-parent: copies parent directory, then applies changes.
/// For multi-parent: creates new directory from scratch.
pub fn derive_skill(
    parent_dirs: &[&Path],
    target_dir: &Path,
    content: &str,
) -> Result<PatchResult, String> {
    if parent_dirs.len() == 1 {
        // Single-parent: copy then patch
        copy_dir(parent_dirs[0], target_dir)?;
        // Remove .skill_id sidecar (new skill gets its own)
        let sidecar = target_dir.join(".skill_id");
        if sidecar.exists() {
            let _ = std::fs::remove_file(&sidecar);
        }
        fix_skill(target_dir, content)
    } else {
        // Multi-parent: create from scratch
        create_skill(target_dir, content)
    }
}

/// Create a brand-new skill (CAPTURED evolution type).
pub fn create_skill(target_dir: &Path, content: &str) -> Result<PatchResult, String> {
    std::fs::create_dir_all(target_dir)
        .map_err(|e| format!("failed to create target dir: {e}"))?;

    let format = detect_format(content);
    match format {
        PatchFormat::FullContent => apply_full_content(target_dir, content),
        _ => {
            // For captured skills, if not in full-content format, treat as raw SKILL.md
            let skill_md = target_dir.join("SKILL.md");
            std::fs::write(&skill_md, content)
                .map_err(|e| format!("failed to write SKILL.md: {e}"))?;
            build_patch_result(target_dir)
        }
    }
}

/// Validate that a skill directory contains a valid SKILL.md with parseable frontmatter.
/// Returns `Some(error_message)` if invalid, `None` if valid.
pub fn validate_skill_dir(dir: &Path) -> Option<String> {
    let skill_md = dir.join("SKILL.md");
    if !skill_md.exists() {
        return Some("SKILL.md not found".into());
    }

    let content = match std::fs::read_to_string(&skill_md) {
        Ok(c) => c,
        Err(e) => return Some(format!("failed to read SKILL.md: {e}")),
    };

    if content.trim().is_empty() {
        return Some("SKILL.md is empty".into());
    }

    // Check for YAML frontmatter
    if !content.starts_with("---") {
        return Some("SKILL.md missing YAML frontmatter (must start with ---)".into());
    }

    let end = content[3..].find("---");
    if end.is_none() {
        return Some("SKILL.md has unclosed YAML frontmatter".into());
    }

    let frontmatter = &content[3..3 + end.unwrap()];
    if !frontmatter.contains("name:") {
        return Some("SKILL.md frontmatter missing 'name' field".into());
    }
    if !frontmatter.contains("description:") {
        return Some("SKILL.md frontmatter missing 'description' field".into());
    }

    None
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum PatchOpKind {
    Update,
    Add,
    Delete,
}

#[derive(Debug)]
struct PatchOp {
    file: String,
    kind: PatchOpKind,
    content: String,
}

/// Extract added lines (lines starting with '+') from hunk content.
fn extract_added_lines(hunk: &str) -> String {
    hunk.lines()
        .filter_map(|line| line.strip_prefix('+'))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Apply a unified-diff-style hunk to file content using `diffy`.
///
/// Surgical-fail: when the hunk's context doesn't match, `diffy::apply`
/// returns an error. The caller (`evolver::apply_with_retry`) feeds the
/// failure back into the LLM via `prompt::retry_prompt`, so an unmatched
/// hunk produces a useful retry instead of a silently-misapplied file.
///
/// The LLM is instructed (see `prompt::evolver_system_prompt`) to use
/// `@@ anchor_line` rather than proper `@@ -A,B +C,D @@` headers — we
/// normalize that to a valid diffy hunk header before applying.
fn apply_hunk_to_content(original: &str, hunk: &str) -> Result<String, String> {
    let normalized = normalize_hunk(hunk);
    let patch_text = if normalized.trim_start().starts_with("--- ") {
        normalized
    } else {
        format!("--- a\n+++ b\n{normalized}")
    };

    let patch = diffy::Patch::from_str(&patch_text)
        .map_err(|e| format!("invalid hunk: {e}"))?;
    diffy::apply(original, &patch)
        .map_err(|e| format!("hunk apply failed: {e}"))
}

/// Replace any `@@ ... @@` (or `@@ anchor_line`) header in the hunk body
/// with a synthesized `@@ -1,N +1,M @@` header where N counts context+del
/// lines and M counts context+add lines. If no `@@` is present, prepend one.
fn normalize_hunk(hunk: &str) -> String {
    // Drop existing hunk headers
    let body: Vec<&str> = hunk
        .lines()
        .filter(|l| !l.trim_start().starts_with("@@"))
        .collect();

    let mut n_old = 0usize;
    let mut n_new = 0usize;
    for line in &body {
        if let Some(c) = line.chars().next() {
            match c {
                ' ' => {
                    n_old += 1;
                    n_new += 1;
                }
                '-' => n_old += 1,
                '+' => n_new += 1,
                _ => {
                    // Plain line (no prefix) — treat as context, same as old code.
                    n_old += 1;
                    n_new += 1;
                }
            }
        }
    }

    let header = format!("@@ -1,{n_old} +1,{n_new} @@");
    let mut out = String::with_capacity(hunk.len() + header.len() + 8);
    out.push_str(&header);
    out.push('\n');
    // Normalize unprefixed lines to context lines (diffy requires one of ' '/-/+).
    for line in body {
        if line.is_empty() {
            out.push(' ');
            out.push('\n');
            continue;
        }
        let first = line.chars().next().unwrap();
        if first == ' ' || first == '-' || first == '+' || first == '\\' {
            out.push_str(line);
        } else {
            out.push(' ');
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

/// Parse files from Format B (full content) output.
fn parse_full_content_files(content: &str) -> Result<Vec<(String, String)>, String> {
    let mut files = Vec::new();

    // Try structured format first
    if content.contains("*** Begin Files") || content.contains("*** File:") {
        let mut current_file: Option<String> = None;
        let mut current_content: Vec<String> = Vec::new();
        let mut in_files = false;

        for line in content.lines() {
            if line.contains("*** Begin Files") {
                in_files = true;
                continue;
            }
            if line.contains("*** End Files") {
                break;
            }
            if !in_files && !line.starts_with("*** File:") {
                continue;
            }

            if let Some(path) = line.strip_prefix("*** File: ") {
                if let Some(file) = current_file.take() {
                    files.push((file, current_content.join("\n")));
                    current_content.clear();
                }
                // Normalize: extract just the filename to prevent absolute paths
                // from escaping the skill directory via Path::join()
                let trimmed = path.trim();
                let normalized = std::path::Path::new(trimmed)
                    .file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| "SKILL.md".to_string());
                current_file = Some(normalized);
                in_files = true;
            } else if in_files {
                current_content.push(line.to_string());
            }
        }

        if let Some(file) = current_file {
            files.push((file, current_content.join("\n")));
        }
    }

    if files.is_empty() {
        // Treat entire content as SKILL.md
        files.push(("SKILL.md".to_string(), content.to_string()));
    }

    Ok(files)
}

/// Build a PatchResult by snapshotting all files in the skill directory.
fn build_patch_result(skill_dir: &Path) -> Result<PatchResult, String> {
    let mut snapshot = HashMap::new();

    if skill_dir.exists() {
        collect_files(skill_dir, skill_dir, &mut snapshot)?;
    }

    Ok(PatchResult {
        content_diff: String::new(), // Caller can compute diff if needed
        content_snapshot: snapshot,
    })
}

/// Recursively collect files relative to base_dir.
fn collect_files(
    dir: &Path,
    base_dir: &Path,
    snapshot: &mut HashMap<String, String>,
) -> Result<(), String> {
    let entries =
        std::fs::read_dir(dir).map_err(|e| format!("failed to read dir {}: {e}", dir.display()))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("dir entry error: {e}"))?;
        let path = entry.path();

        if path.is_dir() {
            collect_files(&path, base_dir, snapshot)?;
        } else {
            // Skip .skill_id sidecar
            if path.file_name().map(|f| f == ".skill_id").unwrap_or(false) {
                continue;
            }
            let relative = path
                .strip_prefix(base_dir)
                .map_err(|e| format!("path strip error: {e}"))?
                .to_string_lossy()
                .to_string();
            if let Ok(content) = std::fs::read_to_string(&path) {
                snapshot.insert(relative, content);
            }
        }
    }
    Ok(())
}

/// Copy a directory recursively.
fn copy_dir(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| format!("failed to create {}: {e}", dst.display()))?;

    let entries = std::fs::read_dir(src)
        .map_err(|e| format!("failed to read {}: {e}", src.display()))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("dir entry error: {e}"))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)
                .map_err(|e| format!("failed to copy {}: {e}", src_path.display()))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_test_skill(dir: &Path) {
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("SKILL.md"),
            "---\nname: \"test-skill\"\ndescription: \"A test skill\"\n---\n\n# Test Skill\n\nStep 1: Do something\nStep 2: Do something else\n",
        )
        .unwrap();
    }

    #[test]
    fn detect_patch_format() {
        assert_eq!(
            detect_format("*** Begin Patch\n*** Update File: SKILL.md\n*** End Patch"),
            PatchFormat::Patch
        );
        assert_eq!(
            detect_format("*** Begin Files\n*** File: SKILL.md\ncontent\n*** End Files"),
            PatchFormat::FullContent
        );
        assert_eq!(
            detect_format("<<<<<<< SEARCH\nold\n=======\nnew\n>>>>>>> REPLACE"),
            PatchFormat::SearchReplace
        );
        // Default
        assert_eq!(detect_format("just some content"), PatchFormat::FullContent);
    }

    #[test]
    fn full_content_apply() {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("test-skill");

        let content = "*** Begin Files\n*** File: SKILL.md\n---\nname: \"updated\"\ndescription: \"Updated skill\"\n---\n\n# Updated\n\nNew content.\n*** End Files";
        let result = apply_full_content(&skill_dir, content).unwrap();
        assert!(result.content_snapshot.contains_key("SKILL.md"));
        assert!(
            fs::read_to_string(skill_dir.join("SKILL.md"))
                .unwrap()
                .contains("Updated")
        );
    }

    #[test]
    fn full_content_apply_absolute_path_normalized() {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("test-skill");

        // LLM outputs an absolute path instead of just SKILL.md
        let content = "*** Begin Files\n*** File: /data/workspaces/evolution-evolver/skills/reference/user-query-priority.md\n---\nname: \"test\"\ndescription: \"test\"\n---\n\n# Test\n*** End Files";
        let result = apply_full_content(&skill_dir, content).unwrap();
        // Should normalize to just the filename and write inside skill_dir
        assert!(result.content_snapshot.contains_key("user-query-priority.md"));
        assert!(skill_dir.join("user-query-priority.md").exists());
    }

    #[test]
    fn search_replace_apply() {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("test-skill");
        create_test_skill(&skill_dir);

        let content =
            "<<<<<<< SEARCH\nStep 1: Do something\n=======\nStep 1: Do the right thing\n>>>>>>> REPLACE";
        let result = apply_search_replace(&skill_dir, content).unwrap();
        let skill_content = fs::read_to_string(skill_dir.join("SKILL.md")).unwrap();
        assert!(skill_content.contains("Do the right thing"));
        assert!(!skill_content.contains("Do something\n"));
        assert!(!result.content_snapshot.is_empty());
    }

    #[test]
    fn search_replace_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("test-skill");
        create_test_skill(&skill_dir);

        let content =
            "<<<<<<< SEARCH\nNonexistent content\n=======\nReplacement\n>>>>>>> REPLACE";
        let result = apply_search_replace(&skill_dir, content);
        assert!(result.is_err());
    }

    #[test]
    fn validate_valid_skill() {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("valid");
        create_test_skill(&skill_dir);
        assert!(validate_skill_dir(&skill_dir).is_none());
    }

    #[test]
    fn validate_missing_skill_md() {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("empty");
        fs::create_dir_all(&skill_dir).unwrap();
        assert!(validate_skill_dir(&skill_dir).is_some());
    }

    #[test]
    fn validate_no_frontmatter() {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("no-fm");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(skill_dir.join("SKILL.md"), "# Just markdown\n").unwrap();
        let err = validate_skill_dir(&skill_dir).unwrap();
        assert!(err.contains("frontmatter"));
    }

    #[test]
    fn validate_missing_name() {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("no-name");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(
            skill_dir.join("SKILL.md"),
            "---\ndescription: \"test\"\n---\n# Test\n",
        )
        .unwrap();
        let err = validate_skill_dir(&skill_dir).unwrap();
        assert!(err.contains("name"));
    }

    #[test]
    fn create_skill_from_raw() {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("new-skill");

        let content =
            "---\nname: \"new-skill\"\ndescription: \"A new skill\"\n---\n\n# New Skill\n\nInstructions here.\n";
        let result = create_skill(&skill_dir, content).unwrap();
        assert!(result.content_snapshot.contains_key("SKILL.md"));
        assert!(validate_skill_dir(&skill_dir).is_none());
    }

    #[test]
    fn derive_skill_single_parent() {
        let dir = tempfile::tempdir().unwrap();
        let parent_dir = dir.path().join("parent");
        create_test_skill(&parent_dir);

        let target_dir = dir.path().join("derived");
        let content =
            "<<<<<<< SEARCH\nStep 1: Do something\n=======\nStep 1: Enhanced approach\n>>>>>>> REPLACE";

        let result = derive_skill(&[parent_dir.as_path()], &target_dir, content).unwrap();
        let skill_content = fs::read_to_string(target_dir.join("SKILL.md")).unwrap();
        assert!(skill_content.contains("Enhanced approach"));
        assert!(!result.content_snapshot.is_empty());
        // .skill_id should not exist in derived copy
        assert!(!target_dir.join(".skill_id").exists());
    }

    #[test]
    fn diffy_patch_simple_update() {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("p");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: \"t\"\ndescription: \"d\"\n---\n\nline a\nline b\nline c\n",
        )
            .unwrap();

        let patch_input = "*** Begin Patch\n\
*** Update File: SKILL.md\n\
@@ anchor\n\
 line a\n\
-line b\n\
+line BB\n\
 line c\n\
*** End Patch";
        let result = apply_patch(&skill_dir, patch_input).unwrap();
        let after = fs::read_to_string(skill_dir.join("SKILL.md")).unwrap();
        assert!(after.contains("line BB"), "patch should have replaced line b");
        assert!(!after.contains("line b\n"), "old line should be gone");
        assert!(!result.content_snapshot.is_empty());
    }

    #[test]
    fn diffy_patch_context_mismatch_errors() {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("p");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(
            skill_dir.join("SKILL.md"),
            "---\nname: \"t\"\ndescription: \"d\"\n---\nactual content\n",
        )
            .unwrap();

        // Context line that doesn't exist in original.
        let bad = "*** Begin Patch\n\
*** Update File: SKILL.md\n\
@@\n\
 nonexistent context\n\
-line b\n\
+line BB\n\
*** End Patch";
        let result = apply_patch(&skill_dir, bad);
        assert!(result.is_err(), "diffy should refuse to apply a mismatched hunk");
    }

    #[test]
    fn fix_skill_with_search_replace() {
        let dir = tempfile::tempdir().unwrap();
        let skill_dir = dir.path().join("fix-target");
        create_test_skill(&skill_dir);

        let content =
            "<<<<<<< SEARCH\nStep 2: Do something else\n=======\nStep 2: Do it correctly\n>>>>>>> REPLACE";
        let result = fix_skill(&skill_dir, content).unwrap();
        let skill_content = fs::read_to_string(skill_dir.join("SKILL.md")).unwrap();
        assert!(skill_content.contains("Do it correctly"));
        assert!(!result.content_snapshot.is_empty());
    }
}
