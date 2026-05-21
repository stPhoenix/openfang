//! Evolution-engine glue: helpers used by `kernel.rs::execute_evolution`
//! and the canary/GC cron handlers.
//!
//! Lives in a sibling module to keep `kernel.rs` from accreting yet more
//! evolution-specific helpers. The big `impl OpenFangKernel` methods
//! (`execute_evolution`, `evolve_analyze_unanalyzed`, etc.) remain in
//! `kernel.rs` because they're tightly coupled to private kernel state;
//! moving them would require widening visibility we don't want to grant.

use std::collections::HashMap;
use std::path::Path;

/// Recursively snapshot a skill directory into `{relative_path: contents}`.
/// Used to capture a parent's pre-fix state so the canary lifecycle can
/// roll back to it if the fix regresses.
pub(crate) fn snapshot_skill_dir(dir: &Path) -> Result<HashMap<String, String>, std::io::Error> {
    let mut out = HashMap::new();
    walk(dir, dir, &mut out)?;
    Ok(out)
}

fn walk(
    dir: &Path,
    base: &Path,
    out: &mut HashMap<String, String>,
) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.file_name().map(|f| f == ".skill_id").unwrap_or(false) {
            continue;
        }
        if path.is_dir() {
            walk(&path, base, out)?;
        } else if let Ok(content) = std::fs::read_to_string(&path) {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            out.insert(rel, content);
        }
    }
    Ok(())
}

/// Restore a skill directory's contents from a snapshot. Used by canary rollback.
pub(crate) fn restore_skill_dir(
    dir: &Path,
    snapshot: &HashMap<String, String>,
) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(dir)?;
    for (rel, content) in snapshot {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content)?;
    }
    Ok(())
}
