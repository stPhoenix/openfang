//! Tool quality manager — tracks tool execution metrics and identifies degraded tools.

use crate::store::EvolveStore;
use crate::types::*;
use chrono::Utc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, warn};

/// Tool quality manager: records executions, computes penalties, finds problems.
pub struct ToolQualityManager {
    store: EvolveStore,
    /// Global execution counter for triggering quality evolution cycles.
    execution_count: AtomicU64,
}

impl ToolQualityManager {
    /// Create a new manager sharing the same store as the evolve engine.
    pub fn new(store: EvolveStore) -> Self {
        Self {
            store,
            execution_count: AtomicU64::new(0),
        }
    }

    /// Record a single tool execution.
    ///
    /// Updates the tool quality record with the new execution data.
    /// This is designed to be called after every tool invocation with minimal overhead.
    pub fn record_execution(
        &self,
        tool_key: &str,
        success: bool,
        execution_time_ms: f64,
        error_message: Option<&str>,
    ) {
        let now = Utc::now();
        let exec_record = ToolExecutionRecord {
            timestamp: now,
            success,
            execution_time_ms,
            error_message: error_message.map(|s| s.to_string()),
        };

        match self.store.get_tool_quality_record(tool_key) {
            Ok(Some(mut record)) => {
                record.total_calls += 1;
                if success {
                    record.success_count += 1;
                }
                record.total_execution_time_ms += execution_time_ms;
                record.recent_executions.push(exec_record);
                // Trim to max window
                while record.recent_executions.len() > MAX_RECENT_EXECUTIONS {
                    record.recent_executions.remove(0);
                }
                record.last_updated = now;

                if let Err(e) = self.store.save_tool_quality_record(&record) {
                    warn!(tool_key, error = %e, "failed to update tool quality record");
                }
            }
            Ok(None) => {
                // First execution — create a new record
                let parts = parse_tool_key(tool_key);
                let record = ToolQualityRecord {
                    tool_key: tool_key.to_string(),
                    backend: parts.0.to_string(),
                    server: parts.1.to_string(),
                    tool_name: parts.2.to_string(),
                    total_calls: 1,
                    success_count: if success { 1 } else { 0 },
                    total_execution_time_ms: execution_time_ms,
                    recent_executions: vec![exec_record],
                    description_quality: None,
                    llm_flagged_count: 0,
                    description_hash: None,
                    first_seen: now,
                    last_updated: now,
                };
                if let Err(e) = self.store.save_tool_quality_record(&record) {
                    warn!(tool_key, error = %e, "failed to create tool quality record");
                }
            }
            Err(e) => {
                warn!(tool_key, error = %e, "failed to load tool quality record");
            }
        }

        self.execution_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an LLM-identified tool issue.
    ///
    /// Injects a synthetic failure into the tool's recent executions
    /// WITHOUT incrementing total_calls (the real execution was already counted).
    pub fn record_llm_tool_issue(&self, tool_key: &str, description: &str) {
        let now = Utc::now();

        match self.store.get_tool_quality_record(tool_key) {
            Ok(Some(mut record)) => {
                record.llm_flagged_count += 1;
                record.recent_executions.push(ToolExecutionRecord {
                    timestamp: now,
                    success: false,
                    execution_time_ms: 0.0,
                    error_message: Some(format!("[LLM] {description}")),
                });
                while record.recent_executions.len() > MAX_RECENT_EXECUTIONS {
                    record.recent_executions.remove(0);
                }
                record.last_updated = now;

                if let Err(e) = self.store.save_tool_quality_record(&record) {
                    warn!(tool_key, error = %e, "failed to record LLM tool issue");
                }
            }
            Ok(None) => {
                debug!(tool_key, "LLM flagged unknown tool, creating record");
                let parts = parse_tool_key(tool_key);
                let record = ToolQualityRecord {
                    tool_key: tool_key.to_string(),
                    backend: parts.0.to_string(),
                    server: parts.1.to_string(),
                    tool_name: parts.2.to_string(),
                    total_calls: 0,
                    success_count: 0,
                    total_execution_time_ms: 0.0,
                    recent_executions: vec![ToolExecutionRecord {
                        timestamp: now,
                        success: false,
                        execution_time_ms: 0.0,
                        error_message: Some(format!("[LLM] {description}")),
                    }],
                    description_quality: None,
                    llm_flagged_count: 1,
                    description_hash: None,
                    first_seen: now,
                    last_updated: now,
                };
                let _ = self.store.save_tool_quality_record(&record);
            }
            Err(e) => {
                warn!(tool_key, error = %e, "failed to load tool quality for LLM issue");
            }
        }
    }

    /// Get tools with recent_success_rate < threshold AND total_calls >= min.
    pub fn get_problematic_tools(&self) -> Vec<ToolQualityRecord> {
        self.store
            .get_problematic_tools(
                crate::triggers::PROBLEMATIC_MIN_CALLS,
                crate::triggers::PROBLEMATIC_SUCCESS_RATE,
            )
            .unwrap_or_default()
    }

    /// Get the penalty factor for a specific tool.
    pub fn penalty(&self, tool_key: &str) -> f64 {
        match self.store.get_tool_quality_record(tool_key) {
            Ok(Some(record)) => record.penalty(),
            _ => 1.0,
        }
    }

    /// Get the global execution count since startup.
    pub fn execution_count(&self) -> u64 {
        self.execution_count.load(Ordering::Relaxed)
    }
}

/// Parse a tool key (format: `backend:server:tool_name`) into components.
fn parse_tool_key(key: &str) -> (&str, &str, &str) {
    let parts: Vec<&str> = key.splitn(3, ':').collect();
    match parts.len() {
        3 => (parts[0], parts[1], parts[2]),
        2 => (parts[0], "", parts[1]),
        _ => ("", "", key),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::sync::{Arc, Mutex};

    fn setup_store() -> EvolveStore {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS tool_quality_records (
                tool_key TEXT PRIMARY KEY,
                backend TEXT,
                server TEXT,
                tool_name TEXT,
                total_calls INTEGER DEFAULT 0,
                success_count INTEGER DEFAULT 0,
                total_execution_time_ms REAL DEFAULT 0,
                recent_executions TEXT,
                description_quality TEXT,
                llm_flagged_count INTEGER DEFAULT 0,
                description_hash TEXT,
                first_seen TEXT,
                last_updated TEXT
            );
            CREATE TABLE IF NOT EXISTS skill_records (
                skill_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                path TEXT,
                is_active INTEGER DEFAULT 1,
                category TEXT,
                tags TEXT,
                visibility TEXT,
                creator_id TEXT,
                lineage TEXT,
                tool_dependencies TEXT,
                critical_tools TEXT,
                total_selections INTEGER DEFAULT 0,
                total_applied INTEGER DEFAULT 0,
                total_completions INTEGER DEFAULT 0,
                total_fallbacks INTEGER DEFAULT 0,
                first_seen TEXT,
                last_updated TEXT
            );
            ",
        )
        .unwrap();
        EvolveStore::new(Arc::new(Mutex::new(conn)))
    }

    #[test]
    fn record_execution_creates_new_record() {
        let store = setup_store();
        let mgr = ToolQualityManager::new(store);

        mgr.record_execution("builtin::web_search", true, 150.0, None);

        assert_eq!(mgr.execution_count(), 1);
        assert_eq!(mgr.penalty("builtin::web_search"), 1.0);
    }

    #[test]
    fn record_execution_updates_existing() {
        let store = setup_store();
        let mgr = ToolQualityManager::new(store);

        for _ in 0..5 {
            mgr.record_execution("test::tool", true, 100.0, None);
        }
        mgr.record_execution("test::tool", false, 200.0, Some("timeout"));

        assert_eq!(mgr.execution_count(), 6);
    }

    #[test]
    fn llm_issue_injection() {
        let store = setup_store();
        let mgr = ToolQualityManager::new(store);

        // First create a normal record
        for _ in 0..3 {
            mgr.record_execution("test::tool", true, 100.0, None);
        }

        // Inject LLM issue
        mgr.record_llm_tool_issue("test::tool", "returned wrong data format");

        // total_calls should still be 3 (LLM issues don't increment)
        // but recent_executions has 4 entries (3 real + 1 LLM)
    }

    #[test]
    fn parse_tool_key_formats() {
        assert_eq!(parse_tool_key("builtin:mcp:web_search"), ("builtin", "mcp", "web_search"));
        assert_eq!(parse_tool_key("builtin:web_search"), ("builtin", "", "web_search"));
        assert_eq!(parse_tool_key("web_search"), ("", "", "web_search"));
    }
}
