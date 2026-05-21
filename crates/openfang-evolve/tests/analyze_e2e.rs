//! End-to-end test of the analyzer pipeline with a canned LLM closure.
//!
//! Exercises: prompt build → JSON parse → transactional save → counter
//! update → mark-analyzed. Uses an in-memory SQLite mirroring the real
//! schema (analyses + child tables) so transaction rollback can be
//! observed when parsing fails.

use openfang_evolve::{EvolveEngine, ItemStatus, ProgressEvent};
use openfang_types::agent::AgentId;
use openfang_types::config::EvolveConfig;
use openfang_types::message::{Message, MessageContent, Role};
use rusqlite::Connection;
use std::sync::{Arc, Mutex};

fn setup_db() -> Arc<Mutex<Connection>> {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            messages BLOB NOT NULL,
            context_window_tokens INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            label TEXT,
            evolution_analyzed INTEGER NOT NULL DEFAULT 0,
            evolve_parse_attempts INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS execution_analyses (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            task_completed INTEGER NOT NULL,
            execution_note TEXT NOT NULL,
            model_used TEXT NOT NULL,
            input_tokens INTEGER NOT NULL DEFAULT 0,
            output_tokens INTEGER NOT NULL DEFAULT 0,
            analyzed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evolve_tool_issues (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL REFERENCES execution_analyses(id) ON DELETE CASCADE,
            tool_name TEXT NOT NULL,
            issue_type TEXT NOT NULL,
            description TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evolve_skill_judgments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL REFERENCES execution_analyses(id) ON DELETE CASCADE,
            skill_name TEXT NOT NULL,
            applied INTEGER NOT NULL,
            quality TEXT NOT NULL,
            note TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evolve_suggestions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL REFERENCES execution_analyses(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            target_skill TEXT,
            description TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 3,
            executed_at TEXT,
            failed_at TEXT,
            failure_reason TEXT
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
            last_updated TEXT,
            is_canary INTEGER NOT NULL DEFAULT 0,
            canary_selections INTEGER NOT NULL DEFAULT 0,
            canary_completions INTEGER NOT NULL DEFAULT 0,
            parent_completion_rate_at_birth REAL NOT NULL DEFAULT 0.0,
            canary_parent_skill_id TEXT
        );
        CREATE TABLE IF NOT EXISTS evolve_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        ",
    )
    .unwrap();
    Arc::new(Mutex::new(conn))
}

fn engine_enabled(conn: Arc<Mutex<Connection>>) -> EvolveEngine {
    let cfg = EvolveConfig {
        enabled: true,
        ..Default::default()
    };
    let eng = EvolveEngine::new(cfg, conn);
    // Spawn-detected via the agent ID setter — bypasses the actual kernel.
    eng.set_analyzer_agent(AgentId::from_string("evolution-analyzer"));
    eng
}

fn dummy_msg() -> Message {
    Message {
        role: Role::User,
        content: MessageContent::Text("test user message".into()),
        uuid: None,
        timestamp: None,
        session_id: None,
        metadata: Default::default(),
    }
}

#[tokio::test]
async fn analyze_session_full_pipeline() {
    let conn = setup_db();
    let engine = engine_enabled(conn.clone());

    // Insert a session row so mark_session_analyzed has something to update.
    {
        let c = conn.lock().unwrap();
        c.execute(
            "INSERT INTO sessions (id, agent_id, messages, context_window_tokens, created_at, updated_at)
             VALUES ('s-1', 'a-1', X'', 0, '2024-01-01', '2024-01-01')",
            [],
        )
        .unwrap();
    }

    let canned = r#"{
        "task_completed": true,
        "execution_note": "Agent completed the docker setup task.",
        "tool_issues": [
            {"tool_name": "shell_exec", "issue_type": "failure", "description": "exit code 1 on first run"}
        ],
        "skill_judgments": [
            {"skill_name": "docker", "applied": true, "quality": "good", "note": "followed steps"}
        ],
        "evolution_suggestions": [
            {"kind": "fix", "target_skill": "docker", "description": "Clarify port mapping step", "priority": 4}
        ]
    }"#;

    let result = engine
        .analyze_session(
            "s-1",
            "a-1",
            &[dummy_msg()],
            &["docker".to_string()],
            &[],
            32_000,
            |_msg| async move { Ok((canned.to_string(), 1500, 300)) },
        )
        .await
        .expect("analysis should succeed");

    assert_eq!(result.session_id, "s-1");
    assert!(result.task_completed);
    assert_eq!(result.tool_issues.len(), 1);
    assert_eq!(result.skill_judgments.len(), 1);
    assert_eq!(result.evolution_suggestions.len(), 1);

    // Loaded back: all child rows present (proves transaction Fix 1 committed).
    let loaded = engine
        .store()
        .get_analysis(&result.id.to_string())
        .unwrap()
        .expect("analysis row should exist");
    assert_eq!(loaded.tool_issues.len(), 1);
    assert_eq!(loaded.skill_judgments.len(), 1);
    assert_eq!(loaded.evolution_suggestions.len(), 1);

    // Session was marked analyzed.
    let pending = engine.store().list_unanalyzed_session_ids(10, &[]).unwrap();
    assert!(
        pending.iter().all(|(sid, _)| sid != "s-1"),
        "s-1 should be marked analyzed"
    );
}

#[tokio::test]
async fn analyze_unanalyzed_batch_progress_events() {
    let conn = setup_db();
    let engine = engine_enabled(conn.clone());

    {
        let c = conn.lock().unwrap();
        for i in 0..3 {
            c.execute(
                "INSERT INTO sessions (id, agent_id, messages, context_window_tokens, created_at, updated_at)
                 VALUES (?1, 'a-1', X'', 0, '2024-01-01', '2024-01-01')",
                rusqlite::params![format!("s-{i}")],
            )
            .unwrap();
        }
    }

    let canned = r#"{"task_completed": true, "execution_note": "ok", "tool_issues": [], "skill_judgments": [], "evolution_suggestions": []}"#;

    let mut events: Vec<ProgressEvent> = Vec::new();
    let results = engine
        .analyze_unanalyzed(
            |_sid, _aid| Some(vec![dummy_msg()]),
            &[],
            &[],
            32_000,
            |_msg| async move { Ok((canned.to_string(), 100, 50)) },
            |ev| events.push(ev),
        )
        .await
        .expect("batch ok");

    assert_eq!(results.len(), 3);
    assert!(events.iter().any(|e| matches!(e, ProgressEvent::Started { total: 3 })));
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(e, ProgressEvent::Item { status: ItemStatus::Analyzed, .. }))
            .count(),
        3
    );
    assert!(events
        .iter()
        .any(|e| matches!(e, ProgressEvent::Completed { analyzed: 3 })));
}

#[tokio::test]
async fn analyze_session_parse_failure_no_orphan_rows() {
    let conn = setup_db();
    let engine = engine_enabled(conn.clone());

    {
        let c = conn.lock().unwrap();
        c.execute(
            "INSERT INTO sessions (id, agent_id, messages, context_window_tokens, created_at, updated_at)
             VALUES ('s-bad', 'a-1', X'', 0, '2024-01-01', '2024-01-01')",
            [],
        )
        .unwrap();
    }

    let bad = "this is not JSON at all";
    let result = engine
        .analyze_session(
            "s-bad",
            "a-1",
            &[dummy_msg()],
            &[],
            &[],
            32_000,
            |_msg| async move { Ok((bad.to_string(), 100, 50)) },
        )
        .await;
    assert!(result.is_err(), "parse failure should propagate");

    // No analysis rows persisted (proves transaction integrity + no orphan).
    let c = conn.lock().unwrap();
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM execution_analyses", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 0);
}
