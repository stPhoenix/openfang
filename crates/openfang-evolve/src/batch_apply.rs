//! Batch-apply pipeline: gather pending suggestions across all analyses,
//! optionally dedup via LLM judge, then return `EvolutionContext`s ready for
//! the execute queue.
//!
//! Pure logic — does not enqueue or call the evolver. The caller (kernel cron
//! or API endpoint) decides how to execute the resulting contexts.

use crate::dedup::{dedup_pending, DedupGroup, DedupResult};
use crate::store::EvolveStore;
use crate::types::{AnalysisId, EvolutionContext, EvolutionSuggestion};
use std::collections::HashSet;
use std::future::Future;
use tracing::{info, warn};

/// Outcome of one batch-apply run.
#[derive(Debug, Default, Clone)]
pub struct BatchApplyReport {
    /// Total pending suggestions found at the start of the run.
    pub total_pending: usize,
    /// Number of suggestions marked superseded by dedup.
    pub superseded: usize,
    /// Whether the LLM judge produced a usable response.
    pub used_llm: bool,
    /// Contexts ready to be enqueued/executed, in priority desc order, capped
    /// by `apply_max_per_run`.
    pub contexts: Vec<EvolutionContext>,
    /// Dedup decisions (useful for preview endpoints).
    pub dedup_groups: Vec<DedupGroup>,
    /// Whether dedup was skipped (dedup_enabled=false or <2 candidates).
    pub dedup_skipped: bool,
}

/// Run the batch-apply pipeline.
///
/// 1. List all pending suggestions across analyses.
/// 2. If `dedup_enabled`, run the LLM judge (with heuristic fallback).
///    Mark losers superseded in the store (skipped when `dry_run=true`).
/// 3. Build `EvolutionContext` per survivor, in priority desc order.
/// 4. Cap at `apply_max_per_run` if set.
///
/// `dry_run=true` computes the dedup grouping in-memory without writing to
/// the store — used by the Preview endpoint so reload mid-flow leaves no
/// orphan superseded rows.
///
/// `judge_fn` is the LLM call closure (same shape as `dedup::dedup_pending`).
/// Pass a closure returning `Err` when LLM is not configured — heuristic
/// fallback will run inside `dedup_pending`.
pub async fn run_batch_apply<F, Fut>(
    store: &EvolveStore,
    dedup_enabled: bool,
    apply_max_per_run: Option<usize>,
    dry_run: bool,
    judge_fn: F,
) -> Result<BatchApplyReport, crate::types::EvolveError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    let pending = store.list_all_pending_suggestions()?;
    let total_pending = pending.len();
    info!(total_pending, "batch apply: starting");

    if pending.is_empty() {
        return Ok(BatchApplyReport {
            total_pending,
            dedup_skipped: true,
            ..Default::default()
        });
    }

    // Build (id, suggestion) candidate list for dedup.
    let dedup_input: Vec<(i64, EvolutionSuggestion)> = pending
        .iter()
        .map(|(id, _, sug)| (*id, sug.clone()))
        .collect();

    let (dedup_result, dedup_skipped) = if dedup_enabled && dedup_input.len() >= 2 {
        (dedup_pending(dedup_input, judge_fn).await, false)
    } else {
        (DedupResult::default(), true)
    };

    // Collect loser ids to filter survivors from the pending list. When not
    // dry_run, also mark each loser in the store before we build contexts (so
    // a crash mid-run leaves a clean state — superseded rows are filtered out
    // next run).
    let mut loser_ids: HashSet<i64> = HashSet::new();
    let mut superseded = 0usize;
    for group in &dedup_result.groups {
        for loser_id in &group.loser_ids {
            if loser_ids.insert(*loser_id) {
                if dry_run {
                    superseded += 1;
                } else if let Err(e) =
                    store.mark_suggestion_superseded(*loser_id, group.survivor_id, &group.reason)
                {
                    warn!(loser_id, error = %e, "failed to mark suggestion superseded");
                } else {
                    superseded += 1;
                }
            }
        }
    }

    // Survivors retain original priority order from `list_all_pending_suggestions`
    // (priority DESC, id ASC). Caller-side ordering matches execution order.
    let survivors: Vec<(i64, AnalysisId, EvolutionSuggestion)> = pending
        .into_iter()
        .filter(|(id, _, _)| !loser_ids.contains(id))
        .collect();

    let capped: Vec<_> = match apply_max_per_run {
        Some(n) => survivors.into_iter().take(n).collect(),
        None => survivors,
    };

    let mut contexts = Vec::with_capacity(capped.len());
    for (_id, analysis_id, suggestion) in capped {
        let target_skills = if let Some(ref target) = suggestion.target_skill {
            store
                .get_skill_record(target)
                .ok()
                .flatten()
                .into_iter()
                .collect()
        } else {
            vec![]
        };

        contexts.push(EvolutionContext {
            evolution_type: suggestion.kind.clone(),
            target_skills,
            direction: suggestion.description.clone(),
            category: None,
            trigger_context: format!(
                "Batch apply from analysis {analysis_id}. Priority: {}",
                suggestion.priority
            ),
            source_analysis: Some(analysis_id),
        });
    }

    info!(
        total_pending,
        superseded,
        used_llm = dedup_result.used_llm,
        queued = contexts.len(),
        "batch apply: ready"
    );

    Ok(BatchApplyReport {
        total_pending,
        superseded,
        used_llm: dedup_result.used_llm,
        contexts,
        dedup_groups: dedup_result.groups,
        dedup_skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExecutionAnalysis, SuggestionKind};
    use chrono::Utc;
    use rusqlite::Connection;
    use std::sync::{Arc, Mutex};

    fn setup_store() -> EvolveStore {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "
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
                failure_reason TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                supersedes_id INTEGER REFERENCES evolve_suggestions(id),
                dedup_reason TEXT
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
            ",
        )
        .unwrap();
        EvolveStore::new(Arc::new(Mutex::new(conn)))
    }

    fn save_analysis_with_suggestions(
        store: &EvolveStore,
        suggestions: Vec<EvolutionSuggestion>,
    ) -> AnalysisId {
        let analysis = ExecutionAnalysis {
            id: AnalysisId::new(),
            session_id: "s1".into(),
            agent_id: "a1".into(),
            task_completed: true,
            execution_note: "ok".into(),
            tool_issues: vec![],
            skill_judgments: vec![],
            evolution_suggestions: suggestions,
            model_used: "test".into(),
            input_tokens: 0,
            output_tokens: 0,
            analyzed_at: Utc::now(),
        };
        let id = analysis.id;
        store.save_analysis(&analysis).unwrap();
        id
    }

    fn sug(kind: SuggestionKind, target: Option<&str>, desc: &str, prio: u8) -> EvolutionSuggestion {
        EvolutionSuggestion {
            kind,
            target_skill: target.map(String::from),
            description: desc.to_string(),
            priority: prio,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn empty_pending_returns_empty_report() {
        let store = setup_store();
        let report = run_batch_apply(&store, true, None, false, |_| async {
            panic!("judge must not run for empty pending");
            #[allow(unreachable_code)]
            Ok::<String, String>(String::new())
        })
        .await
        .unwrap();
        assert_eq!(report.total_pending, 0);
        assert_eq!(report.superseded, 0);
        assert!(report.contexts.is_empty());
        assert!(report.dedup_skipped);
    }

    #[tokio::test]
    async fn dedup_marks_losers_and_emits_survivor_contexts() {
        let store = setup_store();
        save_analysis_with_suggestions(
            &store,
            vec![
                sug(SuggestionKind::Fix, Some("ra"), "retry on timeout", 4),
                sug(SuggestionKind::Fix, Some("ra"), "add retry for timeout", 3),
                sug(SuggestionKind::Derived, Some("other"), "alt approach", 2),
            ],
        );
        save_analysis_with_suggestions(
            &store,
            vec![sug(SuggestionKind::Fix, Some("ra"), "same retry idea again", 5)],
        );

        // Judge groups all three "ra" Fix suggestions, picks highest priority (5).
        let report = run_batch_apply(&store, true, None, false, |_p| async {
            Ok(
                r#"{"groups":[{"survivor_id":4,"loser_ids":[1,2],"reason":"same retry fix"}]}"#
                    .to_string(),
            )
        })
        .await
        .unwrap();

        assert_eq!(report.total_pending, 4);
        assert_eq!(report.superseded, 2);
        assert!(report.used_llm);
        // 4 pending - 2 superseded = 2 contexts (priority 5 fix, priority 2 derived)
        assert_eq!(report.contexts.len(), 2);
        assert_eq!(report.contexts[0].evolution_type, SuggestionKind::Fix);
        assert_eq!(report.contexts[1].evolution_type, SuggestionKind::Derived);

        // Re-querying pending should now exclude superseded rows.
        let remaining = store.list_all_pending_suggestions().unwrap();
        assert_eq!(remaining.len(), 2);
    }

    #[tokio::test]
    async fn dedup_disabled_skips_judge() {
        let store = setup_store();
        save_analysis_with_suggestions(
            &store,
            vec![
                sug(SuggestionKind::Fix, Some("ra"), "a", 4),
                sug(SuggestionKind::Fix, Some("ra"), "b", 3),
            ],
        );

        let report = run_batch_apply(&store, false, None, false, |_| async {
            panic!("judge must not run when dedup disabled");
            #[allow(unreachable_code)]
            Ok::<String, String>(String::new())
        })
        .await
        .unwrap();

        assert_eq!(report.total_pending, 2);
        assert_eq!(report.superseded, 0);
        assert_eq!(report.contexts.len(), 2);
        assert!(report.dedup_skipped);
    }

    #[tokio::test]
    async fn apply_max_per_run_caps_contexts() {
        let store = setup_store();
        save_analysis_with_suggestions(
            &store,
            vec![
                sug(SuggestionKind::Fix, Some("a"), "x", 5),
                sug(SuggestionKind::Fix, Some("b"), "y", 4),
                sug(SuggestionKind::Fix, Some("c"), "z", 3),
            ],
        );

        let report = run_batch_apply(&store, false, Some(2), false, |_| async {
            Ok::<String, String>(String::new())
        })
        .await
        .unwrap();

        assert_eq!(report.total_pending, 3);
        assert_eq!(report.contexts.len(), 2);
        // Capped to top 2 by priority — priority 5 and 4 survive the cap.
        assert_eq!(report.contexts[0].direction, "x");
        assert_eq!(report.contexts[1].direction, "y");
    }

    #[tokio::test]
    async fn malformed_judge_response_falls_back_to_heuristic() {
        let store = setup_store();
        save_analysis_with_suggestions(
            &store,
            vec![
                sug(SuggestionKind::Fix, Some("ra"), "x", 4),
                sug(SuggestionKind::Fix, Some("ra"), "y", 3),
                sug(SuggestionKind::Fix, Some("other"), "z", 2),
            ],
        );

        let report = run_batch_apply(&store, true, None, false, |_| async {
            Ok("not json".to_string())
        })
        .await
        .unwrap();

        assert!(!report.used_llm);
        // Heuristic dedups the two "ra" Fix suggestions: priority 4 survives, 3 superseded.
        assert_eq!(report.superseded, 1);
        assert_eq!(report.contexts.len(), 2);
    }

    #[tokio::test]
    async fn dry_run_leaves_all_rows_pending() {
        let store = setup_store();
        save_analysis_with_suggestions(
            &store,
            vec![
                sug(SuggestionKind::Fix, Some("ra"), "retry on timeout", 4),
                sug(SuggestionKind::Fix, Some("ra"), "add retry for timeout", 3),
                sug(SuggestionKind::Derived, Some("other"), "alt approach", 2),
            ],
        );

        let report = run_batch_apply(&store, true, None, true, |_p| async {
            Ok(
                r#"{"groups":[{"survivor_id":1,"loser_ids":[2],"reason":"same retry fix"}]}"#
                    .to_string(),
            )
        })
        .await
        .unwrap();

        // Report still reflects the would-be dedup outcome.
        assert_eq!(report.total_pending, 3);
        assert_eq!(report.superseded, 1);
        assert!(report.used_llm);
        assert_eq!(report.dedup_groups.len(), 1);
        // Survivors still computed: priority 4 fix + priority 2 derived.
        assert_eq!(report.contexts.len(), 2);

        // Crucially: no DB writes — all 3 rows still pending.
        let remaining = store.list_all_pending_suggestions().unwrap();
        assert_eq!(remaining.len(), 3);
    }
}
