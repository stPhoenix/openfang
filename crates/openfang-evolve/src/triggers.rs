//! Evolution triggers and anti-loop mechanisms.
//!
//! Two independent triggers feed into the SkillEvolver pipeline:
//! 1. Post-Analysis (synchronous) — after analysis produces suggestions
//! 2. Metric Monitor (background) — periodic skill health checks

use crate::store::EvolveStore;
use crate::types::*;
use tracing::debug;

// ---------------------------------------------------------------------------
// Metric Monitor Thresholds (intentionally relaxed — LLM filters false positives)
// ---------------------------------------------------------------------------

/// Fallback rate above this triggers FIX candidate.
pub const FALLBACK_THRESHOLD: f64 = 0.4;

/// Completion rate below this (with high applied) triggers FIX candidate.
pub const LOW_COMPLETION_THRESHOLD: f64 = 0.35;

/// Applied rate above this (with low completion) triggers FIX.
pub const HIGH_APPLIED_FOR_FIX: f64 = 0.4;

/// Effective rate below this triggers DERIVED candidate.
pub const MODERATE_EFFECTIVE_THRESHOLD: f64 = 0.55;

/// Minimum applied rate to consider for DERIVED.
pub const MIN_APPLIED_FOR_DERIVED: f64 = 0.25;

/// Minimum total_selections before a skill is eligible for metric checks.
pub const MIN_SELECTIONS: u64 = 5;

// ---------------------------------------------------------------------------
// Trigger 1: Post-Analysis (Synchronous)
// ---------------------------------------------------------------------------

/// Build evolution contexts from analysis suggestions.
///
/// Called immediately after analysis produces suggestions.
pub fn build_contexts_from_analysis(
    analysis: &ExecutionAnalysis,
    store: &EvolveStore,
) -> Vec<EvolutionContext> {
    let mut contexts = Vec::new();

    for suggestion in &analysis.evolution_suggestions {
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
                "Post-analysis trigger from session {}. Task completed: {}. Note: {}",
                analysis.session_id, analysis.task_completed, analysis.execution_note
            ),
            source_analysis: Some(analysis.id),
        });
    }

    contexts
}

// ---------------------------------------------------------------------------
// Trigger 2: Metric Monitor (Background)
// ---------------------------------------------------------------------------

/// Diagnose a skill's health based on cumulative metrics.
///
/// Returns `(proposed_type, proposed_direction)` or `None` if healthy.
pub fn diagnose_skill_health(record: &SkillRecord) -> Option<(SuggestionKind, String)> {
    if record.total_selections < MIN_SELECTIONS {
        return None;
    }

    let fallback_rate = record.fallback_rate();
    let applied_rate = record.applied_rate();
    let completion_rate = record.completion_rate();
    let effective_rate = record.effective_rate();

    // High fallback rate → FIX (selected but not used → unclear/outdated instructions)
    if fallback_rate > FALLBACK_THRESHOLD {
        return Some((
            SuggestionKind::Fix,
            format!(
                "High fallback rate ({:.0}%): skill is selected but not applied by agents. \
                 Instructions may be unclear, outdated, or not applicable.",
                fallback_rate * 100.0
            ),
        ));
    }

    // High applied + low completion → FIX (used but tasks fail → incorrect instructions)
    if applied_rate > HIGH_APPLIED_FOR_FIX && completion_rate < LOW_COMPLETION_THRESHOLD {
        return Some((
            SuggestionKind::Fix,
            format!(
                "Applied often ({:.0}%) but low completion ({:.0}%): \
                 skill instructions may be incorrect or incomplete.",
                applied_rate * 100.0,
                completion_rate * 100.0
            ),
        ));
    }

    // Moderate effectiveness → DERIVED (works sometimes → could be enhanced)
    if effective_rate < MODERATE_EFFECTIVE_THRESHOLD && applied_rate > MIN_APPLIED_FOR_DERIVED {
        return Some((
            SuggestionKind::Derived,
            format!(
                "Moderate effectiveness ({:.0}%): skill works sometimes but could be enhanced \
                 for better results.",
                effective_rate * 100.0
            ),
        ));
    }

    None
}

/// Check all active skills for metric-based evolution candidates.
pub fn check_metric_triggers(store: &EvolveStore) -> Vec<EvolutionContext> {
    let active_skills = match store.list_skill_records(true) {
        Ok(skills) => skills,
        Err(_) => return vec![],
    };

    let mut contexts = Vec::new();

    for skill in active_skills {
        if let Some((kind, direction)) = diagnose_skill_health(&skill) {
            debug!(
                skill_id = %skill.skill_id,
                kind = %kind,
                "metric trigger candidate"
            );

            contexts.push(EvolutionContext {
                evolution_type: kind,
                target_skills: vec![skill.clone()],
                direction,
                category: None,
                trigger_context: format!(
                    "Metric monitor: selections={}, applied={}, completions={}, fallbacks={}",
                    skill.total_selections,
                    skill.total_applied,
                    skill.total_completions,
                    skill.total_fallbacks
                ),
                source_analysis: None,
            });
        }
    }

    contexts
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn make_skill(
        id: &str,
        selections: u64,
        applied: u64,
        completions: u64,
        fallbacks: u64,
    ) -> SkillRecord {
        SkillRecord {
            skill_id: id.into(),
            name: id.split("__").next().unwrap_or(id).into(),
            description: "test".into(),
            path: format!("/tmp/{id}"),
            is_active: true,
            category: SkillCategory::Reference,
            tags: vec![],
            visibility: SkillVisibility::Private,
            creator_id: "system".into(),
            lineage: SkillLineage {
                origin: SkillOrigin::Imported,
                generation: 0,
                parent_skill_ids: vec![],
                source_task_id: None,
                change_summary: String::new(),
                content_diff: String::new(),
                content_snapshot: HashMap::new(),
                created_at: Utc::now(),
                created_by: "human".into(),
            },
            tool_dependencies: vec!["web_search".into()],
            critical_tools: vec![],
            total_selections: selections,
            total_applied: applied,
            total_completions: completions,
            total_fallbacks: fallbacks,
            first_seen: Utc::now(),
            last_updated: Utc::now(),
        }
    }

    #[test]
    fn diagnose_healthy_skill() {
        // 10 selections, 8 applied, 7 completed, 1 fallback
        let skill = make_skill("healthy__imp_1234", 10, 8, 7, 1);
        assert!(diagnose_skill_health(&skill).is_none());
    }

    #[test]
    fn diagnose_insufficient_data() {
        // Only 3 selections — below MIN_SELECTIONS
        let skill = make_skill("new__imp_1234", 3, 2, 1, 0);
        assert!(diagnose_skill_health(&skill).is_none());
    }

    #[test]
    fn diagnose_high_fallback() {
        // 10 selections, 2 applied, 1 completed, 6 fallbacks → fallback_rate = 60%
        let skill = make_skill("bad__imp_1234", 10, 2, 1, 6);
        let (kind, direction) = diagnose_skill_health(&skill).unwrap();
        assert_eq!(kind, SuggestionKind::Fix);
        assert!(direction.contains("fallback"));
    }

    #[test]
    fn diagnose_high_applied_low_completion() {
        // 10 selections, 8 applied, 2 completed, 0 fallbacks
        let skill = make_skill("broken__imp_1234", 10, 8, 2, 0);
        let (kind, direction) = diagnose_skill_health(&skill).unwrap();
        assert_eq!(kind, SuggestionKind::Fix);
        assert!(direction.contains("completion"));
    }

    #[test]
    fn diagnose_moderate_effectiveness() {
        // 10 selections, 6 applied, 4 completed, 2 fallbacks → effective = 40%
        let skill = make_skill("mediocre__imp_1234", 10, 6, 4, 2);
        let (kind, _) = diagnose_skill_health(&skill).unwrap();
        assert_eq!(kind, SuggestionKind::Derived);
    }

    #[test]
    fn build_contexts_empty_suggestions() {
        let analysis = ExecutionAnalysis {
            id: AnalysisId::new(),
            session_id: "s1".into(),
            agent_id: "a1".into(),
            task_completed: true,
            execution_note: "ok".into(),
            tool_issues: vec![],
            skill_judgments: vec![],
            evolution_suggestions: vec![],
            model_used: "test".into(),
            input_tokens: 0,
            output_tokens: 0,
            analyzed_at: Utc::now(),
        };

        let store = crate::store::EvolveStore::new(
            std::sync::Arc::new(std::sync::Mutex::new(
                rusqlite::Connection::open_in_memory().unwrap(),
            )),
        );
        let contexts = build_contexts_from_analysis(&analysis, &store);
        assert!(contexts.is_empty());
    }

    #[test]
    fn build_contexts_from_suggestions() {
        let analysis = ExecutionAnalysis {
            id: AnalysisId::new(),
            session_id: "s1".into(),
            agent_id: "a1".into(),
            task_completed: false,
            execution_note: "failed".into(),
            tool_issues: vec![],
            skill_judgments: vec![],
            evolution_suggestions: vec![
                EvolutionSuggestion {
                    kind: SuggestionKind::Fix,
                    target_skill: Some("docker".into()),
                    description: "Fix port mapping".into(),
                    priority: 4,
                    executed_at: None,
                    failed_at: None,
                    failure_reason: None,
                },
                EvolutionSuggestion {
                    kind: SuggestionKind::Captured,
                    target_skill: None,
                    description: "Capture debugging pattern".into(),
                    priority: 2,
                    executed_at: None,
                    failed_at: None,
                    failure_reason: None,
                },
            ],
            model_used: "test".into(),
            input_tokens: 0,
            output_tokens: 0,
            analyzed_at: Utc::now(),
        };

        let store = crate::store::EvolveStore::new(
            std::sync::Arc::new(std::sync::Mutex::new(
                rusqlite::Connection::open_in_memory().unwrap(),
            )),
        );
        let contexts = build_contexts_from_analysis(&analysis, &store);
        assert_eq!(contexts.len(), 2);
        assert_eq!(contexts[0].evolution_type, SuggestionKind::Fix);
        assert_eq!(contexts[1].evolution_type, SuggestionKind::Captured);
    }
}
