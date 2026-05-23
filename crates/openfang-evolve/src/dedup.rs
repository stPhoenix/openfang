//! Dedup pending evolution suggestions before batch apply.
//!
//! Operates on already-corrected suggestions (skill ids run through
//! `correction::correct_skill_id` at analysis time). Groups suggestions that
//! propose the same/overlapping change and picks the highest-priority as
//! survivor.
//!
//! Two-tier strategy:
//! 1. LLM-as-judge (primary). Reuses the analyzer/evolver provider.
//! 2. Heuristic fallback (target_skill + kind exact match) when the LLM
//!    response cannot be parsed.

use crate::types::{EvolutionSuggestion, SuggestionKind};
use serde::Deserialize;
use std::collections::HashMap;
use std::future::Future;
use tracing::warn;

/// One dedup grouping decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupGroup {
    /// Row id of the suggestion that survives.
    pub survivor_id: i64,
    /// Row ids of duplicate suggestions that should be marked superseded.
    pub loser_ids: Vec<i64>,
    /// Short reason recorded with each loser.
    pub reason: String,
}

/// Result of running dedup over a candidate list.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DedupResult {
    /// Grouping decisions (singletons are omitted).
    pub groups: Vec<DedupGroup>,
    /// Whether the LLM judge produced a usable response.
    /// `false` means the heuristic fallback ran.
    pub used_llm: bool,
}

/// JSON shape we expect back from the judge.
#[derive(Debug, Deserialize)]
struct RawJudgeResponse {
    #[serde(default)]
    groups: Vec<RawGroup>,
}

#[derive(Debug, Deserialize)]
struct RawGroup {
    survivor_id: i64,
    #[serde(default)]
    loser_ids: Vec<i64>,
    #[serde(default)]
    reason: Option<String>,
}

/// Build the judge prompt for a candidate list.
///
/// The candidate slice MUST be in stable order — the LLM picks survivors by
/// the explicit `id=` field in the prompt, so caller-provided ordering does
/// not affect correctness.
pub fn build_judge_prompt(candidates: &[(i64, EvolutionSuggestion)]) -> String {
    let mut lines = Vec::with_capacity(candidates.len() + 12);
    lines.push(
        "You are deduplicating evolution suggestions. Each suggestion targets a skill \
and proposes a change. Group suggestions that propose the SAME or SUBSTANTIALLY \
OVERLAPPING change. Within each group, pick the highest-priority as survivor, others as losers.\n\
Be conservative — only group if the action is the same. Singletons should be omitted.\n\n\
Output STRICT JSON with this shape (no markdown, no commentary):\n\
{\"groups\": [{\"survivor_id\": <int>, \"loser_ids\": [<int>, ...], \"reason\": \"<short>\"}, ...]}\n\n\
Suggestions:"
            .to_string(),
    );
    for (id, s) in candidates {
        let target = s.target_skill.as_deref().unwrap_or("(none)");
        lines.push(format!(
            "- id={id} kind={kind} target={target} priority={prio} desc={desc}",
            kind = s.kind,
            prio = s.priority,
            desc = s.description.replace('\n', " "),
        ));
    }
    lines.join("\n")
}

/// Parse the judge's raw text into structured groups. Mirrors the fence/substring
/// fallback ladder used by `analyzer::parse_json_from_response`.
fn parse_judge_response(text: &str) -> Option<RawJudgeResponse> {
    let trimmed = text.trim();
    if let Ok(p) = serde_json::from_str::<RawJudgeResponse>(trimmed) {
        return Some(p);
    }
    let stripped = strip_fences(trimmed);
    if let Ok(p) = serde_json::from_str::<RawJudgeResponse>(&stripped) {
        return Some(p);
    }
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if end > start {
            if let Ok(p) = serde_json::from_str::<RawJudgeResponse>(&trimmed[start..=end]) {
                return Some(p);
            }
        }
    }
    None
}

fn strip_fences(s: &str) -> String {
    let mut t = s.trim().to_string();
    if t.starts_with("```json") {
        t = t.trim_start_matches("```json").to_string();
    } else if t.starts_with("```") {
        t = t.trim_start_matches("```").to_string();
    }
    if t.ends_with("```") {
        t = t.trim_end_matches("```").to_string();
    }
    t.trim().to_string()
}

/// Validate raw groups against the candidate id set. Drops references to ids
/// the judge hallucinated and drops groups left with no losers.
fn validate_groups(
    raw: RawJudgeResponse,
    valid_ids: &std::collections::HashSet<i64>,
) -> Vec<DedupGroup> {
    raw.groups
        .into_iter()
        .filter_map(|g| {
            if !valid_ids.contains(&g.survivor_id) {
                return None;
            }
            let losers: Vec<i64> = g
                .loser_ids
                .into_iter()
                .filter(|id| *id != g.survivor_id && valid_ids.contains(id))
                .collect();
            if losers.is_empty() {
                return None;
            }
            Some(DedupGroup {
                survivor_id: g.survivor_id,
                loser_ids: losers,
                reason: g
                    .reason
                    .unwrap_or_else(|| "llm judge grouped".to_string()),
            })
        })
        .collect()
}

/// Heuristic fallback dedup. Groups by `(kind, target_skill)` exact match.
/// Within a group, survivor = max priority (ties broken by first occurrence).
pub fn heuristic_dedup(candidates: &[(i64, EvolutionSuggestion)]) -> Vec<DedupGroup> {
    type BucketKey = (SuggestionKind, Option<String>);
    type Entry = (i64, u8);
    let mut buckets: HashMap<BucketKey, Vec<Entry>> = HashMap::new();
    for (id, s) in candidates {
        // CAPTURED has no target_skill; skip — can't reliably dedup by heuristic.
        if matches!(s.kind, SuggestionKind::Captured) {
            continue;
        }
        let key = (s.kind.clone(), s.target_skill.clone());
        buckets.entry(key).or_default().push((*id, s.priority));
    }
    let mut groups = Vec::new();
    for ((kind, target), mut entries) in buckets {
        if entries.len() < 2 {
            continue;
        }
        // Stable sort: priority desc, then id asc.
        entries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let survivor_id = entries[0].0;
        let loser_ids: Vec<i64> = entries[1..].iter().map(|(id, _)| *id).collect();
        groups.push(DedupGroup {
            survivor_id,
            loser_ids,
            reason: format!(
                "heuristic: same kind={kind} target={target}",
                target = target.as_deref().unwrap_or("(none)")
            ),
        });
    }
    groups
}

/// Run dedup over a candidate list using the supplied async judge fn.
///
/// `judge_fn` is invoked with the constructed prompt and must return the raw
/// LLM text. On any error or parse failure, the heuristic fallback runs.
///
/// Skips the LLM call entirely when fewer than 2 candidates are supplied.
pub async fn dedup_pending<F, Fut>(
    candidates: Vec<(i64, EvolutionSuggestion)>,
    judge_fn: F,
) -> DedupResult
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<String, String>>,
{
    if candidates.len() < 2 {
        return DedupResult::default();
    }
    let prompt = build_judge_prompt(&candidates);
    let valid_ids: std::collections::HashSet<i64> =
        candidates.iter().map(|(id, _)| *id).collect();

    match judge_fn(prompt).await {
        Ok(text) => {
            if let Some(raw) = parse_judge_response(&text) {
                let mut groups = validate_groups(raw, &valid_ids);
                // Additive safety: judge may parse but return an empty
                // groups list (LLM said "all distinct"). Run the heuristic
                // as a second pass so obvious (kind, target_skill) ties
                // still get deduped — keeps batch-apply idempotent across
                // runs even when the judge is conservative.
                if groups.is_empty() {
                    groups = heuristic_dedup(&candidates);
                }
                return DedupResult {
                    groups,
                    used_llm: true,
                };
            }
            warn!("dedup judge response not parseable, falling back to heuristic");
        }
        Err(e) => {
            warn!("dedup judge call failed: {e} — falling back to heuristic");
        }
    }
    DedupResult {
        groups: heuristic_dedup(&candidates),
        used_llm: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SuggestionStatus;

    fn s(kind: SuggestionKind, target: Option<&str>, desc: &str, priority: u8) -> EvolutionSuggestion {
        EvolutionSuggestion {
            kind,
            target_skill: target.map(String::from),
            description: desc.to_string(),
            priority,
            executed_at: None,
            failed_at: None,
            failure_reason: None,
            status: SuggestionStatus::Pending,
            supersedes_id: None,
            dedup_reason: None,
        }
    }

    #[tokio::test]
    async fn skips_when_below_two_candidates() {
        let res = dedup_pending(vec![(1, s(SuggestionKind::Fix, Some("a"), "x", 3))], |_| async {
            panic!("judge_fn must not be called for <2 candidates");
            #[allow(unreachable_code)]
            Ok::<String, String>(String::new())
        })
        .await;
        assert!(res.groups.is_empty());
        assert!(!res.used_llm);
    }

    #[tokio::test]
    async fn llm_judge_happy_path() {
        let candidates = vec![
            (10, s(SuggestionKind::Fix, Some("ra"), "retry on timeout", 4)),
            (20, s(SuggestionKind::Fix, Some("ra"), "add retry for timeout", 3)),
            (30, s(SuggestionKind::Derived, Some("ra"), "new variant", 2)),
        ];
        let res = dedup_pending(candidates, |_p| async {
            Ok(
                r#"{"groups":[{"survivor_id":10,"loser_ids":[20],"reason":"same retry fix"}]}"#
                    .to_string(),
            )
        })
        .await;
        assert!(res.used_llm);
        assert_eq!(res.groups.len(), 1);
        assert_eq!(res.groups[0].survivor_id, 10);
        assert_eq!(res.groups[0].loser_ids, vec![20]);
    }

    #[tokio::test]
    async fn heuristic_runs_when_llm_returns_empty_groups() {
        // Regression for Bug A: judge says "all distinct" but two candidates
        // share (kind, target_skill). The heuristic must still group them so
        // batch-apply doesn't re-emit both rows on the next run.
        let candidates = vec![
            (10, s(SuggestionKind::Fix, Some("ra"), "x", 4)),
            (20, s(SuggestionKind::Fix, Some("ra"), "y", 3)),
        ];
        let res = dedup_pending(candidates, |_| async {
            Ok(r#"{"groups":[]}"#.to_string())
        })
            .await;
        assert!(res.used_llm, "judge parsed successfully");
        assert_eq!(res.groups.len(), 1, "heuristic must run on empty LLM groups");
        assert_eq!(res.groups[0].survivor_id, 10);
        assert_eq!(res.groups[0].loser_ids, vec![20]);
    }

    #[tokio::test]
    async fn heuristic_fallback_on_malformed_json() {
        let candidates = vec![
            (10, s(SuggestionKind::Fix, Some("ra"), "x", 4)),
            (20, s(SuggestionKind::Fix, Some("ra"), "y", 3)),
            (30, s(SuggestionKind::Fix, Some("other"), "z", 5)),
        ];
        let res = dedup_pending(candidates, |_| async {
            Ok("garbage not json".to_string())
        })
        .await;
        assert!(!res.used_llm);
        assert_eq!(res.groups.len(), 1);
        assert_eq!(res.groups[0].survivor_id, 10);
        assert_eq!(res.groups[0].loser_ids, vec![20]);
    }

    #[tokio::test]
    async fn heuristic_fallback_on_judge_error() {
        let candidates = vec![
            (1, s(SuggestionKind::Fix, Some("k"), "a", 1)),
            (2, s(SuggestionKind::Fix, Some("k"), "b", 5)),
        ];
        let res = dedup_pending(candidates, |_| async {
            Err::<String, String>("provider 500".to_string())
        })
        .await;
        assert!(!res.used_llm);
        assert_eq!(res.groups.len(), 1);
        assert_eq!(res.groups[0].survivor_id, 2);
        assert_eq!(res.groups[0].loser_ids, vec![1]);
    }

    #[test]
    fn validate_drops_hallucinated_ids() {
        let raw = RawJudgeResponse {
            groups: vec![
                RawGroup {
                    survivor_id: 999, // not in valid set
                    loser_ids: vec![10],
                    reason: None,
                },
                RawGroup {
                    survivor_id: 10,
                    loser_ids: vec![20, 999], // 999 is hallucinated
                    reason: Some("same".into()),
                },
                RawGroup {
                    survivor_id: 10,
                    loser_ids: vec![10], // self-reference
                    reason: None,
                },
            ],
        };
        let valid: std::collections::HashSet<i64> = [10i64, 20].into_iter().collect();
        let groups = validate_groups(raw, &valid);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].survivor_id, 10);
        assert_eq!(groups[0].loser_ids, vec![20]);
    }

    #[test]
    fn heuristic_skips_captured() {
        let candidates = vec![
            (1, s(SuggestionKind::Captured, None, "x", 3)),
            (2, s(SuggestionKind::Captured, None, "y", 3)),
        ];
        let groups = heuristic_dedup(&candidates);
        assert!(groups.is_empty(), "CAPTURED suggestions must not be grouped heuristically");
    }

    #[test]
    fn parse_fenced_json() {
        let text = "```json\n{\"groups\":[{\"survivor_id\":1,\"loser_ids\":[2]}]}\n```";
        let raw = parse_judge_response(text).expect("should parse fenced");
        assert_eq!(raw.groups.len(), 1);
    }
}
