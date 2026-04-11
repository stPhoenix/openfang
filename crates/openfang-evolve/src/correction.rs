//! Skill ID fuzzy correction for hallucinated IDs in analysis output.

use crate::types::ExecutionAnalysis;

/// Maximum edit distance for fuzzy skill ID correction.
const MAX_EDIT_DISTANCE: usize = 3;

/// Compute Levenshtein edit distance between two strings.
fn edit_distance(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0; b_len + 1];

    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j] + cost)
                .min(curr[j] + 1)
                .min(prev[j + 1] + 1);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

/// Extract the name prefix from a skill ID (everything before "__").
fn name_prefix(skill_id: &str) -> &str {
    skill_id.split("__").next().unwrap_or(skill_id)
}

/// Correct a single skill ID against a set of known IDs.
///
/// If the ID is already known, returns it unchanged.
/// Otherwise, finds candidates with the same name prefix and returns
/// the unique best match within MAX_EDIT_DISTANCE, or the original if
/// no unique match is found.
pub fn correct_skill_id(raw_id: &str, known_ids: &[String]) -> String {
    if known_ids.iter().any(|k| k == raw_id) {
        return raw_id.to_string();
    }

    let prefix = name_prefix(raw_id);
    let candidates: Vec<&String> = known_ids
        .iter()
        .filter(|k| name_prefix(k) == prefix)
        .collect();

    if candidates.is_empty() {
        // No prefix match — try all known IDs by edit distance
        let mut best_dist = usize::MAX;
        let mut best_match = None;
        let mut ambiguous = false;

        for known in known_ids {
            let dist = edit_distance(raw_id, known);
            if dist < best_dist {
                best_dist = dist;
                best_match = Some(known.clone());
                ambiguous = false;
            } else if dist == best_dist {
                ambiguous = true;
            }
        }

        if !ambiguous && best_dist <= MAX_EDIT_DISTANCE {
            if let Some(m) = best_match {
                return m;
            }
        }
        return raw_id.to_string();
    }

    // Find best match among same-prefix candidates
    let mut best_dist = usize::MAX;
    let mut best_match = None;
    let mut ambiguous = false;

    for candidate in &candidates {
        let dist = edit_distance(raw_id, candidate);
        if dist < best_dist {
            best_dist = dist;
            best_match = Some((*candidate).clone());
            ambiguous = false;
        } else if dist == best_dist {
            ambiguous = true;
        }
    }

    if !ambiguous && best_dist <= MAX_EDIT_DISTANCE {
        if let Some(m) = best_match {
            return m;
        }
    }

    raw_id.to_string()
}

/// Apply skill ID correction to all skill_judgments and evolution_suggestions in an analysis.
pub fn correct_analysis_skill_ids(analysis: &mut ExecutionAnalysis, known_ids: &[String]) {
    for judgment in &mut analysis.skill_judgments {
        judgment.skill_name = correct_skill_id(&judgment.skill_name, known_ids);
    }
    for suggestion in &mut analysis.evolution_suggestions {
        if let Some(ref target) = suggestion.target_skill {
            let corrected = correct_skill_id(target, known_ids);
            suggestion.target_skill = Some(corrected);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_returns_unchanged() {
        let known = vec!["docker__imp_abcd1234".to_string()];
        assert_eq!(
            correct_skill_id("docker__imp_abcd1234", &known),
            "docker__imp_abcd1234"
        );
    }

    #[test]
    fn prefix_match_with_small_edit_distance() {
        let known = vec!["docker__imp_abcd1234".to_string()];
        // Typo in the UUID part
        assert_eq!(
            correct_skill_id("docker__imp_abcd1235", &known),
            "docker__imp_abcd1234"
        );
    }

    #[test]
    fn no_match_returns_original() {
        let known = vec!["docker__imp_abcd1234".to_string()];
        // Completely different
        assert_eq!(
            correct_skill_id("completely_different_id", &known),
            "completely_different_id"
        );
    }

    #[test]
    fn ambiguous_match_returns_original() {
        let known = vec![
            "docker__imp_abcd1234".to_string(),
            "docker__imp_abcd5678".to_string(),
        ];
        // Equidistant from both (distance 4 each, beyond threshold)
        assert_eq!(
            correct_skill_id("docker__imp_abcd0000", &known),
            "docker__imp_abcd0000"
        );
    }

    #[test]
    fn non_ambiguous_picks_closest() {
        let known = vec![
            "docker__imp_abcd1234".to_string(),
            "docker__imp_xyzw9999".to_string(),
        ];
        // distance to abcd1234 = 1 (only last char differs), distance to xyzw9999 = much larger
        assert_eq!(
            correct_skill_id("docker__imp_abcd1235", &known),
            "docker__imp_abcd1234"
        );
    }

    #[test]
    fn corrects_analysis_skill_ids() {
        use crate::types::{EvolutionSuggestion, SkillJudgment};
        let known = vec!["docker__imp_abcd1234".to_string()];
        let mut analysis = ExecutionAnalysis {
            id: crate::types::AnalysisId::new(),
            session_id: "s1".into(),
            agent_id: "a1".into(),
            task_completed: true,
            execution_note: "ok".into(),
            tool_issues: vec![],
            skill_judgments: vec![SkillJudgment {
                skill_name: "docker__imp_abcd1235".into(), // typo
                applied: true,
                quality: crate::types::SkillQuality::Good,
                note: "ok".into(),
            }],
            evolution_suggestions: vec![EvolutionSuggestion {
                kind: crate::types::SuggestionKind::Fix,
                target_skill: Some("docker__imp_abcd1235".into()), // typo
                description: "fix it".into(),
                priority: 3,
                executed_at: None,
                failed_at: None,
                failure_reason: None,
            }],
            model_used: "test".into(),
            input_tokens: 0,
            output_tokens: 0,
            analyzed_at: chrono::Utc::now(),
        };

        correct_analysis_skill_ids(&mut analysis, &known);
        assert_eq!(
            analysis.skill_judgments[0].skill_name,
            "docker__imp_abcd1234"
        );
        assert_eq!(
            analysis.evolution_suggestions[0].target_skill.as_deref(),
            Some("docker__imp_abcd1234")
        );
    }

    #[test]
    fn edit_distance_basic() {
        assert_eq!(edit_distance("", ""), 0);
        assert_eq!(edit_distance("abc", "abc"), 0);
        assert_eq!(edit_distance("abc", "abd"), 1);
        assert_eq!(edit_distance("abc", ""), 3);
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }

    #[test]
    fn empty_known_returns_original() {
        assert_eq!(correct_skill_id("anything", &[]), "anything");
    }
}
