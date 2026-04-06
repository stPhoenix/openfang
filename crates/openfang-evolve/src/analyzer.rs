//! Response parsing for execution analysis.
//!
//! The actual LLM call is made by the kernel via a spawned agent. This module
//! handles parsing the agent's JSON response into structured types.

use crate::types::*;
use tracing::warn;

/// Raw LLM response structure (before we add server-side fields).
#[derive(Debug, serde::Deserialize)]
pub struct RawAnalysisResponse {
    #[serde(default)]
    pub task_completed: bool,
    #[serde(default)]
    pub execution_note: String,
    #[serde(default)]
    pub tool_issues: Vec<ToolIssue>,
    #[serde(default)]
    pub skill_judgments: Vec<SkillJudgment>,
    #[serde(default)]
    pub evolution_suggestions: Vec<EvolutionSuggestion>,
}

/// Parse JSON from the LLM response text.
///
/// Tries multiple strategies:
/// 1. Direct JSON parse
/// 2. Extract from markdown code fences
/// 3. Find the first `{` to last `}` substring
pub fn parse_json_from_response(text: &str) -> Result<RawAnalysisResponse, EvolveError> {
    let trimmed = text.trim();

    // Strategy 1: direct parse
    if let Ok(parsed) = serde_json::from_str::<RawAnalysisResponse>(trimmed) {
        return Ok(parsed);
    }

    // Strategy 2: strip markdown code fences
    let stripped = strip_markdown_fences(trimmed);
    if let Ok(parsed) = serde_json::from_str::<RawAnalysisResponse>(&stripped) {
        return Ok(parsed);
    }

    // Strategy 3: find JSON object boundaries
    if let Some(start) = trimmed.find('{') {
        if let Some(end) = trimmed.rfind('}') {
            if end > start {
                let json_slice = &trimmed[start..=end];
                if let Ok(parsed) = serde_json::from_str::<RawAnalysisResponse>(json_slice) {
                    return Ok(parsed);
                }
            }
        }
    }

    warn!("failed to parse analysis response JSON");
    Err(EvolveError::ParseError(format!(
        "could not extract valid JSON from LLM response (length: {} chars)",
        text.len()
    )))
}

/// Strip markdown code fences (```json ... ``` or ``` ... ```).
fn strip_markdown_fences(text: &str) -> String {
    let mut s = text.trim().to_string();
    if s.starts_with("```json") {
        s = s.trim_start_matches("```json").to_string();
    } else if s.starts_with("```") {
        s = s.trim_start_matches("```").to_string();
    }
    if s.ends_with("```") {
        s = s.trim_end_matches("```").to_string();
    }
    s.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_direct_json() {
        let json = r#"{
            "task_completed": true,
            "execution_note": "All good.",
            "tool_issues": [],
            "skill_judgments": [],
            "evolution_suggestions": []
        }"#;
        let result = parse_json_from_response(json).unwrap();
        assert!(result.task_completed);
        assert_eq!(result.execution_note, "All good.");
    }

    #[test]
    fn parse_markdown_fenced_json() {
        let text = r#"```json
{
    "task_completed": false,
    "execution_note": "Failed.",
    "tool_issues": [{"tool_name": "shell", "issue_type": "failure", "description": "timed out"}],
    "skill_judgments": [],
    "evolution_suggestions": []
}
```"#;
        let result = parse_json_from_response(text).unwrap();
        assert!(!result.task_completed);
        assert_eq!(result.tool_issues.len(), 1);
    }

    #[test]
    fn parse_json_with_preamble() {
        let text = r#"Here is my analysis:

{
    "task_completed": true,
    "execution_note": "Done.",
    "tool_issues": [],
    "skill_judgments": [{"skill_name": "docker", "applied": true, "quality": "good", "note": "ok"}],
    "evolution_suggestions": []
}

That's my assessment."#;
        let result = parse_json_from_response(text).unwrap();
        assert!(result.task_completed);
        assert_eq!(result.skill_judgments.len(), 1);
    }

    #[test]
    fn parse_invalid_json_returns_error() {
        let text = "This is not JSON at all.";
        let result = parse_json_from_response(text);
        assert!(result.is_err());
    }

    #[test]
    fn parse_with_defaults() {
        let json = r#"{"task_completed": true, "execution_note": "ok"}"#;
        let result = parse_json_from_response(json).unwrap();
        assert!(result.tool_issues.is_empty());
        assert!(result.skill_judgments.is_empty());
        assert!(result.evolution_suggestions.is_empty());
    }

    #[test]
    fn strip_fences_json() {
        assert_eq!(
            strip_markdown_fences("```json\n{\"a\":1}\n```"),
            "{\"a\":1}"
        );
    }

    #[test]
    fn strip_fences_plain() {
        assert_eq!(strip_markdown_fences("```\n{\"a\":1}\n```"), "{\"a\":1}");
    }

    #[test]
    fn strip_fences_no_fences() {
        assert_eq!(strip_markdown_fences("{\"a\":1}"), "{\"a\":1}");
    }
}
