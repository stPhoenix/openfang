//! LLM confirmation gate for rule-based evolution triggers.

use crate::types::EvolveError;
use serde::Deserialize;

/// Parsed confirmation response from the LLM.
#[derive(Debug, Clone)]
pub struct ConfirmationResponse {
    /// Whether to proceed with evolution.
    pub proceed: bool,
    /// LLM's reasoning for the decision.
    pub reasoning: String,
    /// Refined direction if the original should be tweaked.
    pub adjusted_direction: Option<String>,
}

#[derive(Deserialize)]
struct RawConfirmation {
    #[serde(default)]
    proceed: bool,
    #[serde(default)]
    reasoning: String,
    adjusted_direction: Option<String>,
}

/// Parse a confirmation response from the LLM.
///
/// Uses the same 3-strategy fallback as the analyzer parser.
pub fn parse_confirmation(response: &str) -> Result<ConfirmationResponse, EvolveError> {
    let raw: RawConfirmation = parse_json(response)?;
    Ok(ConfirmationResponse {
        proceed: raw.proceed,
        reasoning: raw.reasoning,
        adjusted_direction: raw.adjusted_direction,
    })
}

fn parse_json(text: &str) -> Result<RawConfirmation, EvolveError> {
    // Strategy 1: direct parse
    if let Ok(r) = serde_json::from_str::<RawConfirmation>(text) {
        return Ok(r);
    }

    // Strategy 2: strip markdown fences
    let stripped = strip_fences(text);
    if let Ok(r) = serde_json::from_str::<RawConfirmation>(&stripped) {
        return Ok(r);
    }

    // Strategy 3: find { to }
    if let (Some(start), Some(end)) = (text.find('{'), text.rfind('}')) {
        if start < end {
            if let Ok(r) = serde_json::from_str::<RawConfirmation>(&text[start..=end]) {
                return Ok(r);
            }
        }
    }

    Err(EvolveError::ParseError(
        "failed to parse confirmation response as JSON".into(),
    ))
}

fn strip_fences(text: &str) -> String {
    let mut result = text.to_string();
    // Remove ```json ... ``` or ``` ... ```
    if let Some(start) = result.find("```json") {
        result = result[start + 7..].to_string();
    } else if let Some(start) = result.find("```") {
        result = result[start + 3..].to_string();
    }
    if let Some(end) = result.rfind("```") {
        result = result[..end].to_string();
    }
    result.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_direct_json() {
        let response = r#"{"proceed": true, "reasoning": "The skill is outdated."}"#;
        let result = parse_confirmation(response).unwrap();
        assert!(result.proceed);
        assert_eq!(result.reasoning, "The skill is outdated.");
        assert!(result.adjusted_direction.is_none());
    }

    #[test]
    fn parse_with_adjusted_direction() {
        let response = r#"{"proceed": true, "reasoning": "Valid concern.", "adjusted_direction": "Focus on error handling."}"#;
        let result = parse_confirmation(response).unwrap();
        assert!(result.proceed);
        assert_eq!(
            result.adjusted_direction.as_deref(),
            Some("Focus on error handling.")
        );
    }

    #[test]
    fn parse_fenced_json() {
        let response = "Some preamble\n```json\n{\"proceed\": false, \"reasoning\": \"Not needed.\"}\n```\nDone.";
        let result = parse_confirmation(response).unwrap();
        assert!(!result.proceed);
    }

    #[test]
    fn parse_embedded_json() {
        let response = "I think {\"proceed\": true, \"reasoning\": \"Yes.\"} is my answer.";
        let result = parse_confirmation(response).unwrap();
        assert!(result.proceed);
    }

    #[test]
    fn parse_failure() {
        let response = "This is not JSON at all.";
        let result = parse_confirmation(response);
        assert!(result.is_err());
    }

    #[test]
    fn defaults_to_false() {
        let response = r#"{}"#;
        let result = parse_confirmation(response).unwrap();
        assert!(!result.proceed);
        assert_eq!(result.reasoning, "");
    }
}
