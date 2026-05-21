//! Evolution agent loop with sentinel detection and apply-retry cycle.

use crate::patch::{self, PatchResult};
use crate::prompt;
use crate::types::*;
use openfang_types::config::EvolveConfig;
use std::path::Path;
use tracing::{debug, info, warn};

/// Default tool-calling rounds when no `EvolveConfig` is supplied (test fallback).
pub const MAX_EVOLUTION_ITERATIONS: usize = 5;

/// Default apply-retry attempts when no `EvolveConfig` is supplied (test fallback).
pub const MAX_EVOLUTION_ATTEMPTS: usize = 3;

/// Sentinel indicating successful evolution.
pub const EVOLUTION_COMPLETE: &str = "<EVOLUTION_COMPLETE>";

/// Sentinel indicating failed evolution.
pub const EVOLUTION_FAILED: &str = "<EVOLUTION_FAILED>";

/// Parsed output from the evolver agent.
#[derive(Debug, Clone)]
pub struct EvolverOutput {
    /// One-sentence description of the change.
    pub change_summary: String,
    /// Raw patch/full content from the LLM.
    pub raw_content: String,
}

/// Parse the evolver's response for sentinels and content.
///
/// - `Ok(output)` if `EVOLUTION_COMPLETE` found
/// - `Err(Some(reason))` if `EVOLUTION_FAILED` found
/// - `Err(None)` if neither sentinel found (needs nudge)
pub fn parse_evolver_response(response: &str) -> Result<EvolverOutput, Option<String>> {
    // EVOLUTION_FAILED takes priority
    if let Some(fail_pos) = response.find(EVOLUTION_FAILED) {
        let reason = response[fail_pos + EVOLUTION_FAILED.len()..]
            .trim()
            .chars()
            .take(500)
            .collect::<String>();
        return Err(Some(reason));
    }

    if let Some(complete_pos) = response.find(EVOLUTION_COMPLETE) {
        let before = &response[..complete_pos];

        // Extract CHANGE_SUMMARY
        let change_summary = if let Some(summary_pos) = before.find("CHANGE_SUMMARY:") {
            let after_marker = &before[summary_pos + "CHANGE_SUMMARY:".len()..];
            after_marker
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string()
        } else {
            String::new()
        };

        // Extract content (everything between CHANGE_SUMMARY line and sentinel)
        let raw_content = if let Some(summary_pos) = before.find("CHANGE_SUMMARY:") {
            let after_summary = &before[summary_pos..];
            let content_start = after_summary
                .find('\n')
                .map(|p| summary_pos + p + 1)
                .unwrap_or(summary_pos);
            before[content_start..].trim().to_string()
        } else {
            before.trim().to_string()
        };

        let raw_content = strip_markdown_fences(&raw_content);

        return Ok(EvolverOutput {
            change_summary,
            raw_content,
        });
    }

    Err(None)
}

/// Run the evolution agent loop via the send_message callback.
///
/// Sends the initial evolution prompt, then iterates checking for sentinels.
/// On the final iteration, appends a nudge to force a decision.
/// `cfg` provides `max_iterations`.
pub async fn run_evolution<F, Fut>(
    context: &EvolutionContext,
    cfg: &EvolveConfig,
    mut send_message: F,
) -> Result<EvolverOutput, EvolveError>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<(String, u64, u64), String>>,
{
    // Build the initial prompt based on evolution type
    let initial_prompt = build_evolution_prompt(context);

    // Accumulate content from responses that lack sentinels.
    // LLMs often produce the content in one message and the sentinel in the next.
    let mut accumulated_content = String::new();

    let max_iter = cfg.max_iterations.max(1);
    for iteration in 0..max_iter {
        let is_final = iteration == max_iter - 1;

        let prompt = if iteration == 0 {
            initial_prompt.clone()
        } else if is_final {
            "No more iterations available. You must output your decision now. Output your skill changes followed by <EVOLUTION_COMPLETE>, or output <EVOLUTION_FAILED> with a reason.".to_string()
        } else {
            "Please continue. When you are done, end with <EVOLUTION_COMPLETE> or <EVOLUTION_FAILED>.".to_string()
        };

        debug!(iteration, is_final, "evolution iteration");

        let (response, _input_tokens, _output_tokens) =
            send_message(prompt).await.map_err(EvolveError::LlmError)?;

        // Try parsing the current response alone first.
        match parse_evolver_response(&response) {
            Ok(output) => {
                // If the sentinel arrived but content is empty/missing file markers,
                // check if accumulated content from previous iterations has it.
                let output = if output.raw_content.is_empty()
                    || (!output.raw_content.contains("*** Begin Files")
                        && !output.raw_content.contains("<<<<<<< SEARCH")
                        && !output.raw_content.contains("*** Begin Patch")
                        && !output.raw_content.contains("---\nname:"))
                {
                    if let Ok(from_accumulated) =
                        parse_evolver_response(&format!("{accumulated_content}\n{response}"))
                    {
                        debug!("using accumulated content from previous iterations");
                        from_accumulated
                    } else {
                        output
                    }
                } else {
                    output
                };

                info!(
                    summary = %output.change_summary,
                    "evolution complete"
                );
                return Ok(output);
            }
            Err(Some(reason)) => {
                info!(reason = %reason, "evolution failed by LLM decision");
                return Err(EvolveError::Other(format!(
                    "evolution failed: {reason}"
                )));
            }
            Err(None) => {
                // No sentinel — accumulate content for later.
                accumulated_content.push_str(&response);
                accumulated_content.push('\n');
                if is_final {
                    warn!("evolution exhausted iterations without sentinel");
                    return Err(EvolveError::Other(
                        "evolution exhausted iterations without producing a result".into(),
                    ));
                }
                debug!("no sentinel found, accumulating and continuing...");
            }
        }
    }

    Err(EvolveError::Other(
        "evolution loop ended unexpectedly".into(),
    ))
}

/// Apply evolution output to disk with retry on failure.
///
/// Attempts to apply the patch, validates the result, and retries with
/// LLM feedback if it fails (up to `cfg.max_attempts`).
pub async fn apply_with_retry<F, Fut>(
    context: &EvolutionContext,
    cfg: &EvolveConfig,
    initial_content: &str,
    skill_dir: &Path,
    mut send_message: F,
) -> Result<PatchResult, EvolveError>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<(String, u64, u64), String>>,
{
    let mut current_content = initial_content.to_string();
    let max_attempts = cfg.max_attempts.max(1);

    for attempt in 1..=max_attempts {
        debug!(attempt, "applying evolution output");

        let apply_result = match context.evolution_type {
            SuggestionKind::Fix => {
                patch::fix_skill(skill_dir, &current_content)
            }
            SuggestionKind::Derived => {
                let parent_dirs: Vec<&Path> = context
                    .target_skills
                    .iter()
                    .map(|s| Path::new(&s.path))
                    .collect();
                patch::derive_skill(&parent_dirs, skill_dir, &current_content)
            }
            SuggestionKind::Captured => {
                patch::create_skill(skill_dir, &current_content)
            }
        };

        match apply_result {
            Ok(result) => {
                // Validate the skill directory
                if let Some(validation_error) = patch::validate_skill_dir(skill_dir) {
                    if attempt == max_attempts {
                        cleanup_on_failure(skill_dir, context);
                        return Err(EvolveError::Other(format!(
                            "validation failed after {max_attempts} attempts: {validation_error}"
                        )));
                    }

                    warn!(attempt, error = %validation_error, "validation failed, retrying");
                    let current_on_disk = read_skill_content(skill_dir);
                    let retry = prompt::retry_prompt(&validation_error, &current_on_disk);
                    let (response, _, _) =
                        send_message(retry).await.map_err(EvolveError::LlmError)?;
                    current_content = strip_sentinels(&response);
                    continue;
                }

                info!(attempt, "evolution applied successfully");
                return Ok(result);
            }
            Err(error) => {
                if attempt == max_attempts {
                    cleanup_on_failure(skill_dir, context);
                    return Err(EvolveError::Other(format!(
                        "apply failed after {max_attempts} attempts: {error}"
                    )));
                }

                warn!(attempt, error = %error, "apply failed, retrying");

                // Clean up failed target dir for derive/create before retry
                if matches!(
                    context.evolution_type,
                    SuggestionKind::Derived | SuggestionKind::Captured
                ) && skill_dir.exists()
                {
                    let _ = std::fs::remove_dir_all(skill_dir);
                }

                let current_on_disk = read_skill_content(skill_dir);
                let retry = prompt::retry_prompt(&error, &current_on_disk);
                let (response, _, _) =
                    send_message(retry).await.map_err(EvolveError::LlmError)?;
                current_content = strip_sentinels(&response);
            }
        }
    }

    Err(EvolveError::Other("apply-retry loop ended unexpectedly".into()))
}

/// Execute a full evolution: run the agent loop, then apply with retry.
pub async fn evolve<F, Fut>(
    context: &EvolutionContext,
    cfg: &EvolveConfig,
    skill_dir: &Path,
    mut send_message: F,
) -> Result<EvolutionResult, EvolveError>
where
    F: FnMut(String) -> Fut,
    Fut: std::future::Future<Output = Result<(String, u64, u64), String>>,
{
    // Phase 1: Run the evolution agent loop to get the changes
    let output = run_evolution(context, cfg, &mut send_message).await?;

    // Phase 2: Apply the changes with retry
    let patch_result = apply_with_retry(
        context,
        cfg,
        &output.raw_content,
        skill_dir,
        &mut send_message,
    )
        .await?;

    // Generate the skill ID for the result
    let evolved_skill_id = generate_skill_id(context);

    // If change_summary is empty, try to extract description from SKILL.md frontmatter.
    let change_summary = if output.change_summary.is_empty() {
        patch_result
            .content_snapshot
            .get("SKILL.md")
            .and_then(|content| {
                content
                    .strip_prefix("---\n")
                    .and_then(|after| after.split_once("\n---"))
                    .and_then(|(fm, _)| {
                        fm.lines().find_map(|line| {
                            line.strip_prefix("description:")
                                .map(|v| v.trim().trim_matches('"').to_string())
                        })
                    })
            })
            .unwrap_or_default()
    } else {
        output.change_summary
    };

    Ok(EvolutionResult {
        evolved_skill_id,
        change_summary,
        content_diff: patch_result.content_diff,
        content_snapshot: patch_result.content_snapshot,
        success: true,
        failure_reason: None,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn build_evolution_prompt(context: &EvolutionContext) -> String {
    match context.evolution_type {
        SuggestionKind::Fix => {
            let content = context
                .target_skills
                .first()
                .map(|s| read_skill_content(Path::new(&s.path)))
                .unwrap_or_default();
            prompt::fix_prompt(&content, &context.direction, &context.trigger_context)
        }
        SuggestionKind::Derived => {
            let parents: Vec<(&str, String)> = context
                .target_skills
                .iter()
                .map(|s| (s.name.as_str(), read_skill_content(Path::new(&s.path))))
                .collect();
            let parent_refs: Vec<(&str, &str)> =
                parents.iter().map(|(n, c)| (*n, c.as_str())).collect();
            prompt::derived_prompt(&parent_refs, &context.direction, &context.trigger_context)
        }
        SuggestionKind::Captured => {
            let cat = context.category.as_ref().map(|c| c.to_string());
            prompt::captured_prompt(
                &context.direction,
                cat.as_deref(),
                &context.trigger_context,
            )
        }
    }
}

fn read_skill_content(skill_dir: &Path) -> String {
    if skill_dir == Path::new(crate::BUNDLED_PATH) {
        warn!(
            "attempted to read skill from <bundled> path; \
             caller should have materialized first"
        );
        return String::new();
    }
    let skill_md = skill_dir.join("SKILL.md");
    std::fs::read_to_string(&skill_md).unwrap_or_default()
}

fn strip_markdown_fences(content: &str) -> String {
    let mut result = content.to_string();
    // Remove leading ```<lang>
    if let Some(pos) = result.find("```") {
        let after = &result[pos + 3..];
        let line_end = after.find('\n').unwrap_or(0);
        result = after[line_end..].to_string();
    }
    // Remove trailing ```
    if let Some(pos) = result.rfind("```") {
        result = result[..pos].to_string();
    }
    result.trim().to_string()
}

fn strip_sentinels(response: &str) -> String {
    let mut result = response.to_string();
    // Extract content based on sentinels
    if let Some(pos) = result.find(EVOLUTION_COMPLETE) {
        result = result[..pos].to_string();
    }
    if let Some(pos) = result.find(EVOLUTION_FAILED) {
        result = result[..pos].to_string();
    }
    // Remove CHANGE_SUMMARY line (keep content on both sides)
    if let Some(pos) = result.find("CHANGE_SUMMARY:") {
        let line_end = result[pos..].find('\n').unwrap_or(result.len() - pos);
        result = format!("{}{}", &result[..pos], &result[pos + line_end..]);
    }
    result.trim().to_string()
}

fn generate_skill_id(context: &EvolutionContext) -> String {
    let uuid_part = &uuid::Uuid::new_v4().to_string()[..8];
    match context.evolution_type {
        SuggestionKind::Fix => {
            let parent = context.target_skills.first();
            let name = parent.map(|s| s.name.as_str()).unwrap_or("unknown");
            let gen = parent
                .map(|s| s.lineage.generation + 1)
                .unwrap_or(1);
            format!("{name}__v{gen}_{uuid_part}")
        }
        SuggestionKind::Derived => {
            // New name will be determined by the LLM — use placeholder
            format!("derived__v0_{uuid_part}")
        }
        SuggestionKind::Captured => {
            format!("captured__v0_{uuid_part}")
        }
    }
}

fn cleanup_on_failure(skill_dir: &Path, context: &EvolutionContext) {
    match context.evolution_type {
        SuggestionKind::Derived | SuggestionKind::Captured => {
            if skill_dir.exists() {
                let _ = std::fs::remove_dir_all(skill_dir);
            }
        }
        SuggestionKind::Fix => {
            // Don't clean up fix targets — they're existing directories
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn parse_complete_response() {
        let response = "CHANGE_SUMMARY: Updated port mapping instructions\n\n<<<<<<< SEARCH\nold content\n=======\nnew content\n>>>>>>> REPLACE\n\n<EVOLUTION_COMPLETE>";
        let output = parse_evolver_response(response).unwrap();
        assert_eq!(output.change_summary, "Updated port mapping instructions");
        assert!(output.raw_content.contains("SEARCH"));
    }

    #[test]
    fn parse_failed_response() {
        let response = "I analyzed the skill but <EVOLUTION_FAILED>\nReason: The skill is already correct.";
        let result = parse_evolver_response(response);
        match result {
            Err(Some(reason)) => assert!(reason.contains("The skill is already correct")),
            _ => panic!("expected Err(Some(_))"),
        }
    }

    #[test]
    fn parse_no_sentinel() {
        let response = "I'm still thinking about this...";
        let result = parse_evolver_response(response);
        match result {
            Err(None) => {} // expected
            _ => panic!("expected Err(None)"),
        }
    }

    #[test]
    fn parse_failed_takes_priority() {
        let response = "Some content <EVOLUTION_COMPLETE> but then <EVOLUTION_FAILED>\nNot feasible.";
        let result = parse_evolver_response(response);
        assert!(matches!(result, Err(Some(_))));
    }

    #[test]
    fn parse_without_change_summary() {
        let response = "*** Begin Files\n*** File: SKILL.md\ncontent\n*** End Files\n<EVOLUTION_COMPLETE>";
        let output = parse_evolver_response(response).unwrap();
        assert!(output.change_summary.is_empty());
        assert!(output.raw_content.contains("SKILL.md"));
    }

    #[test]
    fn strip_sentinels_cleanup() {
        let text = "CHANGE_SUMMARY: test\n\nactual content\n<EVOLUTION_COMPLETE>";
        let result = strip_sentinels(text);
        assert!(result.contains("actual content"));
        assert!(!result.contains("EVOLUTION_COMPLETE"));
        assert!(!result.contains("CHANGE_SUMMARY"));
    }

    #[test]
    fn strip_sentinels_change_summary_after_content() {
        // LLM sometimes places CHANGE_SUMMARY after the file content
        let text = "*** Begin Files\n*** File: SKILL.md\n---\nname: \"test\"\ndescription: \"test\"\n---\n# Test\n*** End Files\n\nCHANGE_SUMMARY: Created test skill\n\n<EVOLUTION_COMPLETE>";
        let result = strip_sentinels(text);
        assert!(result.contains("*** Begin Files"));
        assert!(result.contains("*** File: SKILL.md"));
        assert!(result.contains("name: \"test\""));
        assert!(!result.contains("CHANGE_SUMMARY"));
        assert!(!result.contains("EVOLUTION_COMPLETE"));
    }

    #[test]
    fn generate_fix_skill_id() {
        let context = EvolutionContext {
            evolution_type: SuggestionKind::Fix,
            target_skills: vec![SkillRecord {
                skill_id: "docker__imp_abcd1234".into(),
                name: "docker".into(),
                description: String::new(),
                path: "/tmp/docker".into(),
                is_active: true,
                category: SkillCategory::ToolGuide,
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
                    pre_fix_snapshot: HashMap::new(),
                    created_at: chrono::Utc::now(),
                    created_by: "human".into(),
                },
                tool_dependencies: vec![],
                critical_tools: vec![],
                total_selections: 0,
                total_applied: 0,
                total_completions: 0,
                total_fallbacks: 0,
                first_seen: chrono::Utc::now(),
                last_updated: chrono::Utc::now(),
                is_canary: false,
                canary_selections: 0,
                canary_completions: 0,
                parent_completion_rate_at_birth: 0.0,
                canary_parent_skill_id: None,
            }],
            direction: String::new(),
            category: None,
            trigger_context: String::new(),
            source_analysis: None,
        };
        let id = generate_skill_id(&context);
        assert!(id.starts_with("docker__v1_"));
    }
}
