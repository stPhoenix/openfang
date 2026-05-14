//! Prompt construction for the execution analyzer LLM call.

use openfang_types::message::{ContentBlock, Message, MessageContent, Role};
use openfang_types::truncate_str;

/// Maximum number of messages to include in the analysis prompt.
/// If a session exceeds this, we keep the first 1/4 and last 3/4.
const MAX_MESSAGES: usize = 100;

/// Rough chars-per-token estimate (conservative — overestimates tokens slightly).
const CHARS_PER_TOKEN: usize = 4;

/// Tokens reserved for the system prompt (~1500 tokens) and model response headroom.
const RESERVED_TOKENS: usize = 4000;

/// Fallback context window when the model's actual limit is unknown.
pub const DEFAULT_CONTEXT_WINDOW: usize = 32_000;

/// Build the system prompt for the execution analyzer.
pub fn system_prompt() -> String {
    r#"You are an Execution Analyzer for an AI agent system. Your job is to review a completed agent conversation and produce a structured analysis.

## Your Task

Analyze the conversation transcript below and produce a JSON object with your assessment. Evaluate:

1. **Task completion** — Did the agent actually complete the user's request? Judge independently based on the conversation, not on any self-reported status.

2. **Execution quality** — Write a 2-3 sentence overview of what happened, including any notable decisions, detours, or failures.

3. **Tool issues** — Identify tools that had actual problems (errors, wrong output, semantic failures, misuse). Only flag real issues, not normal tool usage.

4. **Skill judgments** — For each skill that was available to the agent, assess: was it applied? How well? If the agent had no skills, return an empty list.

5. **Evolution suggestions** — Suggest 0 to N improvements:
   - `fix`: Skill instructions are incorrect, outdated, or incomplete
   - `derived`: Skill worked but execution revealed a better approach
   - `captured`: Agent solved something novel without skill guidance; the pattern is reusable

## Output Format

Return ONLY a single JSON object (no markdown fences, no explanation outside the JSON):

```json
{
  "task_completed": true,
  "execution_note": "2-3 sentence overview of the execution.",
  "tool_issues": [
    {
      "tool_name": "tool_key",
      "issue_type": "failure|misuse|unnecessary|missing",
      "description": "What went wrong and why."
    }
  ],
  "skill_judgments": [
    {
      "skill_name": "skill-name",
      "applied": true,
      "quality": "good|partial|poor|not_applicable",
      "note": "How the skill was used or why it wasn't."
    }
  ],
  "evolution_suggestions": [
    {
      "kind": "fix|derived|captured",
      "target_skill": "skill-name-or-null",
      "description": "What to change and why.",
      "priority": 3
    }
  ]
}
```

Rules:
- `tool_issues`: only include tools with ACTUAL problems. Empty list is fine.
- `skill_judgments`: one entry per available skill. Empty list if no skills were available.
- `evolution_suggestions`: 0 entries is perfectly valid. Only suggest when there's a clear improvement.
- `priority`: 1 (low) to 5 (critical).
- Return ONLY the JSON object. No preamble, no explanation after."#
        .to_string()
}

/// Per-field truncation limits, reduced progressively to fit the budget.
struct FieldLimits {
    tool_input: usize,
    tool_result: usize,
    thinking: usize,
}

impl FieldLimits {
    fn default_limits() -> Self {
        Self {
            tool_input: 500,
            tool_result: 1000,
            thinking: 200,
        }
    }

    fn reduced() -> Self {
        Self {
            tool_input: 200,
            tool_result: 300,
            thinking: 50,
        }
    }

    fn minimal() -> Self {
        Self {
            tool_input: 100,
            tool_result: 150,
            thinking: 0,
        }
    }
}

/// Build the user message containing the conversation transcript and skill list.
///
/// `context_window` is the model's context window in tokens. The prompt is
/// progressively truncated to fit within `(context_window - RESERVED_TOKENS)`.
pub fn build_user_message(
    messages: &[Message],
    available_skills: &[String],
    context_window: usize,
) -> String {
    let budget_tokens = context_window.saturating_sub(RESERVED_TOKENS);
    let char_budget = budget_tokens * CHARS_PER_TOKEN;

    // Phase 1: Try with default limits
    let result = build_with_limits(messages, available_skills, MAX_MESSAGES, &FieldLimits::default_limits());
    if result.len() <= char_budget {
        return result;
    }

    // Phase 2: Reduce message count (keep head/tail ratio 1:3)
    let reduced_max = MAX_MESSAGES / 2;
    let result = build_with_limits(messages, available_skills, reduced_max, &FieldLimits::reduced());
    if result.len() <= char_budget {
        return result;
    }

    // Phase 3: Aggressive reduction
    let minimal_max = 30;
    let result = build_with_limits(messages, available_skills, minimal_max, &FieldLimits::minimal());
    if result.len() <= char_budget {
        return result;
    }

    // Phase 4: Hard-truncate as last resort
    if result.len() > char_budget && char_budget > 20 {
        let mut truncated = truncate_str(&result, char_budget - 15).to_string();
        truncated.push_str("\n[TRUNCATED]\n");
        return truncated;
    }

    result
}

fn build_with_limits(
    messages: &[Message],
    available_skills: &[String],
    max_messages: usize,
    limits: &FieldLimits,
) -> String {
    let mut parts = Vec::new();

    // Skills section
    if available_skills.is_empty() {
        parts.push("## Available Skills\nNone — the agent had no skills loaded.\n".to_string());
    } else {
        parts.push(format!(
            "## Available Skills\n{}\n",
            available_skills
                .iter()
                .map(|s| format!("- {s}"))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }

    // Conversation transcript
    parts.push("## Conversation Transcript\n".to_string());

    let msgs = truncate_messages(messages, max_messages);
    for msg in &msgs {
        let role_label = match msg.role {
            Role::User => "USER",
            Role::Assistant => "ASSISTANT",
            Role::System => "SYSTEM",
        };

        let content_text = extract_message_text(&msg.content, limits);
        if !content_text.is_empty() {
            parts.push(format!("[{role_label}]\n{content_text}\n"));
        }
    }

    parts.join("\n")
}

/// Truncate messages if they exceed the limit, keeping head and tail.
fn truncate_messages(messages: &[Message], max_messages: usize) -> Vec<&Message> {
    if messages.len() <= max_messages {
        return messages.iter().collect();
    }

    // Keep head/tail ratio at roughly 1:3
    let keep_head = max_messages / 4;
    let keep_tail = max_messages - keep_head;
    let keep_head = keep_head.max(1);

    let mut result: Vec<&Message> = messages[..keep_head].iter().collect();
    let tail_start = messages.len().saturating_sub(keep_tail);
    if tail_start > keep_head {
        result.extend(messages[tail_start..].iter());
    } else {
        result.extend(messages[keep_head..].iter());
    }
    result
}

/// Extract readable text from a MessageContent (either simple text or blocks).
fn extract_message_text(content: &MessageContent, limits: &FieldLimits) -> String {
    match content {
        MessageContent::Text(text) => text.clone(),
        MessageContent::Blocks(blocks) => extract_text_from_blocks(blocks, limits),
    }
}

/// Extract readable text content from content blocks.
fn extract_text_from_blocks(content: &[ContentBlock], limits: &FieldLimits) -> String {
    let mut parts = Vec::new();
    for block in content {
        match block {
            ContentBlock::Text { text, .. } => {
                parts.push(text.clone());
            }
            ContentBlock::ToolUse {
                name, input, id, ..
            } => {
                let input_str = if input.is_string() {
                    input.as_str().unwrap_or("").to_string()
                } else {
                    serde_json::to_string(input).unwrap_or_default()
                };
                let truncated = if input_str.len() > limits.tool_input {
                    format!("{}... [truncated]", truncate_str(&input_str, limits.tool_input))
                } else {
                    input_str
                };
                parts.push(format!("[Tool Call: {name} (id: {id})]\n{truncated}"));
            }
            ContentBlock::ToolResult {
                tool_use_id,
                content: result_content,
                is_error,
                ..
            } => {
                let error_tag = if *is_error { " ERROR" } else { "" };
                let truncated = if result_content.len() > limits.tool_result {
                    format!("{}... [truncated]", truncate_str(result_content, limits.tool_result))
                } else {
                    result_content.clone()
                };
                parts.push(format!(
                    "[Tool Result{error_tag} for {tool_use_id}]\n{truncated}"
                ));
            }
            ContentBlock::Thinking { thinking, .. } => {
                if limits.thinking == 0 {
                    continue;
                }
                let preview = if thinking.len() > limits.thinking {
                    format!("{}...", truncate_str(thinking, limits.thinking))
                } else {
                    thinking.clone()
                };
                parts.push(format!("[Thinking] {preview}"));
            }
            _ => {}
        }
    }
    parts.join("\n")
}

/// Maximum characters of skill content to include in evolution prompts.
const SKILL_CONTENT_MAX_CHARS: usize = 16000;

/// Truncate skill content to fit in prompts.
fn truncate_content(content: &str) -> &str {
    truncate_str(content, SKILL_CONTENT_MAX_CHARS)
}

/// Build the system prompt for the evolution evolver agent.
pub fn evolver_system_prompt() -> String {
    r#"You are a Skill Evolver for an AI agent system. Your job is to modify, enhance, or create skills (reusable instruction documents) that agents follow.

## Skill Format

Skills are directories containing a SKILL.md file with YAML frontmatter:

```yaml
---
name: "skill-name"
description: "One-line description"
---

# Skill Title

Step-by-step instructions the agent should follow...
```

## Output Requirements

Your output MUST follow this exact sequence — no preamble, no reasoning, no analysis text:

1. `CHANGE_SUMMARY: <one-sentence description>`
2. Skill content in one of the formats below
3. `<EVOLUTION_COMPLETE>` (success) or `<EVOLUTION_FAILED>` with a reason (failure)

IMPORTANT:
- The `*** File:` path MUST be just `SKILL.md` — never use absolute paths or subdirectories
- Output ONLY the structured format. Do not add explanations, reasoning, or commentary
- Do not use tools — produce text output only

## Format A — Patch (for surgical edits)
```
*** Begin Patch
*** Update File: SKILL.md
@@ anchor_line
 context line
-removed line
+added line
 context line
*** End Patch
```

## Format B — Full content (for major rewrites or new skills)
```
*** Begin Files
*** File: SKILL.md
(complete file content here)
*** End Files
```

## Format C — Search/Replace (for simple edits)
```
<<<<<<< SEARCH
old content
=======
new content
>>>>>>> REPLACE
```

## Complete Example

```
CHANGE_SUMMARY: Added error-handling step to deployment skill

*** Begin Files
*** File: SKILL.md
---
name: "safe-deploy"
description: "Step-by-step deployment with rollback on failure"
---

# Safe Deploy

1. Run pre-deploy checks
2. Deploy to staging
3. If staging fails, rollback immediately
4. Deploy to production only after staging succeeds
*** End Files

<EVOLUTION_COMPLETE>
```

## Rules
- Preserve YAML frontmatter structure (name and description are required)
- Keep instructions clear, actionable, and agent-followable
- Make skills self-contained (no references to parent versions needed)
- Choose meaningful names (not just appending "-enhanced" or "-v2")"#
        .to_string()
}

/// Build the prompt for a FIX evolution.
pub fn fix_prompt(
    skill_content: &str,
    direction: &str,
    trigger_context: &str,
) -> String {
    format!(
        r#"## Task: Fix Skill

The following skill has issues that need to be repaired.

### Direction
{direction}

### Trigger Context
{trigger_context}

### Current Skill Content
```
{content}
```

## Instructions
1. Analyze the failure context and root cause
2. Fix the affected files with surgical, targeted changes
3. Preserve the YAML frontmatter structure
4. Keep the name and description unless the purpose changed
5. Output CHANGE_SUMMARY + your changes + <EVOLUTION_COMPLETE>

If the skill cannot be reasonably fixed, output <EVOLUTION_FAILED> with a reason."#,
        content = truncate_content(skill_content),
    )
}

/// Build the prompt for a DERIVED evolution.
pub fn derived_prompt(
    parent_contents: &[(&str, &str)], // (name, content) pairs
    direction: &str,
    trigger_context: &str,
) -> String {
    let parents_section: String = parent_contents
        .iter()
        .map(|(name, content)| {
            format!(
                "### Parent: {name}\n```\n{}\n```\n",
                truncate_content(content)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"## Task: Derive Enhanced Skill

Create an enhanced version of the skill(s) below based on execution insights.

### Direction
{direction}

### Trigger Context
{trigger_context}

{parents_section}

## Instructions
1. Create an enhanced version addressing the direction above
2. Give it a **different, concise name** (not just "-enhanced" or "-v2")
3. Update the description to reflect the new capability
4. Make it self-contained (no reference to parent needed)
5. Output CHANGE_SUMMARY + your changes + <EVOLUTION_COMPLETE>

If enhancement is not worthwhile, output <EVOLUTION_FAILED> with a reason."#
    )
}

/// Build the prompt for a CAPTURED skill creation.
pub fn captured_prompt(
    direction: &str,
    category: Option<&str>,
    trigger_context: &str,
) -> String {
    let cat = category.unwrap_or("reference");
    format!(
        r#"## Task: Capture New Skill

The agent solved a task using a novel approach that should be captured as a reusable skill.

### Direction
{direction}

### Suggested Category
{cat}

### Context
{trigger_context}

## Instructions
1. Distill the observed pattern into clear, reusable instructions
2. Choose a concise, descriptive name
3. Make it generalizable (abstract away task-specific details)
4. Structure as agent-followable steps
5. Category: {cat}
6. Output using the exact format below — no preamble or reasoning text

## Expected Output Format

```
CHANGE_SUMMARY: <one sentence describing the new skill>

*** Begin Files
*** File: SKILL.md
---
name: "<skill-name>"
description: "<one-line description>"
---

# <Skill Title>

<Step-by-step instructions>
*** End Files

<EVOLUTION_COMPLETE>
```

If the pattern is not worth capturing, output <EVOLUTION_FAILED> with a reason."#
    )
}

/// Build the prompt for the LLM confirmation gate.
pub fn confirmation_prompt(
    skill_id: &str,
    skill_content: &str,
    proposed_type: &str,
    direction: &str,
    trigger_context: &str,
    recent_analyses: &str,
) -> String {
    format!(
        r#"## Evolution Confirmation

A rule-based system has identified a skill that may need evolution. Before investing in the evolution process, please assess whether this is worthwhile.

### Skill
- ID: {skill_id}
- Proposed action: {proposed_type}
- Proposed direction: {direction}

### Trigger Context
{trigger_context}

### Skill Content (truncated)
```
{content}
```

### Recent Execution Analyses
{recent_analyses}

## Your Assessment

Evaluate:
1. Is the signal real? (Could poor metrics be caused by external factors?)
2. Is the skill actually problematic? (Read the content)
3. Is evolution worth the cost? (Will it help future executions?)
4. Is the proposed direction correct? (Does it address the root cause?)

Respond with ONLY a JSON object:
```json
{{
  "proceed": true,
  "reasoning": "1-2 sentence explanation.",
  "adjusted_direction": "Optional: refined direction if the original should be tweaked."
}}
```

If unsure, default to `"proceed": false` (conservative)."#,
        content = truncate_content(skill_content),
    )
}

/// Build the retry prompt when patch application fails.
pub fn retry_prompt(error: &str, current_content: &str) -> String {
    format!(
        r#"## Patch Application Failed

Your previous output could not be applied. The error was:

```
{error}
```

### Current File Content on Disk
```
{content}
```

## Required Output Format

Output your corrected changes using this exact sequence — no preamble or reasoning:

1. `CHANGE_SUMMARY: <description>`
2. Skill content using `*** Begin Files` / `*** File: SKILL.md` / `*** End Files`
3. `<EVOLUTION_COMPLETE>` or `<EVOLUTION_FAILED>`

IMPORTANT: The `*** File:` path MUST be just `SKILL.md` — never use absolute paths."#,
        content = truncate_content(current_content),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_prompt_not_empty() {
        let prompt = system_prompt();
        assert!(prompt.contains("Execution Analyzer"));
        assert!(prompt.contains("task_completed"));
        assert!(prompt.contains("evolution_suggestions"));
    }

    fn test_msg(text: &str) -> Message {
        Message {
            role: Role::User,
            content: MessageContent::Text(text.to_string()),
            uuid: None,
            timestamp: None,
            session_id: None,
            metadata: Default::default(),
        }
    }

    #[test]
    fn build_user_message_no_skills() {
        let msgs = vec![test_msg("Hello")];
        let result = build_user_message(&msgs, &[], 200_000);
        assert!(result.contains("None"));
        assert!(result.contains("[USER]"));
        assert!(result.contains("Hello"));
    }

    #[test]
    fn build_user_message_with_skills() {
        let msgs = vec![];
        let skills = vec!["docker".to_string(), "git-expert".to_string()];
        let result = build_user_message(&msgs, &skills, 200_000);
        assert!(result.contains("- docker"));
        assert!(result.contains("- git-expert"));
    }

    #[test]
    fn truncate_under_limit() {
        let msgs: Vec<Message> = (0..50).map(|i| test_msg(&format!("msg {i}"))).collect();
        let result = truncate_messages(&msgs, MAX_MESSAGES);
        assert_eq!(result.len(), 50);
    }

    #[test]
    fn truncate_over_limit() {
        let msgs: Vec<Message> = (0..200).map(|i| test_msg(&format!("msg {i}"))).collect();
        let result = truncate_messages(&msgs, MAX_MESSAGES);
        // KEEP_HEAD (25) + KEEP_TAIL (75) = 100
        assert_eq!(result.len(), MAX_MESSAGES);
    }

    #[test]
    fn small_context_window_truncates() {
        // 200 messages with ~100 chars each ≈ 20K chars ≈ 5K tokens
        let msgs: Vec<Message> = (0..200)
            .map(|_| test_msg(&"x".repeat(100)))
            .collect();
        let large = build_user_message(&msgs, &[], 200_000);
        let small = build_user_message(&msgs, &[], 2_000);
        assert!(small.len() < large.len(), "small context should produce shorter prompt");
        // 2000 tokens - 4000 reserved = 0 (saturating), so it should hard-truncate
    }

    #[test]
    fn context_budget_respected() {
        let msgs: Vec<Message> = (0..100)
            .map(|_| test_msg(&"word ".repeat(200)))
            .collect();
        let context_window = 8_000; // 8K tokens
        let result = build_user_message(&msgs, &[], context_window);
        let estimated_tokens = result.len() / CHARS_PER_TOKEN;
        let budget = context_window.saturating_sub(RESERVED_TOKENS);
        assert!(
            estimated_tokens <= budget,
            "prompt ({estimated_tokens} tokens) should fit within budget ({budget} tokens)"
        );
    }

    #[test]
    fn evolver_system_prompt_has_sentinels() {
        let prompt = evolver_system_prompt();
        assert!(prompt.contains("EVOLUTION_COMPLETE"));
        assert!(prompt.contains("EVOLUTION_FAILED"));
        assert!(prompt.contains("CHANGE_SUMMARY"));
    }

    #[test]
    fn fix_prompt_includes_content() {
        let result = fix_prompt("# My Skill\nStep 1", "Fix step 1", "low completion rate");
        assert!(result.contains("# My Skill"));
        assert!(result.contains("Fix step 1"));
        assert!(result.contains("low completion rate"));
    }

    #[test]
    fn derived_prompt_multiple_parents() {
        let parents = vec![
            ("skill-a", "# Skill A"),
            ("skill-b", "# Skill B"),
        ];
        let result = derived_prompt(&parents, "Merge features", "metrics suggest enhancement");
        assert!(result.contains("skill-a"));
        assert!(result.contains("skill-b"));
        assert!(result.contains("Merge features"));
    }

    #[test]
    fn captured_prompt_includes_category() {
        let result = captured_prompt("Novel debugging approach", Some("workflow"), "agent solved without skill");
        assert!(result.contains("workflow"));
        assert!(result.contains("Novel debugging approach"));
    }

    #[test]
    fn confirmation_prompt_structure() {
        let result = confirmation_prompt(
            "docker__imp_abc",
            "# Docker\nSteps...",
            "fix",
            "Update port mapping",
            "completion rate 20%",
            "Recent analysis: task failed due to incorrect ports",
        );
        assert!(result.contains("docker__imp_abc"));
        assert!(result.contains("fix"));
        assert!(result.contains("proceed"));
    }

    #[test]
    fn retry_prompt_includes_error() {
        let result = retry_prompt("search text not found", "# Current content");
        assert!(result.contains("search text not found"));
        assert!(result.contains("# Current content"));
    }

    // Regression: prompt.rs:259 panicked when a multibyte char (e.g. '°' from
    // a weather-forecast tool result) straddled the byte-truncation point.
    // '°' (U+00B0) is 2 bytes (0xC2 0xB0); placing it at bytes 999..1001 with
    // a 1000-byte limit reproduces the original `byte index 1000 is not a
    // char boundary` panic when raw byte slicing is used.

    #[test]
    fn tool_result_with_multibyte_char_no_panic() {
        let content = format!("{}°C extra", "x".repeat(999));
        let block = ContentBlock::ToolResult {
            tool_use_id: "tu_1".into(),
            tool_name: String::new(),
            content,
            is_error: false,
        };
        let limits = FieldLimits {
            tool_input: 100,
            tool_result: 1000,
            thinking: 0,
        };
        let out = extract_text_from_blocks(&[block], &limits);
        assert!(out.contains("[truncated]"));
        assert!(out.contains("Tool Result"));
    }

    #[test]
    fn tool_input_with_multibyte_char_no_panic() {
        let payload = format!("{}°C extra", "x".repeat(999));
        let block = ContentBlock::ToolUse {
            id: "tu_2".into(),
            name: "weather".into(),
            input: serde_json::Value::String(payload),
            provider_metadata: None,
        };
        let limits = FieldLimits {
            tool_input: 1000,
            tool_result: 100,
            thinking: 0,
        };
        let out = extract_text_from_blocks(&[block], &limits);
        assert!(out.contains("[truncated]"));
        assert!(out.contains("Tool Call"));
    }

    #[test]
    fn thinking_with_multibyte_char_no_panic() {
        let block = ContentBlock::Thinking {
            thinking: format!("{}°C extra", "x".repeat(999)),
            signature: None,
            provider_metadata: None,
        };
        let limits = FieldLimits {
            tool_input: 100,
            tool_result: 100,
            thinking: 1000,
        };
        let out = extract_text_from_blocks(&[block], &limits);
        assert!(out.contains("Thinking"));
        assert!(out.ends_with("..."));
    }

    #[test]
    fn hard_truncate_phase4_with_multibyte_no_panic() {
        // Force Phase-4 hard-truncate (line 149) by giving a tiny budget that
        // still passes `char_budget > 20`, with messages full of multibyte
        // chars. Sweep several budgets so at least one slice point lands on
        // a non-boundary byte if `truncate_str` is missing.
        let msgs: Vec<Message> = (0..200)
            .map(|_| test_msg(&"°".repeat(200)))
            .collect();
        for context_window in [4006usize, 4008, 4010, 4015, 4020, 4030] {
            let out = build_user_message(&msgs, &[], context_window);
            assert!(out.contains("[TRUNCATED]") || out.len() <= context_window * CHARS_PER_TOKEN);
        }
    }
}
