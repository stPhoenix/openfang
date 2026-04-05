//! Microcompaction — lightweight pre-API token pruning (Layer 1).
//!
//! Reduces token usage **before** the API call by clearing old tool result
//! content, without LLM summarization. Only tool results from "compactable"
//! tools are eligible for clearing.
//!
//! ## Time-Based Microcompaction
//!
//! When the gap since the last assistant message exceeds a configurable
//! threshold (default: 60 minutes), old tool results are replaced with
//! `"[Old tool result content cleared]"`, keeping only the most recent N.
//! This reclaims tokens that would otherwise be wasted on stale cache-miss
//! context.

use chrono::{DateTime, Utc};
use openfang_types::config::MicrocompactConfig;
use openfang_types::message::{ContentBlock, Message, MessageContent, Role};
use tracing::{debug, info};

/// Tools whose results are eligible for microcompaction clearing.
const COMPACTABLE_TOOLS: &[&str] = &[
    "Read",
    "file_read",
    "Bash",
    "shell_exec",
    "Grep",
    "Glob",
    "file_search",
    "WebSearch",
    "web_search",
    "WebFetch",
    "web_fetch",
    "Edit",
    "file_write",
    "Write",
];

/// Result of a microcompaction pass.
#[derive(Debug, Clone)]
pub struct MicrocompactResult {
    /// Estimated tokens saved by clearing old tool results.
    pub tokens_saved: usize,
    /// Number of tool results that were cleared.
    pub tools_cleared: usize,
    /// Number of tool results that were kept.
    pub tools_kept: usize,
}

/// Placeholder text inserted when a tool result is cleared.
const CLEARED_MARKER: &str = "[Old tool result content cleared]";

/// Check if a tool name is eligible for microcompaction.
fn is_compactable_tool(name: &str) -> bool {
    COMPACTABLE_TOOLS.iter().any(|&t| t.eq_ignore_ascii_case(name))
}

/// Find the timestamp of the last assistant message.
fn last_assistant_timestamp(messages: &[Message]) -> Option<DateTime<Utc>> {
    messages
        .iter()
        .rev()
        .find(|m| m.role == Role::Assistant)
        .and_then(|m| m.timestamp)
}

/// Collect tool_use IDs from assistant messages, in order, for compactable tools.
fn collect_compactable_tool_ids(messages: &[Message]) -> Vec<String> {
    let mut ids = Vec::new();
    for msg in messages {
        if msg.role != Role::Assistant {
            continue;
        }
        if let MessageContent::Blocks(blocks) = &msg.content {
            for block in blocks {
                if let ContentBlock::ToolUse { id, name, .. } = block {
                    if is_compactable_tool(name) {
                        ids.push(id.clone());
                    }
                }
            }
        }
    }
    ids
}

/// Run time-based microcompaction on the message list.
///
/// If the gap since the last assistant message exceeds `config.gap_threshold_minutes`,
/// clears old compactable tool results, keeping only the most recent `config.keep_recent`.
///
/// Returns `None` if no tokens were saved (either the gap is too short or there's
/// nothing to clear).
pub fn microcompact_messages(
    messages: &mut [Message],
    config: &MicrocompactConfig,
) -> Option<MicrocompactResult> {
    if !config.enabled {
        return None;
    }

    let now = Utc::now();
    let last_ts = last_assistant_timestamp(messages)?;

    let gap_minutes = (now - last_ts).num_minutes();
    if gap_minutes < 0 || (gap_minutes as u64) < config.gap_threshold_minutes {
        return None;
    }

    debug!(
        gap_minutes,
        threshold = config.gap_threshold_minutes,
        "Microcompaction: time gap exceeded"
    );

    // Collect all compactable tool_use IDs in order
    let all_ids = collect_compactable_tool_ids(messages);
    if all_ids.is_empty() {
        return None;
    }

    // Determine which IDs to keep (the most recent N)
    let keep_recent = config.keep_recent.max(1);
    let keep_start = all_ids.len().saturating_sub(keep_recent);
    let ids_to_clear: std::collections::HashSet<&str> = all_ids[..keep_start]
        .iter()
        .map(|s| s.as_str())
        .collect();

    if ids_to_clear.is_empty() {
        return None;
    }

    // Clear the old tool results
    let mut tokens_saved: usize = 0;
    let mut tools_cleared: usize = 0;

    for msg in messages.iter_mut() {
        if let MessageContent::Blocks(blocks) = &mut msg.content {
            for block in blocks.iter_mut() {
                if let ContentBlock::ToolResult {
                    tool_use_id,
                    content,
                    ..
                } = block
                {
                    if ids_to_clear.contains(tool_use_id.as_str())
                        && content != CLEARED_MARKER
                    {
                        let old_len = content.len();
                        let new_len = CLEARED_MARKER.len();
                        if old_len > new_len {
                            tokens_saved += (old_len - new_len) / 4;
                        }
                        *content = CLEARED_MARKER.to_string();
                        tools_cleared += 1;
                    }
                }
            }
        }
    }

    if tools_cleared == 0 {
        return None;
    }

    let tools_kept = all_ids.len() - keep_start;

    info!(
        tools_cleared,
        tools_kept,
        tokens_saved,
        gap_minutes,
        "Microcompaction: cleared old tool results"
    );

    Some(MicrocompactResult {
        tokens_saved,
        tools_cleared,
        tools_kept,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfang_types::message::{ContentBlock, Message, MessageContent};

    fn make_config(enabled: bool, gap_minutes: u64, keep_recent: usize) -> MicrocompactConfig {
        MicrocompactConfig {
            enabled,
            gap_threshold_minutes: gap_minutes,
            keep_recent,
        }
    }

    fn make_tool_use_msg(id: &str, tool_name: &str) -> Message {
        Message::assistant_with_blocks(vec![ContentBlock::ToolUse {
            id: id.to_string(),
            name: tool_name.to_string(),
            input: serde_json::json!({}),
            provider_metadata: None,
        }])
    }

    fn make_tool_result_msg(tool_use_id: &str, content: &str) -> Message {
        Message::user_with_blocks(vec![ContentBlock::ToolResult {
            tool_use_id: tool_use_id.to_string(),
            tool_name: String::new(),
            content: content.to_string(),
            is_error: false,
        }])
    }

    #[test]
    fn test_disabled_returns_none() {
        let config = make_config(false, 0, 5);
        let mut messages = vec![Message::user("hi")];
        assert!(microcompact_messages(&mut messages, &config).is_none());
    }

    #[test]
    fn test_no_assistant_returns_none() {
        let config = make_config(true, 0, 5);
        let mut messages = vec![Message::user("hi")];
        assert!(microcompact_messages(&mut messages, &config).is_none());
    }

    #[test]
    fn test_gap_too_short_returns_none() {
        let config = make_config(true, 120, 5); // 2 hour threshold
        let mut messages = vec![
            Message::user("hi"),
            Message::assistant("hello"), // timestamp is now()
        ];
        assert!(microcompact_messages(&mut messages, &config).is_none());
    }

    #[test]
    fn test_clears_old_tool_results() {
        let config = make_config(true, 0, 2); // 0 minute threshold, keep 2

        // Build messages: 4 tool calls, keep last 2
        let mut messages = vec![
            Message::user("start"),
            make_tool_use_msg("t1", "Read"),
            make_tool_result_msg("t1", "file content 1 ".repeat(100).trim()),
            make_tool_use_msg("t2", "Grep"),
            make_tool_result_msg("t2", "grep results ".repeat(100).trim()),
            make_tool_use_msg("t3", "Read"),
            make_tool_result_msg("t3", "file content 3"),
            make_tool_use_msg("t4", "Bash"),
            make_tool_result_msg("t4", "shell output"),
        ];

        // Set the last assistant message timestamp to 2 hours ago
        // to trigger microcompaction. We need at least one assistant msg.
        // The tool_use messages already have timestamps from ::assistant_with_blocks()
        // Since gap threshold is 0, any assistant message with a timestamp will work.

        let result = microcompact_messages(&mut messages, &config);
        assert!(result.is_some());

        let result = result.unwrap();
        assert_eq!(result.tools_cleared, 2); // t1 and t2
        assert_eq!(result.tools_kept, 2); // t3 and t4

        // Verify t1 and t2 are cleared
        let get_content = |msgs: &[Message], id: &str| -> String {
            for msg in msgs {
                if let MessageContent::Blocks(blocks) = &msg.content {
                    for block in blocks {
                        if let ContentBlock::ToolResult {
                            tool_use_id,
                            content,
                            ..
                        } = block
                        {
                            if tool_use_id == id {
                                return content.clone();
                            }
                        }
                    }
                }
            }
            String::new()
        };

        assert_eq!(get_content(&messages, "t1"), CLEARED_MARKER);
        assert_eq!(get_content(&messages, "t2"), CLEARED_MARKER);
        assert_ne!(get_content(&messages, "t3"), CLEARED_MARKER);
        assert_ne!(get_content(&messages, "t4"), CLEARED_MARKER);
    }

    #[test]
    fn test_non_compactable_tools_skipped() {
        let config = make_config(true, 0, 1);

        let mut messages = vec![
            Message::user("start"),
            // "custom_tool" is not in COMPACTABLE_TOOLS
            make_tool_use_msg("t1", "custom_tool"),
            make_tool_result_msg("t1", "big result ".repeat(100).trim()),
            make_tool_use_msg("t2", "Read"),
            make_tool_result_msg("t2", "file content"),
        ];

        let result = microcompact_messages(&mut messages, &config);
        // t1 is not compactable, t2 is kept (keep_recent=1), so nothing to clear
        assert!(result.is_none());
    }

    #[test]
    fn test_is_compactable_tool() {
        assert!(is_compactable_tool("Read"));
        assert!(is_compactable_tool("file_read"));
        assert!(is_compactable_tool("Bash"));
        assert!(is_compactable_tool("shell_exec"));
        assert!(is_compactable_tool("Grep"));
        assert!(is_compactable_tool("Glob"));
        assert!(is_compactable_tool("WebSearch"));
        assert!(is_compactable_tool("web_fetch"));
        assert!(is_compactable_tool("Edit"));
        assert!(is_compactable_tool("Write"));
        assert!(!is_compactable_tool("custom_tool"));
        assert!(!is_compactable_tool("agent_send"));
    }

    #[test]
    fn test_idempotent_clearing() {
        let config = make_config(true, 0, 0); // keep 0 = keep 1 (clamped)

        let mut messages = vec![
            Message::user("start"),
            make_tool_use_msg("t1", "Read"),
            make_tool_result_msg("t1", "big file ".repeat(500).trim()),
            make_tool_use_msg("t2", "Read"),
            make_tool_result_msg("t2", "another file"),
        ];

        // First pass
        let r1 = microcompact_messages(&mut messages, &config).unwrap();
        assert_eq!(r1.tools_cleared, 1); // t1 cleared, t2 kept

        // Second pass should be no-op (t1 already cleared)
        let r2 = microcompact_messages(&mut messages, &config);
        assert!(r2.is_none());
    }
}
