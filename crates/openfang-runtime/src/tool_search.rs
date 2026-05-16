//! Deferred-tool loading via a built-in `ToolSearch` meta-tool.
//!
//! When a session has many tools (typically MCP + skill-provided), sending
//! every full JSON schema in `request.tools` dominates the context window.
//! This module implements client-side deferral: undiscovered tools are
//! announced by name in the system prompt; the model invokes `ToolSearch`
//! to fetch the full schemas of the tools it needs; discovered tools are
//! then included with full schemas on subsequent turns.
//!
//! Provider-agnostic: works with every `LlmDriver` because the meta-tool
//! returns its result as plain text (a `<functions>{...}</functions>` block
//! the model has been trained to read), so no provider beta features are
//! required. See `toolsearch.md` at the repo root for the full spec.

use openfang_types::config::ToolSearchConfig;
use openfang_types::message::{ContentBlock, Message, MessageContent};
use openfang_types::tool::ToolDefinition;
use std::collections::BTreeSet;

/// Canonical name of the built-in discovery meta-tool.
pub const TOOL_SEARCH_NAME: &str = "ToolSearch";

const DESCRIPTION: &str = "Fetches full schema definitions for deferred tools so they can be called.\n\n\
    Deferred tools appear by name in the system prompt under \"Available On-Demand Tools\". \
    Until fetched, only the name is known — there is no parameter schema, so the tool cannot \
    be invoked. This tool takes a query, matches it against the deferred tool list, and \
    returns the matched tools' complete JSON schema definitions inside a <functions> block. \
    Once a tool's schema appears in that result, it is callable exactly like any tool defined \
    at the top of the prompt.\n\n\
    Query forms:\n\
    - \"select:Read,Edit,Grep\" — fetch these exact tools by name\n\
    - \"notebook jupyter\" — keyword search, up to max_results best matches\n\
    - \"+slack send\" — require \"slack\" in the name, rank by remaining terms\n\
    - \"mcp__server_\" — return up to max_results tools whose name starts with the prefix";

/// Build the canonical `ToolSearch` tool definition.
pub fn tool_search_definition() -> ToolDefinition {
    ToolDefinition {
        name: TOOL_SEARCH_NAME.to_string(),
        description: DESCRIPTION.to_string(),
        input_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Query to find deferred tools. Use \"select:<tool_name>[,<tool_name>...]\" for direct selection, or keywords to search."
                },
                "max_results": {
                    "type": "integer",
                    "description": "Maximum number of results to return (default: 5)"
                }
            },
            "required": ["query"]
        }),
        defer: false,
        search_hint: None,
        is_mcp: false,
        always_load: true,
    }
}

/// Honor `OPENFANG_DISABLE_TOOL_SEARCH=1` kill-switch in addition to config.
pub fn is_enabled(cfg: &ToolSearchConfig) -> bool {
    if !cfg.enabled {
        return false;
    }
    matches!(
        std::env::var("OPENFANG_DISABLE_TOOL_SEARCH").as_deref(),
        Err(_) | Ok("") | Ok("0") | Ok("false")
    )
}

/// Decide whether a given tool should be deferred. Priority order:
///   1. `always_load` → not deferred
///   2. name == `ToolSearch` → not deferred
///   3. MCP tool → deferred iff `always_defer_mcp`
///   4. otherwise → deferred iff `always_defer_skills` (skill / external)
///
/// Built-in tool recognition is handled by the caller (kernel) since the
/// canonical builtin list lives in `tool_runner`. This function is invoked
/// only on tools the kernel hasn't already classified as builtin.
pub fn classify_deferral(t: &ToolDefinition, cfg: &ToolSearchConfig) -> bool {
    if t.always_load {
        return false;
    }
    if t.name == TOOL_SEARCH_NAME {
        return false;
    }
    if t.is_mcp {
        return cfg.always_defer_mcp;
    }
    cfg.always_defer_skills
}

/// Returns `true` if the given model lacks ToolSearch support (e.g. Haiku).
pub fn model_unsupported(model: &str, cfg: &ToolSearchConfig) -> bool {
    let lower = model.to_lowercase();
    cfg.unsupported_model_substrings
        .iter()
        .any(|s| !s.is_empty() && lower.contains(&s.to_lowercase()))
}

/// Scan message history and collect tool names the model has already
/// discovered via `ToolSearch`.
///
/// Strategy:
///   1. For every assistant message, find `ToolUse{ name == "ToolSearch", … }`.
///   2. For each such call, find the next `User` message containing a
///      matching `ToolResult{ tool_use_id, content }`. Parse names out of the
///      `<function>{...}</function>` lines in the result text.
///   3. Also extract names from `select:` queries as a fallback (the model
///      may have been told the names exist even if the result text is gone).
pub fn extract_discovered(messages: &[Message]) -> BTreeSet<String> {
    let mut discovered = BTreeSet::new();
    let mut pending: Vec<(String, Option<String>)> = Vec::new();

    for msg in messages {
        if let MessageContent::Blocks(blocks) = &msg.content {
            for block in blocks {
                match block {
                    ContentBlock::ToolUse { id, name, input, .. }
                        if name == TOOL_SEARCH_NAME =>
                    {
                        let query = input
                            .get("query")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                        pending.push((id.clone(), query));
                    }
                    ContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                        ..
                    } => {
                        if let Some(pos) = pending.iter().position(|(id, _)| id == tool_use_id) {
                            let (_, query) = pending.remove(pos);
                            if !*is_error {
                                discovered.extend(parse_function_names(content));
                            }
                            if let Some(q) = query {
                                discovered.extend(parse_select_names(&q));
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Calls that never received a result (e.g. truncated by compaction) —
    // fall back to whatever the `select:` query implied.
    for (_, q) in pending {
        if let Some(q) = q {
            discovered.extend(parse_select_names(&q));
        }
    }

    discovered
}

fn parse_function_names(content: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("<function>") else {
            continue;
        };
        let Some(json_str) = rest.strip_suffix("</function>") else {
            continue;
        };
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) {
            if let Some(name) = v.get("name").and_then(|n| n.as_str()) {
                out.push(name.to_string());
            }
        }
    }
    out
}

fn parse_select_names(query: &str) -> Vec<String> {
    let lower = query.trim().to_lowercase();
    let Some(rest) = lower.strip_prefix("select:") else {
        return Vec::new();
    };
    // Use the original (non-lowercased) tail so we preserve case in names.
    let tail = query.trim()[7..].trim_start_matches(' ');
    let _ = rest; // suppress warning; we used lower only for prefix check
    tail.split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

/// Filter the full tool list down to what should be sent in `request.tools`
/// for this turn.
///
/// Rules:
///   - If subagent / Claude-Code subprocess / disabled / unsupported model →
///     return the full list unchanged (no deferral).
///   - Otherwise: drop tools where `t.defer && !discovered.contains(&t.name)`.
///     The discovery tool itself (`always_load`) is always retained.
pub fn filter_for_request(
    all: &[ToolDefinition],
    discovered: &BTreeSet<String>,
    cfg: &ToolSearchConfig,
    model: &str,
    is_subagent: bool,
    provider: &str,
) -> Vec<ToolDefinition> {
    if is_subagent
        || provider.eq_ignore_ascii_case("claude-code")
        || !is_enabled(cfg)
        || model_unsupported(model, cfg)
    {
        return all.to_vec();
    }

    all.iter()
        .filter(|t| !t.defer || t.always_load || discovered.contains(&t.name))
        .cloned()
        .collect()
}

/// Execute a `ToolSearch` invocation and return the synthetic `ToolResult`
/// the agent loop should feed back to the model. The result content is a
/// plain-text `<functions>{...}</functions>` block.
pub fn execute_tool_search(
    tool_use_id: &str,
    input: &serde_json::Value,
    all: &[ToolDefinition],
    cfg: &ToolSearchConfig,
) -> openfang_types::tool::ToolResult {
    let query = input.get("query").and_then(|v| v.as_str()).unwrap_or("");
    let max_results = input
        .get("max_results")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .unwrap_or(5);
    let engine = ToolSearchEngine::new(all, cfg);
    let matches = engine.execute(query, max_results);
    openfang_types::tool::ToolResult {
        tool_use_id: tool_use_id.to_string(),
        content: render_result(&matches, all),
        is_error: false,
    }
}

/// Names of tools that are deferred and have not yet been discovered.
/// These appear in the "Available On-Demand Tools" system-prompt section.
pub fn pending_names(all: &[ToolDefinition], discovered: &BTreeSet<String>) -> Vec<String> {
    let mut names: Vec<String> = all
        .iter()
        .filter(|t| t.defer && !t.always_load && !discovered.contains(&t.name))
        .map(|t| t.name.clone())
        .collect();
    names.sort();
    names
}

/// Search engine for `ToolSearch` invocations.
pub struct ToolSearchEngine<'a> {
    all: &'a [ToolDefinition],
    #[allow(dead_code)]
    cfg: &'a ToolSearchConfig,
}

impl<'a> ToolSearchEngine<'a> {
    pub fn new(all: &'a [ToolDefinition], cfg: &'a ToolSearchConfig) -> Self {
        Self { all, cfg }
    }

    /// Run a query, returning matched tool names (in order, up to `max_results`).
    pub fn execute(&self, query: &str, max_results: usize) -> Vec<String> {
        let trimmed = query.trim();
        let max_results = max_results.max(1);

        // §4.1 — select: prefix
        let lower = trimmed.to_lowercase();
        if let Some(rest) = lower.strip_prefix("select:") {
            let _ = rest;
            let raw = trimmed[7..].trim_start_matches(' ');
            let mut out = Vec::new();
            for name in raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                if let Some(t) = self
                    .all
                    .iter()
                    .find(|t| t.name.eq_ignore_ascii_case(name))
                {
                    out.push(t.name.clone());
                }
            }
            return out;
        }

        // §4.2 — exact match fast path
        if let Some(t) = self
            .all
            .iter()
            .find(|t| t.name.eq_ignore_ascii_case(trimmed))
        {
            return vec![t.name.clone()];
        }

        // §4.3 — MCP prefix shortcut
        if trimmed.starts_with("mcp__") && trimmed.len() > 5 {
            let prefix = trimmed.to_lowercase();
            let mut out: Vec<String> = self
                .all
                .iter()
                .filter(|t| t.defer && t.name.to_lowercase().starts_with(&prefix))
                .map(|t| t.name.clone())
                .take(max_results)
                .collect();
            out.sort();
            return out;
        }

        // §4.4 — keyword search
        self.keyword_search(trimmed, max_results)
    }

    fn keyword_search(&self, query: &str, max_results: usize) -> Vec<String> {
        let tokens: Vec<&str> = query.split_whitespace().collect();
        if tokens.is_empty() {
            return Vec::new();
        }

        let mut required: Vec<String> = Vec::new();
        let mut optional: Vec<String> = Vec::new();
        for t in &tokens {
            let lower = t.to_lowercase();
            if let Some(rest) = lower.strip_prefix('+') {
                if !rest.is_empty() {
                    required.push(rest.to_string());
                }
            } else {
                optional.push(lower);
            }
        }

        let all_terms: Vec<&String> = required.iter().chain(optional.iter()).collect();
        if all_terms.is_empty() {
            return Vec::new();
        }

        // Pre-build word-boundary regex per term once.
        let term_res: Vec<(&str, regex_lite::Regex)> = all_terms
            .iter()
            .filter_map(|t| {
                let pat = format!(r"\b{}\b", regex_escape(t));
                regex_lite::Regex::new(&pat).ok().map(|r| (t.as_str(), r))
            })
            .collect();

        let mut scored: Vec<(i32, &str)> = Vec::new();
        for tool in self.all {
            // Only consider deferred tools — the schemas of non-deferred tools
            // are already in the prompt and don't need fetching.
            if !tool.defer {
                continue;
            }
            let (parts, full) = parse_tool_name(&tool.name);
            let desc_lower = tool.description.to_lowercase();
            let hint_lower = tool.search_hint.as_deref().unwrap_or("").to_lowercase();
            let is_mcp = tool.is_mcp || tool.name.starts_with("mcp__");

            // Required terms must all match somewhere.
            if !required.is_empty() {
                let all_required_match = required.iter().all(|term| {
                    parts.iter().any(|p| p == term)
                        || parts.iter().any(|p| p.contains(term.as_str()))
                        || desc_lower.contains(term.as_str())
                        || hint_lower.contains(term.as_str())
                });
                if !all_required_match {
                    continue;
                }
            }

            let mut score: i32 = 0;
            for (term, re) in &term_res {
                let exact_word = parts.iter().any(|p| p == term);
                if exact_word {
                    score += if is_mcp { 12 } else { 10 };
                    continue;
                }
                let substr_part = parts.iter().any(|p| p.contains(term));
                if substr_part {
                    score += if is_mcp { 6 } else { 5 };
                }
                if score == 0 && full.contains(term) {
                    score += 3;
                }
                if !hint_lower.is_empty() && re.is_match(&hint_lower) {
                    score += 4;
                }
                if re.is_match(&desc_lower) {
                    score += 2;
                }
            }

            if score > 0 {
                scored.push((score, tool.name.as_str()));
            }
        }

        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
        scored
            .into_iter()
            .take(max_results)
            .map(|(_, n)| n.to_string())
            .collect()
    }
}

fn regex_escape(term: &str) -> String {
    let mut out = String::with_capacity(term.len());
    for ch in term.chars() {
        match ch {
            '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '\\'
            | '\0' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Parse a tool name into space-separated parts (lowercased) plus a `full`
/// joined string. Handles two naming conventions:
///   - MCP tools: `mcp__server__action` → ["server", "action"] (strip `mcp__`)
///   - CamelCase: `ToolSearch` → ["tool", "search"]
fn parse_tool_name(name: &str) -> (Vec<String>, String) {
    let base = name.strip_prefix("mcp__").unwrap_or(name);
    let parts: Vec<String> = if base.contains("__") || base.contains('_') {
        base.split('_')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_lowercase())
            .collect()
    } else {
        // CamelCase split: insert space at lower→upper boundary.
        let mut buf = String::with_capacity(base.len() * 2);
        let mut prev_lower = false;
        for ch in base.chars() {
            if ch.is_ascii_uppercase() && prev_lower {
                buf.push(' ');
            }
            buf.push(ch.to_ascii_lowercase());
            prev_lower = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        }
        buf.split_whitespace().map(|s| s.to_string()).collect()
    };
    let full = parts.join(" ");
    (parts, full)
}

/// Render the result of a `ToolSearch` invocation as plain text the model can
/// read. Emits a `<functions>...</functions>` block containing one
/// `<function>{json}</function>` line per matched tool. This mirrors the
/// canonical tool-block syntax Claude has been trained against.
pub fn render_result(matches: &[String], all: &[ToolDefinition]) -> String {
    if matches.is_empty() {
        return "No matching deferred tools found. Try a different query, or use \
            `select:<exact-name>` if you know the tool name."
            .to_string();
    }
    let mut out = String::from("<functions>\n");
    for name in matches {
        let Some(tool) = all.iter().find(|t| &t.name == name) else {
            continue;
        };
        let json = serde_json::json!({
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.input_schema,
        });
        out.push_str("<function>");
        out.push_str(&serde_json::to_string(&json).unwrap_or_default());
        out.push_str("</function>\n");
    }
    out.push_str("</functions>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use openfang_types::message::{ContentBlock, Message, MessageContent, MessageMetadata, Role};

    fn tool(name: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: format!("Description for {name}"),
            input_schema: serde_json::json!({"type": "object"}),
            defer: true,
            ..Default::default()
        }
    }

    fn cfg() -> ToolSearchConfig {
        ToolSearchConfig::default()
    }

    fn mk_msg(role: Role, blocks: Vec<ContentBlock>) -> Message {
        Message {
            role,
            content: MessageContent::Blocks(blocks),
            uuid: None,
            timestamp: None,
            session_id: None,
            metadata: MessageMetadata::default(),
        }
    }

    #[test]
    fn select_returns_exact_names() {
        let tools = vec![tool("Read"), tool("Edit"), tool("Grep")];
        let cfg_v = cfg();
        let engine = ToolSearchEngine::new(&tools, &cfg_v);
        let out = engine.execute("select:Read,Edit", 5);
        assert_eq!(out, vec!["Read".to_string(), "Edit".to_string()]);
    }

    #[test]
    fn select_is_case_insensitive() {
        let tools = vec![tool("Read")];
        let cfg_v = cfg(); let engine = ToolSearchEngine::new(&tools, &cfg_v);
        assert_eq!(engine.execute("select:read", 5), vec!["Read"]);
    }

    #[test]
    fn select_ignores_missing_and_returns_found() {
        let tools = vec![tool("Read")];
        let cfg_v = cfg(); let engine = ToolSearchEngine::new(&tools, &cfg_v);
        let out = engine.execute("select:Read,Nonexistent", 5);
        assert_eq!(out, vec!["Read".to_string()]);
    }

    #[test]
    fn exact_match_fast_path() {
        let tools = vec![tool("ToolSearch"), tool("Read")];
        let cfg_v = cfg(); let engine = ToolSearchEngine::new(&tools, &cfg_v);
        assert_eq!(engine.execute("read", 5), vec!["Read"]);
    }

    #[test]
    fn mcp_prefix_returns_server_tools() {
        let mut t1 = tool("mcp__slack__post_message");
        t1.is_mcp = true;
        let mut t2 = tool("mcp__slack__list_channels");
        t2.is_mcp = true;
        let mut t3 = tool("mcp__github__create_issue");
        t3.is_mcp = true;
        let tools = vec![t1, t2, t3];
        let cfg_v = cfg(); let engine = ToolSearchEngine::new(&tools, &cfg_v);
        let out = engine.execute("mcp__slack__", 10);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|n| n.starts_with("mcp__slack__")));
    }

    #[test]
    fn keyword_search_ranks_by_name_match() {
        let mut t1 = tool("mcp__slack__post_message");
        t1.is_mcp = true;
        let mut t2 = tool("mcp__github__create_issue");
        t2.is_mcp = true;
        let tools = vec![t1, t2];
        let cfg_v = cfg(); let engine = ToolSearchEngine::new(&tools, &cfg_v);
        let out = engine.execute("slack post", 5);
        assert_eq!(out, vec!["mcp__slack__post_message"]);
    }

    #[test]
    fn keyword_search_required_filters() {
        let mut t1 = tool("mcp__slack__post_message");
        t1.is_mcp = true;
        let mut t2 = tool("mcp__github__post_comment");
        t2.is_mcp = true;
        let tools = vec![t1, t2];
        let cfg_v = cfg(); let engine = ToolSearchEngine::new(&tools, &cfg_v);
        let out = engine.execute("+slack post", 5);
        assert_eq!(out, vec!["mcp__slack__post_message"]);
    }

    #[test]
    fn keyword_search_uses_description() {
        let mut t1 = tool("NotebookEdit");
        t1.description = "Edit a Jupyter notebook cell".to_string();
        t1.search_hint = Some("jupyter ipynb".to_string());
        let tools = vec![t1];
        let cfg_v = cfg(); let engine = ToolSearchEngine::new(&tools, &cfg_v);
        let out = engine.execute("jupyter", 5);
        assert_eq!(out, vec!["NotebookEdit"]);
    }

    #[test]
    fn keyword_search_skips_non_deferred() {
        let mut t1 = tool("Read");
        t1.defer = false;
        let tools = vec![t1];
        let cfg_v = cfg(); let engine = ToolSearchEngine::new(&tools, &cfg_v);
        // Even though name matches, non-deferred tools are not surfaced —
        // the schema is already in the prompt.
        assert_eq!(engine.execute("read", 5), vec!["Read"]); // exact-match fast path returns
        assert!(engine.execute("reading something", 5).is_empty()); // keyword pass skips
    }

    #[test]
    fn classify_deferral_priority() {
        let mut always = tool("Special");
        always.always_load = true;
        assert!(!classify_deferral(&always, &cfg()));

        let mut mcp = tool("mcp__slack__post");
        mcp.is_mcp = true;
        assert!(classify_deferral(&mcp, &cfg()));

        let mut cfg_no_mcp = cfg();
        cfg_no_mcp.always_defer_mcp = false;
        assert!(!classify_deferral(&mcp, &cfg_no_mcp));

        let skill = tool("MySkill");
        assert!(classify_deferral(&skill, &cfg()));

        let ts = tool_search_definition();
        assert!(!classify_deferral(&ts, &cfg()));
    }

    #[test]
    fn model_unsupported_matches_substring() {
        let c = cfg();
        assert!(model_unsupported("claude-haiku-4-5-20251001", &c));
        assert!(model_unsupported("claude-3-5-haiku-latest", &c));
        assert!(!model_unsupported("claude-sonnet-4-6", &c));
    }

    #[test]
    fn filter_for_request_drops_undiscovered() {
        let mut a = tool("A");
        a.defer = false;
        let b = tool("B"); // deferred
        let c = tool("C"); // deferred
        let tools = vec![a, b, c];
        let discovered: BTreeSet<String> = ["B".to_string()].into_iter().collect();

        let out = filter_for_request(&tools, &discovered, &cfg(), "claude-sonnet-4-6", false, "anthropic");
        let names: Vec<_> = out.iter().map(|t| t.name.clone()).collect();
        assert_eq!(names, vec!["A".to_string(), "B".to_string()]);
    }

    #[test]
    fn filter_for_request_passthrough_for_subagent() {
        let b = tool("B"); // deferred
        let tools = vec![b];
        let out = filter_for_request(
            &tools,
            &BTreeSet::new(),
            &cfg(),
            "claude-sonnet-4-6",
            true,
            "anthropic",
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn filter_for_request_passthrough_for_haiku() {
        let b = tool("B"); // deferred
        let tools = vec![b];
        let out = filter_for_request(
            &tools,
            &BTreeSet::new(),
            &cfg(),
            "claude-3-5-haiku-latest",
            false,
            "anthropic",
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn filter_for_request_passthrough_for_claude_code_provider() {
        let b = tool("B"); // deferred
        let tools = vec![b];
        let out = filter_for_request(
            &tools,
            &BTreeSet::new(),
            &cfg(),
            "claude-sonnet-4-6",
            false,
            "claude-code",
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn extract_discovered_from_history() {
        let result_text = render_result(
            &["mcp__slack__post_message".to_string()],
            &[tool("mcp__slack__post_message")],
        );
        let msgs = vec![
            mk_msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "tu_1".to_string(),
                    name: TOOL_SEARCH_NAME.to_string(),
                    input: serde_json::json!({"query": "select:mcp__slack__post_message"}),
                    provider_metadata: None,
                }],
            ),
            mk_msg(
                Role::User,
                vec![ContentBlock::ToolResult {
                    tool_use_id: "tu_1".to_string(),
                    tool_name: TOOL_SEARCH_NAME.to_string(),
                    content: result_text,
                    is_error: false,
                }],
            ),
        ];

        let out = extract_discovered(&msgs);
        assert!(out.contains("mcp__slack__post_message"));
    }

    #[test]
    fn extract_discovered_falls_back_to_select_query() {
        // Result text was wiped (e.g. by compactor) but the assistant's
        // `select:` query still names the tools.
        let msgs = vec![
            mk_msg(
                Role::Assistant,
                vec![ContentBlock::ToolUse {
                    id: "tu_2".to_string(),
                    name: TOOL_SEARCH_NAME.to_string(),
                    input: serde_json::json!({"query": "select:Foo,Bar"}),
                    provider_metadata: None,
                }],
            ),
            mk_msg(
                Role::User,
                vec![ContentBlock::ToolResult {
                    tool_use_id: "tu_2".to_string(),
                    tool_name: TOOL_SEARCH_NAME.to_string(),
                    content: "[compacted]".to_string(),
                    is_error: false,
                }],
            ),
        ];
        let out = extract_discovered(&msgs);
        assert!(out.contains("Foo"));
        assert!(out.contains("Bar"));
    }

    #[test]
    fn render_result_empty_returns_fallback_text() {
        let out = render_result(&[], &[]);
        assert!(out.starts_with("No matching deferred tools"));
    }

    #[test]
    fn render_result_emits_function_lines() {
        let tools = vec![tool("Foo")];
        let out = render_result(&["Foo".to_string()], &tools);
        assert!(out.contains("<functions>"));
        assert!(out.contains("<function>"));
        assert!(out.contains("\"name\":\"Foo\""));
    }

    #[test]
    fn parse_tool_name_camel_case() {
        let (parts, full) = parse_tool_name("NotebookEdit");
        assert_eq!(parts, vec!["notebook", "edit"]);
        assert_eq!(full, "notebook edit");
    }

    #[test]
    fn parse_tool_name_mcp_format() {
        let (parts, _full) = parse_tool_name("mcp__slack__post_message");
        assert_eq!(parts, vec!["slack", "post", "message"]);
    }

    #[test]
    fn pending_names_excludes_discovered_and_always_load() {
        let mut a = tool("A");
        a.always_load = true;
        let b = tool("B");
        let c = tool("C");
        let tools = vec![a, b, c];
        let discovered: BTreeSet<String> = ["B".to_string()].into_iter().collect();
        let out = pending_names(&tools, &discovered);
        assert_eq!(out, vec!["C".to_string()]);
    }
}
