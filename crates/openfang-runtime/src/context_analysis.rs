//! Rich context window analysis, grid visualization, and actionable suggestions.
//!
//! Implements the `/context` command spec: per-category token breakdown,
//! Unicode grid, per-tool/file detail, and optimization suggestions.

use std::collections::HashMap;

use openfang_types::message::{ContentBlock, Message, MessageContent, Role};
use openfang_types::tool::ToolDefinition;
use serde::Serialize;

use crate::compactor::rough_token_count_estimation;

// ---------------------------------------------------------------------------
// Constants (spec section 16)
// ---------------------------------------------------------------------------

const NEAR_CAPACITY_PERCENT: f64 = 80.0;
const LARGE_TOOL_RESULT_PERCENT: f64 = 15.0;
const LARGE_TOOL_RESULT_TOKENS: usize = 10_000;
const READ_BLOAT_PERCENT: f64 = 5.0;
const MEMORY_HIGH_PERCENT: f64 = 5.0;
const MEMORY_HIGH_TOKENS: usize = 5_000;
const MANUAL_COMPACT_BUFFER_TOKENS: usize = 3_000;

// Grid symbols (spec section 9.5)
const SYM_FULL: char = '\u{25C9}'; // ◉
const SYM_PARTIAL: char = '\u{25D0}'; // ◐
const SYM_FREE: char = '\u{25FB}'; // ◻
const SYM_BUFFER: char = '\u{26A1}'; // ⚡

// ANSI color codes
const ANSI_RESET: &str = "\x1b[0m";
const ANSI_BOLD: &str = "\x1b[1m";
const ANSI_DIM: &str = "\x1b[2m";

// ---------------------------------------------------------------------------
// Data model (spec section 7)
// ---------------------------------------------------------------------------

/// Main output of `/context` analysis.
#[derive(Debug, Clone, Serialize)]
pub struct ContextData {
    pub categories: Vec<ContextCategory>,
    pub total_tokens: usize,
    pub max_tokens: usize,
    pub percentage: f64,
    pub grid_rows: Vec<Vec<GridSquare>>,
    pub model: String,
    pub memory_files: Vec<MemoryFileInfo>,
    pub mcp_tools: Vec<McpToolInfo>,
    pub agents: Vec<AgentInfo>,
    pub skills: Option<SkillInfo>,
    pub auto_compact_threshold: Option<usize>,
    pub is_auto_compact_enabled: bool,
    pub message_breakdown: Option<MessageBreakdown>,
    pub api_usage: Option<ApiUsage>,
    pub suggestions: Vec<ContextSuggestion>,
    pub system_prompt_sections: Vec<SystemPromptSection>,
    pub system_tools: Vec<SystemToolDetail>,
}

/// A single category in the token breakdown.
#[derive(Debug, Clone, Serialize)]
pub struct ContextCategory {
    pub name: String,
    pub tokens: usize,
    pub color: CategoryColor,
    pub is_deferred: bool,
}

/// Color key for categories (mapped to ANSI in rendering).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CategoryColor {
    PromptBorder,
    Inactive,
    Cyan,
    Permission,
    Claude,
    Warning,
    Purple,
    Dimmed,
    Buffer,
}

impl CategoryColor {
    fn ansi_fg(self) -> &'static str {
        match self {
            Self::PromptBorder => "\x1b[34m",  // blue
            Self::Inactive => "\x1b[90m",      // dark gray
            Self::Cyan => "\x1b[36m",          // cyan
            Self::Permission => "\x1b[32m",    // green
            Self::Claude => "\x1b[95m",        // bright magenta
            Self::Warning => "\x1b[33m",       // yellow
            Self::Purple => "\x1b[35m",        // magenta
            Self::Dimmed => "\x1b[90m",        // dark gray
            Self::Buffer => "\x1b[93m",        // bright yellow
        }
    }
}

/// One square in the grid visualization.
#[derive(Debug, Clone, Serialize)]
pub struct GridSquare {
    pub color: CategoryColor,
    pub category_name: String,
    pub tokens: usize,
    pub percentage: f64,
    pub square_fullness: f64,
}

/// Actionable suggestion to reduce context usage.
#[derive(Debug, Clone, Serialize)]
pub struct ContextSuggestion {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub savings_tokens: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info = 0,
    Warning = 1,
}

/// Per-message-type token breakdown.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MessageBreakdown {
    pub tool_call_tokens: usize,
    pub tool_result_tokens: usize,
    pub attachment_tokens: usize,
    pub assistant_message_tokens: usize,
    pub user_message_tokens: usize,
    pub tool_calls_by_type: Vec<ToolTokenEntry>,
    pub attachments_by_type: Vec<AttachmentTokenEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolTokenEntry {
    pub name: String,
    pub call_tokens: usize,
    pub result_tokens: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttachmentTokenEntry {
    pub name: String,
    pub tokens: usize,
}

/// Actual API usage from the last LLM response.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ApiUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_creation: u64,
    pub cache_read: u64,
}

impl ApiUsage {
    pub fn total_input(&self) -> u64 {
        self.input_tokens + self.cache_creation + self.cache_read
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryFileInfo {
    pub file_type: String,
    pub path: String,
    pub tokens: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct McpToolInfo {
    pub name: String,
    pub server_name: String,
    pub tokens: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentInfo {
    pub agent_type: String,
    pub source: String,
    pub tokens: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkillInfo {
    pub total_skills: usize,
    pub included_skills: usize,
    pub tokens: usize,
    pub skill_frontmatter: Vec<SkillFrontmatterEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkillFrontmatterEntry {
    pub name: String,
    pub source: String,
    pub tokens: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemPromptSection {
    pub name: String,
    pub tokens: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemToolDetail {
    pub name: String,
    pub tokens: usize,
    pub is_deferred: bool,
}

// ---------------------------------------------------------------------------
// Analysis input (bridge from kernel)
// ---------------------------------------------------------------------------

/// Everything the analysis engine needs, pre-collected by the kernel.
pub struct AnalysisInput {
    pub messages: Vec<Message>,
    pub model_id: String,
    pub context_window: usize,
    pub max_output_tokens: usize,
    pub system_prompt: String,
    pub tools: Vec<ToolDefinition>,
    pub mcp_tools: Vec<ToolDefinition>,
    /// (file_type, path, content)
    pub memory_files: Vec<(String, String, String)>,
    /// (name, source, estimated_tokens)
    pub skill_entries: Vec<(String, String, usize)>,
    /// (agent_type, source)
    pub custom_agents: Vec<(String, String)>,
    pub auto_compact_enabled: bool,
    pub autocompact_buffer_tokens: usize,
    pub terminal_width: Option<u16>,
    pub last_api_usage: Option<ApiUsage>,
}

// ---------------------------------------------------------------------------
// Token formatting utility
// ---------------------------------------------------------------------------

pub fn format_tokens(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        format!("{n}")
    }
}

// ---------------------------------------------------------------------------
// Counting functions (spec section 6)
// ---------------------------------------------------------------------------

/// Split system prompt on markdown headings and count tokens per section.
fn count_system_prompt_sections(system_prompt: &str) -> Vec<SystemPromptSection> {
    let mut sections = Vec::new();
    let mut current_name = String::from("Preamble");
    let mut current_text = String::new();

    for line in system_prompt.lines() {
        if let Some(heading) = line.strip_prefix("## ").or_else(|| line.strip_prefix("# ")) {
            // Flush previous section
            if !current_text.is_empty() {
                let tokens = rough_token_count_estimation(&current_text, 4);
                if tokens > 0 {
                    sections.push(SystemPromptSection {
                        name: current_name,
                        tokens,
                    });
                }
            }
            current_name = heading.trim().to_string();
            current_text.clear();
        } else {
            current_text.push_str(line);
            current_text.push('\n');
        }
    }
    // Flush last section
    if !current_text.is_empty() {
        let tokens = rough_token_count_estimation(&current_text, 4);
        if tokens > 0 {
            sections.push(SystemPromptSection {
                name: current_name,
                tokens,
            });
        }
    }
    sections
}

/// Count tokens for each memory/identity file.
fn count_memory_file_tokens(
    files: &[(String, String, String)],
) -> (usize, Vec<MemoryFileInfo>) {
    let mut total = 0;
    let mut infos = Vec::with_capacity(files.len());
    for (file_type, path, content) in files {
        let tokens = rough_token_count_estimation(content, 4);
        total += tokens;
        infos.push(MemoryFileInfo {
            file_type: file_type.clone(),
            path: path.clone(),
            tokens,
        });
    }
    (total, infos)
}

/// Count tokens for built-in (non-MCP) tools.
fn count_builtin_tool_tokens(tools: &[ToolDefinition]) -> (usize, Vec<SystemToolDetail>) {
    let mut total = 0;
    let mut details = Vec::with_capacity(tools.len());
    for tool in tools {
        let schema_str = serde_json::to_string(&tool.input_schema).unwrap_or_default();
        let combined = format!("{}{}{}", tool.name, tool.description, schema_str);
        let tokens = rough_token_count_estimation(&combined, 4);
        total += tokens;
        details.push(SystemToolDetail {
            name: tool.name.clone(),
            tokens,
            is_deferred: false,
        });
    }
    (total, details)
}

/// Count tokens for MCP tools, extracting server name from naming convention.
fn count_mcp_tool_tokens(mcp_tools: &[ToolDefinition]) -> (usize, Vec<McpToolInfo>) {
    let mut total = 0;
    let mut infos = Vec::with_capacity(mcp_tools.len());
    for tool in mcp_tools {
        let schema_str = serde_json::to_string(&tool.input_schema).unwrap_or_default();
        let combined = format!("{}{}{}", tool.name, tool.description, schema_str);
        let tokens = rough_token_count_estimation(&combined, 4);
        total += tokens;

        // Extract server name from "mcp__server__tool" naming convention
        let server_name = tool
            .name
            .strip_prefix("mcp__")
            .and_then(|rest| rest.split("__").next())
            .unwrap_or("unknown")
            .to_string();

        infos.push(McpToolInfo {
            name: tool.name.clone(),
            server_name,
            tokens,
        });
    }
    (total, infos)
}

/// Count tokens for custom agent definitions.
fn count_agent_tokens(agents: &[(String, String)]) -> (usize, Vec<AgentInfo>) {
    let mut total = 0;
    let mut infos = Vec::with_capacity(agents.len());
    for (agent_type, source) in agents {
        let combined = format!("{agent_type}{source}");
        let tokens = rough_token_count_estimation(&combined, 4);
        total += tokens;
        infos.push(AgentInfo {
            agent_type: agent_type.clone(),
            source: source.clone(),
            tokens,
        });
    }
    (total, infos)
}

/// Aggregate pre-computed skill token estimates.
fn count_skill_tokens(entries: &[(String, String, usize)]) -> Option<SkillInfo> {
    if entries.is_empty() {
        return None;
    }
    let mut total = 0;
    let mut frontmatter = Vec::with_capacity(entries.len());
    for (name, source, tokens) in entries {
        total += tokens;
        frontmatter.push(SkillFrontmatterEntry {
            name: name.clone(),
            source: source.clone(),
            tokens: *tokens,
        });
    }
    Some(SkillInfo {
        total_skills: entries.len(),
        included_skills: entries.len(),
        tokens: total,
        skill_frontmatter: frontmatter,
    })
}

/// Walk all messages and produce a per-type token breakdown.
fn analyze_messages(messages: &[Message]) -> MessageBreakdown {
    let mut breakdown = MessageBreakdown::default();
    // Map tool_use_id -> tool name for attribution
    let mut tool_id_to_name: HashMap<String, String> = HashMap::new();
    // Accumulate per-tool tokens
    let mut call_by_tool: HashMap<String, usize> = HashMap::new();
    let mut result_by_tool: HashMap<String, usize> = HashMap::new();
    let mut attach_by_type: HashMap<String, usize> = HashMap::new();

    for msg in messages {
        let blocks = match &msg.content {
            MessageContent::Text(s) => {
                let tokens = rough_token_count_estimation(s, 4);
                match msg.role {
                    Role::Assistant => breakdown.assistant_message_tokens += tokens,
                    Role::User => breakdown.user_message_tokens += tokens,
                    Role::System => breakdown.user_message_tokens += tokens,
                }
                continue;
            }
            MessageContent::Blocks(b) => b,
        };

        for block in blocks {
            match block {
                ContentBlock::ToolUse { id, name, input, .. } => {
                    let input_str = serde_json::to_string(input).unwrap_or_default();
                    let tokens =
                        rough_token_count_estimation(&format!("{name}{input_str}"), 4);
                    breakdown.tool_call_tokens += tokens;
                    tool_id_to_name.insert(id.clone(), name.clone());
                    *call_by_tool.entry(name.clone()).or_default() += tokens;
                }
                ContentBlock::ToolResult {
                    tool_use_id,
                    tool_name,
                    content,
                    ..
                } => {
                    let tokens = rough_token_count_estimation(content, 4);
                    breakdown.tool_result_tokens += tokens;
                    // Attribute to tool name (prefer mapped name, fall back to tool_name field)
                    let name = tool_id_to_name
                        .get(tool_use_id)
                        .cloned()
                        .unwrap_or_else(|| tool_name.clone());
                    *result_by_tool.entry(name).or_default() += tokens;
                }
                ContentBlock::Text { text, .. } => {
                    let tokens = rough_token_count_estimation(text, 4);
                    match msg.role {
                        Role::Assistant => breakdown.assistant_message_tokens += tokens,
                        Role::User => breakdown.user_message_tokens += tokens,
                        Role::System => breakdown.user_message_tokens += tokens,
                    }
                }
                ContentBlock::Image { data, .. } => {
                    // Images: flat 2000 tokens (same as compactor)
                    let tokens = 2000.min(data.len() / 4);
                    let tokens = tokens.max(2000);
                    breakdown.attachment_tokens += tokens;
                    *attach_by_type.entry("image".to_string()).or_default() += tokens;
                }
                ContentBlock::Thinking { thinking, .. } => {
                    let tokens = rough_token_count_estimation(thinking, 4);
                    breakdown.assistant_message_tokens += tokens;
                }
                ContentBlock::Unknown => {}
            }
        }
    }

    // Build sorted per-tool entries (combined call+result, descending)
    let mut all_tools: HashMap<String, (usize, usize)> = HashMap::new();
    for (name, call_tok) in &call_by_tool {
        all_tools.entry(name.clone()).or_default().0 += call_tok;
    }
    for (name, res_tok) in &result_by_tool {
        all_tools.entry(name.clone()).or_default().1 += res_tok;
    }
    let mut tool_entries: Vec<ToolTokenEntry> = all_tools
        .into_iter()
        .map(|(name, (c, r))| ToolTokenEntry {
            name,
            call_tokens: c,
            result_tokens: r,
        })
        .collect();
    tool_entries.sort_by(|a, b| {
        (b.call_tokens + b.result_tokens).cmp(&(a.call_tokens + a.result_tokens))
    });
    breakdown.tool_calls_by_type = tool_entries;

    let mut attach_entries: Vec<AttachmentTokenEntry> = attach_by_type
        .into_iter()
        .map(|(name, tokens)| AttachmentTokenEntry { name, tokens })
        .collect();
    attach_entries.sort_by(|a, b| b.tokens.cmp(&a.tokens));
    breakdown.attachments_by_type = attach_entries;

    breakdown
}

// ---------------------------------------------------------------------------
// Core analysis orchestrator (spec section 6)
// ---------------------------------------------------------------------------

/// Analyze context usage and produce a full `ContextData` report.
pub fn analyze_context_usage(input: &AnalysisInput) -> ContextData {
    // 1. Count each category
    let sp_sections = count_system_prompt_sections(&input.system_prompt);
    let sp_total: usize = sp_sections.iter().map(|s| s.tokens).sum();

    let (builtin_total, system_tools) = count_builtin_tool_tokens(&input.tools);
    let (mcp_total, mcp_tools) = count_mcp_tool_tokens(&input.mcp_tools);
    let (memory_total, memory_files) = count_memory_file_tokens(&input.memory_files);
    let (agent_total, agents) = count_agent_tokens(&input.custom_agents);
    let skills = count_skill_tokens(&input.skill_entries);
    let skill_total = skills.as_ref().map_or(0, |s| s.tokens);
    let msg_breakdown = analyze_messages(&input.messages);
    let msg_total = msg_breakdown.tool_call_tokens
        + msg_breakdown.tool_result_tokens
        + msg_breakdown.attachment_tokens
        + msg_breakdown.assistant_message_tokens
        + msg_breakdown.user_message_tokens;

    // 2. Build categories in spec order (section 8)
    let mut categories = Vec::new();

    if sp_total > 0 {
        categories.push(ContextCategory {
            name: "System prompt".into(),
            tokens: sp_total,
            color: CategoryColor::PromptBorder,
            is_deferred: false,
        });
    }
    if builtin_total > 0 {
        categories.push(ContextCategory {
            name: "System tools".into(),
            tokens: builtin_total,
            color: CategoryColor::Inactive,
            is_deferred: false,
        });
    }
    if mcp_total > 0 {
        categories.push(ContextCategory {
            name: "MCP tools".into(),
            tokens: mcp_total,
            color: CategoryColor::Cyan,
            is_deferred: false,
        });
    }
    if agent_total > 0 {
        categories.push(ContextCategory {
            name: "Custom agents".into(),
            tokens: agent_total,
            color: CategoryColor::Permission,
            is_deferred: false,
        });
    }
    if memory_total > 0 {
        categories.push(ContextCategory {
            name: "Memory files".into(),
            tokens: memory_total,
            color: CategoryColor::Claude,
            is_deferred: false,
        });
    }
    if skill_total > 0 {
        categories.push(ContextCategory {
            name: "Skills".into(),
            tokens: skill_total,
            color: CategoryColor::Warning,
            is_deferred: false,
        });
    }
    if msg_total > 0 {
        categories.push(ContextCategory {
            name: "Messages".into(),
            tokens: msg_total,
            color: CategoryColor::Purple,
            is_deferred: false,
        });
    }

    // 3. Calculate usage and reserved buffer
    let actual_usage: usize = categories
        .iter()
        .filter(|c| !c.is_deferred)
        .map(|c| c.tokens)
        .sum();

    let reserved_tokens = if input.auto_compact_enabled {
        input.autocompact_buffer_tokens
    } else {
        MANUAL_COMPACT_BUFFER_TOKENS
    };

    let auto_compact_threshold = if input.auto_compact_enabled {
        Some(input.context_window.saturating_sub(input.autocompact_buffer_tokens))
    } else {
        None
    };

    // Buffer category
    let buffer_name = if input.auto_compact_enabled {
        "Autocompact buffer"
    } else {
        "Manual compact buffer"
    };
    categories.push(ContextCategory {
        name: buffer_name.into(),
        tokens: reserved_tokens,
        color: CategoryColor::Buffer,
        is_deferred: false,
    });

    // Free space
    let free_tokens = input
        .context_window
        .saturating_sub(actual_usage)
        .saturating_sub(reserved_tokens);
    categories.push(ContextCategory {
        name: "Free space".into(),
        tokens: free_tokens,
        color: CategoryColor::Dimmed,
        is_deferred: false,
    });

    // 4. Prefer API usage for total if available, otherwise use estimation
    let total_tokens = input
        .last_api_usage
        .map(|u| u.total_input() as usize)
        .unwrap_or(actual_usage);

    let percentage = if input.context_window > 0 {
        ((total_tokens as f64 / input.context_window as f64) * 100.0)
            .clamp(0.0, 100.0)
            .round()
    } else {
        0.0
    };

    // 5. Build grid
    let grid_rows = build_grid(
        &categories,
        input.context_window,
        input.terminal_width,
    );

    // 6. Generate suggestions
    let suggestions = generate_suggestions(
        percentage,
        input.auto_compact_enabled,
        input.context_window,
        &msg_breakdown,
        &memory_files,
        memory_total,
    );

    ContextData {
        categories,
        total_tokens,
        max_tokens: input.context_window,
        percentage,
        grid_rows,
        model: input.model_id.clone(),
        memory_files,
        mcp_tools,
        agents,
        skills,
        auto_compact_threshold,
        is_auto_compact_enabled: input.auto_compact_enabled,
        message_breakdown: Some(msg_breakdown),
        api_usage: input.last_api_usage,
        suggestions,
        system_prompt_sections: sp_sections,
        system_tools,
    }
}

// ---------------------------------------------------------------------------
// Grid visualization (spec section 9)
// ---------------------------------------------------------------------------

fn build_grid(
    categories: &[ContextCategory],
    context_window: usize,
    terminal_width: Option<u16>,
) -> Vec<Vec<GridSquare>> {
    let tw = terminal_width.unwrap_or(80) as usize;
    let is_1m = context_window >= 1_000_000;

    let (grid_width, grid_height) = match (is_1m, tw >= 80) {
        (false, false) => (5, 5),
        (false, true) => (10, 10),
        (true, false) => (5, 10),
        (true, true) => (20, 10),
    };
    let total_squares = grid_width * grid_height;

    if context_window == 0 {
        return Vec::new();
    }

    // Allocate squares proportionally
    struct Alloc {
        cat_idx: usize,
        squares: usize,
        fullness_last: f64,
    }

    let mut allocs: Vec<Alloc> = Vec::new();
    let mut used_squares = 0usize;

    for (i, cat) in categories.iter().enumerate() {
        let exact = (cat.tokens as f64 / context_window as f64) * total_squares as f64;
        let is_free = cat.name == "Free space";

        let squares = if is_free {
            exact.round() as usize
        } else if exact > 0.0 {
            (exact.round() as usize).max(1)
        } else {
            0
        };

        let whole = exact.floor() as usize;
        let fractional = exact - whole as f64;
        let fullness_last = if squares > 0 && squares > whole {
            fractional
        } else {
            1.0
        };

        allocs.push(Alloc {
            cat_idx: i,
            squares,
            fullness_last: if fullness_last == 0.0 {
                1.0
            } else {
                fullness_last
            },
        });
        used_squares += squares;
    }

    // Adjust to fit exactly total_squares
    if used_squares > total_squares {
        // Shrink free space first
        if let Some(free_alloc) = allocs.iter_mut().find(|a| {
            categories[a.cat_idx].name == "Free space"
        }) {
            let excess = used_squares - total_squares;
            let reduce = excess.min(free_alloc.squares);
            free_alloc.squares -= reduce;
            used_squares -= reduce;
        }
        // If still over, shrink buffer
        if used_squares > total_squares {
            if let Some(buf_alloc) = allocs.iter_mut().find(|a| {
                categories[a.cat_idx].name.contains("buffer")
            }) {
                let excess = used_squares - total_squares;
                let reduce = excess.min(buf_alloc.squares);
                buf_alloc.squares -= reduce;
            }
        }
    } else if used_squares < total_squares {
        // Give extra to free space
        if let Some(free_alloc) = allocs.iter_mut().find(|a| {
            categories[a.cat_idx].name == "Free space"
        }) {
            free_alloc.squares += total_squares - used_squares;
        }
    }

    // Build flat list of squares in rendering order:
    // content categories -> free space -> buffer
    let mut flat: Vec<GridSquare> = Vec::with_capacity(total_squares);

    let content_indices: Vec<usize> = allocs
        .iter()
        .enumerate()
        .filter(|(_, a)| {
            let name = &categories[a.cat_idx].name;
            name != "Free space" && !name.contains("buffer")
        })
        .map(|(i, _)| i)
        .collect();
    let free_idx = allocs
        .iter()
        .position(|a| categories[a.cat_idx].name == "Free space");
    let buffer_idx = allocs
        .iter()
        .position(|a| categories[a.cat_idx].name.contains("buffer"));

    let ordered: Vec<usize> = content_indices
        .into_iter()
        .chain(free_idx)
        .chain(buffer_idx)
        .collect();

    for alloc_idx in ordered {
        let alloc = &allocs[alloc_idx];
        let cat = &categories[alloc.cat_idx];
        let pct = if context_window > 0 {
            (cat.tokens as f64 / context_window as f64) * 100.0
        } else {
            0.0
        };

        for sq_i in 0..alloc.squares {
            let fullness = if sq_i + 1 == alloc.squares {
                alloc.fullness_last
            } else {
                1.0
            };
            flat.push(GridSquare {
                color: cat.color,
                category_name: cat.name.clone(),
                tokens: cat.tokens,
                percentage: pct,
                square_fullness: fullness,
            });
        }
    }

    // Chunk into rows
    flat.chunks(grid_width)
        .map(|chunk| chunk.to_vec())
        .collect()
}

// ---------------------------------------------------------------------------
// Suggestion generation (spec section 12)
// ---------------------------------------------------------------------------

fn generate_suggestions(
    percentage: f64,
    auto_compact_enabled: bool,
    context_window: usize,
    breakdown: &MessageBreakdown,
    memory_files: &[MemoryFileInfo],
    memory_total: usize,
) -> Vec<ContextSuggestion> {
    let mut suggestions = Vec::new();

    // 1. Near capacity
    if percentage >= NEAR_CAPACITY_PERCENT {
        let detail = if auto_compact_enabled {
            "Use /compact now to control what gets kept."
        } else {
            "Use /compact or enable autocompact in config."
        };
        suggestions.push(ContextSuggestion {
            severity: Severity::Warning,
            title: "Near context capacity".into(),
            detail: detail.into(),
            savings_tokens: None,
        });
    }

    // 2. Large tool results
    let mut flagged_read = false;

    for entry in &breakdown.tool_calls_by_type {
        let result_pct = if context_window > 0 {
            (entry.result_tokens as f64 / context_window as f64) * 100.0
        } else {
            0.0
        };

        if result_pct > LARGE_TOOL_RESULT_PERCENT
            && entry.result_tokens > LARGE_TOOL_RESULT_TOKENS
        {
            let (advice, savings_pct) = tool_specific_advice(&entry.name);
            let savings = (entry.result_tokens as f64 * savings_pct) as usize;

            suggestions.push(ContextSuggestion {
                severity: Severity::Warning,
                title: format!("Large {} results ({:.0}% of context)", entry.name, result_pct),
                detail: advice.into(),
                savings_tokens: Some(savings),
            });

            if entry.name == "Read" || entry.name == "file_read" {
                flagged_read = true;
            }
        }
    }

    // 3. Read result bloat (if not already flagged)
    if !flagged_read {
        let read_tokens: usize = breakdown
            .tool_calls_by_type
            .iter()
            .filter(|e| e.name == "Read" || e.name == "file_read")
            .map(|e| e.result_tokens)
            .sum();
        let read_pct = if context_window > 0 {
            (read_tokens as f64 / context_window as f64) * 100.0
        } else {
            0.0
        };
        if read_pct >= READ_BLOAT_PERCENT && read_tokens >= LARGE_TOOL_RESULT_TOKENS {
            suggestions.push(ContextSuggestion {
                severity: Severity::Info,
                title: format!("Read results using {:.1}% of context", read_pct),
                detail: "Reference earlier reads or use offset/limit parameters.".into(),
                savings_tokens: Some((read_tokens as f64 * 0.3) as usize),
            });
        }
    }

    // 4. Memory bloat
    let memory_pct = if context_window > 0 {
        (memory_total as f64 / context_window as f64) * 100.0
    } else {
        0.0
    };
    if memory_pct >= MEMORY_HIGH_PERCENT && memory_total >= MEMORY_HIGH_TOKENS {
        let mut top_files: Vec<&MemoryFileInfo> = memory_files.iter().collect();
        top_files.sort_by(|a, b| b.tokens.cmp(&a.tokens));
        let top3: Vec<String> = top_files
            .iter()
            .take(3)
            .map(|f| format!("{} ({})", f.path, format_tokens(f.tokens)))
            .collect();

        suggestions.push(ContextSuggestion {
            severity: Severity::Info,
            title: format!("Memory files using {:.1}% of context", memory_pct),
            detail: format!("Largest: {}. Review with /memory.", top3.join(", ")),
            savings_tokens: Some((memory_total as f64 * 0.3) as usize),
        });
    }

    // 5. Autocompact disabled (50-79%)
    if !auto_compact_enabled
        && (50.0..NEAR_CAPACITY_PERCENT).contains(&percentage)
    {
        suggestions.push(ContextSuggestion {
            severity: Severity::Info,
            title: "Autocompact is disabled".into(),
            detail: "Enable autocompact in config or use /compact manually.".into(),
            savings_tokens: None,
        });
    }

    // Sort: warnings first, then by savings descending
    suggestions.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| {
                let sa = a.savings_tokens.unwrap_or(0);
                let sb = b.savings_tokens.unwrap_or(0);
                sb.cmp(&sa)
            })
    });

    suggestions
}

fn tool_specific_advice(tool_name: &str) -> (&'static str, f64) {
    match tool_name {
        "Bash" | "shell_exec" => (
            "Use head, tail, or grep to limit command output.",
            0.5,
        ),
        "Read" | "file_read" => (
            "Use offset/limit parameters to read only needed sections.",
            0.3,
        ),
        "Grep" | "file_search" => (
            "Refine search pattern or use Glob for file-level matching.",
            0.3,
        ),
        "WebFetch" | "web_fetch" => (
            "Extract specific content instead of fetching entire pages.",
            0.4,
        ),
        _ => (
            "Consider reducing tool output or filtering results.",
            0.2,
        ),
    }
}

// ---------------------------------------------------------------------------
// Terminal rendering (spec sections 9-10)
// ---------------------------------------------------------------------------

/// Render a full context report as ANSI-colored terminal output.
pub fn render_context_terminal(data: &ContextData) -> String {
    let mut out = String::with_capacity(4096);

    // Header
    out.push_str(&format!(
        "\n{ANSI_BOLD}  Context Usage{ANSI_RESET}\n\n"
    ));

    // Grid
    for row in &data.grid_rows {
        out.push_str("  ");
        for sq in row {
            let sym = grid_symbol(sq);
            let color = sq.color.ansi_fg();
            out.push_str(&format!("{color}{sym}{ANSI_RESET}"));
        }
        out.push('\n');
    }
    out.push('\n');

    // Model + summary
    out.push_str(&format!(
        "  {ANSI_BOLD}Model:{ANSI_RESET} {}\n",
        data.model
    ));
    out.push_str(&format!(
        "  {ANSI_BOLD}Tokens:{ANSI_RESET} {} / {} ({:.0}%)\n\n",
        format_tokens(data.total_tokens),
        format_tokens(data.max_tokens),
        data.percentage
    ));

    // Category legend
    for cat in &data.categories {
        let color = cat.color.ansi_fg();
        let sym = if cat.name == "Free space" {
            SYM_FREE
        } else if cat.name.contains("buffer") {
            SYM_BUFFER
        } else {
            SYM_FULL
        };
        let pct = if data.max_tokens > 0 {
            (cat.tokens as f64 / data.max_tokens as f64) * 100.0
        } else {
            0.0
        };
        let deferred_tag = if cat.is_deferred { " (deferred)" } else { "" };
        out.push_str(&format!(
            "  {color}{sym}{ANSI_RESET} {:<25} {:>8}  {:>5.1}%{deferred_tag}\n",
            cat.name,
            format_tokens(cat.tokens),
            pct
        ));
    }
    out.push('\n');

    // MCP tools detail
    if !data.mcp_tools.is_empty() {
        out.push_str(&format!("  {ANSI_BOLD}MCP Tools:{ANSI_RESET}\n"));
        for tool in &data.mcp_tools {
            out.push_str(&format!(
                "    {:<30} {:<15} {:>6}\n",
                tool.name,
                tool.server_name,
                format_tokens(tool.tokens)
            ));
        }
        out.push('\n');
    }

    // Memory files detail
    if !data.memory_files.is_empty() {
        out.push_str(&format!("  {ANSI_BOLD}Memory Files:{ANSI_RESET}\n"));
        for f in &data.memory_files {
            out.push_str(&format!(
                "    {:<10} {:<35} {:>6}\n",
                f.file_type,
                f.path,
                format_tokens(f.tokens)
            ));
        }
        out.push('\n');
    }

    // Agents detail
    if !data.agents.is_empty() {
        out.push_str(&format!("  {ANSI_BOLD}Custom Agents:{ANSI_RESET}\n"));
        for a in &data.agents {
            out.push_str(&format!(
                "    {:<25} {:<15} {:>6}\n",
                a.agent_type,
                a.source,
                format_tokens(a.tokens)
            ));
        }
        out.push('\n');
    }

    // Skills detail
    if let Some(ref skills) = data.skills {
        out.push_str(&format!(
            "  {ANSI_BOLD}Skills ({}/{}):{ANSI_RESET}\n",
            skills.included_skills, skills.total_skills
        ));
        for s in &skills.skill_frontmatter {
            out.push_str(&format!(
                "    {:<30} {:<15} {:>6}\n",
                s.name,
                s.source,
                format_tokens(s.tokens)
            ));
        }
        out.push('\n');
    }

    // Message breakdown
    if let Some(ref mb) = data.message_breakdown {
        let total_msg = mb.tool_call_tokens
            + mb.tool_result_tokens
            + mb.attachment_tokens
            + mb.assistant_message_tokens
            + mb.user_message_tokens;
        if total_msg > 0 {
            out.push_str(&format!("  {ANSI_BOLD}Message Breakdown:{ANSI_RESET}\n"));
            if mb.user_message_tokens > 0 {
                out.push_str(&format!(
                    "    User messages          {:>8}\n",
                    format_tokens(mb.user_message_tokens)
                ));
            }
            if mb.assistant_message_tokens > 0 {
                out.push_str(&format!(
                    "    Assistant messages      {:>8}\n",
                    format_tokens(mb.assistant_message_tokens)
                ));
            }
            if mb.tool_call_tokens > 0 {
                out.push_str(&format!(
                    "    Tool calls             {:>8}\n",
                    format_tokens(mb.tool_call_tokens)
                ));
            }
            if mb.tool_result_tokens > 0 {
                out.push_str(&format!(
                    "    Tool results           {:>8}\n",
                    format_tokens(mb.tool_result_tokens)
                ));
            }
            if mb.attachment_tokens > 0 {
                out.push_str(&format!(
                    "    Attachments            {:>8}\n",
                    format_tokens(mb.attachment_tokens)
                ));
            }
            out.push('\n');

            // Top tools
            if !mb.tool_calls_by_type.is_empty() {
                out.push_str(&format!("  {ANSI_BOLD}Top Tools:{ANSI_RESET}\n"));
                for entry in mb.tool_calls_by_type.iter().take(10) {
                    out.push_str(&format!(
                        "    {:<25} call {:>6}  result {:>6}\n",
                        entry.name,
                        format_tokens(entry.call_tokens),
                        format_tokens(entry.result_tokens)
                    ));
                }
                out.push('\n');
            }
        }
    }

    // System prompt sections
    if !data.system_prompt_sections.is_empty() {
        out.push_str(&format!(
            "  {ANSI_BOLD}System Prompt Sections:{ANSI_RESET}\n"
        ));
        for sec in &data.system_prompt_sections {
            out.push_str(&format!(
                "    {:<35} {:>6}\n",
                sec.name,
                format_tokens(sec.tokens)
            ));
        }
        out.push('\n');
    }

    // Suggestions
    if !data.suggestions.is_empty() {
        out.push_str(&format!("  {ANSI_BOLD}Suggestions:{ANSI_RESET}\n"));
        for sug in &data.suggestions {
            let icon = match sug.severity {
                Severity::Warning => "\x1b[33m!\x1b[0m",
                Severity::Info => "\x1b[36mi\x1b[0m",
            };
            let savings = sug
                .savings_tokens
                .map(|s| format!(" -> save ~{}", format_tokens(s)))
                .unwrap_or_default();
            out.push_str(&format!(
                "  {icon} {ANSI_BOLD}{}{ANSI_RESET}{savings}\n",
                sug.title
            ));
            out.push_str(&format!(
                "    {ANSI_DIM}{}{ANSI_RESET}\n",
                sug.detail
            ));
        }
        out.push('\n');
    }

    out
}

fn grid_symbol(sq: &GridSquare) -> char {
    if sq.category_name == "Free space" {
        SYM_FREE
    } else if sq.category_name.contains("buffer") {
        SYM_BUFFER
    } else if sq.square_fullness >= 0.7 {
        SYM_FULL
    } else {
        SYM_PARTIAL
    }
}

// ---------------------------------------------------------------------------
// Markdown rendering (spec section 11)
// ---------------------------------------------------------------------------

/// Render context report as a markdown document for API/non-interactive consumers.
pub fn render_context_markdown(data: &ContextData) -> String {
    let mut out = String::with_capacity(2048);

    out.push_str("## Context Usage\n\n");
    out.push_str(&format!("**Model:** {}\n", data.model));
    out.push_str(&format!(
        "**Tokens:** {} / {} ({:.0}%)\n\n",
        format_tokens(data.total_tokens),
        format_tokens(data.max_tokens),
        data.percentage
    ));

    // Category table
    out.push_str("### Estimated usage by category\n\n");
    out.push_str("| Category | Tokens | Percentage |\n");
    out.push_str("|----------|--------|------------|\n");
    for cat in &data.categories {
        let pct = if data.max_tokens > 0 {
            (cat.tokens as f64 / data.max_tokens as f64) * 100.0
        } else {
            0.0
        };
        let deferred = if cat.is_deferred { " (deferred)" } else { "" };
        out.push_str(&format!(
            "| {}{} | {} | {:.1}% |\n",
            cat.name,
            deferred,
            format_tokens(cat.tokens),
            pct
        ));
    }
    out.push('\n');

    // MCP tools
    if !data.mcp_tools.is_empty() {
        out.push_str("### MCP Tools\n\n");
        out.push_str("| Tool | Server | Tokens |\n");
        out.push_str("|------|--------|--------|\n");
        for tool in &data.mcp_tools {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                tool.name,
                tool.server_name,
                format_tokens(tool.tokens)
            ));
        }
        out.push('\n');
    }

    // Memory files
    if !data.memory_files.is_empty() {
        out.push_str("### Memory Files\n\n");
        out.push_str("| Type | Path | Tokens |\n");
        out.push_str("|------|------|--------|\n");
        for f in &data.memory_files {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                f.file_type,
                f.path,
                format_tokens(f.tokens)
            ));
        }
        out.push('\n');
    }

    // Custom agents
    if !data.agents.is_empty() {
        out.push_str("### Custom Agents\n\n");
        out.push_str("| Agent Type | Source | Tokens |\n");
        out.push_str("|------------|--------|--------|\n");
        for a in &data.agents {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                a.agent_type,
                a.source,
                format_tokens(a.tokens)
            ));
        }
        out.push('\n');
    }

    // Skills
    if let Some(ref skills) = data.skills {
        out.push_str("### Skills\n\n");
        out.push_str("| Skill | Source | Tokens |\n");
        out.push_str("|-------|--------|--------|\n");
        for s in &skills.skill_frontmatter {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                s.name,
                s.source,
                format_tokens(s.tokens)
            ));
        }
        out.push('\n');
    }

    // Message breakdown
    if let Some(ref mb) = data.message_breakdown {
        out.push_str("### Message Breakdown\n\n");
        out.push_str("| Category | Tokens |\n");
        out.push_str("|----------|--------|\n");
        out.push_str(&format!(
            "| User messages | {} |\n",
            format_tokens(mb.user_message_tokens)
        ));
        out.push_str(&format!(
            "| Assistant messages | {} |\n",
            format_tokens(mb.assistant_message_tokens)
        ));
        out.push_str(&format!(
            "| Tool calls | {} |\n",
            format_tokens(mb.tool_call_tokens)
        ));
        out.push_str(&format!(
            "| Tool results | {} |\n",
            format_tokens(mb.tool_result_tokens)
        ));
        out.push_str(&format!(
            "| Attachments | {} |\n",
            format_tokens(mb.attachment_tokens)
        ));
        out.push('\n');

        // Top tools
        if !mb.tool_calls_by_type.is_empty() {
            out.push_str("### Top Tools\n\n");
            out.push_str("| Tool | Call Tokens | Result Tokens |\n");
            out.push_str("|------|-------------|---------------|\n");
            for entry in mb.tool_calls_by_type.iter().take(10) {
                out.push_str(&format!(
                    "| {} | {} | {} |\n",
                    entry.name,
                    format_tokens(entry.call_tokens),
                    format_tokens(entry.result_tokens)
                ));
            }
            out.push('\n');
        }
    }

    // Suggestions
    if !data.suggestions.is_empty() {
        out.push_str("### Suggestions\n\n");
        for sug in &data.suggestions {
            let icon = match sug.severity {
                Severity::Warning => "!",
                Severity::Info => "i",
            };
            let savings = sug
                .savings_tokens
                .map(|s| format!(" -> save ~{}", format_tokens(s)))
                .unwrap_or_default();
            out.push_str(&format!(
                "- **[{}] {}**{}\n  {}\n",
                icon, sug.title, savings, sug.detail
            ));
        }
        out.push('\n');
    }

    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_tokens() {
        assert_eq!(format_tokens(0), "0");
        assert_eq!(format_tokens(500), "500");
        assert_eq!(format_tokens(999), "999");
        assert_eq!(format_tokens(1000), "1.0k");
        assert_eq!(format_tokens(3200), "3.2k");
        assert_eq!(format_tokens(45200), "45.2k");
        assert_eq!(format_tokens(1_000_000), "1.0M");
        assert_eq!(format_tokens(2_500_000), "2.5M");
    }

    #[test]
    fn test_system_prompt_sections() {
        let prompt = "Preamble text here.\n## Tools\nTool section.\n## Memory\nMemory section.\n";
        let sections = count_system_prompt_sections(prompt);
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].name, "Preamble");
        assert_eq!(sections[1].name, "Tools");
        assert_eq!(sections[2].name, "Memory");
        assert!(sections.iter().all(|s| s.tokens > 0));
    }

    #[test]
    fn test_message_breakdown_empty() {
        let breakdown = analyze_messages(&[]);
        assert_eq!(breakdown.tool_call_tokens, 0);
        assert_eq!(breakdown.tool_result_tokens, 0);
        assert_eq!(breakdown.user_message_tokens, 0);
        assert_eq!(breakdown.assistant_message_tokens, 0);
    }

    fn test_msg(role: Role, text: &str) -> Message {
        Message {
            role,
            content: MessageContent::Text(text.into()),
            uuid: None,
            timestamp: None,
            session_id: None,
            metadata: Default::default(),
        }
    }

    #[test]
    fn test_message_breakdown_text() {
        let messages = vec![
            test_msg(Role::User, "Hello world, this is a test message."),
            test_msg(Role::Assistant, "I can help with that request."),
        ];
        let breakdown = analyze_messages(&messages);
        assert!(breakdown.user_message_tokens > 0);
        assert!(breakdown.assistant_message_tokens > 0);
        assert_eq!(breakdown.tool_call_tokens, 0);
    }

    #[test]
    fn test_grid_sizing_small() {
        let categories = vec![
            ContextCategory {
                name: "Messages".into(),
                tokens: 50_000,
                color: CategoryColor::Purple,
                is_deferred: false,
            },
            ContextCategory {
                name: "Free space".into(),
                tokens: 150_000,
                color: CategoryColor::Dimmed,
                is_deferred: false,
            },
        ];
        // < 1M context, < 80 cols -> 5x5
        let grid = build_grid(&categories, 200_000, Some(60));
        assert_eq!(grid.len(), 5);
        assert!(grid.iter().all(|row| row.len() == 5));
    }

    #[test]
    fn test_grid_sizing_large() {
        let categories = vec![
            ContextCategory {
                name: "Messages".into(),
                tokens: 50_000,
                color: CategoryColor::Purple,
                is_deferred: false,
            },
            ContextCategory {
                name: "Free space".into(),
                tokens: 950_000,
                color: CategoryColor::Dimmed,
                is_deferred: false,
            },
        ];
        // >= 1M context, >= 80 cols -> 20x10
        let grid = build_grid(&categories, 1_000_000, Some(120));
        assert_eq!(grid.len(), 10);
        assert!(grid.iter().all(|row| row.len() == 20));
    }

    #[test]
    fn test_suggestions_near_capacity() {
        let suggestions = generate_suggestions(
            85.0,
            true,
            200_000,
            &MessageBreakdown::default(),
            &[],
            0,
        );
        assert!(!suggestions.is_empty());
        assert_eq!(suggestions[0].severity, Severity::Warning);
        assert!(suggestions[0].title.contains("capacity"));
    }

    #[test]
    fn test_suggestions_autocompact_disabled() {
        let suggestions = generate_suggestions(
            60.0,
            false,
            200_000,
            &MessageBreakdown::default(),
            &[],
            0,
        );
        assert!(!suggestions.is_empty());
        assert!(suggestions[0].title.contains("Autocompact"));
    }

    #[test]
    fn test_suggestions_healthy() {
        let suggestions = generate_suggestions(
            20.0,
            true,
            200_000,
            &MessageBreakdown::default(),
            &[],
            0,
        );
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_analyze_full() {
        let input = AnalysisInput {
            messages: vec![test_msg(Role::User, "Hello")],
            model_id: "claude-sonnet-4-20250514".into(),
            context_window: 200_000,
            max_output_tokens: 64_000,
            system_prompt: "## Identity\nYou are a helpful assistant.\n## Tools\nYou have tools.\n".into(),
            tools: vec![],
            mcp_tools: vec![],
            memory_files: vec![],
            skill_entries: vec![],
            custom_agents: vec![],
            auto_compact_enabled: true,
            autocompact_buffer_tokens: 13_000,
            terminal_width: Some(80),
            last_api_usage: None,
        };
        let data = analyze_context_usage(&input);
        assert!(data.total_tokens > 0);
        assert!(data.percentage < 100.0);
        assert!(!data.categories.is_empty());
        assert!(!data.grid_rows.is_empty());
        assert_eq!(data.model, "claude-sonnet-4-20250514");
        assert!(data.system_prompt_sections.len() >= 2);
    }

    #[test]
    fn test_mcp_tool_server_extraction() {
        let tools = vec![ToolDefinition {
            name: "mcp__serena__find_symbol".into(),
            description: "Find a symbol".into(),
            input_schema: serde_json::json!({"type": "object"}),
        }];
        let (_, infos) = count_mcp_tool_tokens(&tools);
        assert_eq!(infos[0].server_name, "serena");
    }

    #[test]
    fn test_memory_file_tokens() {
        let files = vec![
            ("project".into(), "SOUL.md".into(), "x".repeat(400)),
            ("user".into(), "USER.md".into(), "y".repeat(800)),
        ];
        let (total, infos) = count_memory_file_tokens(&files);
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].tokens, 100); // 400/4
        assert_eq!(infos[1].tokens, 200); // 800/4
        assert_eq!(total, 300);
    }

    #[test]
    fn test_render_markdown_not_empty() {
        let data = ContextData {
            categories: vec![ContextCategory {
                name: "Messages".into(),
                tokens: 5000,
                color: CategoryColor::Purple,
                is_deferred: false,
            }],
            total_tokens: 5000,
            max_tokens: 200_000,
            percentage: 2.5,
            grid_rows: vec![],
            model: "test-model".into(),
            memory_files: vec![],
            mcp_tools: vec![],
            agents: vec![],
            skills: None,
            auto_compact_threshold: None,
            is_auto_compact_enabled: true,
            message_breakdown: None,
            api_usage: None,
            suggestions: vec![],
            system_prompt_sections: vec![],
            system_tools: vec![],
        };
        let md = render_context_markdown(&data);
        assert!(md.contains("Context Usage"));
        assert!(md.contains("test-model"));
        assert!(md.contains("Messages"));
    }
}
