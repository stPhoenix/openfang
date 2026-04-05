//! TUI-native context report renderer using ratatui Line/Span primitives.
//!
//! Uses colored background blocks for the grid instead of Unicode symbols,
//! guaranteeing consistent rendering across all terminal emulators.

use crate::tui::theme;
use openfang_runtime::context_analysis::{
    CategoryColor, ContextData, GridSquare, Severity,
};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// Dim version of a color for partial-fill grid squares.
fn dim_color(c: Color) -> Color {
    match c {
        Color::Rgb(r, g, b) => Color::Rgb(r / 3, g / 3, b / 3),
        other => other,
    }
}

fn cat_color(c: CategoryColor) -> Color {
    match c {
        CategoryColor::PromptBorder => theme::BLUE,
        CategoryColor::Inactive => theme::TEXT_TERTIARY,
        CategoryColor::Cyan => theme::CYAN,
        CategoryColor::Permission => theme::GREEN,
        CategoryColor::Claude => theme::PURPLE,
        CategoryColor::Warning => theme::YELLOW,
        CategoryColor::Purple => theme::PURPLE,
        CategoryColor::Dimmed => theme::TEXT_TERTIARY,
        CategoryColor::Buffer => theme::YELLOW,
    }
}

/// Render a grid square as a 2-char span using background color.
fn grid_cell(sq: &GridSquare) -> Span<'static> {
    let color = cat_color(sq.color);

    if sq.category_name == "Free space" {
        // Dim dotted block for free space
        Span::styled("  ", Style::default().bg(Color::Rgb(30, 28, 26)))
    } else if sq.category_name.contains("buffer") {
        // Striped pattern for buffer
        Span::styled("//", Style::default().fg(color).bg(Color::Rgb(40, 36, 32)))
    } else if sq.square_fullness >= 0.7 {
        // Solid colored block
        Span::styled("  ", Style::default().bg(color))
    } else {
        // Partial — dimmer shade
        Span::styled("  ", Style::default().bg(dim_color(color)))
    }
}

/// Legend swatch: small colored block for category list.
fn legend_swatch(name: &str, color: Color) -> Span<'static> {
    if name == "Free space" {
        Span::styled("  ", Style::default().bg(Color::Rgb(30, 28, 26)))
    } else if name.contains("buffer") {
        Span::styled("//", Style::default().fg(color).bg(Color::Rgb(40, 36, 32)))
    } else {
        Span::styled("  ", Style::default().bg(color))
    }
}

fn fmt_tokens(n: usize) -> String {
    openfang_runtime::context_analysis::format_tokens(n)
}

fn bold() -> Style {
    Style::default()
        .fg(theme::TEXT_PRIMARY)
        .add_modifier(Modifier::BOLD)
}

fn dim() -> Style {
    Style::default().fg(theme::TEXT_SECONDARY)
}

fn normal() -> Style {
    Style::default().fg(theme::TEXT_PRIMARY)
}

/// Render a `ContextData` report into styled ratatui lines.
pub fn render_context_lines(data: &ContextData) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = Vec::with_capacity(64);

    // Header
    out.push(Line::from(""));
    out.push(Line::from(Span::styled("  Context Usage", bold())));
    out.push(Line::from(""));

    // Grid — colored background blocks with 1px gap
    for row in &data.grid_rows {
        let mut spans: Vec<Span<'static>> = vec![Span::raw("  ")];
        for (i, sq) in row.iter().enumerate() {
            if i > 0 {
                spans.push(Span::raw(" "));
            }
            spans.push(grid_cell(sq));
        }
        out.push(Line::from(spans));
    }
    out.push(Line::from(""));

    // Model + summary
    out.push(Line::from(vec![
        Span::styled("  Model: ", bold()),
        Span::styled(data.model.clone(), normal()),
    ]));
    out.push(Line::from(vec![
        Span::styled("  Tokens: ", bold()),
        Span::styled(
            format!(
                "{} / {} ({:.0}%)",
                fmt_tokens(data.total_tokens),
                fmt_tokens(data.max_tokens),
                data.percentage
            ),
            normal(),
        ),
    ]));
    out.push(Line::from(""));

    // Category legend
    for cat in &data.categories {
        let color = cat_color(cat.color);
        let pct = if data.max_tokens > 0 {
            (cat.tokens as f64 / data.max_tokens as f64) * 100.0
        } else {
            0.0
        };
        let deferred = if cat.is_deferred { " (deferred)" } else { "" };
        out.push(Line::from(vec![
            Span::raw("  "),
            legend_swatch(&cat.name, color),
            Span::raw(" "),
            Span::styled(format!("{:<25}", cat.name), normal()),
            Span::styled(format!("{:>8}", fmt_tokens(cat.tokens)), normal()),
            Span::styled(format!("  {:>5.1}%{deferred}", pct), dim()),
        ]));
    }
    out.push(Line::from(""));

    // Memory files
    if !data.memory_files.is_empty() {
        out.push(Line::from(Span::styled("  Memory Files:", bold())));
        for f in &data.memory_files {
            out.push(Line::from(Span::styled(
                format!(
                    "    {:<10} {:<35} {:>6}",
                    f.file_type,
                    f.path,
                    fmt_tokens(f.tokens)
                ),
                dim(),
            )));
        }
        out.push(Line::from(""));
    }

    // Skills
    if let Some(ref skills) = data.skills {
        out.push(Line::from(Span::styled(
            format!(
                "  Skills ({}/{}):",
                skills.included_skills, skills.total_skills
            ),
            bold(),
        )));
        for s in &skills.skill_frontmatter {
            out.push(Line::from(Span::styled(
                format!("    {:<30} {:>6}", s.name, fmt_tokens(s.tokens)),
                dim(),
            )));
        }
        out.push(Line::from(""));
    }

    // Message breakdown
    if let Some(ref mb) = data.message_breakdown {
        let total = mb.tool_call_tokens
            + mb.tool_result_tokens
            + mb.attachment_tokens
            + mb.assistant_message_tokens
            + mb.user_message_tokens;
        if total > 0 {
            out.push(Line::from(Span::styled(
                "  Message Breakdown:",
                bold(),
            )));
            let pairs = [
                ("User messages", mb.user_message_tokens),
                ("Assistant messages", mb.assistant_message_tokens),
                ("Tool calls", mb.tool_call_tokens),
                ("Tool results", mb.tool_result_tokens),
                ("Attachments", mb.attachment_tokens),
            ];
            for (label, tokens) in &pairs {
                if *tokens > 0 {
                    out.push(Line::from(Span::styled(
                        format!("    {:<25} {:>8}", label, fmt_tokens(*tokens)),
                        normal(),
                    )));
                }
            }
            out.push(Line::from(""));

            // Top tools
            if !mb.tool_calls_by_type.is_empty() {
                out.push(Line::from(Span::styled("  Top Tools:", bold())));
                for entry in mb.tool_calls_by_type.iter().take(10) {
                    out.push(Line::from(Span::styled(
                        format!(
                            "    {:<25} call {:>6}  result {:>6}",
                            entry.name,
                            fmt_tokens(entry.call_tokens),
                            fmt_tokens(entry.result_tokens)
                        ),
                        dim(),
                    )));
                }
                out.push(Line::from(""));
            }
        }
    }

    // System prompt sections
    if !data.system_prompt_sections.is_empty() {
        out.push(Line::from(Span::styled(
            "  System Prompt Sections:",
            bold(),
        )));
        for sec in &data.system_prompt_sections {
            out.push(Line::from(Span::styled(
                format!("    {:<35} {:>6}", sec.name, fmt_tokens(sec.tokens)),
                dim(),
            )));
        }
        out.push(Line::from(""));
    }

    // MCP tools
    if !data.mcp_tools.is_empty() {
        out.push(Line::from(Span::styled("  MCP Tools:", bold())));
        for tool in &data.mcp_tools {
            out.push(Line::from(Span::styled(
                format!(
                    "    {:<30} {:<15} {:>6}",
                    tool.name,
                    tool.server_name,
                    fmt_tokens(tool.tokens)
                ),
                dim(),
            )));
        }
        out.push(Line::from(""));
    }

    // Agents
    if !data.agents.is_empty() {
        out.push(Line::from(Span::styled("  Custom Agents:", bold())));
        for a in &data.agents {
            out.push(Line::from(Span::styled(
                format!(
                    "    {:<25} {:<15} {:>6}",
                    a.agent_type,
                    a.source,
                    fmt_tokens(a.tokens)
                ),
                dim(),
            )));
        }
        out.push(Line::from(""));
    }

    // Suggestions
    if !data.suggestions.is_empty() {
        out.push(Line::from(Span::styled("  Suggestions:", bold())));
        for sug in &data.suggestions {
            let (icon, icon_color) = match sug.severity {
                Severity::Warning => ("!", theme::YELLOW),
                Severity::Info => ("i", theme::CYAN),
            };
            let savings = sug
                .savings_tokens
                .map(|s| format!(" -> save ~{}", fmt_tokens(s)))
                .unwrap_or_default();
            out.push(Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    icon.to_string(),
                    Style::default().fg(icon_color),
                ),
                Span::raw(" "),
                Span::styled(format!("{}{savings}", sug.title), bold()),
            ]));
            out.push(Line::from(Span::styled(
                format!("    {}", sug.detail),
                dim(),
            )));
        }
        out.push(Line::from(""));
    }

    out
}
