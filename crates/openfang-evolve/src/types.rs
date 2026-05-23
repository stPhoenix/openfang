//! Core domain types for the execution analysis and skill evolution system.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// AnalysisId
// ---------------------------------------------------------------------------

/// Unique identifier for an execution analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AnalysisId(pub Uuid);

impl AnalysisId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for AnalysisId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AnalysisId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for AnalysisId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

// ---------------------------------------------------------------------------
// ExecutionAnalysis
// ---------------------------------------------------------------------------

/// The top-level result of analyzing one agent session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionAnalysis {
    /// Unique analysis identifier.
    pub id: AnalysisId,
    /// Session that was analyzed.
    pub session_id: String,
    /// Agent that owned the session.
    pub agent_id: String,
    /// LLM's independent judgment of whether the task completed successfully.
    pub task_completed: bool,
    /// 2-3 sentence overview of what happened in the execution.
    pub execution_note: String,
    /// Tools that had issues during execution.
    pub tool_issues: Vec<ToolIssue>,
    /// Per-skill assessment.
    pub skill_judgments: Vec<SkillJudgment>,
    /// Suggested evolution actions (0 to N).
    pub evolution_suggestions: Vec<EvolutionSuggestion>,
    /// Model identifier used for analysis.
    pub model_used: String,
    /// Input tokens consumed by the analysis call.
    pub input_tokens: u64,
    /// Output tokens produced by the analysis call.
    pub output_tokens: u64,
    /// When the analysis was performed.
    pub analyzed_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// ToolIssue
// ---------------------------------------------------------------------------

/// A tool that had problems during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolIssue {
    /// Tool name or key (e.g., "web_search", "shell_exec").
    pub tool_name: String,
    /// What kind of issue occurred.
    pub issue_type: ToolIssueType,
    /// Description: symptom and cause.
    pub description: String,
}

/// Classification of tool issues.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolIssueType {
    /// Tool returned an error or failed to execute.
    Failure,
    /// Tool was used incorrectly (wrong arguments, wrong context).
    Misuse,
    /// Tool was called unnecessarily (wasted tokens/time).
    Unnecessary,
    /// A tool that should have been used was not available or not called.
    Missing,
}

impl std::fmt::Display for ToolIssueType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failure => write!(f, "failure"),
            Self::Misuse => write!(f, "misuse"),
            Self::Unnecessary => write!(f, "unnecessary"),
            Self::Missing => write!(f, "missing"),
        }
    }
}

impl std::str::FromStr for ToolIssueType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "failure" => Ok(Self::Failure),
            "misuse" => Ok(Self::Misuse),
            "unnecessary" => Ok(Self::Unnecessary),
            "missing" => Ok(Self::Missing),
            _ => Err(format!("unknown tool issue type: {s}")),
        }
    }
}

// ---------------------------------------------------------------------------
// SkillJudgment
// ---------------------------------------------------------------------------

/// Per-skill assessment within an analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillJudgment {
    /// Skill name (from manifest or SKILL.md frontmatter).
    pub skill_name: String,
    /// Whether the skill's instructions were actually followed by the agent.
    pub applied: bool,
    /// Quality assessment of how the skill was used.
    pub quality: SkillQuality,
    /// Explanation of how the skill was used, or why it wasn't.
    pub note: String,
}

/// Quality rating for skill usage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillQuality {
    /// Skill was applied correctly and effectively.
    Good,
    /// Skill was partially applied or somewhat helpful.
    Partial,
    /// Skill was applied but led to poor results.
    Poor,
    /// Skill was not applicable to the task.
    NotApplicable,
}

impl std::fmt::Display for SkillQuality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Good => write!(f, "good"),
            Self::Partial => write!(f, "partial"),
            Self::Poor => write!(f, "poor"),
            Self::NotApplicable => write!(f, "not_applicable"),
        }
    }
}

impl std::str::FromStr for SkillQuality {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "good" => Ok(Self::Good),
            "partial" => Ok(Self::Partial),
            "poor" => Ok(Self::Poor),
            "not_applicable" => Ok(Self::NotApplicable),
            _ => Err(format!("unknown skill quality: {s}")),
        }
    }
}

// ---------------------------------------------------------------------------
// EvolutionSuggestion
// ---------------------------------------------------------------------------

/// One proposed evolution action from the analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EvolutionSuggestion {
    /// Type of evolution suggested.
    pub kind: SuggestionKind,
    /// Target skill name (for FIX/DERIVED); None for CAPTURED.
    pub target_skill: Option<String>,
    /// Free-text: what to evolve/fix/capture and why.
    pub description: String,
    /// Priority 1 (low) to 5 (critical).
    pub priority: u8,
    /// When this suggestion was successfully executed (ISO 8601 timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executed_at: Option<String>,
    /// When this suggestion failed execution (ISO 8601 timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_at: Option<String>,
    /// Reason the execution failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// Lifecycle status. Defaults to Pending. Set to Superseded by dedup,
    /// Applied/Failed by execute pipeline.
    #[serde(default)]
    pub status: SuggestionStatus,
    /// Row id of the survivor suggestion that superseded this one (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_id: Option<i64>,
    /// Short reason explaining why this row was marked superseded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedup_reason: Option<String>,
}

/// Lifecycle states for an evolution suggestion in the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionStatus {
    #[default]
    Pending,
    Applied,
    Failed,
    /// Refused by the LLM confirmation gate or cost cap. Not a failure;
    /// surface a distinct badge in the UI and don't re-try on next batch.
    Declined,
    Superseded,
    /// Structurally invalid — missing a required field (e.g. FIX with no
    /// target_skill). Filtered out of pending lists so batch-apply never
    /// re-emits it.
    Unprocessable,
}

impl std::fmt::Display for SuggestionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Applied => write!(f, "applied"),
            Self::Failed => write!(f, "failed"),
            Self::Declined => write!(f, "declined"),
            Self::Superseded => write!(f, "superseded"),
            Self::Unprocessable => write!(f, "unprocessable"),
        }
    }
}

impl std::str::FromStr for SuggestionStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "applied" => Ok(Self::Applied),
            "failed" => Ok(Self::Failed),
            "declined" => Ok(Self::Declined),
            "superseded" => Ok(Self::Superseded),
            "unprocessable" => Ok(Self::Unprocessable),
            _ => Err(format!("unknown suggestion status: {s}")),
        }
    }
}

/// Predicate that returns `Some(reason)` when the suggestion is structurally
/// invalid and cannot be executed as-is. Used at `save_analysis` time and as
/// a lazy backfill sweep at batch-apply entry. Add new rules here as
/// one-liners — keep it pure and synchronous so the same predicate runs in
/// both contexts.
pub fn is_unprocessable(sug: &EvolutionSuggestion) -> Option<&'static str> {
    let empty_target = sug
        .target_skill
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty);
    match sug.kind {
        SuggestionKind::Fix if empty_target => {
            Some("fix requires target_skill but analyzer named none")
        }
        SuggestionKind::Derived if empty_target => {
            Some("derived requires a parent target_skill")
        }
        _ => None,
    }
}

/// Classification of evolution suggestions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionKind {
    /// In-place repair: skill instructions are incorrect or outdated.
    #[default]
    Fix,
    /// Enhanced version: skill worked but execution revealed a better approach.
    Derived,
    /// Brand-new skill: agent solved task without skill guidance; approach is reusable.
    Captured,
}

impl std::fmt::Display for SuggestionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fix => write!(f, "fix"),
            Self::Derived => write!(f, "derived"),
            Self::Captured => write!(f, "captured"),
        }
    }
}

impl std::str::FromStr for SuggestionKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "fix" => Ok(Self::Fix),
            "derived" => Ok(Self::Derived),
            "captured" => Ok(Self::Captured),
            _ => Err(format!("unknown suggestion kind: {s}")),
        }
    }
}

// ---------------------------------------------------------------------------
// SkillOrigin
// ---------------------------------------------------------------------------

/// How a skill version came into existence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillOrigin {
    /// Originally imported from disk or bundled.
    Imported,
    /// Captured from a novel execution pattern.
    Captured,
    /// Derived (enhanced/merged) from one or more parent skills.
    Derived,
    /// In-place fix of an existing skill.
    Fixed,
}

impl std::fmt::Display for SkillOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Imported => write!(f, "imported"),
            Self::Captured => write!(f, "captured"),
            Self::Derived => write!(f, "derived"),
            Self::Fixed => write!(f, "fixed"),
        }
    }
}

impl std::str::FromStr for SkillOrigin {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "imported" => Ok(Self::Imported),
            "captured" => Ok(Self::Captured),
            "derived" => Ok(Self::Derived),
            "fixed" => Ok(Self::Fixed),
            _ => Err(format!("unknown skill origin: {s}")),
        }
    }
}

// ---------------------------------------------------------------------------
// SkillCategory
// ---------------------------------------------------------------------------

/// Classification of a skill's purpose.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillCategory {
    ToolGuide,
    Workflow,
    #[default]
    Reference,
}

impl std::fmt::Display for SkillCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolGuide => write!(f, "tool_guide"),
            Self::Workflow => write!(f, "workflow"),
            Self::Reference => write!(f, "reference"),
        }
    }
}

impl std::str::FromStr for SkillCategory {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tool_guide" => Ok(Self::ToolGuide),
            "workflow" => Ok(Self::Workflow),
            "reference" => Ok(Self::Reference),
            _ => Err(format!("unknown skill category: {s}")),
        }
    }
}

// ---------------------------------------------------------------------------
// SkillVisibility
// ---------------------------------------------------------------------------

/// Visibility scope for a skill.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillVisibility {
    #[default]
    Private,
    Public,
}

impl std::fmt::Display for SkillVisibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Private => write!(f, "private"),
            Self::Public => write!(f, "public"),
        }
    }
}

impl std::str::FromStr for SkillVisibility {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "private" => Ok(Self::Private),
            "public" => Ok(Self::Public),
            _ => Err(format!("unknown skill visibility: {s}")),
        }
    }
}

// ---------------------------------------------------------------------------
// SkillLineage
// ---------------------------------------------------------------------------

/// Tracks the evolutionary history of a single skill version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillLineage {
    /// How this version was created.
    pub origin: SkillOrigin,
    /// Distance from root in the version DAG (0 for imported/captured).
    pub generation: u32,
    /// Parent skill IDs: empty for IMPORTED/CAPTURED, 1 for FIX, 1+ for DERIVED.
    pub parent_skill_ids: Vec<String>,
    /// Task that triggered the evolution (if any).
    pub source_task_id: Option<String>,
    /// LLM-generated one-sentence description of the change.
    pub change_summary: String,
    /// Unified diff (empty for multi-parent DERIVED).
    pub content_diff: String,
    /// Full snapshot of the skill directory: {relative_path: file_content}.
    pub content_snapshot: HashMap<String, String>,
    /// For FIX evolutions: snapshot of the parent's directory BEFORE the fix
    /// was applied. Lets `evolve_canary_check` roll back cleanly if the canary
    /// underperforms. Empty for non-FIX origins. Stored alongside the new
    /// content so a single record carries both versions for the canary window.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub pre_fix_snapshot: HashMap<String, String>,
    /// When this version was created.
    pub created_at: DateTime<Utc>,
    /// "human" or LLM model identifier.
    pub created_by: String,
}

// ---------------------------------------------------------------------------
// SkillImport
// ---------------------------------------------------------------------------

/// Lightweight skill description used to import kernel-registered skills into
/// the evolution store on startup.
#[derive(Debug, Clone)]
pub struct SkillImport {
    pub name: String,
    pub description: String,
    pub path: String,
    pub tags: Vec<String>,
    pub tools: Vec<String>,
}

// ---------------------------------------------------------------------------
// SkillRecord
// ---------------------------------------------------------------------------

/// Full profile of a skill — identity, lineage, and cumulative execution statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillRecord {
    /// Unique persistent identifier (format: `{name}__v{gen}_{uuid8}` or `{name}__imp_{uuid8}`).
    pub skill_id: String,
    /// Human-readable name (lowercase, hyphens, max 50 chars).
    pub name: String,
    /// One-line description from frontmatter.
    pub description: String,
    /// Absolute path to SKILL.md on disk.
    pub path: String,
    /// Only the latest version is active; parents deactivated on evolution.
    pub is_active: bool,
    /// Skill classification.
    pub category: SkillCategory,
    /// Freeform tags.
    pub tags: Vec<String>,
    /// Visibility scope.
    pub visibility: SkillVisibility,
    /// Who created the skill (user id or "system").
    pub creator_id: String,
    /// Evolutionary history.
    pub lineage: SkillLineage,
    /// All tool keys this skill references.
    pub tool_dependencies: Vec<String>,
    /// Subset of dependencies that are required.
    pub critical_tools: Vec<String>,
    /// Times skill was selected for a task.
    pub total_selections: u64,
    /// Times agent actually used the skill.
    pub total_applied: u64,
    /// Times task completed when skill was applied.
    pub total_completions: u64,
    /// Times skill was selected but not applied.
    pub total_fallbacks: u64,
    /// Creation timestamp.
    pub first_seen: DateTime<Utc>,
    /// Last modification timestamp.
    pub last_updated: DateTime<Utc>,

    // --- Canary rollout (FIX evolution promotion gate) ---
    /// True while this record is a canary of `canary_parent_skill_id`.
    /// Parent stays active alongside; traffic split governed by
    /// `EvolveConfig.canary_traffic_split` in the registry layer.
    #[serde(default)]
    pub is_canary: bool,
    /// Selections routed to this skill *while it was a canary*. Reset on
    /// promote (and the record drops `is_canary`).
    #[serde(default)]
    pub canary_selections: u64,
    /// Task completions on this canary while it was a canary.
    #[serde(default)]
    pub canary_completions: u64,
    /// Snapshot of parent's `completion_rate()` at the moment the canary
    /// was created. Promotion gate compares canary's rate to this.
    #[serde(default)]
    pub parent_completion_rate_at_birth: f64,
    /// Set on canary records — the parent skill they're testing against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary_parent_skill_id: Option<String>,
}

impl SkillRecord {
    /// How often the skill is actually used when selected.
    pub fn applied_rate(&self) -> f64 {
        if self.total_selections == 0 {
            return 0.0;
        }
        self.total_applied as f64 / self.total_selections as f64
    }

    /// How often using the skill leads to task completion.
    pub fn completion_rate(&self) -> f64 {
        if self.total_applied == 0 {
            return 0.0;
        }
        self.total_completions as f64 / self.total_applied as f64
    }

    /// End-to-end success rate.
    pub fn effective_rate(&self) -> f64 {
        if self.total_selections == 0 {
            return 0.0;
        }
        self.total_completions as f64 / self.total_selections as f64
    }

    /// How often the skill is ignored after selection.
    pub fn fallback_rate(&self) -> f64 {
        if self.total_selections == 0 {
            return 0.0;
        }
        self.total_fallbacks as f64 / self.total_selections as f64
    }

    /// Canary-only completion rate (only meaningful when `is_canary == true`).
    pub fn canary_completion_rate(&self) -> f64 {
        if self.canary_selections == 0 {
            return 0.0;
        }
        self.canary_completions as f64 / self.canary_selections as f64
    }
}

// ---------------------------------------------------------------------------
// EvolutionContext
// ---------------------------------------------------------------------------

/// Context for executing a skill evolution (FIX, DERIVED, or CAPTURED).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionContext {
    /// Type of evolution to perform.
    pub evolution_type: SuggestionKind,
    /// Target skill records (FIX: 1, DERIVED: 1+, CAPTURED: 0).
    pub target_skills: Vec<SkillRecord>,
    /// Free-text direction: what to evolve/fix/capture and why.
    pub direction: String,
    /// Desired category for the result skill.
    pub category: Option<SkillCategory>,
    /// Trigger context (metrics, tool issue summary, etc.).
    pub trigger_context: String,
    /// Analysis that triggered this evolution (if any).
    pub source_analysis: Option<AnalysisId>,
}

// ---------------------------------------------------------------------------
// EvolutionResult
// ---------------------------------------------------------------------------

/// Outcome of a skill evolution attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvolutionResult {
    /// Skill ID of the evolved skill.
    pub evolved_skill_id: String,
    /// One-sentence description of the change.
    pub change_summary: String,
    /// Unified diff of changes.
    pub content_diff: String,
    /// Full snapshot: {relative_path: file_content}.
    pub content_snapshot: HashMap<String, String>,
    /// Whether the evolution succeeded.
    pub success: bool,
    /// Reason for failure (if any).
    pub failure_reason: Option<String>,
}

// ---------------------------------------------------------------------------
// EvolveStats
// ---------------------------------------------------------------------------

/// Aggregate statistics from the evolve system.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvolveStats {
    /// Total number of analyses performed.
    pub total_analyses: u64,
    /// Number of sessions that have been analyzed.
    pub sessions_analyzed: u64,
    /// Number of sessions pending analysis.
    pub sessions_pending: u64,
    /// Average task completion rate across analyses.
    pub avg_completion_rate: f64,
    /// Total evolution suggestions generated.
    pub total_suggestions: u64,
    /// Total tool issues identified.
    pub total_tool_issues: u64,
}

// ---------------------------------------------------------------------------
// EvolveError
// ---------------------------------------------------------------------------

/// Errors that can occur in the evolve subsystem.
#[derive(Debug, thiserror::Error)]
pub enum EvolveError {
    #[error("evolve engine is not enabled")]
    NotEnabled,
    #[error("LLM driver error: {0}")]
    LlmError(String),
    #[error("failed to parse analysis response: {0}")]
    ParseError(String),
    #[error("database error: {0}")]
    DbError(#[from] rusqlite::Error),
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("analysis already exists for session: {0}")]
    AlreadyAnalyzed(String),
    /// Evolution was deliberately skipped (LLM confirmation gate said no,
    /// cost cap reached, etc.). Callers should treat this as an expected,
    /// non-error outcome — distinct from `Other` which signals a real failure.
    #[error("evolution declined: {0}")]
    Declined(String),
    #[error("{0}")]
    Other(String),
}

impl EvolveError {
    /// True when the error is a deliberate skip (declined / cost cap),
    /// not an actual failure.
    pub fn is_declined(&self) -> bool {
        matches!(self, EvolveError::Declined(_))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_id_roundtrip() {
        let id = AnalysisId::new();
        let s = id.to_string();
        let parsed: AnalysisId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn tool_issue_type_roundtrip() {
        for t in &["failure", "misuse", "unnecessary", "missing"] {
            let parsed: ToolIssueType = t.parse().unwrap();
            assert_eq!(&parsed.to_string(), t);
        }
    }

    #[test]
    fn skill_quality_roundtrip() {
        for q in &["good", "partial", "poor", "not_applicable"] {
            let parsed: SkillQuality = q.parse().unwrap();
            assert_eq!(&parsed.to_string(), q);
        }
    }

    #[test]
    fn suggestion_kind_roundtrip() {
        for k in &["fix", "derived", "captured"] {
            let parsed: SuggestionKind = k.parse().unwrap();
            assert_eq!(&parsed.to_string(), k);
        }
    }

    #[test]
    fn suggestion_status_roundtrip_includes_unprocessable() {
        for s in &[
            "pending",
            "applied",
            "failed",
            "declined",
            "superseded",
            "unprocessable",
        ] {
            let parsed: SuggestionStatus = s.parse().unwrap();
            assert_eq!(&parsed.to_string(), s);
        }
    }

    fn make_sug(kind: SuggestionKind, target: Option<&str>) -> EvolutionSuggestion {
        EvolutionSuggestion {
            kind,
            target_skill: target.map(String::from),
            description: "x".into(),
            priority: 3,
            ..Default::default()
        }
    }

    #[test]
    fn is_unprocessable_fix_without_target_skill() {
        assert!(is_unprocessable(&make_sug(SuggestionKind::Fix, None)).is_some());
    }

    #[test]
    fn is_unprocessable_fix_with_empty_target_skill() {
        assert!(is_unprocessable(&make_sug(SuggestionKind::Fix, Some(""))).is_some());
        assert!(is_unprocessable(&make_sug(SuggestionKind::Fix, Some("   "))).is_some());
    }

    #[test]
    fn is_unprocessable_derived_without_target_skill() {
        assert!(is_unprocessable(&make_sug(SuggestionKind::Derived, None)).is_some());
    }

    #[test]
    fn is_unprocessable_fix_with_target_is_processable() {
        assert!(is_unprocessable(&make_sug(SuggestionKind::Fix, Some("docker"))).is_none());
    }

    #[test]
    fn is_unprocessable_captured_without_target_is_processable() {
        // CAPTURED has no target by design — it proposes a brand-new skill.
        assert!(is_unprocessable(&make_sug(SuggestionKind::Captured, None)).is_none());
    }

    #[test]
    fn skill_origin_roundtrip() {
        for o in &["imported", "captured", "derived", "fixed"] {
            let parsed: SkillOrigin = o.parse().unwrap();
            assert_eq!(&parsed.to_string(), o);
        }
    }

    #[test]
    fn skill_category_roundtrip() {
        for c in &["tool_guide", "workflow", "reference"] {
            let parsed: SkillCategory = c.parse().unwrap();
            assert_eq!(&parsed.to_string(), c);
        }
    }

    #[test]
    fn skill_visibility_roundtrip() {
        for v in &["private", "public"] {
            let parsed: SkillVisibility = v.parse().unwrap();
            assert_eq!(&parsed.to_string(), v);
        }
    }

    #[test]
    fn skill_record_rates() {
        let mut rec = SkillRecord {
            skill_id: "test__imp_12345678".into(),
            name: "test".into(),
            description: "test skill".into(),
            path: "/tmp/test".into(),
            is_active: true,
            category: SkillCategory::Reference,
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
                created_at: Utc::now(),
                created_by: "human".into(),
            },
            tool_dependencies: vec![],
            critical_tools: vec![],
            total_selections: 10,
            total_applied: 8,
            total_completions: 6,
            total_fallbacks: 1,
            first_seen: Utc::now(),
            last_updated: Utc::now(),
            is_canary: false,
            canary_selections: 0,
            canary_completions: 0,
            parent_completion_rate_at_birth: 0.0,
            canary_parent_skill_id: None,
        };

        assert!((rec.applied_rate() - 0.8).abs() < f64::EPSILON);
        assert!((rec.completion_rate() - 0.75).abs() < f64::EPSILON);
        assert!((rec.effective_rate() - 0.6).abs() < f64::EPSILON);
        assert!((rec.fallback_rate() - 0.1).abs() < f64::EPSILON);

        // Zero selections => all rates 0
        rec.total_selections = 0;
        assert_eq!(rec.applied_rate(), 0.0);
        assert_eq!(rec.effective_rate(), 0.0);
        assert_eq!(rec.fallback_rate(), 0.0);
    }

    #[test]
    fn skill_lineage_serde_roundtrip() {
        let lineage = SkillLineage {
            origin: SkillOrigin::Derived,
            generation: 2,
            parent_skill_ids: vec!["parent1".into(), "parent2".into()],
            source_task_id: Some("task-123".into()),
            change_summary: "Merged two skills".into(),
            content_diff: String::new(),
            content_snapshot: HashMap::from([("SKILL.md".into(), "# Test".into())]),
            pre_fix_snapshot: HashMap::new(),
            created_at: Utc::now(),
            created_by: "claude-haiku".into(),
        };
        let json = serde_json::to_string(&lineage).unwrap();
        let back: SkillLineage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.origin, SkillOrigin::Derived);
        assert_eq!(back.generation, 2);
        assert_eq!(back.parent_skill_ids.len(), 2);
    }

    #[test]
    fn execution_analysis_serde_roundtrip() {
        let analysis = ExecutionAnalysis {
            id: AnalysisId::new(),
            session_id: "sess-123".into(),
            agent_id: "agent-456".into(),
            task_completed: true,
            execution_note: "Agent completed the task successfully.".into(),
            tool_issues: vec![ToolIssue {
                tool_name: "web_search".into(),
                issue_type: ToolIssueType::Failure,
                description: "Search returned empty results".into(),
            }],
            skill_judgments: vec![SkillJudgment {
                skill_name: "docker".into(),
                applied: true,
                quality: SkillQuality::Good,
                note: "Followed docker skill instructions correctly".into(),
            }],
            evolution_suggestions: vec![EvolutionSuggestion {
                kind: SuggestionKind::Fix,
                target_skill: Some("docker".into()),
                description: "Update port mapping instructions".into(),
                priority: 3,
                ..Default::default()
            }],
            model_used: "claude-haiku-4-5-20251001".into(),
            input_tokens: 1500,
            output_tokens: 300,
            analyzed_at: Utc::now(),
        };

        let json = serde_json::to_string(&analysis).unwrap();
        let deserialized: ExecutionAnalysis = serde_json::from_str(&json).unwrap();
        assert_eq!(analysis.id, deserialized.id);
        assert_eq!(analysis.session_id, deserialized.session_id);
        assert_eq!(analysis.task_completed, deserialized.task_completed);
        assert_eq!(analysis.tool_issues.len(), deserialized.tool_issues.len());
        assert_eq!(
            analysis.skill_judgments.len(),
            deserialized.skill_judgments.len()
        );
        assert_eq!(
            analysis.evolution_suggestions.len(),
            deserialized.evolution_suggestions.len()
        );
    }
}
