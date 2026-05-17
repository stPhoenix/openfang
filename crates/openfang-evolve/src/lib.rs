//! Execution analysis and skill evolution engine for OpenFang.
//!
//! Phase 1: Execution Analyzer — spawns a real agent that reviews completed
//! agent sessions and produces structured analyses with skill judgments and
//! evolution suggestions. The analyzer agent is visible in the chat tab.

pub mod analyzer;
pub mod confirm;
pub mod correction;
pub mod evolver;
pub mod patch;
pub mod prompt;
pub mod store;
pub mod triggers;
pub mod types;

pub use types::*;

/// Sentinel path value used for bundled (compile-time embedded) skills.
pub const BUNDLED_PATH: &str = "<bundled>";

/// Check if a skill record path refers to a bundled (non-disk) skill.
pub fn is_bundled_path(path: &str) -> bool {
    path == BUNDLED_PATH
}

use openfang_types::agent::AgentId;
use openfang_types::config::EvolveConfig;
use openfang_types::message::Message;
use rusqlite::Connection;
use serde::Serialize;
use std::sync::{Arc, Mutex, RwLock};
use tracing::{debug, info, warn};

/// Per-item outcome status for batch analysis progress events.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemStatus {
    Analyzed,
    NoMessages,
    LoadFailed,
    ParseFailed,
    SendFailed,
}

/// Progress event emitted during `analyze_unanalyzed`.
///
/// `type` is the serde discriminant; consumed by the SSE handler and the
/// Evolution dashboard tab.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProgressEvent {
    Started {
        total: usize,
    },
    Item {
        index: usize,
        total: usize,
        session_id: String,
        agent_id: String,
        status: ItemStatus,
    },
    Completed {
        analyzed: usize,
    },
}

/// The evolution engine — orchestrates analysis of agent sessions.
///
/// On first use, the kernel spawns a persistent "evolution-analyzer" agent
/// whose conversations are visible in the dashboard chat tab. This engine
/// stores the agent ID and delegates analysis to the kernel via callbacks.
pub struct EvolveEngine {
    config: RwLock<EvolveConfig>,
    store: store::EvolveStore,
    /// The agent ID of the spawned analyzer agent (set by the kernel after spawn).
    analyzer_agent_id: RwLock<Option<AgentId>>,
    /// The agent ID of the spawned evolver agent (set by the kernel after spawn).
    evolver_agent_id: RwLock<Option<AgentId>>,
}

impl EvolveEngine {
    /// Create a new engine with the given config and shared DB connection.
    ///
    /// If a persisted config exists in SQLite it overrides the file-based
    /// defaults (so UI changes survive restarts).
    pub fn new(config: EvolveConfig, conn: Arc<Mutex<Connection>>) -> Self {
        let store = store::EvolveStore::new(conn);

        // Prefer persisted config from the DB over file defaults.
        let effective = match store.load_config() {
            Ok(Some(persisted)) => {
                info!(
                    enabled = persisted.enabled,
                    provider = %persisted.provider,
                    model = %persisted.model,
                    "evolve engine: loaded persisted config"
                );
                persisted
            }
            _ => {
                info!(
                    enabled = config.enabled,
                    provider = %config.provider,
                    model = %config.model,
                    "evolve engine initialized"
                );
                config
            }
        };

        Self {
            config: RwLock::new(effective),
            store,
            analyzer_agent_id: RwLock::new(None),
            evolver_agent_id: RwLock::new(None),
        }
    }

    /// Whether the engine is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.read().map(|c| c.enabled).unwrap_or(false)
    }

    /// Get a snapshot of the current config.
    pub fn config(&self) -> EvolveConfig {
        self.config
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Update the config (hot-reload) and persist to SQLite.
    pub fn update_config(&self, new_config: EvolveConfig) {
        if let Ok(mut c) = self.config.write() {
            info!(
                enabled = new_config.enabled,
                provider = %new_config.provider,
                model = %new_config.model,
                "evolve config updated"
            );
            *c = new_config.clone();
        }
        if let Err(e) = self.store.save_config(&new_config) {
            warn!("failed to persist evolve config: {e}");
        }
    }

    /// Get a reference to the store for direct queries.
    pub fn store(&self) -> &store::EvolveStore {
        &self.store
    }

    /// Get the analyzer agent ID (if spawned).
    pub fn analyzer_agent_id(&self) -> Option<AgentId> {
        self.analyzer_agent_id.read().ok().and_then(|g| *g)
    }

    /// Set the analyzer agent ID (called by the kernel after spawning).
    pub fn set_analyzer_agent(&self, id: AgentId) {
        if let Ok(mut g) = self.analyzer_agent_id.write() {
            *g = Some(id);
        }
    }

    /// Clear the analyzer agent ID (called before respawn).
    pub fn clear_analyzer_agent(&self) {
        if let Ok(mut g) = self.analyzer_agent_id.write() {
            *g = None;
        }
    }

    /// Get the evolver agent ID (if spawned).
    pub fn evolver_agent_id(&self) -> Option<AgentId> {
        self.evolver_agent_id.read().ok().and_then(|g| *g)
    }

    /// Set the evolver agent ID (called by the kernel after spawning).
    pub fn set_evolver_agent(&self, id: AgentId) {
        if let Ok(mut g) = self.evolver_agent_id.write() {
            *g = Some(id);
        }
    }

    /// Clear the evolver agent ID (called before respawn).
    pub fn clear_evolver_agent(&self) {
        if let Ok(mut g) = self.evolver_agent_id.write() {
            *g = None;
        }
    }

    /// Analyze a single session by sending a message to the analyzer agent.
    ///
    /// `send_message` is a callback provided by the kernel that sends a user
    /// message to the analyzer agent and returns `(response_text, input_tokens, output_tokens)`.
    /// `known_skill_ids` is used for fuzzy correction of hallucinated skill IDs.
    /// `context_window` is the model's context window in tokens for budget-aware truncation.
    #[allow(clippy::too_many_arguments)]
    pub async fn analyze_session<F, Fut>(
        &self,
        session_id: &str,
        agent_id: &str,
        messages: &[Message],
        available_skills: &[String],
        known_skill_ids: &[String],
        context_window: usize,
        send_message: F,
    ) -> Result<ExecutionAnalysis, EvolveError>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<(String, u64, u64), String>>,
    {
        let config = self.config();
        if !config.enabled {
            return Err(EvolveError::NotEnabled);
        }

        if self.analyzer_agent_id().is_none() {
            return Err(EvolveError::Other(
                "analyzer agent not spawned yet".into(),
            ));
        }

        let user_content =
            prompt::build_user_message(messages, available_skills, context_window);
        debug!(session_id, "sending analysis request to analyzer agent");

        let (response_text, input_tokens, output_tokens) = send_message(user_content)
            .await
            .map_err(EvolveError::LlmError)?;

        let raw = analyzer::parse_json_from_response(&response_text)?;

        let mut analysis = ExecutionAnalysis {
            id: AnalysisId::new(),
            session_id: session_id.to_string(),
            agent_id: agent_id.to_string(),
            task_completed: raw.task_completed,
            execution_note: raw.execution_note,
            tool_issues: raw.tool_issues,
            skill_judgments: raw.skill_judgments,
            evolution_suggestions: raw.evolution_suggestions,
            model_used: config.model.clone(),
            input_tokens,
            output_tokens,
            analyzed_at: chrono::Utc::now(),
        };

        // Fuzzy-correct hallucinated skill IDs
        if !known_skill_ids.is_empty() {
            correction::correct_analysis_skill_ids(&mut analysis, known_skill_ids);
        }

        self.store.save_analysis(&analysis)?;
        self.store.mark_session_analyzed(session_id)?;

        // Update skill counters based on judgments
        self.update_counters_from_analysis(&analysis);

        info!(
            session_id,
            analysis_id = %analysis.id,
            task_completed = analysis.task_completed,
            suggestions = analysis.evolution_suggestions.len(),
            "session analysis complete"
        );

        Ok(analysis)
    }

    /// Analyze all unanalyzed sessions up to batch_size.
    ///
    /// `session_loader` loads messages for a session.
    /// `send_message` sends a user message to the analyzer agent (called once per session).
    /// `known_skill_ids` is used for fuzzy correction of hallucinated skill IDs.
    /// `on_progress` is called for `Started`, each `Item` outcome, and `Completed`.
    pub async fn analyze_unanalyzed<L, S, Fut, P>(
        &self,
        session_loader: L,
        available_skills: &[String],
        known_skill_ids: &[String],
        context_window: usize,
        mut send_message: S,
        mut on_progress: P,
    ) -> Result<Vec<ExecutionAnalysis>, EvolveError>
    where
        L: Fn(&str, &str) -> Option<Vec<Message>>,
        S: FnMut(String) -> Fut,
        Fut: std::future::Future<Output = Result<(String, u64, u64), String>>,
        P: FnMut(ProgressEvent),
    {
        let config = self.config();
        if !config.enabled {
            return Err(EvolveError::NotEnabled);
        }

        if self.analyzer_agent_id().is_none() {
            return Err(EvolveError::Other(
                "analyzer agent not spawned yet".into(),
            ));
        }

        // Exclude evolution agents' own sessions to prevent endless self-analysis loops
        let mut exclude_ids = Vec::new();
        if let Some(id) = self.analyzer_agent_id() {
            exclude_ids.push(id.to_string());
        }
        if let Some(id) = self.evolver_agent_id() {
            exclude_ids.push(id.to_string());
        }

        // Mark evolution agents' own sessions as analyzed so they don't
        // accumulate in the pending count (they'll never be analyzed anyway).
        self.store.mark_agent_sessions_analyzed(&exclude_ids)?;

        let pending = self.store.list_unanalyzed_session_ids(config.batch_size, &exclude_ids)?;
        let total = pending.len();
        on_progress(ProgressEvent::Started { total });

        if pending.is_empty() {
            debug!("no unanalyzed sessions found");
            on_progress(ProgressEvent::Completed { analyzed: 0 });
            return Ok(vec![]);
        }

        info!(count = total, "analyzing unanalyzed sessions");

        let mut results = Vec::new();
        for (index, (session_id, agent_id)) in pending.iter().enumerate() {
            let status: ItemStatus = 'item: {
                let Some(messages) = session_loader(session_id, agent_id) else {
                    warn!(session_id, "could not load session, skipping");
                    break 'item ItemStatus::LoadFailed;
                };

                if messages.is_empty() {
                    debug!(session_id, "session has no messages, marking as analyzed");
                    let _ = self.store.mark_session_analyzed(session_id);
                    break 'item ItemStatus::NoMessages;
                }

                let user_content =
                    prompt::build_user_message(&messages, available_skills, context_window);
                debug!(session_id, "sending analysis request to analyzer agent");

                match send_message(user_content).await {
                    Ok((response_text, input_tokens, output_tokens)) => {
                        match analyzer::parse_json_from_response(&response_text) {
                            Ok(raw) => {
                                let mut analysis = ExecutionAnalysis {
                                    id: AnalysisId::new(),
                                    session_id: session_id.to_string(),
                                    agent_id: agent_id.to_string(),
                                    task_completed: raw.task_completed,
                                    execution_note: raw.execution_note,
                                    tool_issues: raw.tool_issues,
                                    skill_judgments: raw.skill_judgments,
                                    evolution_suggestions: raw.evolution_suggestions,
                                    model_used: config.model.clone(),
                                    input_tokens,
                                    output_tokens,
                                    analyzed_at: chrono::Utc::now(),
                                };

                                if !known_skill_ids.is_empty() {
                                    correction::correct_analysis_skill_ids(
                                        &mut analysis,
                                        known_skill_ids,
                                    );
                                }

                                if let Err(e) = self.store.save_analysis(&analysis) {
                                    warn!(session_id, error = %e, "failed to save analysis");
                                    break 'item ItemStatus::ParseFailed;
                                }
                                let _ = self.store.mark_session_analyzed(session_id);

                                self.update_counters_from_analysis(&analysis);

                                info!(
                                    session_id,
                                    analysis_id = %analysis.id,
                                    task_completed = analysis.task_completed,
                                    suggestions = analysis.evolution_suggestions.len(),
                                    "session analysis complete"
                                );
                                results.push(analysis);
                                ItemStatus::Analyzed
                            }
                            Err(e) => {
                                warn!(session_id, error = %e, "failed to parse analysis response");
                                let _ = self.store.mark_session_analyzed(session_id);
                                ItemStatus::ParseFailed
                            }
                        }
                    }
                    Err(e) => {
                        warn!(session_id, error = %e, "failed to send analysis message");
                        ItemStatus::SendFailed
                    }
                }
            };

            on_progress(ProgressEvent::Item {
                index,
                total,
                session_id: session_id.to_string(),
                agent_id: agent_id.to_string(),
                status,
            });
        }

        on_progress(ProgressEvent::Completed {
            analyzed: results.len(),
        });
        Ok(results)
    }

    /// Get aggregate statistics.
    ///
    /// Excludes evolution agents' own sessions from pending/analyzed counts
    /// so the stats match what "Run Analysis" would actually process.
    pub fn stats(&self) -> Result<EvolveStats, EvolveError> {
        let mut exclude_ids = Vec::new();
        if let Some(id) = self.analyzer_agent_id() {
            exclude_ids.push(id.to_string());
        }
        if let Some(id) = self.evolver_agent_id() {
            exclude_ids.push(id.to_string());
        }
        self.store.stats(&exclude_ids)
    }

    /// Update skill record counters based on analysis judgments.
    ///
    /// Uses name-based lookup since analyzer judgments reference skills by name.
    fn update_counters_from_analysis(&self, analysis: &ExecutionAnalysis) {
        for judgment in &analysis.skill_judgments {
            let selections = 1u64;
            let applied = if judgment.applied { 1u64 } else { 0 };
            let completions = if judgment.applied && analysis.task_completed {
                1u64
            } else {
                0
            };
            let fallbacks = if !judgment.applied && !analysis.task_completed {
                1u64
            } else {
                0
            };

            if let Err(e) = self.store.update_skill_counters_by_name(
                &judgment.skill_name,
                selections,
                applied,
                completions,
                fallbacks,
            ) {
                debug!(
                    skill = %judgment.skill_name,
                    error = %e,
                    "failed to update skill counters (skill may not have a record yet)"
                );
            }
        }
    }

    /// Import kernel-registered skills into the evolution store.
    ///
    /// Called once at kernel startup to ensure all installed skills have
    /// records in the evolution store. Skips skills that already have records.
    pub fn sync_skills_from_registry(&self, skills: Vec<SkillImport>) {
        let mut synced = 0u32;
        for skill in skills {
            // Skip if a record already exists for this skill name
            if let Ok(Some(_)) = self.store.get_skill_record_by_name(&skill.name) {
                continue;
            }

            let uuid_short = uuid::Uuid::new_v4().to_string()[..8].to_string();
            let now = chrono::Utc::now();

            let record = SkillRecord {
                skill_id: format!("{}__imp_{}", skill.name, uuid_short),
                name: skill.name,
                description: skill.description,
                path: skill.path,
                is_active: true,
                category: SkillCategory::Reference,
                tags: skill.tags,
                visibility: SkillVisibility::Private,
                creator_id: "system".into(),
                lineage: SkillLineage {
                    origin: SkillOrigin::Imported,
                    generation: 0,
                    parent_skill_ids: vec![],
                    source_task_id: None,
                    change_summary: "Imported from skill registry".into(),
                    content_diff: String::new(),
                    content_snapshot: std::collections::HashMap::new(),
                    created_at: now,
                    created_by: "system".into(),
                },
                tool_dependencies: skill.tools,
                critical_tools: vec![],
                total_selections: 0,
                total_applied: 0,
                total_completions: 0,
                total_fallbacks: 0,
                first_seen: now,
                last_updated: now,
            };

            if let Err(e) = self.store.save_skill_record(&record) {
                debug!(skill = %record.skill_id, error = %e, "failed to sync skill record");
            } else {
                synced += 1;
            }
        }
        if synced > 0 {
            info!(count = synced, "synced skills from registry into evolution store");
        }
    }

}
