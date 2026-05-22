//! SQLite persistence for execution analyses and evolve state.

use crate::types::*;
use rusqlite::Connection;
use std::sync::{Arc, Mutex};

/// Persistent store for execution analyses backed by SQLite.
///
/// Shares the same database connection as the rest of the memory substrate.
#[derive(Clone)]
pub struct EvolveStore {
    conn: Arc<Mutex<Connection>>,
}

impl EvolveStore {
    /// Create a new store wrapping the shared SQLite connection.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// Save an execution analysis and all its child records atomically.
    ///
    /// Wrapped in a single SQLite transaction — if any child insert fails,
    /// the whole write rolls back so we never leave an orphan parent row
    /// or a parent with partial children.
    pub fn save_analysis(&self, analysis: &ExecutionAnalysis) -> Result<(), EvolveError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| EvolveError::Other(e.to_string()))?;
        let tx = conn.transaction()?;

        tx.execute(
            "INSERT INTO execution_analyses (id, session_id, agent_id, task_completed, execution_note, model_used, input_tokens, output_tokens, analyzed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                analysis.id.to_string(),
                analysis.session_id,
                analysis.agent_id,
                analysis.task_completed as i32,
                analysis.execution_note,
                analysis.model_used,
                analysis.input_tokens as i64,
                analysis.output_tokens as i64,
                analysis.analyzed_at.to_rfc3339(),
            ],
        )?;

        let analysis_id = analysis.id.to_string();

        for issue in &analysis.tool_issues {
            tx.execute(
                "INSERT INTO evolve_tool_issues (analysis_id, tool_name, issue_type, description)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    analysis_id,
                    issue.tool_name,
                    issue.issue_type.to_string(),
                    issue.description,
                ],
            )?;
        }

        for judgment in &analysis.skill_judgments {
            tx.execute(
                "INSERT INTO evolve_skill_judgments (analysis_id, skill_name, applied, quality, note)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    analysis_id,
                    judgment.skill_name,
                    judgment.applied as i32,
                    judgment.quality.to_string(),
                    judgment.note,
                ],
            )?;
        }

        for suggestion in &analysis.evolution_suggestions {
            tx.execute(
                "INSERT INTO evolve_suggestions (analysis_id, kind, target_skill, description, priority)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    analysis_id,
                    suggestion.kind.to_string(),
                    suggestion.target_skill,
                    suggestion.description,
                    suggestion.priority as i32,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Mark a session as having been analyzed.
    pub fn mark_session_analyzed(&self, session_id: &str) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "UPDATE sessions SET evolution_analyzed = 1 WHERE id = ?1",
            [session_id],
        )?;
        Ok(())
    }

    /// Mark all unanalyzed sessions belonging to the given agent IDs as analyzed.
    pub fn mark_agent_sessions_analyzed(&self, agent_ids: &[String]) -> Result<(), EvolveError> {
        if agent_ids.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let placeholders: Vec<String> = agent_ids
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect();
        let sql = format!(
            "UPDATE sessions SET evolution_analyzed = 1 WHERE (evolution_analyzed = 0 OR evolution_analyzed IS NULL) AND agent_id IN ({})",
            placeholders.join(", ")
        );
        let params: Vec<&dyn rusqlite::types::ToSql> = agent_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();
        conn.execute(&sql, params.as_slice())?;
        Ok(())
    }

    /// List session IDs that have not yet been analyzed.
    ///
    /// `exclude_agent_ids` filters out sessions belonging to the given agents
    /// (e.g. the evolution analyzer/evolver), preventing the analyzer from
    /// analyzing its own conversations (which would create an endless loop).
    pub fn list_unanalyzed_session_ids(
        &self,
        limit: usize,
        exclude_agent_ids: &[String],
    ) -> Result<Vec<(String, String)>, EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;

        let query = if exclude_agent_ids.is_empty() {
            "SELECT id, agent_id FROM sessions
             WHERE (evolution_analyzed = 0 OR evolution_analyzed IS NULL)
             ORDER BY created_at DESC
             LIMIT ?1"
                .to_string()
        } else {
            let placeholders: Vec<String> = exclude_agent_ids
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", i + 2))
                .collect();
            format!(
                "SELECT id, agent_id FROM sessions
                 WHERE (evolution_analyzed = 0 OR evolution_analyzed IS NULL)
                 AND agent_id NOT IN ({})
                 ORDER BY created_at DESC
                 LIMIT ?1",
                placeholders.join(", ")
            )
        };

        let mut stmt = conn.prepare(&query)?;

        let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(limit as i64)];
        for id in exclude_agent_ids {
            params.push(Box::new(id.clone()));
        }
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            params.iter().map(|p| p.as_ref()).collect();

        let rows = stmt
            .query_map(param_refs.as_slice(), |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// List analyses with pagination, most recent first.
    pub fn list_analyses(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ExecutionAnalysis>, EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT id, session_id, agent_id, task_completed, execution_note, model_used, input_tokens, output_tokens, analyzed_at
             FROM execution_analyses
             ORDER BY analyzed_at DESC
             LIMIT ?1 OFFSET ?2",
        )?;

        let analysis_rows: Vec<ExecutionAnalysis> = stmt
            .query_map(rusqlite::params![limit as i64, offset as i64], |row| {
                Ok(ExecutionAnalysis {
                    id: row
                        .get::<_, String>(0)?
                        .parse()
                        .unwrap_or_else(|_| AnalysisId::new()),
                    session_id: row.get(1)?,
                    agent_id: row.get(2)?,
                    task_completed: row.get::<_, i32>(3)? != 0,
                    execution_note: row.get(4)?,
                    model_used: row.get(5)?,
                    input_tokens: row.get::<_, i64>(6)? as u64,
                    output_tokens: row.get::<_, i64>(7)? as u64,
                    analyzed_at: chrono::DateTime::parse_from_rfc3339(
                        &row.get::<_, String>(8)?,
                    )
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                    tool_issues: vec![],
                    skill_judgments: vec![],
                    evolution_suggestions: vec![],
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        // Load child records for each analysis
        let mut results = Vec::with_capacity(analysis_rows.len());
        for mut analysis in analysis_rows {
            let aid = analysis.id.to_string();
            analysis.tool_issues = self.load_tool_issues(&conn, &aid)?;
            analysis.skill_judgments = self.load_skill_judgments(&conn, &aid)?;
            analysis.evolution_suggestions = self.load_suggestions(&conn, &aid)?;
            results.push(analysis);
        }
        Ok(results)
    }

    /// Total number of analyses (for paginated UIs).
    pub fn count_analyses(&self) -> Result<i64, EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM execution_analyses",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// Get a single analysis by ID with all child records.
    pub fn get_analysis(&self, id: &str) -> Result<Option<ExecutionAnalysis>, EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT id, session_id, agent_id, task_completed, execution_note, model_used, input_tokens, output_tokens, analyzed_at
             FROM execution_analyses WHERE id = ?1",
        )?;

        let mut analysis = match stmt.query_row([id], |row| {
            Ok(ExecutionAnalysis {
                id: row
                    .get::<_, String>(0)?
                    .parse()
                    .unwrap_or_else(|_| AnalysisId::new()),
                session_id: row.get(1)?,
                agent_id: row.get(2)?,
                task_completed: row.get::<_, i32>(3)? != 0,
                execution_note: row.get(4)?,
                model_used: row.get(5)?,
                input_tokens: row.get::<_, i64>(6)? as u64,
                output_tokens: row.get::<_, i64>(7)? as u64,
                analyzed_at: chrono::DateTime::parse_from_rfc3339(
                    &row.get::<_, String>(8)?,
                )
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
                tool_issues: vec![],
                skill_judgments: vec![],
                evolution_suggestions: vec![],
            })
        }) {
            Ok(a) => a,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        analysis.tool_issues = self.load_tool_issues(&conn, id)?;
        analysis.skill_judgments = self.load_skill_judgments(&conn, id)?;
        analysis.evolution_suggestions = self.load_suggestions(&conn, id)?;
        Ok(Some(analysis))
    }

    /// Get aggregate statistics.
    ///
    /// `exclude_agent_ids` filters out sessions belonging to evolution agents
    /// (analyzer, evolver) so the pending count matches what "Run Analysis" sees.
    pub fn stats(&self, exclude_agent_ids: &[String]) -> Result<EvolveStats, EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;

        let total_analyses: u64 = conn
            .query_row("SELECT COUNT(*) FROM execution_analyses", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as u64;

        let (analyzed_query, pending_query) = if exclude_agent_ids.is_empty() {
            (
                "SELECT COUNT(*) FROM sessions WHERE evolution_analyzed = 1".to_string(),
                "SELECT COUNT(*) FROM sessions WHERE evolution_analyzed = 0 OR evolution_analyzed IS NULL".to_string(),
            )
        } else {
            let placeholders: Vec<String> = exclude_agent_ids
                .iter()
                .enumerate()
                .map(|(i, _)| format!("?{}", i + 1))
                .collect();
            let not_in = placeholders.join(", ");
            (
                format!("SELECT COUNT(*) FROM sessions WHERE evolution_analyzed = 1 AND agent_id NOT IN ({})", not_in),
                format!("SELECT COUNT(*) FROM sessions WHERE (evolution_analyzed = 0 OR evolution_analyzed IS NULL) AND agent_id NOT IN ({})", not_in),
            )
        };

        let params: Vec<&dyn rusqlite::types::ToSql> = exclude_agent_ids
            .iter()
            .map(|s| s as &dyn rusqlite::types::ToSql)
            .collect();

        let sessions_analyzed: u64 = conn
            .query_row(&analyzed_query, params.as_slice(), |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as u64;

        let sessions_pending: u64 = conn
            .query_row(&pending_query, params.as_slice(), |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as u64;

        let avg_completion_rate: f64 = conn
            .query_row(
                "SELECT COALESCE(AVG(CAST(task_completed AS REAL)), 0.0) FROM execution_analyses",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0.0);

        let total_suggestions: u64 = conn
            .query_row("SELECT COUNT(*) FROM evolve_suggestions", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as u64;

        let total_tool_issues: u64 = conn
            .query_row("SELECT COUNT(*) FROM evolve_tool_issues", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_or(0) as u64;

        Ok(EvolveStats {
            total_analyses,
            sessions_analyzed,
            sessions_pending,
            avg_completion_rate,
            total_suggestions,
            total_tool_issues,
        })
    }

    // -- Skill Records --

    /// Save or upsert a skill record.
    pub fn save_skill_record(&self, record: &SkillRecord) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "INSERT INTO skill_records (skill_id, name, description, path, is_active, category, tags, visibility, creator_id, lineage, tool_dependencies, critical_tools, total_selections, total_applied, total_completions, total_fallbacks, first_seen, last_updated, is_canary, canary_selections, canary_completions, parent_completion_rate_at_birth, canary_parent_skill_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)
             ON CONFLICT(skill_id) DO UPDATE SET
                name = excluded.name,
                description = excluded.description,
                path = excluded.path,
                is_active = excluded.is_active,
                category = excluded.category,
                tags = excluded.tags,
                visibility = excluded.visibility,
                lineage = excluded.lineage,
                tool_dependencies = excluded.tool_dependencies,
                critical_tools = excluded.critical_tools,
                total_selections = excluded.total_selections,
                total_applied = excluded.total_applied,
                total_completions = excluded.total_completions,
                total_fallbacks = excluded.total_fallbacks,
                last_updated = excluded.last_updated,
                is_canary = excluded.is_canary,
                canary_selections = excluded.canary_selections,
                canary_completions = excluded.canary_completions,
                parent_completion_rate_at_birth = excluded.parent_completion_rate_at_birth,
                canary_parent_skill_id = excluded.canary_parent_skill_id",
            rusqlite::params![
                record.skill_id,
                record.name,
                record.description,
                record.path,
                record.is_active as i32,
                record.category.to_string(),
                serde_json::to_string(&record.tags).unwrap_or_default(),
                record.visibility.to_string(),
                record.creator_id,
                serde_json::to_string(&record.lineage).unwrap_or_default(),
                serde_json::to_string(&record.tool_dependencies).unwrap_or_default(),
                serde_json::to_string(&record.critical_tools).unwrap_or_default(),
                record.total_selections as i64,
                record.total_applied as i64,
                record.total_completions as i64,
                record.total_fallbacks as i64,
                record.first_seen.to_rfc3339(),
                record.last_updated.to_rfc3339(),
                record.is_canary as i32,
                record.canary_selections as i64,
                record.canary_completions as i64,
                record.parent_completion_rate_at_birth,
                record.canary_parent_skill_id,
            ],
        )?;
        Ok(())
    }

    /// Get a skill record by ID.
    pub fn get_skill_record(&self, skill_id: &str) -> Result<Option<SkillRecord>, EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT skill_id, name, description, path, is_active, category, tags, visibility, creator_id, lineage, tool_dependencies, critical_tools, total_selections, total_applied, total_completions, total_fallbacks, first_seen, last_updated, is_canary, canary_selections, canary_completions, parent_completion_rate_at_birth, canary_parent_skill_id
             FROM skill_records WHERE skill_id = ?1",
        )?;
        match stmt.query_row([skill_id], Self::row_to_skill_record) {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Get a skill record by human-readable name (returns the first match).
    pub fn get_skill_record_by_name(&self, name: &str) -> Result<Option<SkillRecord>, EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT skill_id, name, description, path, is_active, category, tags, visibility, creator_id, lineage, tool_dependencies, critical_tools, total_selections, total_applied, total_completions, total_fallbacks, first_seen, last_updated, is_canary, canary_selections, canary_completions, parent_completion_rate_at_birth, canary_parent_skill_id
             FROM skill_records WHERE name = ?1 LIMIT 1",
        )?;
        match stmt.query_row([name], Self::row_to_skill_record) {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Update the filesystem path of a skill record by name.
    ///
    /// Used when a bundled skill is materialized to disk for evolution.
    pub fn update_skill_path_by_name(&self, name: &str, new_path: &str) -> Result<(), EvolveError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "UPDATE skill_records SET path = ?1, last_updated = ?2 WHERE name = ?3",
            rusqlite::params![new_path, chrono::Utc::now().to_rfc3339(), name],
        )?;
        Ok(())
    }

    /// Atomically increment skill counters by skill **name** (not ID).
    ///
    /// Only updates the active row for that name. Deactivated parents are
    /// preserved as historical records — incrementing their counters would
    /// pollute aggregate stats and corrupt completion-rate trend lines.
    pub fn update_skill_counters_by_name(
        &self,
        name: &str,
        selections: u64,
        applied: u64,
        completions: u64,
        fallbacks: u64,
    ) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "UPDATE skill_records SET
                total_selections = total_selections + ?2,
                total_applied = total_applied + ?3,
                total_completions = total_completions + ?4,
                total_fallbacks = total_fallbacks + ?5,
                last_updated = ?6
             WHERE name = ?1 AND is_active = 1",
            rusqlite::params![
                name,
                selections as i64,
                applied as i64,
                completions as i64,
                fallbacks as i64,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// List skill records, optionally filtering to active only.
    pub fn list_skill_records(&self, active_only: bool) -> Result<Vec<SkillRecord>, EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let sql = if active_only {
            "SELECT skill_id, name, description, path, is_active, category, tags, visibility, creator_id, lineage, tool_dependencies, critical_tools, total_selections, total_applied, total_completions, total_fallbacks, first_seen, last_updated, is_canary, canary_selections, canary_completions, parent_completion_rate_at_birth, canary_parent_skill_id
             FROM skill_records WHERE is_active = 1 ORDER BY name"
        } else {
            "SELECT skill_id, name, description, path, is_active, category, tags, visibility, creator_id, lineage, tool_dependencies, critical_tools, total_selections, total_applied, total_completions, total_fallbacks, first_seen, last_updated, is_canary, canary_selections, canary_completions, parent_completion_rate_at_birth, canary_parent_skill_id
             FROM skill_records ORDER BY name"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt
            .query_map([], Self::row_to_skill_record)?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Atomically increment skill counters.
    pub fn update_skill_counters(
        &self,
        skill_id: &str,
        selections: u64,
        applied: u64,
        completions: u64,
        fallbacks: u64,
    ) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "UPDATE skill_records SET
                total_selections = total_selections + ?2,
                total_applied = total_applied + ?3,
                total_completions = total_completions + ?4,
                total_fallbacks = total_fallbacks + ?5,
                last_updated = ?6
             WHERE skill_id = ?1",
            rusqlite::params![
                skill_id,
                selections as i64,
                applied as i64,
                completions as i64,
                fallbacks as i64,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Mark a suggestion as executed after successful evolution.
    pub fn mark_suggestion_executed(
        &self,
        analysis_id: &AnalysisId,
        kind: &SuggestionKind,
        description: &str,
    ) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE evolve_suggestions SET executed_at = ?1, status = 'applied' \
             WHERE analysis_id = ?2 AND kind = ?3 AND description = ?4 AND executed_at IS NULL",
            rusqlite::params![now, analysis_id.to_string(), kind.to_string(), description],
        )?;
        Ok(())
    }

    /// Mark a suggestion as failed after unsuccessful evolution.
    pub fn mark_suggestion_failed(
        &self,
        analysis_id: &AnalysisId,
        kind: &SuggestionKind,
        description: &str,
        reason: &str,
    ) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE evolve_suggestions SET failed_at = ?1, failure_reason = ?2, status = 'failed' \
             WHERE analysis_id = ?3 AND kind = ?4 AND description = ?5 AND executed_at IS NULL",
            rusqlite::params![now, reason, analysis_id.to_string(), kind.to_string(), description],
        )?;
        Ok(())
    }

    /// Mark a suggestion as declined by the LLM confirmation gate or cost cap.
    /// Distinct from `failed` so the UI can show a different badge and the
    /// row is not re-tried on the next batch apply.
    pub fn mark_suggestion_declined(
        &self,
        analysis_id: &AnalysisId,
        kind: &SuggestionKind,
        description: &str,
        reason: &str,
    ) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "UPDATE evolve_suggestions SET status = 'declined', dedup_reason = ?1 \
             WHERE analysis_id = ?2 AND kind = ?3 AND description = ?4 \
                AND executed_at IS NULL AND failed_at IS NULL \
                AND COALESCE(status, 'pending') = 'pending'",
            rusqlite::params![reason, analysis_id.to_string(), kind.to_string(), description],
        )?;
        Ok(())
    }

    /// Delete a single suggestion by its composite key.
    ///
    /// `evolve_suggestions.supersedes_id` is a self-FK with no `ON DELETE`
    /// action, so a straight DELETE fails with `FOREIGN KEY constraint failed`
    /// whenever the target row was later superseded. Detach child refs first,
    /// then delete — all in one transaction.
    pub fn delete_suggestion(
        &self,
        analysis_id: &AnalysisId,
        kind: &SuggestionKind,
        description: &str,
    ) -> Result<(), EvolveError> {
        let mut conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE evolve_suggestions SET supersedes_id = NULL \
             WHERE supersedes_id IN ( \
                 SELECT id FROM evolve_suggestions \
                 WHERE analysis_id = ?1 AND kind = ?2 AND description = ?3 \
             )",
            rusqlite::params![analysis_id.to_string(), kind.to_string(), description],
        )?;
        tx.execute(
            "DELETE FROM evolve_suggestions WHERE analysis_id = ?1 AND kind = ?2 AND description = ?3",
            rusqlite::params![analysis_id.to_string(), kind.to_string(), description],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Deactivate a skill (set is_active = false).
    pub fn deactivate_skill(&self, skill_id: &str) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "UPDATE skill_records SET is_active = 0, last_updated = ?2 WHERE skill_id = ?1",
            rusqlite::params![skill_id, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Reactivate a skill (set is_active = true).
    pub fn reactivate_skill(&self, skill_id: &str) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "UPDATE skill_records SET is_active = 1, last_updated = ?2 WHERE skill_id = ?1",
            rusqlite::params![skill_id, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Delete a skill record from the database.
    pub fn delete_skill_record(&self, skill_id: &str) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "DELETE FROM skill_records WHERE skill_id = ?1",
            rusqlite::params![skill_id],
        )?;
        Ok(())
    }

    /// List all active canary records (skills under canary rollout).
    pub fn list_active_canaries(&self) -> Result<Vec<SkillRecord>, EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT skill_id, name, description, path, is_active, category, tags, visibility, creator_id, lineage, tool_dependencies, critical_tools, total_selections, total_applied, total_completions, total_fallbacks, first_seen, last_updated, is_canary, canary_selections, canary_completions, parent_completion_rate_at_birth, canary_parent_skill_id
             FROM skill_records WHERE is_canary = 1 AND is_active = 1 ORDER BY first_seen",
        )?;
        let rows = stmt
            .query_map([], Self::row_to_skill_record)?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Return the active canary sibling for a given parent skill name (if any).
    /// Used by the registry to decide whether to apply traffic splitting.
    pub fn get_active_canary_for_parent_name(
        &self,
        parent_name: &str,
    ) -> Result<Option<SkillRecord>, EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT skill_id, name, description, path, is_active, category, tags, visibility, creator_id, lineage, tool_dependencies, critical_tools, total_selections, total_applied, total_completions, total_fallbacks, first_seen, last_updated, is_canary, canary_selections, canary_completions, parent_completion_rate_at_birth, canary_parent_skill_id
             FROM skill_records
             WHERE is_canary = 1 AND is_active = 1 AND name = ?1
             LIMIT 1",
        )?;
        match stmt.query_row([parent_name], Self::row_to_skill_record) {
            Ok(r) => Ok(Some(r)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Increment canary-only counters for a record by skill_id.
    pub fn increment_canary_counters(
        &self,
        skill_id: &str,
        selections: u64,
        completions: u64,
    ) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "UPDATE skill_records SET
                canary_selections = canary_selections + ?2,
                canary_completions = canary_completions + ?3,
                last_updated = ?4
             WHERE skill_id = ?1",
            rusqlite::params![
                skill_id,
                selections as i64,
                completions as i64,
                chrono::Utc::now().to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Promote a canary: clear canary flag on child, deactivate the parent.
    /// Done in a single transaction.
    pub fn promote_canary(
        &self,
        canary_skill_id: &str,
        parent_skill_id: &str,
    ) -> Result<(), EvolveError> {
        let mut conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let tx = conn.transaction()?;
        let now = chrono::Utc::now().to_rfc3339();
        tx.execute(
            "UPDATE skill_records SET is_canary = 0, canary_parent_skill_id = NULL, last_updated = ?2
             WHERE skill_id = ?1",
            rusqlite::params![canary_skill_id, now],
        )?;
        tx.execute(
            "UPDATE skill_records SET is_active = 0, last_updated = ?2 WHERE skill_id = ?1",
            rusqlite::params![parent_skill_id, now],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Roll back a canary: deactivate the canary, parent stays active.
    pub fn rollback_canary(&self, canary_skill_id: &str) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "UPDATE skill_records SET is_active = 0, last_updated = ?2 WHERE skill_id = ?1",
            rusqlite::params![canary_skill_id, chrono::Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    /// Increment the analyzer parse-attempt counter for a session.
    /// Returns the new attempt count.
    pub fn bump_session_parse_attempts(&self, session_id: &str) -> Result<u32, EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "UPDATE sessions SET evolve_parse_attempts = evolve_parse_attempts + 1 WHERE id = ?1",
            [session_id],
        )?;
        let count: i64 = conn
            .query_row(
                "SELECT evolve_parse_attempts FROM sessions WHERE id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .unwrap_or(0);
        Ok(count as u32)
    }

    // -- Private helpers --

    fn row_to_skill_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<SkillRecord> {
        let tags_str: String = row.get(6)?;
        let lineage_str: String = row.get(9)?;
        let tool_deps_str: String = row.get(10)?;
        let critical_str: String = row.get(11)?;

        Ok(SkillRecord {
            skill_id: row.get(0)?,
            name: row.get(1)?,
            description: row.get(2)?,
            path: row.get(3)?,
            is_active: row.get::<_, i32>(4)? != 0,
            category: row
                .get::<_, String>(5)?
                .parse()
                .unwrap_or_default(),
            tags: serde_json::from_str(&tags_str).unwrap_or_default(),
            visibility: row
                .get::<_, String>(7)?
                .parse()
                .unwrap_or_default(),
            creator_id: row.get(8)?,
            lineage: serde_json::from_str(&lineage_str).unwrap_or_else(|_| SkillLineage {
                origin: SkillOrigin::Imported,
                generation: 0,
                parent_skill_ids: vec![],
                source_task_id: None,
                change_summary: String::new(),
                content_diff: String::new(),
                content_snapshot: std::collections::HashMap::new(),
                pre_fix_snapshot: std::collections::HashMap::new(),
                created_at: chrono::Utc::now(),
                created_by: "unknown".into(),
            }),
            tool_dependencies: serde_json::from_str(&tool_deps_str).unwrap_or_default(),
            critical_tools: serde_json::from_str(&critical_str).unwrap_or_default(),
            total_selections: row.get::<_, i64>(12)? as u64,
            total_applied: row.get::<_, i64>(13)? as u64,
            total_completions: row.get::<_, i64>(14)? as u64,
            total_fallbacks: row.get::<_, i64>(15)? as u64,
            first_seen: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(16)?)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
            last_updated: chrono::DateTime::parse_from_rfc3339(&row.get::<_, String>(17)?)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
            is_canary: row.get::<_, i32>(18).unwrap_or(0) != 0,
            canary_selections: row.get::<_, i64>(19).unwrap_or(0) as u64,
            canary_completions: row.get::<_, i64>(20).unwrap_or(0) as u64,
            parent_completion_rate_at_birth: row.get::<_, f64>(21).unwrap_or(0.0),
            canary_parent_skill_id: row.get::<_, Option<String>>(22).unwrap_or(None),
        })
    }

    fn load_tool_issues(
        &self,
        conn: &Connection,
        analysis_id: &str,
    ) -> Result<Vec<ToolIssue>, EvolveError> {
        let mut stmt = conn.prepare(
            "SELECT tool_name, issue_type, description FROM evolve_tool_issues WHERE analysis_id = ?1",
        )?;
        let rows = stmt
            .query_map([analysis_id], |row| {
                Ok(ToolIssue {
                    tool_name: row.get(0)?,
                    issue_type: row
                        .get::<_, String>(1)?
                        .parse()
                        .unwrap_or(ToolIssueType::Failure),
                    description: row.get(2)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    fn load_skill_judgments(
        &self,
        conn: &Connection,
        analysis_id: &str,
    ) -> Result<Vec<SkillJudgment>, EvolveError> {
        let mut stmt = conn.prepare(
            "SELECT skill_name, applied, quality, note FROM evolve_skill_judgments WHERE analysis_id = ?1",
        )?;
        let rows = stmt
            .query_map([analysis_id], |row| {
                Ok(SkillJudgment {
                    skill_name: row.get(0)?,
                    applied: row.get::<_, i32>(1)? != 0,
                    quality: row
                        .get::<_, String>(2)?
                        .parse()
                        .unwrap_or(SkillQuality::NotApplicable),
                    note: row.get(3)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    fn load_suggestions(
        &self,
        conn: &Connection,
        analysis_id: &str,
    ) -> Result<Vec<EvolutionSuggestion>, EvolveError> {
        let mut stmt = conn.prepare(
            "SELECT kind, target_skill, description, priority, executed_at, failed_at, failure_reason, \
                    COALESCE(status, 'pending'), supersedes_id, dedup_reason \
             FROM evolve_suggestions WHERE analysis_id = ?1",
        )?;
        let rows = stmt
            .query_map([analysis_id], |row| {
                Ok(EvolutionSuggestion {
                    kind: row
                        .get::<_, String>(0)?
                        .parse()
                        .unwrap_or(SuggestionKind::Fix),
                    target_skill: row.get(1)?,
                    description: row.get(2)?,
                    priority: row.get::<_, i32>(3)? as u8,
                    executed_at: row.get(4)?,
                    failed_at: row.get(5)?,
                    failure_reason: row.get(6)?,
                    status: row
                        .get::<_, String>(7)?
                        .parse()
                        .unwrap_or(SuggestionStatus::Pending),
                    supersedes_id: row.get(8)?,
                    dedup_reason: row.get(9)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// List all suggestions with status='pending' across every analysis.
    /// Returns (row_id, analysis_id, suggestion). Sorted by priority desc, then id asc.
    /// Used by the batch-apply runner to gather candidates for dedup + execution.
    pub fn list_all_pending_suggestions(
        &self,
    ) -> Result<Vec<(i64, AnalysisId, EvolutionSuggestion)>, EvolveError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| EvolveError::Other(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT id, analysis_id, kind, target_skill, description, priority, \
                    executed_at, failed_at, failure_reason, \
                    COALESCE(status, 'pending'), supersedes_id, dedup_reason \
             FROM evolve_suggestions \
             WHERE COALESCE(status, 'pending') = 'pending' \
                AND executed_at IS NULL AND failed_at IS NULL \
             ORDER BY priority DESC, id ASC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let id: i64 = row.get(0)?;
                let analysis_id_str: String = row.get(1)?;
                let analysis_id: AnalysisId =
                    analysis_id_str.parse().map_err(|e: uuid::Error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                let suggestion = EvolutionSuggestion {
                    kind: row
                        .get::<_, String>(2)?
                        .parse()
                        .unwrap_or(SuggestionKind::Fix),
                    target_skill: row.get(3)?,
                    description: row.get(4)?,
                    priority: row.get::<_, i32>(5)? as u8,
                    executed_at: row.get(6)?,
                    failed_at: row.get(7)?,
                    failure_reason: row.get(8)?,
                    status: row
                        .get::<_, String>(9)?
                        .parse()
                        .unwrap_or(SuggestionStatus::Pending),
                    supersedes_id: row.get(10)?,
                    dedup_reason: row.get(11)?,
                };
                Ok((id, analysis_id, suggestion))
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(rows)
    }

    /// Mark a suggestion row as superseded by another suggestion's row id.
    /// Loser row keeps its analysis_id and content but is filtered out of pending lists.
    pub fn mark_suggestion_superseded(
        &self,
        loser_id: i64,
        survivor_id: i64,
        reason: &str,
    ) -> Result<(), EvolveError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "UPDATE evolve_suggestions \
             SET status = 'superseded', supersedes_id = ?1, dedup_reason = ?2 \
             WHERE id = ?3 AND status = 'pending'",
            rusqlite::params![survivor_id, reason, loser_id],
        )?;
        Ok(())
    }

    /// Persist the evolve config to SQLite as a JSON blob.
    pub fn save_config(&self, config: &openfang_types::config::EvolveConfig) -> Result<(), EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let json = serde_json::to_string(config)
            .map_err(|e| EvolveError::Other(e.to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO evolve_config (key, value) VALUES ('config', ?1)",
            rusqlite::params![json],
        )?;
        Ok(())
    }

    /// Load the persisted evolve config from SQLite, if any.
    pub fn load_config(&self) -> Result<Option<openfang_types::config::EvolveConfig>, EvolveError> {
        let conn = self.conn.lock().map_err(|e| EvolveError::Other(e.to_string()))?;
        let mut stmt = conn
            .prepare("SELECT value FROM evolve_config WHERE key = 'config'")
            .map_err(|e| EvolveError::Other(e.to_string()))?;
        let result: Option<String> = stmt
            .query_row([], |row| row.get(0))
            .ok();
        match result {
            Some(json) => {
                let config: openfang_types::config::EvolveConfig =
                    serde_json::from_str(&json).map_err(|e| EvolveError::Other(e.to_string()))?;
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn setup_db() -> Arc<Mutex<Connection>> {
        let conn = Connection::open_in_memory().unwrap();
        // Run the migration manually for testing
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                messages BLOB NOT NULL,
                context_window_tokens INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                label TEXT,
                evolution_analyzed INTEGER NOT NULL DEFAULT 0,
                evolve_parse_attempts INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS execution_analyses (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                task_completed INTEGER NOT NULL,
                execution_note TEXT NOT NULL,
                model_used TEXT NOT NULL,
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                analyzed_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_ea_session ON execution_analyses(session_id);

            CREATE TABLE IF NOT EXISTS evolve_tool_issues (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL REFERENCES execution_analyses(id) ON DELETE CASCADE,
                tool_name TEXT NOT NULL,
                issue_type TEXT NOT NULL,
                description TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evolve_skill_judgments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL REFERENCES execution_analyses(id) ON DELETE CASCADE,
                skill_name TEXT NOT NULL,
                applied INTEGER NOT NULL,
                quality TEXT NOT NULL,
                note TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evolve_suggestions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT NOT NULL REFERENCES execution_analyses(id) ON DELETE CASCADE,
                kind TEXT NOT NULL,
                target_skill TEXT,
                description TEXT NOT NULL,
                priority INTEGER NOT NULL DEFAULT 3,
                executed_at TEXT,
                failed_at TEXT,
                failure_reason TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                supersedes_id INTEGER REFERENCES evolve_suggestions(id),
                dedup_reason TEXT
            );

            CREATE TABLE IF NOT EXISTS skill_records (
                skill_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                path TEXT,
                is_active INTEGER DEFAULT 1,
                category TEXT,
                tags TEXT,
                visibility TEXT,
                creator_id TEXT,
                lineage TEXT,
                tool_dependencies TEXT,
                critical_tools TEXT,
                total_selections INTEGER DEFAULT 0,
                total_applied INTEGER DEFAULT 0,
                total_completions INTEGER DEFAULT 0,
                total_fallbacks INTEGER DEFAULT 0,
                first_seen TEXT,
                last_updated TEXT,
                is_canary INTEGER NOT NULL DEFAULT 0,
                canary_selections INTEGER NOT NULL DEFAULT 0,
                canary_completions INTEGER NOT NULL DEFAULT 0,
                parent_completion_rate_at_birth REAL NOT NULL DEFAULT 0.0,
                canary_parent_skill_id TEXT
            );

            ",
        )
        .unwrap();
        Arc::new(Mutex::new(conn))
    }

    fn sample_analysis() -> ExecutionAnalysis {
        ExecutionAnalysis {
            id: AnalysisId::new(),
            session_id: "sess-1".into(),
            agent_id: "agent-1".into(),
            task_completed: true,
            execution_note: "Task completed successfully.".into(),
            tool_issues: vec![ToolIssue {
                tool_name: "web_search".into(),
                issue_type: ToolIssueType::Failure,
                description: "Returned empty results".into(),
            }],
            skill_judgments: vec![SkillJudgment {
                skill_name: "docker".into(),
                applied: true,
                quality: SkillQuality::Good,
                note: "Followed instructions".into(),
            }],
            evolution_suggestions: vec![EvolutionSuggestion {
                kind: SuggestionKind::Fix,
                target_skill: Some("docker".into()),
                description: "Update port mapping".into(),
                priority: 3,
                ..Default::default()
            }],
            model_used: "test-model".into(),
            input_tokens: 100,
            output_tokens: 50,
            analyzed_at: Utc::now(),
        }
    }

    #[test]
    fn save_and_get_analysis() {
        let conn = setup_db();
        let store = EvolveStore::new(conn);
        let analysis = sample_analysis();
        let id = analysis.id.to_string();

        store.save_analysis(&analysis).unwrap();

        let loaded = store.get_analysis(&id).unwrap().unwrap();
        assert_eq!(loaded.session_id, "sess-1");
        assert!(loaded.task_completed);
        assert_eq!(loaded.tool_issues.len(), 1);
        assert_eq!(loaded.tool_issues[0].tool_name, "web_search");
        assert_eq!(loaded.skill_judgments.len(), 1);
        assert!(loaded.skill_judgments[0].applied);
        assert_eq!(loaded.evolution_suggestions.len(), 1);
        assert_eq!(loaded.evolution_suggestions[0].priority, 3);
    }

    #[test]
    fn list_analyses_pagination() {
        let conn = setup_db();
        let store = EvolveStore::new(conn);

        for i in 0..5 {
            let mut a = sample_analysis();
            a.id = AnalysisId::new();
            a.session_id = format!("sess-{i}");
            store.save_analysis(&a).unwrap();
        }

        let page1 = store.list_analyses(3, 0).unwrap();
        assert_eq!(page1.len(), 3);

        let page2 = store.list_analyses(3, 3).unwrap();
        assert_eq!(page2.len(), 2);
    }

    #[test]
    fn mark_session_analyzed() {
        let conn = setup_db();
        let store = EvolveStore::new(conn.clone());

        // Insert a test session
        {
            let c = conn.lock().unwrap();
            c.execute(
                "INSERT INTO sessions (id, agent_id, messages, context_window_tokens, created_at, updated_at)
                 VALUES ('s1', 'a1', X'', 0, '2024-01-01', '2024-01-01')",
                [],
            )
            .unwrap();
        }

        let unanalyzed = store.list_unanalyzed_session_ids(100, &[]).unwrap();
        assert_eq!(unanalyzed.len(), 1);

        store.mark_session_analyzed("s1").unwrap();

        let unanalyzed = store.list_unanalyzed_session_ids(100, &[]).unwrap();
        assert_eq!(unanalyzed.len(), 0);
    }

    #[test]
    fn list_unanalyzed_excludes_agent_ids() {
        let conn = setup_db();
        let store = EvolveStore::new(conn.clone());

        {
            let c = conn.lock().unwrap();
            c.execute(
                "INSERT INTO sessions (id, agent_id, messages, context_window_tokens, created_at, updated_at)
                 VALUES ('s1', 'user-agent', X'', 0, '2024-01-01', '2024-01-01')",
                [],
            )
            .unwrap();
            c.execute(
                "INSERT INTO sessions (id, agent_id, messages, context_window_tokens, created_at, updated_at)
                 VALUES ('s2', 'evolution-analyzer', X'', 0, '2024-01-02', '2024-01-02')",
                [],
            )
            .unwrap();
            c.execute(
                "INSERT INTO sessions (id, agent_id, messages, context_window_tokens, created_at, updated_at)
                 VALUES ('s3', 'evolver-agent', X'', 0, '2024-01-03', '2024-01-03')",
                [],
            )
            .unwrap();
        }

        // Without exclusion, all 3 are returned
        let all = store.list_unanalyzed_session_ids(100, &[]).unwrap();
        assert_eq!(all.len(), 3);

        // Excluding evolution agents filters them out
        let filtered = store
            .list_unanalyzed_session_ids(
                100,
                &["evolution-analyzer".to_string(), "evolver-agent".to_string()],
            )
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].1, "user-agent");
    }

    #[test]
    fn stats_empty_db() {
        let conn = setup_db();
        let store = EvolveStore::new(conn);

        let stats = store.stats(&[]).unwrap();
        assert_eq!(stats.total_analyses, 0);
        assert_eq!(stats.sessions_analyzed, 0);
    }

    #[test]
    fn stats_with_data() {
        let conn = setup_db();
        let store = EvolveStore::new(conn.clone());

        // Insert sessions
        {
            let c = conn.lock().unwrap();
            c.execute(
                "INSERT INTO sessions (id, agent_id, messages, context_window_tokens, created_at, updated_at, evolution_analyzed)
                 VALUES ('s1', 'a1', X'', 0, '2024-01-01', '2024-01-01', 1)",
                [],
            )
            .unwrap();
            c.execute(
                "INSERT INTO sessions (id, agent_id, messages, context_window_tokens, created_at, updated_at, evolution_analyzed)
                 VALUES ('s2', 'a1', X'', 0, '2024-01-01', '2024-01-01', 0)",
                [],
            )
            .unwrap();
        }

        let analysis = sample_analysis();
        store.save_analysis(&analysis).unwrap();

        let stats = store.stats(&[]).unwrap();
        assert_eq!(stats.total_analyses, 1);
        assert_eq!(stats.sessions_analyzed, 1);
        assert_eq!(stats.sessions_pending, 1);
        assert_eq!(stats.total_suggestions, 1);
        assert_eq!(stats.total_tool_issues, 1);
    }

    #[test]
    fn stats_excludes_evolution_agents() {
        let conn = setup_db();
        let store = EvolveStore::new(conn.clone());

        {
            let c = conn.lock().unwrap();
            c.execute(
                "INSERT INTO sessions (id, agent_id, messages, context_window_tokens, created_at, updated_at, evolution_analyzed)
                 VALUES ('s1', 'user-agent', X'', 0, '2024-01-01', '2024-01-01', 0)",
                [],
            )
            .unwrap();
            c.execute(
                "INSERT INTO sessions (id, agent_id, messages, context_window_tokens, created_at, updated_at, evolution_analyzed)
                 VALUES ('s2', 'evolution-analyzer', X'', 0, '2024-01-02', '2024-01-02', 0)",
                [],
            )
            .unwrap();
            c.execute(
                "INSERT INTO sessions (id, agent_id, messages, context_window_tokens, created_at, updated_at, evolution_analyzed)
                 VALUES ('s3', 'evolver-agent', X'', 0, '2024-01-03', '2024-01-03', 0)",
                [],
            )
            .unwrap();
        }

        // Without exclusion, all 3 are pending
        let stats = store.stats(&[]).unwrap();
        assert_eq!(stats.sessions_pending, 3);

        // With exclusion, only user session is pending
        let stats = store
            .stats(&[
                "evolution-analyzer".to_string(),
                "evolver-agent".to_string(),
            ])
            .unwrap();
        assert_eq!(stats.sessions_pending, 1);
        assert_eq!(stats.sessions_analyzed, 0);
    }

    #[test]
    fn get_nonexistent_analysis() {
        let conn = setup_db();
        let store = EvolveStore::new(conn);
        let result = store.get_analysis("nonexistent").unwrap();
        assert!(result.is_none());
    }

    fn sample_skill_record() -> SkillRecord {
        SkillRecord {
            skill_id: "docker__imp_12345678".into(),
            name: "docker".into(),
            description: "Docker operations guide".into(),
            path: "/tmp/skills/docker".into(),
            is_active: true,
            category: SkillCategory::ToolGuide,
            tags: vec!["docker".into(), "containers".into()],
            visibility: SkillVisibility::Private,
            creator_id: "system".into(),
            lineage: SkillLineage {
                origin: SkillOrigin::Imported,
                generation: 0,
                parent_skill_ids: vec![],
                source_task_id: None,
                change_summary: "Initial import".into(),
                content_diff: String::new(),
                content_snapshot: std::collections::HashMap::new(),
                pre_fix_snapshot: std::collections::HashMap::new(),
                created_at: Utc::now(),
                created_by: "human".into(),
            },
            tool_dependencies: vec!["shell_exec".into()],
            critical_tools: vec!["shell_exec".into()],
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
        }
    }

    #[test]
    fn save_and_get_skill_record() {
        let conn = setup_db();
        let store = EvolveStore::new(conn);
        let rec = sample_skill_record();

        store.save_skill_record(&rec).unwrap();
        let loaded = store.get_skill_record("docker__imp_12345678").unwrap().unwrap();
        assert_eq!(loaded.name, "docker");
        assert!(loaded.is_active);
        assert_eq!(loaded.tags.len(), 2);
        assert_eq!(loaded.total_selections, 10);
        assert_eq!(loaded.lineage.origin, SkillOrigin::Imported);
    }

    #[test]
    fn list_skill_records_active_filter() {
        let conn = setup_db();
        let store = EvolveStore::new(conn);

        let mut rec1 = sample_skill_record();
        rec1.skill_id = "s1".into();
        rec1.is_active = true;
        store.save_skill_record(&rec1).unwrap();

        let mut rec2 = sample_skill_record();
        rec2.skill_id = "s2".into();
        rec2.is_active = false;
        store.save_skill_record(&rec2).unwrap();

        let all = store.list_skill_records(false).unwrap();
        assert_eq!(all.len(), 2);

        let active = store.list_skill_records(true).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].skill_id, "s1");
    }

    #[test]
    fn update_skill_counters_atomically() {
        let conn = setup_db();
        let store = EvolveStore::new(conn);
        let rec = sample_skill_record();
        store.save_skill_record(&rec).unwrap();

        store
            .update_skill_counters("docker__imp_12345678", 1, 1, 0, 0)
            .unwrap();
        let loaded = store
            .get_skill_record("docker__imp_12345678")
            .unwrap()
            .unwrap();
        assert_eq!(loaded.total_selections, 11);
        assert_eq!(loaded.total_applied, 9);
        assert_eq!(loaded.total_completions, 6);
    }

    #[test]
    fn deactivate_skill() {
        let conn = setup_db();
        let store = EvolveStore::new(conn);
        let rec = sample_skill_record();
        store.save_skill_record(&rec).unwrap();

        store.deactivate_skill("docker__imp_12345678").unwrap();
        let loaded = store
            .get_skill_record("docker__imp_12345678")
            .unwrap()
            .unwrap();
        assert!(!loaded.is_active);
    }

}
