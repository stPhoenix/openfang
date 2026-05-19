//! Trait abstraction for kernel operations needed by the agent runtime.
//!
//! This trait allows `openfang-runtime` to call back into the kernel for
//! inter-agent operations (spawn, send, list, kill) without creating
//! a circular dependency. The kernel implements this trait and passes
//! it into the agent loop.

use async_trait::async_trait;

/// Agent info returned by list and discovery operations.
#[derive(Debug, Clone)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub state: String,
    pub model_provider: String,
    pub model_name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub tools: Vec<String>,
}

/// Info about an installed agent template (a TOML manifest under
/// `~/.openfang/agents/<name>/agent.toml`, or a bundled fallback). Templates
/// are spawn-time blueprints — distinct from running agents and from hands.
#[derive(Debug, Clone)]
pub struct AgentTemplateInfo {
    pub name: String,
    pub description: String,
    pub category: String,
}

/// Handle to kernel operations, passed into the agent loop so agents
/// can interact with each other via tools.
#[allow(clippy::too_many_arguments)]
#[async_trait]
pub trait KernelHandle: Send + Sync {
    /// Spawn a new agent from a TOML manifest string.
    /// `parent_id` is the UUID string of the spawning agent (for lineage tracking).
    /// Returns (agent_id, agent_name) on success.
    async fn spawn_agent(
        &self,
        manifest_toml: &str,
        parent_id: Option<&str>,
    ) -> Result<(String, String), String>;

    /// Send a message to another agent and get the response.
    ///
    /// `session_id` selects the conversation context on the target:
    /// - `None`  → allocate a fresh session for this call (default —
    ///             prevents cross-task history bleed when an orchestrator
    ///             dispatches independent subtasks to the same agent).
    /// - `Some(uuid)` → route the message into that existing session,
    ///                  enabling explicit multi-turn conversations.
    async fn send_to_agent(
        &self,
        agent_id: &str,
        message: &str,
        session_id: Option<&str>,
    ) -> Result<String, String>;

    /// Send a message to another agent with a timeout in seconds.
    /// Returns an error if the target agent does not respond within the deadline.
    /// `session_id` semantics match [`send_to_agent`].
    async fn send_to_agent_with_timeout(
        &self,
        agent_id: &str,
        message: &str,
        timeout_secs: u64,
        session_id: Option<&str>,
    ) -> Result<String, String> {
        // Default: delegate to send_to_agent (no timeout enforcement)
        let _ = timeout_secs;
        self.send_to_agent(agent_id, message, session_id).await
    }

    /// Send a message to another agent, giving up only after `idle_secs` of
    /// silence from the target (no `AgentActivity` events). `max_total_secs`
    /// is a hard ceiling so a misbehaving target can't loop forever.
    /// Use for long-running specialists whose total wall-clock time is
    /// unknown but which produce steady per-iteration progress signals.
    async fn send_to_agent_with_idle_timeout(
        &self,
        agent_id: &str,
        message: &str,
        idle_secs: u64,
        max_total_secs: u64,
        session_id: Option<&str>,
    ) -> Result<String, String> {
        // Default fallback: ignore idle_secs, fall back to absolute timeout.
        let _ = idle_secs;
        self.send_to_agent_with_timeout(agent_id, message, max_total_secs, session_id)
            .await
    }

    /// List all running agents.
    fn list_agents(&self) -> Vec<AgentInfo>;

    /// Kill an agent by ID.
    fn kill_agent(&self, agent_id: &str) -> Result<(), String>;

    /// Store a value in shared memory (cross-agent accessible).
    fn memory_store(&self, key: &str, value: serde_json::Value) -> Result<(), String>;

    /// Recall a value from shared memory.
    fn memory_recall(&self, key: &str) -> Result<Option<serde_json::Value>, String>;

    /// Find agents by query (matches on name substring, tag, or tool name; case-insensitive).
    fn find_agents(&self, query: &str) -> Vec<AgentInfo>;

    /// Post a task to the shared task queue. Returns the task ID.
    async fn task_post(
        &self,
        title: &str,
        description: &str,
        assigned_to: Option<&str>,
        created_by: Option<&str>,
    ) -> Result<String, String>;

    /// Claim the next available task (optionally filtered by assignee). Returns task JSON or None.
    async fn task_claim(&self, agent_id: &str) -> Result<Option<serde_json::Value>, String>;

    /// Mark a task as completed with a result string.
    async fn task_complete(&self, task_id: &str, result: &str) -> Result<(), String>;

    /// List tasks, optionally filtered by status.
    async fn task_list(&self, status: Option<&str>) -> Result<Vec<serde_json::Value>, String>;

    /// Publish a custom event that can trigger proactive agents.
    async fn publish_event(
        &self,
        event_type: &str,
        payload: serde_json::Value,
    ) -> Result<(), String>;

    /// Add an entity to the knowledge graph.
    async fn knowledge_add_entity(
        &self,
        entity: openfang_types::memory::Entity,
    ) -> Result<String, String>;

    /// Add a relation to the knowledge graph.
    async fn knowledge_add_relation(
        &self,
        relation: openfang_types::memory::Relation,
    ) -> Result<String, String>;

    /// Query the knowledge graph with a pattern.
    async fn knowledge_query(
        &self,
        pattern: openfang_types::memory::GraphPattern,
    ) -> Result<Vec<openfang_types::memory::GraphMatch>, String>;

    /// Create a cron job for the calling agent.
    async fn cron_create(
        &self,
        agent_id: &str,
        job_json: serde_json::Value,
    ) -> Result<String, String> {
        let _ = (agent_id, job_json);
        Err("Cron scheduler not available".to_string())
    }

    /// List cron jobs for the calling agent.
    async fn cron_list(&self, agent_id: &str) -> Result<Vec<serde_json::Value>, String> {
        let _ = agent_id;
        Err("Cron scheduler not available".to_string())
    }

    /// Cancel a cron job by ID.
    async fn cron_cancel(&self, job_id: &str) -> Result<(), String> {
        let _ = job_id;
        Err("Cron scheduler not available".to_string())
    }

    /// Get the taint policy for an agent. Returns the default (block mode) if
    /// the agent has no custom policy or the agent ID is unknown.
    fn get_taint_policy(&self, agent_id: &str) -> openfang_types::taint::TaintPolicy {
        let _ = agent_id;
        openfang_types::taint::TaintPolicy::default()
    }

    /// Check if a tool requires approval based on current policy.
    fn requires_approval(&self, tool_name: &str) -> bool {
        let _ = tool_name;
        false
    }

    /// Request approval for a tool execution. Blocks until approved/denied/timed out.
    /// Returns `Ok(true)` if approved, `Ok(false)` if denied or timed out.
    async fn request_approval(
        &self,
        agent_id: &str,
        tool_name: &str,
        action_summary: &str,
    ) -> Result<bool, String> {
        let _ = (agent_id, tool_name, action_summary);
        Ok(true) // Default: auto-approve
    }

    /// List available Hands and their activation status.
    async fn hand_list(&self) -> Result<Vec<serde_json::Value>, String> {
        Err("Hands system not available".to_string())
    }

    /// Install a Hand from TOML content.
    async fn hand_install(
        &self,
        toml_content: &str,
        skill_content: &str,
    ) -> Result<serde_json::Value, String> {
        let _ = (toml_content, skill_content);
        Err("Hands system not available".to_string())
    }

    /// Activate a Hand — spawns a specialized autonomous agent.
    ///
    /// `caller_agent_id` is the id of the agent that invoked the
    /// `hand_activate` tool (when known). Used so the spawned hand can
    /// inherit its parent's resolved provider/model rather than falling
    /// through to the daemon default.
    async fn hand_activate(
        &self,
        hand_id: &str,
        config: std::collections::HashMap<String, serde_json::Value>,
        caller_agent_id: Option<&str>,
    ) -> Result<serde_json::Value, String> {
        let _ = (hand_id, config, caller_agent_id);
        Err("Hands system not available".to_string())
    }

    /// Check the status and dashboard metrics of an active Hand.
    async fn hand_status(&self, hand_id: &str) -> Result<serde_json::Value, String> {
        let _ = hand_id;
        Err("Hands system not available".to_string())
    }

    /// Deactivate a running Hand and stop its agent.
    async fn hand_deactivate(&self, instance_id: &str) -> Result<(), String> {
        let _ = instance_id;
        Err("Hands system not available".to_string())
    }

    /// List discovered external A2A agents as (name, url) pairs.
    fn list_a2a_agents(&self) -> Vec<(String, String)> {
        vec![]
    }

    /// Get the URL of a discovered external A2A agent by name.
    fn get_a2a_agent_url(&self, name: &str) -> Option<String> {
        let _ = name;
        None
    }

    /// Send a message to a user on a named channel adapter (e.g., "email", "telegram").
    /// When `thread_id` is provided, the message is sent as a thread reply.
    /// Returns a confirmation string on success.
    /// Get the default recipient for a channel (e.g. default_chat_id for Telegram).
    async fn get_channel_default_recipient(&self, channel: &str) -> Option<String> {
        let _ = channel;
        None
    }

    async fn send_channel_message(
        &self,
        channel: &str,
        recipient: &str,
        message: &str,
        thread_id: Option<&str>,
    ) -> Result<String, String> {
        let _ = (channel, recipient, message, thread_id);
        Err("Channel send not available".to_string())
    }

    /// Send media content (image/file) to a user on a named channel adapter.
    /// `media_type` is "image" or "file", `media_url` is the URL, `caption` is optional text.
    /// When `thread_id` is provided, the media is sent as a thread reply.
    async fn send_channel_media(
        &self,
        channel: &str,
        recipient: &str,
        media_type: &str,
        media_url: &str,
        caption: Option<&str>,
        filename: Option<&str>,
        thread_id: Option<&str>,
    ) -> Result<String, String> {
        let _ = (
            channel, recipient, media_type, media_url, caption, filename, thread_id,
        );
        Err("Channel media send not available".to_string())
    }

    /// Send a local file (raw bytes) to a user on a named channel adapter.
    /// Used by the `channel_send` tool when `file_path` is provided.
    /// When `thread_id` is provided, the file is sent as a thread reply.
    async fn send_channel_file_data(
        &self,
        channel: &str,
        recipient: &str,
        data: Vec<u8>,
        filename: &str,
        mime_type: &str,
        thread_id: Option<&str>,
    ) -> Result<String, String> {
        let _ = (channel, recipient, data, filename, mime_type, thread_id);
        Err("Channel file data send not available".to_string())
    }

    /// Get an agent's full manifest as JSON.
    fn get_agent_manifest(&self, agent_id: &str) -> Result<serde_json::Value, String> {
        let _ = agent_id;
        Err("Agent manifest inspection not available".to_string())
    }

    /// Update an agent's manifest fields. `changes` is a JSON object with optional fields:
    /// `system_prompt`, `description`, `name`, `model`, `provider`, `tags`.
    /// Returns a summary of what was changed.
    async fn update_agent_manifest(
        &self,
        agent_id: &str,
        changes: serde_json::Value,
    ) -> Result<String, String> {
        let _ = (agent_id, changes);
        Err("Agent manifest modification not available".to_string())
    }

    /// Refresh an agent's last_active timestamp without changing any other state.
    /// Called by the agent loop before long LLM calls to prevent heartbeat false-positives.
    fn touch_agent(&self, agent_id: &str) {
        let _ = agent_id;
    }

    /// Return the cgroup.procs fd for the agent's session cgroup, if one was
    /// created at spawn time. Subprocess pre_exec closures write the child's
    /// pid here to enforce the per-agent `pids.max` cap. `None` = fall back to
    /// `RLIMIT_NPROC` only.
    fn cgroup_procs_fd(
        &self,
        agent_id: &str,
    ) -> Option<crate::cgroup_sandbox::CgroupProcsFd> {
        let _ = agent_id;
        None
    }

    /// Spawn a specialist agent, send it a message, get the response, and kill it.
    /// Combines agent_spawn + agent_send + agent_kill into one atomic operation.
    /// The spawned agent is always cleaned up, even on error or timeout.
    async fn delegate_to_agent(
        &self,
        manifest_toml: &str,
        message: &str,
        parent_id: Option<&str>,
        parent_caps: &[openfang_types::capability::Capability],
        timeout_secs: Option<u64>,
    ) -> Result<String, String> {
        let _ = (manifest_toml, message, parent_id, parent_caps, timeout_secs);
        Err("Agent delegation not available".to_string())
    }

    /// Spawn a specialist agent asynchronously and return immediately.
    /// A background task sends the message, collects the response, kills the agent,
    /// and publishes a completion event.
    async fn delegate_async(
        &self,
        manifest_toml: &str,
        message: &str,
        parent_id: Option<&str>,
        parent_caps: &[openfang_types::capability::Capability],
        callback_event_type: Option<&str>,
    ) -> Result<String, String> {
        let _ = (
            manifest_toml,
            message,
            parent_id,
            parent_caps,
            callback_event_type,
        );
        Err("Async agent delegation not available".to_string())
    }

    /// Send a message to an EXISTING agent asynchronously. Returns immediately
    /// with `{delegation_id, agent_id, agent_name, callback_event_type}`. The
    /// agent processes the message in the background; the completion event
    /// (default type `delegation_completed`) lands in the same cache and
    /// channel that `delegate_async` uses, so `delegation_await` correlates
    /// both without changes. Use for hands marked `long_running=true`.
    async fn send_to_agent_async(
        &self,
        agent_id: &str,
        message: &str,
        session_id: Option<&str>,
        callback_event_type: Option<&str>,
    ) -> Result<String, String> {
        let _ = (agent_id, message, session_id, callback_event_type);
        Err("send_to_agent_async not available".to_string())
    }

    /// Spawn an agent with capability inheritance enforcement.
    /// `parent_caps` are the parent's granted capabilities. The kernel MUST verify
    /// that every capability in the child manifest is covered by `parent_caps`.
    async fn spawn_agent_checked(
        &self,
        manifest_toml: &str,
        parent_id: Option<&str>,
        parent_caps: &[openfang_types::capability::Capability],
    ) -> Result<(String, String), String> {
        // Default: delegate to spawn_agent (no enforcement)
        // The kernel MUST override this with real enforcement
        let _ = parent_caps;
        self.spawn_agent(manifest_toml, parent_id).await
    }

    /// Block until each listed async delegation completes, or `timeout_secs`
    /// elapses. Returns one entry per id (preserving input order); ids that
    /// never completed get `error: "timed_out"`. The boolean indicates whether
    /// any id failed to complete in time.
    async fn await_delegations(
        &self,
        ids: Vec<String>,
        timeout_secs: u64,
    ) -> Result<(Vec<serde_json::Value>, bool), String> {
        let _ = (ids, timeout_secs);
        Err("delegation_await not available".to_string())
    }

    /// List installed agent templates (TOML manifests under
    /// `~/.openfang/agents/<name>/agent.toml`, plus bundled fallbacks).
    /// Distinct from `list_agents` (running agents) and `hand_list` (hand
    /// templates) — these are dormant blueprints that demiurg can spawn on
    /// demand when no running agent or hand fits the subtask.
    fn list_agent_templates(&self) -> Vec<AgentTemplateInfo> {
        vec![]
    }

    /// Spawn an agent from an installed template by name. `instance_name`
    /// overrides the manifest's `name` field so multiple instances can
    /// coexist. Returns (agent_id, agent_name) on success.
    async fn spawn_agent_from_template(
        &self,
        template_name: &str,
        instance_name: Option<&str>,
    ) -> Result<(String, String), String> {
        let _ = (template_name, instance_name);
        Err("Agent templates not available".to_string())
    }

    /// Run a single one-shot LLM completion using the caller agent's resolved
    /// model + provider + credentials. No tools, no streaming, no agent-loop
    /// iteration. Returns the response text.
    ///
    /// Designed for tool implementations that need to distill or transform
    /// content (e.g. `web_fetch_extract` does fetch + one-shot reduction).
    /// Avoids spinning up a full subagent for tasks that don't need one.
    ///
    /// `max_tokens` caps the response size. Temperature defaults are model-
    /// specific (the caller agent's manifest temperature is used).
    async fn llm_oneshot(
        &self,
        caller_agent_id: &str,
        system_prompt: &str,
        user_prompt: &str,
        max_tokens: u32,
    ) -> Result<String, String> {
        let _ = (caller_agent_id, system_prompt, user_prompt, max_tokens);
        Err("llm_oneshot not available".to_string())
    }
}
