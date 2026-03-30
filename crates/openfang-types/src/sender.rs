//! Sender identity and role types for cross-crate use.
//!
//! Defines `SenderRole` (the role of a message sender) and `ToolAccessTier`
//! (what tools a given role is allowed to invoke). These types live in
//! `openfang-types` so that both `openfang-runtime` and `openfang-kernel`
//! can use them without circular dependencies.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Verified role of the message sender, mirroring `UserRole` from the kernel
/// RBAC system but usable across all crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SenderRole {
    /// Read-only — can view agent output but cannot interact with tools.
    Viewer = 0,
    /// Standard user — can chat, basic tools only.
    User = 1,
    /// Admin — full tool access except owner-only operations.
    Admin = 2,
    /// Owner — unrestricted access.
    Owner = 3,
}

impl fmt::Display for SenderRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SenderRole::Viewer => write!(f, "viewer"),
            SenderRole::User => write!(f, "user"),
            SenderRole::Admin => write!(f, "admin"),
            SenderRole::Owner => write!(f, "owner"),
        }
    }
}

impl SenderRole {
    /// Parse a role from a string (case-insensitive). Defaults to `User`.
    pub fn from_str_role(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "owner" => SenderRole::Owner,
            "admin" => SenderRole::Admin,
            "viewer" => SenderRole::Viewer,
            _ => SenderRole::User,
        }
    }

    /// What tier of tool access this role grants.
    pub fn tool_access_tier(&self) -> ToolAccessTier {
        match self {
            SenderRole::Viewer => ToolAccessTier::None,
            SenderRole::User => ToolAccessTier::Basic,
            SenderRole::Admin => ToolAccessTier::Full,
            SenderRole::Owner => ToolAccessTier::Unrestricted,
        }
    }
}

/// Tool access tier granted by a sender role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolAccessTier {
    /// No tools at all (Viewer).
    None,
    /// Basic safe tools only — dangerous tools blocked (User).
    Basic,
    /// All agent-granted tools except owner-only (Admin).
    Full,
    /// Everything including config modification (Owner).
    Unrestricted,
}

/// Tools blocked for the `Basic` tier (User role).
/// These are dangerous operations that require elevated privileges.
pub const RESTRICTED_TOOLS: &[&str] = &[
    "shell_exec",
    "file_write",
    "file_delete",
    "web_fetch",
    "agent_spawn",
    "agent_kill",
    "config_set",
];

/// Tools only available to the `Unrestricted` tier (Owner role).
pub const OWNER_ONLY_TOOLS: &[&str] = &["config_set", "config_get"];

/// Filter a list of tool names based on the sender's role.
///
/// Returns the subset of tools the sender is allowed to invoke.
/// When `sender_role` is `None` (RBAC disabled), returns all tools unchanged.
pub fn filter_tools_by_role(tool_names: &[String], role: SenderRole) -> Vec<String> {
    match role.tool_access_tier() {
        ToolAccessTier::None => vec![],
        ToolAccessTier::Basic => tool_names
            .iter()
            .filter(|name| !RESTRICTED_TOOLS.contains(&name.as_str()))
            .cloned()
            .collect(),
        ToolAccessTier::Full => tool_names
            .iter()
            .filter(|name| !OWNER_ONLY_TOOLS.contains(&name.as_str()))
            .cloned()
            .collect(),
        ToolAccessTier::Unrestricted => tool_names.to_vec(),
    }
}

/// Sender context resolved from channel identity + RBAC.
///
/// Carries verified identity information from the channel bridge
/// through the kernel to the agent loop and prompt builder.
#[derive(Debug, Clone)]
pub struct SenderContext {
    /// Platform-specific user ID (e.g. Telegram user ID, Discord user ID).
    pub platform_id: String,
    /// User-chosen display name (unverified — can be spoofed).
    pub display_name: String,
    /// Verified role from RBAC. `None` when RBAC is not configured.
    pub role: Option<SenderRole>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_parsing() {
        assert_eq!(SenderRole::from_str_role("owner"), SenderRole::Owner);
        assert_eq!(SenderRole::from_str_role("admin"), SenderRole::Admin);
        assert_eq!(SenderRole::from_str_role("viewer"), SenderRole::Viewer);
        assert_eq!(SenderRole::from_str_role("user"), SenderRole::User);
        assert_eq!(SenderRole::from_str_role("OWNER"), SenderRole::Owner);
        assert_eq!(SenderRole::from_str_role("Admin"), SenderRole::Admin);
        assert_eq!(SenderRole::from_str_role("unknown"), SenderRole::User);
    }

    #[test]
    fn role_ordering() {
        assert!(SenderRole::Viewer < SenderRole::User);
        assert!(SenderRole::User < SenderRole::Admin);
        assert!(SenderRole::Admin < SenderRole::Owner);
    }

    #[test]
    fn role_display() {
        assert_eq!(SenderRole::Viewer.to_string(), "viewer");
        assert_eq!(SenderRole::User.to_string(), "user");
        assert_eq!(SenderRole::Admin.to_string(), "admin");
        assert_eq!(SenderRole::Owner.to_string(), "owner");
    }

    #[test]
    fn tool_access_tiers() {
        assert_eq!(
            SenderRole::Viewer.tool_access_tier(),
            ToolAccessTier::None
        );
        assert_eq!(
            SenderRole::User.tool_access_tier(),
            ToolAccessTier::Basic
        );
        assert_eq!(
            SenderRole::Admin.tool_access_tier(),
            ToolAccessTier::Full
        );
        assert_eq!(
            SenderRole::Owner.tool_access_tier(),
            ToolAccessTier::Unrestricted
        );
    }

    #[test]
    fn filter_viewer_gets_nothing() {
        let tools = vec![
            "shell_exec".to_string(),
            "file_read".to_string(),
            "web_fetch".to_string(),
        ];
        assert!(filter_tools_by_role(&tools, SenderRole::Viewer).is_empty());
    }

    #[test]
    fn filter_user_blocks_restricted() {
        let tools = vec![
            "shell_exec".to_string(),
            "file_read".to_string(),
            "file_write".to_string(),
            "web_fetch".to_string(),
            "memory_recall".to_string(),
            "agent_list".to_string(),
        ];
        let allowed = filter_tools_by_role(&tools, SenderRole::User);
        assert_eq!(
            allowed,
            vec![
                "file_read".to_string(),
                "memory_recall".to_string(),
                "agent_list".to_string(),
            ]
        );
    }

    #[test]
    fn filter_admin_blocks_owner_only() {
        let tools = vec![
            "shell_exec".to_string(),
            "config_set".to_string(),
            "config_get".to_string(),
            "file_read".to_string(),
        ];
        let allowed = filter_tools_by_role(&tools, SenderRole::Admin);
        assert_eq!(
            allowed,
            vec!["shell_exec".to_string(), "file_read".to_string()]
        );
    }

    #[test]
    fn filter_owner_gets_everything() {
        let tools = vec![
            "shell_exec".to_string(),
            "config_set".to_string(),
            "config_get".to_string(),
            "file_read".to_string(),
        ];
        let allowed = filter_tools_by_role(&tools, SenderRole::Owner);
        assert_eq!(allowed, tools);
    }

    #[test]
    fn sender_context_creation() {
        let ctx = SenderContext {
            platform_id: "123456".to_string(),
            display_name: "Alice".to_string(),
            role: Some(SenderRole::Admin),
        };
        assert_eq!(ctx.role, Some(SenderRole::Admin));
    }

    #[test]
    fn serde_roundtrip() {
        let role = SenderRole::Admin;
        let json = serde_json::to_string(&role).unwrap();
        let parsed: SenderRole = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, role);
    }
}
