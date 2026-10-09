//! Plugins: programs ariodb starts and talks to over stdin and stdout with
//! newline-delimited JSON-RPC, as MCP's stdio transport does. A plugin can
//! be an approver, supply facts for rules, receive notifications, or
//! receive the decisions log. See docs/plugins.md.

use crate::classify::Statement;
use crate::gate::{ApprovalNeed, Ctx, State};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize)]
pub struct PluginConfig {
    pub name: String,
    /// The program and its arguments.
    pub command: Vec<String>,
    /// Environment for the plugin. Nothing else from ariodb's environment
    /// is passed on.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// How long one call may take, unless the call has its own limit.
    pub timeout_ms: Option<u64>,
}

/// Ask a plugin approver. `Ok` allows; `Err` refuses, with the reason.
pub async fn ask(
    _state: &State,
    approver: &crate::approvals::ApproverConfig,
    _ctx: &Ctx<'_>,
    _statements: &[Statement],
    _need: &ApprovalNeed,
) -> Result<(), String> {
    Err(format!(
        "approver '{}': plugins are not built yet",
        approver.name
    ))
}
