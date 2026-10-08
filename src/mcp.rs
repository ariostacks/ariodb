//! An MCP server over stdio, so coding agents can use ariodb as a tool.
//!
//! It offers one tool, `query`, which runs SQL through the same checks as the
//! proxy. Start it with `ariodb mcp --agent <name>`; the agent's token must be
//! in its environment variable, as for the proxy.

use crate::audit::AuditLog;
use crate::config::Config;
use crate::exec::{Outcome, Session};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const MAX_ROWS_RETURNED: usize = 500;

pub async fn serve(
    config: Arc<Config>,
    audit: Arc<AuditLog>,
    agent_name: &str,
) -> Result<(), String> {
    let agent = config
        .agent(agent_name)
        .cloned()
        .ok_or_else(|| format!("unknown agent '{agent_name}'"))?;
    let expected = agent
        .token()
        .ok_or_else(|| format!("set {} to the agent's token", agent.token_env))?;
    let given = std::env::var("ARIODB_AGENT_TOKEN").unwrap_or_default();
    if given != expected {
        return Err("ARIODB_AGENT_TOKEN does not match this agent's token".to_string());
    }

    let mut session = Session::connect(&config, agent, audit).await?;
    eprintln!(
        "ariodb mcp: session {} for agent {}",
        session.id,
        session.agent_name()
    );

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Ok(Some(line)) = lines.next_line().await {
        let Ok(request) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(reply) = handle(&mut session, &request).await else {
            continue; // notifications get no reply
        };
        let mut text = reply.to_string();
        text.push('\n');
        if stdout.write_all(text.as_bytes()).await.is_err() || stdout.flush().await.is_err() {
            break;
        }
    }
    Ok(())
}

async fn handle(session: &mut Session, request: &Value) -> Option<Value> {
    let id = request.get("id")?.clone();
    let method = request["method"].as_str().unwrap_or("");
    let result = match method {
        "initialize" => json!({
            "protocolVersion": request["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "ariodb", "version": env!("CARGO_PKG_VERSION") },
            "instructions": "Run SQL against the database through ariodb. Writes are checked and can be undone; destructive statements and schema changes are refused.",
        }),
        "ping" => json!({}),
        "tools/list" => json!({ "tools": [{
            "name": "query",
            "description": "Run SQL. Reads run read-only. Writes are limited in how many rows they may change, are recorded, and can be undone by a human. Send one statement at a time, without BEGIN or COMMIT.",
            "inputSchema": {
                "type": "object",
                "properties": { "sql": { "type": "string", "description": "The SQL to run" } },
                "required": ["sql"]
            }
        }]}),
        "tools/call" => {
            let sql = request["params"]["arguments"]["sql"].as_str().unwrap_or("");
            if request["params"]["name"] != "query" || sql.is_empty() {
                tool_error("call the 'query' tool with an 'sql' argument")
            } else {
                tool_result(session.run(sql).await)
            }
        }
        _ => {
            return Some(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": format!("unknown method '{method}'") }
            }));
        }
    };
    Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

fn tool_result(outcomes: Vec<Outcome>) -> Value {
    let mut parts = Vec::new();
    let mut is_error = false;
    for outcome in outcomes {
        match outcome {
            Outcome::Rows { columns, rows } => {
                let total = rows.len();
                let objects: Vec<Value> = rows
                    .into_iter()
                    .take(MAX_ROWS_RETURNED)
                    .map(|row| {
                        let map = columns
                            .iter()
                            .cloned()
                            .zip(row.into_iter().map(Value::from));
                        Value::Object(map.collect())
                    })
                    .collect();
                let mut text = serde_json::to_string_pretty(&objects).unwrap_or_default();
                if total > MAX_ROWS_RETURNED {
                    text.push_str(&format!(
                        "\n({total} rows; showing the first {MAX_ROWS_RETURNED})"
                    ));
                }
                parts.push(text);
            }
            Outcome::Done { command, rows } => parts.push(format!("{command} {rows}")),
            Outcome::Refused { message } => {
                is_error = true;
                parts.push(format!("Refused by ariodb: {message}"));
            }
            Outcome::Failed { code, message } => {
                is_error = true;
                parts.push(format!("Postgres error {code}: {message}"));
            }
        }
    }
    json!({ "content": [{ "type": "text", "text": parts.join("\n\n") }], "isError": is_error })
}

fn tool_error(message: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}
