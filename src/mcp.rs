//! An MCP server over stdio, so coding agents can use ariodb as a tool.
//!
//! It offers one tool, `query`, which runs SQL through the same checks as the
//! proxy. Start it with `ariodb mcp --agent <name>`; the agent's token must be
//! in its environment variable, as for the proxy.

use crate::exec::{Collect, Session};
use crate::gate::State;
use crate::wire;
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const MAX_ROWS_RETURNED: usize = 500;

pub async fn serve(state: Arc<State>, agent_name: &str) -> Result<(), String> {
    let config = state.config();
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

    let mut session = Session::open(state.clone(), agent).await?;
    eprintln!(
        "ariodb mcp: session {} for agent {}",
        session.id, session.agent.name
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
                let mut collect = Collect::default();
                match session.simple(sql, &mut collect).await {
                    Ok(()) => tool_result(collect.0),
                    Err(e) => tool_error(&format!("connection to the database failed: {e}")),
                }
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

fn tool_result(frames: Vec<bytes::Bytes>) -> Value {
    let mut parts = Vec::new();
    let mut is_error = false;
    let mut columns: Vec<String> = Vec::new();
    let mut rows: Vec<Value> = Vec::new();
    let mut total = 0usize;
    for raw in frames {
        let (tag, body) = (raw[0], raw.slice(5..));
        match tag {
            b'T' => {
                columns = wire::parse_row_description(&body);
                rows.clear();
                total = 0;
            }
            b'D' => {
                total += 1;
                if rows.len() < MAX_ROWS_RETURNED {
                    let values = wire::parse_data_row(&body).into_iter().map(Value::from);
                    rows.push(Value::Object(columns.iter().cloned().zip(values).collect()));
                }
            }
            b'C' => {
                let tag =
                    String::from_utf8_lossy(body.strip_suffix(&[0]).unwrap_or(&body)).to_string();
                if columns.is_empty() {
                    parts.push(tag);
                } else {
                    let mut text = serde_json::to_string_pretty(&rows).unwrap_or_default();
                    if total > MAX_ROWS_RETURNED {
                        text.push_str(&format!(
                            "\n({total} rows; showing the first {MAX_ROWS_RETURNED})"
                        ));
                    }
                    parts.push(text);
                    columns.clear();
                    rows.clear();
                }
            }
            b'E' => {
                is_error = true;
                let e = wire::parse_error(&body);
                match e.message.strip_prefix("ariodb: ") {
                    Some(m) => parts.push(format!("Refused by ariodb: {m}")),
                    None => parts.push(format!("Postgres error {}: {}", e.code, e.message)),
                }
            }
            _ => {}
        }
    }
    json!({ "content": [{ "type": "text", "text": parts.join("\n\n") }], "isError": is_error })
}

fn tool_error(message: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}
