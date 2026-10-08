
## Stages 2 to 6: the working system

| Concept | What it is | Where |
|---|---|---|
| Nested enums and deep `match` | The parsed SQL is a tree of enums. `match` walks it and handles each statement type. | `judge` in `src/classify.rs` |
| `Option` and `?` on options | A value that may be missing. `.and_then`, `.as_deref` and `let ... else` handle it without null crashes. | `classify_one`, `option_is_true` |
| Recursion | Judging `EXPLAIN ANALYZE <statement>` means judging the inner statement with the same function. | `judge` calling itself |
| Deriving `Ord` | Lets kinds be compared, so "the most dangerous part wins" is one line. | `Kind`, `worst_of` |
| `async` / `.await` | Code that waits on the network without blocking a thread. Tokio runs it. | `src/exec.rs`, `src/proxy.rs` |
| `Arc` | Shared ownership across tasks: one config and one audit log, many connections. | `serve` in `src/main.rs` |
| `Mutex` | One task at a time may use the shared value. Tokio's mutex can be held across `.await`. | `QueryHandler::session`, `AuditLog` |
| `tokio::spawn` | Runs a task in the background, such as the journal next to the proxy. | `serve` in `src/main.rs` |
| Traits from libraries | Implementing `SimpleQueryHandler` and `AuthSource` plugs our code into pgwire. | `src/proxy.rs` |
| `#[async_trait]` | Lets traits have async methods. | `src/proxy.rs` |
| `serde` derive | Turns structs into JSON and back for the journal, the audit log and MCP. | `TxnRecord` in `src/journal.rs` |
| `#[serde(untagged)]` | Picks the enum variant by the shape of the JSON. | `Cell` in `src/journal.rs` |
| Byte parsing | Reading big-endian integers and null-terminated strings from a byte slice, returning errors instead of panicking. | `Reader` in `src/pgoutput.rs` |
| `HashMap` / `BTreeMap` | Lookup tables. `BTreeMap` keeps keys sorted. | `src/undo.rs` |
| Closures | Small inline functions that capture variables, such as the error converters. | `let err = \|e\| ...` in `src/undo.rs` |
| Iterators | `.iter().map().filter().collect()` chains instead of loops. | `effects`, `protected_tables` |
| Database transactions from Rust | `client.transaction()`, savepoints, commit or rollback. | `apply` in `src/undo.rs` |
| Hashing | SHA-256 chains each audit line to the one before. | `src/audit.rs` |
| Integration testing | A shell script drives the real binary against a real database. | `scripts/e2e.sh` |
