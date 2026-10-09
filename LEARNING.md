# Learning Rust from ariodb

Rust ideas, each with a place in this code where it does real work. Read the
named function alongside the explanation.

## The core: SQL, policy, journal and undo

| Concept | What it is | Where |
|---|---|---|
| Nested enums and deep `match` | The parsed SQL is a tree of enums. `match` walks it and handles each statement type. | `judge` in `src/classify.rs` |
| `Option` and `?` on options | A value that may be missing. `.and_then`, `.as_deref` and `let ... else` handle it without null crashes. | `classify_one`, `option_is_true` in `src/classify.rs` |
| Recursion | Judging `EXPLAIN ANALYZE <statement>` means judging the inner statement with the same function. | `judge` calling itself |
| Deriving `Ord` | Lets kinds be compared, so "the most dangerous part wins" is one line. | `Kind`, `worst_of` in `src/classify.rs` |
| `let` chains | `if let Some(x) = a && x.ok()` in one condition (edition 2024). | `Config::check` in `src/config.rs` |
| Custom error enums | An enum of everything that can go wrong, with `Display` and `std::error::Error` implemented by hand. | `ConfigError` in `src/config.rs`, `WireError` in `src/wire.rs` |
| `From` for `?` | Implementing `From<std::io::Error>` lets `?` convert errors automatically. | `impl From<std::io::Error> for WireError` |
| `serde` derive | Turns structs into JSON or TOML and back: the config file, the journal, the decisions log, MCP. | `Config` in `src/config.rs`, `TxnRecord` in `src/journal.rs` |
| `#[serde(default)]` and `rename_all` | Missing fields take a default; `read_only` in TOML becomes `Access::ReadOnly`. | `Proxy`, `Access` in `src/config.rs` |
| `#[serde(untagged)]` | Picks the enum variant by the shape of the JSON. | `Cell` in `src/journal.rs` |
| Byte parsing | Reading big-endian integers and null-terminated strings from a byte slice, returning errors instead of panicking. | `Reader` and `decode` in `src/pgoutput.rs` |
| `HashMap` / `BTreeMap` | Lookup tables. `BTreeMap` keeps keys sorted, so output is stable. | `sessions` in `src/undo.rs` |
| Closures | Small inline functions that capture variables, such as the error converters. | `let err = \|e\| ...` in `apply` in `src/undo.rs` |
| Iterators | `.iter().map().filter().collect()` chains instead of loops. | `parse_effects` in `src/gate.rs`, `Config::protected_tables` |
| Database transactions from Rust | `client.transaction()`, then commit or roll back. | `apply` in `src/undo.rs` |
| Hashing | SHA-256 chains each decision to the one before. | `src/audit.rs`, `verify` |

## Async and shared state

| Concept | What it is | Where |
|---|---|---|
| `async` / `.await` | Code that waits on the network without blocking a thread. Tokio runs it. | `src/exec.rs`, `src/proxy.rs` |
| `tokio::spawn` | Runs a task in the background: one per agent connection, plus the journal, dashboard and ClickHouse listeners. | `serve` in `src/main.rs`, `serve` in `src/proxy.rs` |
| `tokio::select!` | Wait on several things and act on whichever finishes first. | `serve` in `src/main.rs` (proxy or Ctrl-C), `wait_ready` in `src/tunnels.rs` |
| `Arc` | Shared ownership across tasks: one state, many connections. | `make_state` in `src/main.rs`, `gate::State` |
| `std::sync::Mutex` | One thread at a time may use the value. Fine when the lock is never held across `.await`. | `AuditLog` in `src/audit.rs`, `Db` in `src/store.rs`, `CancelMap` in `src/proxy.rs` |
| `tokio::sync::Mutex` | A mutex that can be held across `.await`. | `client_write` in `handle` in `src/clickhouse_native.rs` |
| `RwLock<Arc<T>>` swap | Many readers take a cheap `Arc` clone of the current value; a reload builds a new value and swaps it in under a brief write lock. In-flight statements keep the old one. | `State::config`, `State::replace_config` and `watch_config` in `src/gate.rs` |
| `static` with `LazyLock` | A global built on first use. | `LOGINS` in `src/dashboard.rs` |
| Trait objects | `Box<dyn Io>` holds either a plain TCP stream or a TLS stream behind one type. | `Io` in `src/tls.rs`, `handle` in `src/proxy.rs` |

## Later work: protocols, web, crypto and testing

| Concept | What it is | Where |
|---|---|---|
| A hand-written protocol codec | Postgres frames are a tag byte, a length and a body. Reading is generic over any `AsyncRead`; oversized frames are drained and refused, not buffered. `Bytes` and `BytesMut` build frames without copying. | `read_frame`, `frame`, `take_cstr`, `parse_bind`, `MAX_FRAME` in `src/wire.rs` |
| Traits with `async fn` | Traits can now have async methods without a macro. `Sink` spells out `impl Future + Send` so generic callers can be sent between threads; `FrameIo` uses plain `async fn`. | `Sink`, `Collect` in `src/exec.rs`; `ClientSink`, `FrameIo` in `src/proxy.rs` |
| Generics with trait bounds | One function works for any sink: an agent's socket or a collector for MCP. | `Session::simple<S: Sink>` in `src/exec.rs` |
| Implementing library traits | Plugging our types into someone else's interface. | `ServerCertVerifier` for `AcceptAnyCert` in `src/tls.rs`; `IntoResponse` for `ApiError` in `src/dashboard.rs` |
| An expression language from a library | CEL conditions are compiled once and run against a context of variables and a custom function. `catch_unwind` turns a parser panic into an error. | `compile`, `context_for`, `RuleSet::run` in `src/rules.rs` |
| SQLite with `rusqlite` | Bound parameters with `params!`, `optional()` for "maybe one row", and an immediate transaction so two processes keep one hash chain. | `Db::open`, `Db::with` in `src/store.rs`; `try_record` in `src/audit.rs` |
| A web server with `axum` | Routes map paths to async functions; extractors (`State`, `Path`, `Query`, `Json`, `HeaderMap`, `ConnectInfo`) pull typed values out of the request. | `router` in `src/dashboard.rs`, `routes` in `src/dashboard_api.rs` |
| Files embedded in the binary | `#[derive(RustEmbed)]` bakes `dashboard/dist` into the executable at compile time. | `Files` and `serve` in `src/dashboard_files.rs` |
| AEAD encryption | XChaCha20-Poly1305 seals each secret with a random nonce; the name is associated data, so a sealed value cannot be moved to another name. | `Store::set`, `Store::get`, `master_key` in `src/secrets.rs` |
| Unix file permissions | `OpenOptionsExt::mode(0o600)` creates the key file private. | `write_private`, `ensure_private_dir` in `src/secrets.rs` |
| HMAC signing | HMAC-SHA256 signs webhook links and checks Slack callbacks; comparisons are constant-time. | `sign`, `verify_link`, `verify_slack` in `src/approvals.rs` |
| Password hashing | argon2 hashes dashboard passwords with a random salt; `verify_password` checks them. | `hash_password`, `set_password`, `login` in `src/dashboard.rs` |
| Process supervision | Start a child process in its own process group, relay its output, wait for its port, restart with backoff, stop it on shutdown. A `watch` channel says "stop", a `oneshot` reports "ready", `kill_on_drop` and `Drop` clean up. | `Supervisor::start`, `supervise`, `spawn`, `terminate` and `impl Drop for Supervisor` in `src/tunnels.rs` |
| Property tests | `proptest!` generates thousands of inputs (random bytes, respelled SQL) and checks a property holds for all of them, shrinking any failure to a minimal case. | `src/proptests.rs`, for example `a_wrapped_write_is_never_a_read`, `frames_round_trip` |
| `#[cfg(test)]` modules | Test code compiled only for `cargo test`, next to the code it tests. | `mod tests` at the end of most files; `mod proptests` in `src/main.rs` |
| Integration tests under `tests/` | Each file is its own crate, built by `cargo test`. It drives the real `ariodb` binary over the network, so it skips itself unless the script that starts Postgres has set its environment. | `random_sessions_undo_exactly_what_they_changed` in `tests/sim_undo.rs`, run by `scripts/sim-undo.sh` |
| A tiny deterministic random generator | SplitMix64 in a few lines, so a seed gives the same workload on every machine. | `Rng` in `tests/sim_undo.rs` |
| End-to-end testing | Shell scripts drive the real binary against a real database in Docker. | `scripts/e2e.sh`, `scripts/e2e-clickhouse.sh` |
