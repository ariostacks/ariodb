# Learning Rust through ariodb

One entry per concept, pointing at the code that uses it.

## Stage 1: a command-line tool that reads a config file

| Concept | What it is | Where |
|---|---|---|
| Cargo | Rust's build tool and package manager. `Cargo.toml` lists dependencies; `cargo build`, `cargo test`, `cargo run`. | `Cargo.toml` |
| Crates | Libraries from crates.io. We use `clap` (command line), `serde` and `toml` (reading config). | `Cargo.toml` |
| Modules | `mod config;` pulls in `src/config.rs`. `pub` makes items visible outside the module. | `src/main.rs` |
| Structs | Named groups of fields, like a class with no methods yet. | `Config`, `Limits` in `src/config.rs` |
| Enums | A value that is exactly one of several variants. Variants can carry data. | `FailureMode`, `Access`, `ConfigError` |
| `match` | Handles every variant of an enum. The compiler refuses to build if you miss one. | `print_summary` in `src/main.rs` |
| Derive | `#[derive(...)]` asks the compiler to write standard code for you, such as debug printing or config parsing. | Top of each struct |
| `impl` blocks | Attach functions (methods) to a type. `&self` borrows the value the method is called on. | `impl Config` |
| `Result` and `?` | Functions that can fail return `Result<Ok, Err>`. `?` returns the error early if there is one. No exceptions. | `Config::load` |
| `map_err` | Converts one error type into another, here into our own `ConfigError`. | `Config::load`, `Config::from_toml` |
| Traits | A shared set of methods a type promises to provide. `Display` decides how an error prints. | `impl fmt::Display for ConfigError` |
| Borrowing (`&`) | Passing `&config` lends the value without giving it away. | `print_summary(&config)` |
| `let ... else` | Unpacks a value, or leaves the function early if it does not match. | `redact_url` |
| Tests | `#[cfg(test)]` code only builds for `cargo test`. `#[test]` marks a test. | Bottom of `src/config.rs` |
| Exit codes | `ExitCode::FAILURE` lets scripts tell success from failure. | `main` |
