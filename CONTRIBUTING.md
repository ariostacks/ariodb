# Contributing to ariodb

Thank you for helping. Bug reports, fixes, tests and documentation are all
welcome. For anything larger than a small fix, please open an issue first
so we can agree the approach before you spend time on it.

Security problems are different: report them privately, as described in
[SECURITY.md](SECURITY.md), never in a public issue or pull request.

Everyone taking part is expected to follow the
[code of conduct](CODE_OF_CONDUCT.md).

## Building

You need:

- **Rust**, through [rustup](https://rustup.rs). The repository's
  `rust-toolchain.toml` selects stable Rust with rustfmt and clippy; the
  oldest Rust that builds ariodb is the `rust-version` in `Cargo.toml`.
- **A C compiler, libclang and CMake.** Postgres's parser (through the
  `pg_query` crate), SQLite and the TLS library are compiled from C. On
  Debian or Ubuntu: `sudo apt install build-essential clang libclang-dev
  cmake`. On macOS, the Xcode command line tools, plus `brew install cmake`
  if the build asks for it.
- **Docker**, for the demo and every test suite except the unit and
  property tests.
- **Node.js 22** and npm, only if you change the dashboard.

```bash
cargo build                   # debug build: target/debug/ariodb, used by the scripts
cargo build --release         # release build: target/release/ariodb
./scripts/demo.sh             # try it by hand against Postgres in Docker
```

[Architecture](docs/architecture.md) is the map of the code: the modules,
the life of a statement, and how the tests fit together. Read it, and the
[security model](docs/security-model.md), before changing anything on the
path a statement takes.

## Tests

| Suite | Command | Needs |
|---|---|---|
| Unit tests | `cargo test` | Nothing else |
| Property tests | `cargo test` (included); `PROPTEST_CASES=100000 cargo test proptests` for a longer hunt | Nothing else |
| Undo simulation | `./scripts/sim-undo.sh`; `SIM_SEEDS="42 7" SIM_OPS=120 ./scripts/sim-undo.sh` for other seeds and longer runs | Docker, `nc` |
| Postgres end to end | `./scripts/e2e.sh`; `PG_IMAGE=postgres:18 ./scripts/e2e.sh` for another Postgres or Postgres-based image | Docker, a built ariodb, `python3`, `openssl`, `curl`, `nc` |
| Postgres-compatible databases | `./scripts/e2e-compat.sh cockroach` or `./scripts/e2e-compat.sh yugabyte` | Docker, a built ariodb, `nc` |
| MySQL and MariaDB proxy | `./scripts/e2e-mysql.sh`; `MYSQL_IMAGE=mariadb:11.4 ./scripts/e2e-mysql.sh` | Docker, a built ariodb, `python3`, `openssl`, `nc` |
| MySQL and MariaDB journal and undo | `./scripts/e2e-mysql-journal.sh`; `MYSQL_IMAGE=mariadb:11.4 ./scripts/e2e-mysql-journal.sh` | Docker, `python3`, `curl`, `shasum` (it builds ariodb itself) |
| ClickHouse | `./scripts/e2e-clickhouse.sh` (`CH_IMAGE` for another version) | Docker, a built ariodb, `python3`, `openssl`, `curl`, `nc` |
| Plugins | `./scripts/e2e-plugins.sh` | Docker, a built ariodb, `python3`, `curl`, `nc` |
| Dashboard single sign-on | `./scripts/e2e-sso.sh` (Keycloak; slow to start the first time, `E2E_KEEP_KEYCLOAK=1` keeps it for the next run) | Docker, a built ariodb, `python3`, `curl`, `nc` |

"A built ariodb" means `cargo build` first: the scripts use
`target/debug/ariodb`. Database clients (`psql`, `pgbench`, `mysql`,
`clickhouse-client`) run from the database images, so you do not need them
installed. Every password and token in the scripts is a throwaway test
value, and each script removes its containers when it exits.
`E2E_OFFSET` and `E2E_NAME` shift ports and container names, so several
runs (from different worktrees, say) do not collide.

`tests/sim_undo.rs` does nothing under a plain `cargo test`; it runs only
with the environment `scripts/sim-undo.sh` sets up.

Continuous integration does not run on its own: every run waits until the
maintainer approves it. An approved run checks formatting, clippy, the unit
and property tests on Linux and the dashboard build. The end-to-end suites
run only when the maintainer asks for them (the `full-ci` label on a pull
request, or a manual run), macOS is tested when a release is built, and
changes to documentation alone run nothing. So run the suites that cover
your change yourself before you open a pull request, and say which you ran:
anything touching the Postgres path needs `scripts/e2e.sh`, MySQL changes
need both MySQL scripts against both images, and so on.

What a change needs in the way of tests:

- **A bug fix** comes with a test that fails without the fix.
- **A security fix** always does, as every item in the
  [security review](docs/security-model.md#review-of-october-2026) has.
- **A new refusal or check** needs a test that it refuses, and a test that
  ordinary statements still get through.
- **Parsing and classification** changes deserve a property test if there
  is an invariant to state ("a write wrapped in X is never a read").

## Style

- **British English** everywhere: code comments, messages, documentation
  and commit messages ("behaviour", "licence" as a noun, "organisation").
- **`cargo fmt`** before committing; CI checks it.
- **`cargo clippy --all-targets`** must report zero warnings; CI runs it
  with `-D warnings`.
- **Short doc comments** that say what something is for and anything
  surprising about it, not a restatement of the code. Keep comments true
  when you change the code they describe.
- **Error messages** are written for the person who will read them (often
  an agent, sometimes an operator): say what was refused and why, in plain
  words, and never include a credential or a URL that carries one.
- **Fail closed.** When ariodb cannot tell whether something is safe, it
  refuses. Keep it that way.
- **Dependencies**: add one only when it earns its place, and say why in
  the pull request.
- **Fake values look fake**: `not-a-real-password`,
  `agent-token-local-test-only`, `example.com`. Never put real credentials,
  host names or personal data in code, tests or docs.

## Commit messages

- A subject line of about 50 to 70 characters that says what the change
  does, as a sentence without a full stop: "Refuse native inserts with rows
  hidden after FORMAT as whitespace".
- A blank line, then a body that explains why: what was wrong, what
  changes, and anything a reviewer should know. Wrap it at 72 columns.
- One logical change per commit where you can.
- A `Signed-off-by` line (see
  [licensing of contributions](#licensing-of-contributions)).

## Pull requests

1. Fork the repository and branch from its default branch.
2. Make the change, with tests and documentation.
3. Run `cargo fmt`, `cargo clippy --all-targets`, `cargo test` and the
   end-to-end suites that cover the change.
4. Open the pull request and fill in the template: what changed and why,
   the linked issue, how you tested it, which docs you updated, and
   whether it affects security.
5. Keep the pull request focused. Unrelated clean-ups are welcome as
   separate pull requests.

The maintainer reviews pull requests as time allows. A change that affects
what agents can or cannot do gets a careful look, so expect questions.

## The dashboard front end

The dashboard is a React app (Vite, Tailwind CSS and shadcn/ui) in
`dashboard/`. Its built files in `dashboard/dist` are committed and
embedded in the binary, so `cargo build` needs no Node. After changing
anything in `dashboard/`:

```bash
./scripts/build-dashboard.sh   # npm ci, then build into dashboard/dist
cargo build                    # embeds the new files
```

Commit `dashboard/dist` together with the source change. CI rebuilds the
dashboard from a clean `npm ci` and fails if the result differs from the
committed `dist`.

For live reloading, run ariodb with its dashboard on 127.0.0.1:8080 (for
example `./scripts/demo.sh`), then `cd dashboard && npm run dev`; Vite
passes `/api` through to ariodb. `npm run lint` runs the linter.

## Documentation

The documentation in [docs/](docs/README.md) is part of the product, and a
change that alters behaviour updates it in the same pull request.

- Update the page that describes the behaviour, and the
  [configuration reference](docs/configuration.md) or the
  [CLI reference](docs/cli.md) for a new key or command.
- Every command, key and default you show must exist and be right. Run the
  examples.
- Write for the reader the page names at its top, in British English, in
  plain sentences. Prefer an example to a paragraph.
- Use fake values that read as fake, as in the code.
- A new page goes in the [documentation index](docs/README.md) and the
  table in the [README](README.md).
- A user-visible change gets a line in the
  [changelog](CHANGELOG.md) under "Unreleased".

## Licensing of contributions

ariodb is source-available under the [Sustainable Use License](LICENSE).
By contributing, you agree that your contribution is licensed under the
same licence as the project.

Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/)
(version 1.1), which certifies that you wrote the change or otherwise have
the right to submit it under the project's licence. Sign off by adding a
line to the commit message, with your real name and an email address you
can be reached at:

```text
Signed-off-by: Sam Lee <sam@example.com>
```

`git commit -s` adds it for you. To sign off commits you have already
made on your branch, use `git rebase --signoff <base>`, where `<base>` is
the branch you started from, and force-push the branch.

The maintainer may in future ask contributors to sign a contributor
licence agreement. If that happens, it will be announced here before it
applies to any contribution.
