## Summary

<!-- What does this change do, and why? -->

## Linked issue

<!-- "Fixes #123" or "Part of #123". For a small fix with no issue, say so. -->

## How it was tested

<!-- Tick what you ran, and add anything else (manual steps, a new test). -->

- [ ] `cargo fmt` and `cargo clippy --all-targets` (no warnings)
- [ ] `cargo test` (unit and property tests)
- [ ] `./scripts/sim-undo.sh` (undo simulation)
- [ ] `./scripts/e2e.sh` (Postgres; image: )
- [ ] `./scripts/e2e-compat.sh` (cockroach / yugabyte)
- [ ] `./scripts/e2e-mysql.sh` and `./scripts/e2e-mysql-journal.sh` (mysql:8.4 / mariadb:11.4)
- [ ] `./scripts/e2e-clickhouse.sh`
- [ ] `./scripts/e2e-plugins.sh`
- [ ] `./scripts/e2e-sso.sh`
- [ ] `./scripts/build-dashboard.sh`, with `dashboard/dist` committed (dashboard changes only)
- [ ] A new or changed test fails without this change

## Documentation

- [ ] The docs pages that describe this behaviour are updated
- [ ] `docs/configuration.md` or `docs/cli.md` updated for new keys or commands
- [ ] `CHANGELOG.md` has a line under "Unreleased" for a user-visible change
- [ ] No docs change needed

## Security impact

<!--
Does this change what agents can or cannot do, how statements are
classified, checked or measured, what approvers or people see, how sign-in
or roles work, or where credentials and data go? If so, explain why it is
safe. If not, say "None".

Report vulnerabilities privately (see SECURITY.md), not in a pull request.
-->

## Sign-off

- [ ] Every commit has a `Signed-off-by` line (`git commit -s`), certifying
      the [Developer Certificate of Origin](https://developercertificate.org/),
      and I agree my contribution is licensed under the project's licence
      (see CONTRIBUTING.md)
