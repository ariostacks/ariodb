# Compliance reports

`ariodb report` turns ariodb's own records into a report pack for a
period: what agents did, who approved what, what was changed and undone,
how the policy changed, and what needs following up, with each part tied
to the controls of DORA, SOC 2, ISO/IEC 27001 and the EU AI Act it gives
evidence for. This page is for the people who run ariodb and for the
compliance teams and auditors who receive its packs. It covers what is
collected, how to make a pack, what is in one, how to check that a pack
has not been altered, and the control mappings.

> A pack is evidence that can support the controls it names. It is not a
> certification, an assessment, an attestation or an audit opinion, and it
> is not legal advice. Whether a control is met depends on how your
> organisation designs and operates it, which is for your auditors and
> advisers to judge. The mappings name only controls this evidence plainly
> supports; they do not claim that ariodb meets any control by itself.

## Making a pack

From the command line, on the machine that runs ariodb, with the same
config file:

```bash
ariodb report --from 2026-09-01 --to 2026-09-30 --framework all --out ./pack-2026-09
```

```text
wrote 21 files to ./pack-2026-09
decisions log: 18402 entries in the period, chain intact
exceptions to follow up: 3
manifest.sha256: 9b0c4c2e5f...  (64 hex characters)
```

| Option | Meaning |
|---|---|
| `--from` | The first day of the period, `YYYY-MM-DD` in UTC, or an instant such as `2026-09-01T08:00:00Z`. |
| `--to` | The last day of the period, included, or an instant, excluded. |
| `--framework` | `dora`, `soc2`, `iso27001`, `eu-ai-act` or `all` (the default). The records are the same; only the controls named change. |
| `--out` | A new or empty directory for the pack. ariodb never writes into a directory that already holds files. |

Record the `manifest.sha256` hash the command prints, separately from the
pack (in the ticket, the email that sends the pack, or your evidence
register): it is what lets anyone check the pack later.

The command only reads. It opens `ariodb.db` read-only (SQLite's
write-ahead log lets it read while `ariodb serve` writes, without holding
writers up) and reads the journals, so it can run while ariodb serves.
Run it as the user `ariodb serve` runs as, so it can read the state
directory. If the decisions log's chain is broken in the period, the
command still writes the pack, warns on stderr, and lists each break in
the report.

**From the dashboard**, admins can download the same pack from the
Decisions page with **Report pack**: choose the days and the frameworks,
and the pack arrives as a `.tar` archive (unpack it with `tar -xf`). The
dialog shows the manifest's hash to record, and the server logs who
downloaded a pack and its hash.

## What is in a pack

| File | Holds |
|---|---|
| `report.html` | The report: one self-contained page with its styles inline, no scripts and nothing loaded from elsewhere. It prints cleanly to PDF from a browser (A4, each section on a new page). |
| `summary.json` | The report's key numbers, for tooling: the period, the scope, counts by outcome, the chain check, approvals by result and by kind of decider, changes, policy versions and the number of exceptions. |
| `decisions.csv`, `.json` | Every decisions-log entry in the period, with its chain links (`prev`, `hash`). |
| `approvals.csv`, `.json` | Every approval request made in the period: who decided, whether a person, a model, a plugin or ariodb itself, when, and how long it took. |
| `changes.csv`, `.json` | Every transaction the Postgres and MySQL journals recorded in the period: its session, agent and tables, and how many rows it inserted, updated, deleted or truncated. Row values are left out. |
| `undos.csv`, `.json` | Every undo in the period: the session, the rows restored, and who undid it. |
| `config_versions.csv`, `.json` | The config version in force when the period began and each version recorded during it, with their masked text. |
| `refusals.csv`, `rollbacks.csv` (and `.json`) | Refused statements and rolled-back writes, grouped by rule and reason. |
| `exceptions.csv`, `.json` | Everything to follow up. |
| `controls.csv`, `.json` | Which controls each section gives evidence for. |
| `manifest.sha256` | Every other file and its SHA-256. |

All times are UTC. In the CSV files, a cell that starts with `=`, `+`,
`-`, `@`, a tab or a carriage return gets a leading `'`, so a spreadsheet
does not run it as a formula; the JSON files hold the exact values.
Everything that comes from SQL, the config or names is HTML-escaped in the
report.

Statements appear as the decisions log stores them: with
`[audit] redact_literals = true`, literal values are replaced by `$1`,
`$2` and so on, and the statements in approval requests are redacted the
same way in the pack. Without it, statements carry their literal values,
which may include customer data; treat the pack as you treat the
decisions log.

## The report's sections

1. **Period and scope.** The period, the ariodb version, the config file
   and the SHA-256 of its masked text, the agents, engines and databases,
   and how much was recorded.
2. **Integrity of the decisions log.** Every entry in the period is
   recomputed from its contents and checked against the one before it.
   The first entry is checked against the last entry before the period, and
   the first entry after the period against the last one in it, so entries
   removed from either end show too. Unlike `ariodb audit`, which stops at
   the first break, the report lists every break with the entry's id, and
   any gap in entry ids. It also states the retention setting and the
   oldest entry kept, so a period that reaches back past retention says so.
3. **Access control.** What each agent may do (access level, tables,
   database login and row limit per engine, as configured now), what each
   agent did (statements by outcome, writes, rows, the tables it used), and
   refusals grouped by rule and reason (`policy` is ariodb's built-in
   policy).
4. **Human oversight.** Approval requests: how many were decided by
   people, by models and by plugins, how long people took (median, 90th
   percentile and longest), how many timed out, were withdrawn because the
   agent left, or could not be delivered, and every request with who
   decided it. Decisions by models and plugins are shown apart from
   people's and are not counted as human oversight.
5. **Change control.** Writes committed and the rows they changed (as
   measured before commit), writes rolled back and why, what each agent
   session changed according to the journals, and every undo with who
   applied it and when.
6. **Policy changes.** The config in force when the period began, then each
   version recorded during it, with a line-by-line diff and what caused it
   (`startup`, `reload` or `dashboard:<user>`).
7. **Exceptions to follow up**, most serious first:
   - *high*: a break in the decisions log, the config history or the undo
     records; an approval decided by someone the approver's definition
     does not allow (a model deciding for a people approver, a person for a
     model, a decider outside the approver's `groups`, an approver no
     longer defined);
   - *medium*: missing entry ids where the chain still links; a statement
     let through because a model approver failed open; a day with at least
     10 refusals or rollbacks and at least three times the period's median
     day;
   - *low*: an approval decided through a signed link without signing in
     (the person is not identified); a request that could not be
     delivered; an undo whose author was not recorded; with the EU AI Act
     selected, `retention_days` under six months.

The approver definitions used to judge deciders are those of the config
version in force when each request was made, where the config history
reaches back that far, and the current config otherwise.

## What ariodb records for reports

Most of a pack comes from records ariodb already keeps: the decisions log,
the approvals table and the journals. Two more are kept in `ariodb.db` for
reports.

**Config history.** `ariodb serve` records the config file when it starts
and each time it reloads it (after an edit to the file, or a save from the
dashboard, recorded as `dashboard:<user>`), whenever the file differs from
the last version recorded. A config that fails to load is not in force and
is not recorded. Each version is stored with every password, token and
secret masked as `***`, the way the dashboard's config view masks database
passwords:

- the password in any URL (`postgres://user:***@host`, and the same for
  `mysql://`, `http://` and other schemes);
- query parameters that carry credentials (`token`, `key`, `secret`,
  `sig`, `password`, `auth`, `code` and names containing them);
- the path of webhook addresses that carry their credential there (Slack,
  Discord, Microsoft Teams and Telegram);
- the value of any key whose name says it is a credential (`password`,
  `token`, `secret`, `api_key`, `private_key` and the like), except keys
  that only name an environment variable or a stored secret (`*_env`,
  `*_secret` and `secret`), which stay readable;
- plugin `env` values whose names say they are credentials.

Each masked value is removed wherever it appears in the file, comments
included. Secrets kept where ariodb recommends (environment variables and
the secret store) are never in the file to begin with. Each version also
stores the SHA-256 of its masked text; for a config without inline
secrets, that is the hash of the file itself, so it can be matched against
the copy in version control.

**Undo records.** Each applied undo, from `ariodb undo --apply` or the
dashboard, is recorded with the session, the engine, the rows restored and
who applied it (`cli:<user>` or `dashboard:<user>`). The journals record
when an undo happened; this record adds who.

Both are hash-chained like the decisions log, so an edited or removed row
is reported as an exception. Both are pruned with the decisions log by
`[audit] retention_days`, except that the config version in force at the
cut-off is kept, so the oldest period still kept has a baseline. Neither
exists for anything before an ariodb with reports first ran.

## How an auditor checks a pack

1. Get the manifest's hash from whoever made the pack, by a different
   route from the pack itself.
2. Check the manifest has that hash, then that every file matches the
   manifest:

   ```bash
   cd pack-2026-09
   sha256sum manifest.sha256        # must print the hash you were given
   sha256sum -c manifest.sha256     # every line must say OK
   ```

   On macOS use `shasum -a 256` for `sha256sum`. A changed file fails the
   second check; a changed, added or removed line in the manifest fails the
   first.
3. Read the Integrity section. "Intact" means every entry in the period
   still matches its hash and links to the one before it. Where the
   report says the period reaches back past the oldest entry kept, the
   earlier part of the period is not covered.
4. To check the decisions themselves independently, recompute the chain
   from `decisions.json`: each entry's `hash` is the SHA-256 of a JSON
   rendering of its fields and `prev`, as `chain_text` in
   [`audit.rs`](../src/audit.rs) writes it, and each entry's `prev` is the
   `hash` of the one before it.

The chain is a SHA-256 hash chain without a key. It shows edits and
removals made with ordinary tools, but someone who can rewrite the whole
state directory could rebuild it. For stronger assurance, keep a copy of
the decisions log elsewhere as it is written, with an audit-sink
[plugin](plugins.md), and compare. See the [security
model](security-model.md).

## Control mappings

Each section of the report names the controls it gives evidence for. The
identifiers refer to:

- **DORA**: Regulation (EU) 2022/2554 on digital operational resilience
  for the financial sector ("Art."), and Commission Delegated Regulation
  (EU) 2024/1774, the regulatory technical standards on the ICT risk
  management framework ("RTS 2024/1774 Art.").
- **SOC 2**: the AICPA 2017 Trust Services Criteria (with the revised
  points of focus of 2022), common criteria CC6 to CC8.
- **ISO/IEC 27001:2022**: the information security controls of Annex A.
- **EU AI Act**: Regulation (EU) 2024/1689. The articles cited apply to
  high-risk AI systems; whether an agent is, or is part of, one is for the
  deployer to determine.

| Section | DORA | SOC 2 | ISO/IEC 27001:2022 | EU AI Act |
|---|---|---|---|---|
| Integrity of the decisions log | Art. 9(3)(c); RTS 2024/1774 Art. 12(2)(a), 12(2)(d) | CC7.2 | A.8.15, A.5.28 | Art. 12(1), 19(1), 26(6) |
| Access control | Art. 9(4)(c); RTS 2024/1774 Art. 21(a), 21(c), 12(2)(c)(i) | CC6.1, CC6.3 | A.5.15, A.5.18, A.8.3 | none |
| Human oversight | Art. 9(4)(c); RTS 2024/1774 Art. 21(b), 21(c) | CC8.1 | A.5.3 | Art. 14(4)(d), 26(2) |
| Change control | Art. 9(3)(b), 9(3)(d), 12(1)(b); RTS 2024/1774 Art. 12(2)(c)(iv) | CC8.1, CC7.5 | A.8.15 | Art. 14(4)(d), 12(2)(c) |
| Policy changes | Art. 9(4)(e); RTS 2024/1774 Art. 17(1)(d), 12(2)(c)(iii) | CC8.1, CC7.1 | A.8.9, A.8.32 | none |
| Exceptions to follow up | Art. 10(1), 17(3)(a); RTS 2024/1774 Art. 23(2)(b) | CC7.2, CC7.3 | A.8.16, A.5.25 | Art. 14(4)(a), 26(5) |

Period and scope is context for every section and maps to nothing on its
own.

Why these, briefly:

- **Integrity.** A tamper-evident log with a stated retention period is
  what DORA's logging RTS asks for in Article 12(2)(a) and (d), and what
  ISO A.8.15 (logging) describes; the pack's manifest supports preserving
  it as evidence (A.5.28). The EU AI Act asks for automatic recording of
  events (Article 12(1)) and for logs to be kept at least six months
  (Articles 19(1) and 26(6)); the report flags a shorter `retention_days`.
- **Access control.** Per-agent identities, table lists and access levels,
  and the record of what was refused, are evidence for least privilege and
  limited logical access (DORA Article 9(4)(c), RTS Article 21(a) and
  (c); SOC 2 CC6.1 and CC6.3; ISO A.5.15, A.5.18 and A.8.3).
- **Human oversight.** Held statements decided by named people, apart
  from the agent that asked, are evidence for approved activities and
  segregation of duties (DORA Article 9(4)(c), RTS Article 21(b) and (c);
  SOC 2 CC8.1; ISO A.5.3) and for natural persons able to decide not to use
  or to override a system's output (EU AI Act Articles 14(4)(d) and
  26(2)). Model and plugin decisions are shown separately because they are
  not human oversight.
- **Change control.** Writes measured before commit, rollbacks over limits
  and undo of a whole session are evidence for protecting data from
  corruption, loss and error and for recovery methods (DORA Articles
  9(3)(b), 9(3)(d) and 12(1)(b); SOC 2 CC8.1 and CC7.5), and the journal
  is a log of system activity (RTS Article 12(2)(c)(iv); ISO A.8.15).
  Undo is a way to reverse an agent's output (EU AI Act Article 14(4)(d)).
- **Policy changes.** A recorded, diffable history of the security
  configuration is evidence for change and configuration management (DORA
  Article 9(4)(e), RTS Articles 17(1)(d) and 12(2)(c)(iii); SOC 2 CC8.1 and
  CC7.1; ISO A.8.9 and A.8.32). It shows what changed and when; whether a
  change was assessed and approved beforehand is for your change process
  to show.
- **Exceptions.** Chain breaks, unexpected deciders and spikes are
  detected anomalies for someone to assess (DORA Articles 10(1) and
  17(3)(a), RTS Article 23(2)(b); SOC 2 CC7.2 and CC7.3; ISO A.8.16 and
  A.5.25; EU AI Act Articles 14(4)(a) and 26(5)).

## Limits

- The config history and undo records start when ariodb with reports first
  runs; packs for earlier periods show the current config and list undos
  without who applied them.
- Change control needs the journals (`[journal] enabled`, and
  `[mysql] journal` for MySQL). ClickHouse writes appear in the decisions
  log but have no journal and no undo.
- The access section shows agents' access as the config sets it when the
  report is made; changes during the period are in Policy changes.
- Masking works on what the config's structure says is a credential. A
  secret written anywhere else, under an unusual key name, is only masked
  if it also appears in a credential's place. Keep secrets in environment
  variables or the secret store.

## Next

- [CLI](cli.md#ariodb-report---from-from---to-to---framework-framework---out-out):
  every option of `ariodb report`.
- [Configuration](configuration.md#audit): retention and redaction.
- [Security model](security-model.md): what the hash chain does and does
  not prove.
- [Plugins](plugins.md): audit sinks, for a copy of the decisions log
  kept elsewhere.
