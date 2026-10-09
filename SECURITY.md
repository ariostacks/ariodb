# Security policy

ariodb stands between AI agents and production databases, so a flaw in it
can matter a great deal. Thank you for taking the time to report one
responsibly.

What ariodb defends against, what it guarantees, the risks it accepts and
the findings of its security review are in the
[security model](docs/security-model.md). Read it before reporting: a
behaviour listed there as an accepted risk is known, though a new way to
exploit it, or a reason to rethink it, is still welcome.

## Supported versions

ariodb is young, and fixes go into the latest release only.

| Version | Supported |
|---|---|
| Latest 0.x release | Yes |
| Older releases | No: upgrade to the latest |
| Unreleased commits on `main` | Best effort |

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a
security problem.**

Report it privately through GitHub: on the repository's **Security** tab,
choose **Report a vulnerability**. This opens a private security advisory
that only you and the maintainer can see, where we can discuss the problem
and work on a fix together.

Please include:

- the ariodb version (`ariodb --version`) or commit,
- the database and version involved (Postgres, MySQL, MariaDB, ClickHouse
  or another), and how ariodb connects to it,
- the relevant part of your config, with every credential, token and host
  name you would rather not share removed,
- the SQL, protocol messages or HTTP requests that show the problem, as a
  script or a list of steps,
- what you expected to happen and what happened, and
- what you think an attacker could do with it, and from which position (an
  agent with a valid token, someone on the network, someone with access to
  the host).

A short report with a clear reproduction is better than a long one
without. If you are not sure whether something is a vulnerability, report
it privately anyway.

## What to expect

These are goals, not promises: ariodb is maintained by one person.

- **Acknowledgement** within 3 working days.
- **A first assessment** (whether we agree it is a vulnerability, and how
  severe) within 10 working days.
- **A fix or a mitigation** for high and critical issues as soon as
  practical, normally within 90 days of the report.
- **Updates** in the advisory as the work goes on, at least every two
  weeks until it is resolved.

## Disclosure

We follow coordinated disclosure. Once a fix is released, the advisory is
published with a description of the problem, the affected and fixed
versions, any workaround, and credit to the reporter unless you would
rather not be named. We will agree the publication date with you, and ask
that you do not publish details before then. If 90 days pass without a fix,
we will talk with you about disclosing anyway.

The [security model](docs/security-model.md) is updated with each fixed
issue, and each fix comes with a test that fails without it.

## Scope

In scope: anything that breaks a guarantee in the
[security model](docs/security-model.md), for example:

- an agent running a statement, or touching a table, that the policy or the
  rules should have refused;
- a read that can write, or a write that escapes the effect check, the row
  limit or the rollback;
- an agent interfering with ariodb's own transaction control, the journal,
  the decisions log, or approvals meant for someone else;
- deciding an approval, signing in to the dashboard, or acting with a
  higher role than you have, without the right credentials;
- agent SQL changing what a person or a model approver sees in the
  dashboard, a chat message, an email or a webhook payload;
- database credentials or secrets reaching an agent;
- undo changing rows it should not, or the journal recording the wrong
  session;
- memory exhaustion or a crash triggered by an unauthenticated client.

Out of scope:

- risks listed as accepted in the security model, unless you have found a
  new way to exploit them;
- what the database's own grants allow: the database role's privileges are
  the real boundary (see the security model);
- persuading a model approver with a prompt injection, which the security
  model already treats as possible;
- attacks that need write access to the ariodb host, its config or its
  state directory;
- plugins you install, which are trusted code;
- denial of service by volume alone, rather than by a flaw;
- findings from automated scanners without a demonstrated impact.

## Testing

Please test only against systems you own or are allowed to test, never
against other people's deployments, and never with real customer data. The
demo (`./scripts/demo.sh`) and the end-to-end scripts in `scripts/` start
throwaway databases in Docker that are well suited to this.
