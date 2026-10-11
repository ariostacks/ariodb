//! `ariodb report`: a compliance report pack for a period, built from
//! ariodb's own records.
//!
//! The pack is a directory: a self-contained HTML report that prints
//! cleanly to PDF, CSV and JSON files of the records behind it, and
//! `manifest.sha256`, which lists every other file with its SHA-256. The
//! manifest's own hash is printed, so whoever receives the pack can check
//! that nothing in it was changed. Each section names the controls of
//! DORA, SOC 2, ISO/IEC 27001 and the EU AI Act it gives evidence for.
//!
//! Everything is read, never written: the SQLite store is opened
//! read-only (WAL readers do not block ariodb's writers), and the journals
//! are only read, so a report can run while `ariodb serve` does.

use crate::audit::Chained;
use crate::config::{Access, Config};
use crate::dashboard::html_escape as h;
use crate::history::{self, ConfigVersion, UndoRecord};
use crate::journal::{Op, TxnRecord};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

/// Rows shown in one HTML table; the CSV files hold them all.
const MAX_ROWS: usize = 200;
/// A day's refusals or rollbacks are a spike at this many, and at this
/// many times the period's median day.
const SPIKE_MIN: usize = 10;
const SPIKE_FACTOR: usize = 3;
/// The EU AI Act's minimum for keeping logs (Articles 19(1) and 26(6)).
const SIX_MONTHS_DAYS: u64 = 183;

// ---------------------------------------------------------------------------
// Frameworks and the controls each section gives evidence for.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Framework {
    Dora,
    Soc2,
    Iso27001,
    EuAiAct,
}

impl Framework {
    pub const ALL: [Framework; 4] = [
        Framework::Dora,
        Framework::Soc2,
        Framework::Iso27001,
        Framework::EuAiAct,
    ];

    /// `dora`, `soc2`, `iso27001`, `eu-ai-act` or `all`.
    pub fn parse(s: &str) -> Result<Vec<Framework>, String> {
        Ok(match s {
            "all" => Framework::ALL.to_vec(),
            "dora" => vec![Framework::Dora],
            "soc2" => vec![Framework::Soc2],
            "iso27001" => vec![Framework::Iso27001],
            "eu-ai-act" => vec![Framework::EuAiAct],
            _ => {
                return Err(format!(
                    "--framework must be dora, soc2, iso27001, eu-ai-act or all, not '{s}'"
                ));
            }
        })
    }

    pub fn key(self) -> &'static str {
        match self {
            Framework::Dora => "dora",
            Framework::Soc2 => "soc2",
            Framework::Iso27001 => "iso27001",
            Framework::EuAiAct => "eu-ai-act",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Framework::Dora => "DORA",
            Framework::Soc2 => "SOC 2",
            Framework::Iso27001 => "ISO/IEC 27001:2022",
            Framework::EuAiAct => "EU AI Act",
        }
    }

    /// The texts the identifiers refer to.
    pub fn source(self) -> &'static str {
        match self {
            Framework::Dora => {
                "Regulation (EU) 2022/2554 on digital operational resilience for the financial sector (\"DORA Art.\"), and Commission Delegated Regulation (EU) 2024/1774, the regulatory technical standards on the ICT risk management framework (\"RTS 2024/1774 Art.\")"
            }
            Framework::Soc2 => {
                "AICPA 2017 Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy (revised points of focus, 2022): common criteria CC6 to CC8"
            }
            Framework::Iso27001 => "ISO/IEC 27001:2022, Annex A (information security controls)",
            Framework::EuAiAct => {
                "Regulation (EU) 2024/1689 (the Artificial Intelligence Act). The articles cited apply to high-risk AI systems; whether an agent is, or is part of, one is for the deployer to determine"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Scope,
    Integrity,
    Access,
    Oversight,
    Change,
    Policy,
    Exceptions,
}

impl Section {
    pub const ALL: [Section; 7] = [
        Section::Scope,
        Section::Integrity,
        Section::Access,
        Section::Oversight,
        Section::Change,
        Section::Policy,
        Section::Exceptions,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Section::Scope => "scope",
            Section::Integrity => "integrity",
            Section::Access => "access",
            Section::Oversight => "oversight",
            Section::Change => "change",
            Section::Policy => "policy",
            Section::Exceptions => "exceptions",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Section::Scope => "Period and scope",
            Section::Integrity => "Integrity of the decisions log",
            Section::Access => "Access control",
            Section::Oversight => "Human oversight",
            Section::Change => "Change control",
            Section::Policy => "Policy changes",
            Section::Exceptions => "Exceptions to follow up",
        }
    }
}

/// One control a section gives evidence for.
pub struct Control {
    pub framework: Framework,
    pub id: &'static str,
    /// A short paraphrase, not the text itself.
    pub title: &'static str,
    pub section: Section,
}

const fn c(
    framework: Framework,
    section: Section,
    id: &'static str,
    title: &'static str,
) -> Control {
    Control {
        framework,
        id,
        title,
        section,
    }
}

use Framework::{Dora, EuAiAct, Iso27001, Soc2};
use Section::{
    Access as Acc, Change as Chg, Exceptions as Exc, Integrity as Int, Oversight as Ovs,
    Policy as Pol,
};

/// Only mappings that the evidence plainly supports. The scope section is
/// context for every other one and maps to nothing on its own.
#[rustfmt::skip]
pub const CONTROLS: &[Control] = &[
    // DORA and its RTS on the ICT risk management framework.
    c(Dora, Int, "DORA Art. 9(3)(c)", "ICT solutions prevent impairment of the authenticity and integrity of data"),
    c(Dora, Int, "RTS 2024/1774 Art. 12(2)(a)", "Logging: the events logged, their retention period and how log data is secured"),
    c(Dora, Int, "RTS 2024/1774 Art. 12(2)(d)", "Logging: logs protected against tampering, deletion and unauthorised access"),
    c(Dora, Acc, "DORA Art. 9(4)(c)", "Logical access limited to what legitimate, approved functions require"),
    c(Dora, Acc, "RTS 2024/1774 Art. 21(a)", "Access rights assigned on need-to-know, need-to-use and least privilege"),
    c(Dora, Acc, "RTS 2024/1774 Art. 21(c)", "User accountability: users identifiable for the actions they perform"),
    c(Dora, Acc, "RTS 2024/1774 Art. 12(2)(c)(i)", "Logging of events related to logical access control"),
    c(Dora, Ovs, "DORA Art. 9(4)(c)", "Logical access limited to what legitimate, approved functions require"),
    c(Dora, Ovs, "RTS 2024/1774 Art. 21(b)", "Segregation of duties, so access rights cannot be combined to circumvent controls"),
    c(Dora, Ovs, "RTS 2024/1774 Art. 21(c)", "User accountability: users identifiable for the actions they perform"),
    c(Dora, Chg, "DORA Art. 9(3)(b)", "ICT solutions minimise the risk of corruption or loss of data"),
    c(Dora, Chg, "DORA Art. 9(3)(d)", "Data protected from poor administration, processing-related risks and human error"),
    c(Dora, Chg, "DORA Art. 12(1)(b)", "Documented restoration and recovery procedures and methods"),
    c(Dora, Chg, "RTS 2024/1774 Art. 12(2)(c)(iv)", "Logging of ICT operations, including ICT system activities"),
    c(Dora, Pol, "DORA Art. 9(4)(e)", "Changes to systems and security parameters recorded, assessed, approved and verified"),
    c(Dora, Pol, "RTS 2024/1774 Art. 17(1)(d)", "Change management: documentation of change details"),
    c(Dora, Pol, "RTS 2024/1774 Art. 12(2)(c)(iii)", "Logging of events related to change management"),
    c(Dora, Exc, "DORA Art. 10(1)", "Mechanisms to promptly detect anomalous activities"),
    c(Dora, Exc, "DORA Art. 17(3)(a)", "Incident management process: early warning indicators"),
    c(Dora, Exc, "RTS 2024/1774 Art. 23(2)(b)", "Identify anomalous activities and behaviour"),
    // SOC 2 common criteria.
    c(Soc2, Int, "CC7.2", "System components monitored for anomalies; anomalies analysed as possible security events"),
    c(Soc2, Acc, "CC6.1", "Logical access security over protected information assets"),
    c(Soc2, Acc, "CC6.3", "Access to data authorised, changed or removed by role, least privilege and segregation of duties"),
    c(Soc2, Ovs, "CC8.1", "Changes to infrastructure, data, software and procedures are authorised and approved"),
    c(Soc2, Chg, "CC8.1", "Changes to infrastructure, data, software and procedures are authorised and approved"),
    c(Soc2, Chg, "CC7.5", "Activities to recover from identified security incidents"),
    c(Soc2, Pol, "CC8.1", "Changes to infrastructure, data, software and procedures are authorised and approved"),
    c(Soc2, Pol, "CC7.1", "Detection of configuration changes that introduce vulnerabilities"),
    c(Soc2, Exc, "CC7.2", "System components monitored for anomalies; anomalies analysed as possible security events"),
    c(Soc2, Exc, "CC7.3", "Security events evaluated to decide whether they are incidents"),
    // ISO/IEC 27001:2022 Annex A.
    c(Iso27001, Int, "A.8.15", "Logging"),
    c(Iso27001, Int, "A.5.28", "Collection of evidence"),
    c(Iso27001, Acc, "A.5.15", "Access control"),
    c(Iso27001, Acc, "A.5.18", "Access rights"),
    c(Iso27001, Acc, "A.8.3", "Information access restriction"),
    c(Iso27001, Ovs, "A.5.3", "Segregation of duties"),
    c(Iso27001, Chg, "A.8.15", "Logging"),
    c(Iso27001, Pol, "A.8.9", "Configuration management"),
    c(Iso27001, Pol, "A.8.32", "Change management"),
    c(Iso27001, Exc, "A.8.16", "Monitoring activities"),
    c(Iso27001, Exc, "A.5.25", "Assessment and decision on information security events"),
    // EU AI Act.
    c(EuAiAct, Int, "Art. 12(1)", "Record-keeping: automatic recording of events (logs)"),
    c(EuAiAct, Int, "Art. 19(1)", "Providers keep automatically generated logs for at least six months"),
    c(EuAiAct, Int, "Art. 26(6)", "Deployers keep automatically generated logs for at least six months"),
    c(EuAiAct, Ovs, "Art. 14(4)(d)", "Human oversight: decide not to use, or disregard, override or reverse the output"),
    c(EuAiAct, Ovs, "Art. 26(2)", "Deployers assign human oversight to competent natural persons"),
    c(EuAiAct, Chg, "Art. 14(4)(d)", "Human oversight: decide not to use, or disregard, override or reverse the output"),
    c(EuAiAct, Chg, "Art. 12(2)(c)", "Logs enable monitoring of the system's operation (Art. 26(5))"),
    c(EuAiAct, Exc, "Art. 14(4)(a)", "Human oversight: monitor operation, detect anomalies, dysfunctions and unexpected performance"),
    c(EuAiAct, Exc, "Art. 26(5)", "Deployers monitor the operation of the system"),
];

/// The controls of these frameworks a section gives evidence for.
pub fn controls_for(section: Section, frameworks: &[Framework]) -> Vec<&'static Control> {
    CONTROLS
        .iter()
        .filter(|c| c.section == section && frameworks.contains(&c.framework))
        .collect()
}

pub const DISCLAIMER: &str = "This pack is evidence that can support the controls it names. It is not a certification, an assessment, an attestation or an audit opinion, and it is not legal advice. Whether a control is met depends on how your organisation designs and operates it, which is for your auditors and advisers to judge. The mappings name only controls this evidence plainly supports; they do not claim that ariodb meets any control by itself.";

// ---------------------------------------------------------------------------
// Times. Everything is UTC (GMT).

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DD` (a whole day: its start, or with `end` the start of the
/// next day) or `YYYY-MM-DDTHH:MM[:SS]Z` (that instant), in milliseconds.
pub fn parse_time(s: &str, end: bool) -> Result<i64, String> {
    let bad = || format!("'{s}' is not a date (YYYY-MM-DD) or a UTC time (YYYY-MM-DDTHH:MM:SSZ)");
    let (date, time) = match s.split_once('T') {
        Some((d, t)) => (d, Some(t.strip_suffix('Z').ok_or_else(bad)?)),
        None => (s, None),
    };
    let parts: Vec<&str> = date.split('-').collect();
    let [y, m, d] = parts.as_slice() else {
        return Err(bad());
    };
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return Err(bad());
    }
    let (y, m, d): (i64, u32, u32) = (
        y.parse().map_err(|_| bad())?,
        m.parse().map_err(|_| bad())?,
        d.parse().map_err(|_| bad())?,
    );
    let days_in_month = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => return Err(bad()),
    };
    if d == 0 || d > days_in_month {
        return Err(bad());
    }
    let day = days_from_civil(y, m, d) * 86_400_000;
    let Some(time) = time else {
        return Ok(if end { day + 86_400_000 } else { day });
    };
    let t: Vec<u32> = time
        .split(':')
        .map(|p| p.parse().map_err(|_| bad()))
        .collect::<Result<_, _>>()?;
    let (hh, mm, ss) = match t.as_slice() {
        [hh, mm] => (*hh, *mm, 0),
        [hh, mm, ss] => (*hh, *mm, *ss),
        _ => return Err(bad()),
    };
    if hh > 23 || mm > 59 || ss > 59 {
        return Err(bad());
    }
    Ok(day + (hh as i64 * 3600 + mm as i64 * 60 + ss as i64) * 1000)
}

/// `YYYY-MM-DD HH:MM:SS UTC`.
pub fn when(ms: i64) -> String {
    format!(
        "{} UTC",
        crate::mysql_binlog::timestamp_text(ms.div_euclid(1000).max(1), 0, 0)
    )
}

fn day_of(ms: i64) -> String {
    when(ms)[..10].to_string()
}

fn duration(ms: i64) -> String {
    let s = ms as f64 / 1000.0;
    if s < 60.0 {
        format!("{s:.1} s")
    } else if s < 3600.0 {
        format!("{:.1} min", s / 60.0)
    } else {
        format!("{:.1} h", s / 3600.0)
    }
}

// ---------------------------------------------------------------------------
// Files in the pack.

/// CSV with every field quoted when it must be, and fields that a
/// spreadsheet would run as a formula prefixed with `'`. The JSON files
/// carry the exact values.
fn csv_field(s: &str) -> String {
    let guarded = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

fn csv_line(fields: &[String]) -> String {
    let mut line = fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",");
    line.push_str("\r\n");
    line
}

/// The pack's directory and the files written to it so far.
struct Pack {
    dir: PathBuf,
    files: Vec<String>,
}

impl Pack {
    fn create(&mut self, name: &str) -> Result<std::io::BufWriter<std::fs::File>, String> {
        let path = self.dir.join(name);
        self.files.push(name.to_string());
        std::fs::File::create(&path)
            .map(std::io::BufWriter::new)
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    fn write(&mut self, name: &str, bytes: &[u8]) -> Result<(), String> {
        let mut f = self.create(name)?;
        f.write_all(bytes).map_err(|e| e.to_string())?;
        f.flush().map_err(|e| e.to_string())
    }

    /// A table as `<name>.csv` and the same rows as `<name>.json`.
    fn table(
        &mut self,
        name: &str,
        header: &[&str],
        rows: &[Vec<String>],
        json: &[Value],
    ) -> Result<(), String> {
        let mut text = csv_line(&header.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        for r in rows {
            text.push_str(&csv_line(r));
        }
        self.write(&format!("{name}.csv"), text.as_bytes())?;
        let body = serde_json::to_string_pretty(json).map_err(|e| e.to_string())?;
        self.write(&format!("{name}.json"), format!("{body}\n").as_bytes())
    }

    /// `manifest.sha256`: every file and its SHA-256, in the format
    /// `sha256sum -c` reads. Returns the manifest's own hash.
    fn manifest(&mut self) -> Result<String, String> {
        let mut names = self.files.clone();
        names.sort();
        let mut text = String::new();
        for name in &names {
            let bytes = std::fs::read(self.dir.join(name)).map_err(|e| format!("{name}: {e}"))?;
            let _ = writeln!(text, "{}  {name}", history::sha256_hex(&bytes));
        }
        self.write("manifest.sha256", text.as_bytes())?;
        Ok(history::sha256_hex(text.as_bytes()))
    }
}

/// Stream a JSON array to a file, one element at a time.
struct JsonArray<W: std::io::Write> {
    out: W,
    first: bool,
}

impl<W: std::io::Write> JsonArray<W> {
    fn new(mut out: W) -> Result<Self, String> {
        out.write_all(b"[").map_err(|e| e.to_string())?;
        Ok(JsonArray { out, first: true })
    }

    fn push(&mut self, v: &Value) -> Result<(), String> {
        let sep: &[u8] = if self.first { b"\n  " } else { b",\n  " };
        self.first = false;
        self.out.write_all(sep).map_err(|e| e.to_string())?;
        serde_json::to_writer(&mut self.out, v).map_err(|e| e.to_string())
    }

    fn finish(mut self) -> Result<(), String> {
        self.out.write_all(b"\n]\n").map_err(|e| e.to_string())?;
        self.out.flush().map_err(|e| e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Reading ariodb's state.

/// The store, read-only. Missing means nothing was ever recorded.
fn open_store(dir: &Path) -> Result<Option<Connection>, String> {
    let path = dir.join("ariodb.db");
    if !path.exists() {
        return Ok(None);
    }
    let conn = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("{}: {e}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(10))
        .map_err(|e| e.to_string())?;
    Ok(Some(conn))
}

fn has_table(conn: &Connection, name: &str) -> Result<bool, String> {
    conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n > 0)
    .map_err(|e| e.to_string())
}

fn one_id(conn: &Connection, sql: &str, arg: i64) -> Result<Option<i64>, String> {
    conn.query_row(sql, [arg], |r| r.get::<_, Option<i64>>(0))
        .optional()
        .map(Option::flatten)
        .map_err(|e| e.to_string())
}

/// Who decided, by kind: `person`, `model`, `plugin` or `ariodb` (ariodb
/// itself: a request it could not deliver, one the agent left, or a model
/// that was down when failing open).
pub fn decider_kind(by: &str) -> &'static str {
    if by.starts_with("model:") {
        "model"
    } else if by.starts_with("plugin:") {
        "plugin"
    } else if by == "ariodb" || by.starts_with("ariodb:") {
        "ariodb"
    } else {
        "person"
    }
}

/// One link in the decisions log that does not hold.
#[derive(Debug, Clone, PartialEq)]
pub struct Break {
    pub id: i64,
    pub at_ms: i64,
    pub what: String,
}

/// What the walk over the period's entries found.
#[derive(Default)]
struct Integrity {
    /// Entries in the period.
    checked: usize,
    first_id: Option<i64>,
    last_id: Option<i64>,
    /// The entry before the period whose hash anchors it, and the one after
    /// whose link closes it.
    anchor: Option<i64>,
    follower: Option<i64>,
    breaks: Vec<Break>,
    /// Missing ids between two entries whose links still hold.
    gaps: Vec<(i64, i64)>,
    oldest_kept: Option<(i64, i64)>,
}

/// Follows the links between consecutive entries.
#[derive(Default)]
struct ChainCheck {
    last: Option<(i64, String)>,
    breaks: Vec<Break>,
    gaps: Vec<(i64, i64)>,
}

impl ChainCheck {
    fn next(&mut self, e: &Chained, intact: bool) {
        let d = &e.decision;
        if !intact {
            self.breaks.push(Break {
                id: d.id,
                at_ms: d.at_ms,
                what: format!("entry {} was changed after it was written", d.id),
            });
        }
        if let Some((prev_id, prev_hash)) = &self.last {
            let contiguous = d.id == prev_id + 1;
            if e.prev != *prev_hash {
                self.breaks.push(Break {
                    id: d.id,
                    at_ms: d.at_ms,
                    what: if contiguous {
                        format!(
                            "entry {} does not link to entry {prev_id} (one of them was changed)",
                            d.id
                        )
                    } else {
                        format!("entries {} to {} were removed", prev_id + 1, d.id - 1)
                    },
                });
            } else if !contiguous {
                self.gaps.push((*prev_id, d.id));
            }
        }
        self.last = Some((d.id, e.hash.clone()));
    }
}

/// Day-by-day counts, oldest first, with every day of the period present.
fn daily(counts: &BTreeMap<i64, usize>, from_ms: i64, to_ms: i64) -> Vec<(i64, usize)> {
    let first = from_ms.div_euclid(86_400_000);
    let last = (to_ms - 1).div_euclid(86_400_000);
    // A very long period is judged on the days that have any.
    if last - first > 3660 {
        return counts.iter().map(|(d, n)| (*d, *n)).collect();
    }
    (first..=last)
        .map(|d| (d, counts.get(&d).copied().unwrap_or(0)))
        .collect()
}

/// Days whose count is at least `SPIKE_MIN` and at least `SPIKE_FACTOR`
/// times the median day (counted as at least one). Returns the day, its
/// count and the median.
pub fn spikes(days: &[(i64, usize)]) -> Vec<(i64, usize, usize)> {
    if days.is_empty() {
        return Vec::new();
    }
    let mut sorted: Vec<usize> = days.iter().map(|(_, n)| *n).collect();
    sorted.sort();
    let median = sorted[sorted.len() / 2];
    days.iter()
        .filter(|(_, n)| *n >= SPIKE_MIN && *n >= SPIKE_FACTOR * median.max(1))
        .map(|(d, n)| (*d, *n, median))
        .collect()
}

/// A line-by-line diff: `' '` kept, `'-'` removed, `'+'` added.
pub fn diff_lines(a: &str, b: &str) -> Vec<(char, String)> {
    let a: Vec<&str> = a.lines().collect();
    let b: Vec<&str> = b.lines().collect();
    // Common lines at both ends need no table.
    let head = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let tail = a[head..]
        .iter()
        .rev()
        .zip(b[head..].iter().rev())
        .take_while(|(x, y)| x == y)
        .count();
    let (am, bm) = (&a[head..a.len() - tail], &b[head..b.len() - tail]);
    let mut out: Vec<(char, String)> = a[..head].iter().map(|l| (' ', l.to_string())).collect();
    if am.len() * bm.len() > 4_000_000 {
        out.extend(am.iter().map(|l| ('-', l.to_string())));
        out.extend(bm.iter().map(|l| ('+', l.to_string())));
    } else {
        // Longest common subsequence, from the end.
        let (n, m) = (am.len(), bm.len());
        let mut t = vec![0u32; (n + 1) * (m + 1)];
        for i in (0..n).rev() {
            for j in (0..m).rev() {
                t[i * (m + 1) + j] = if am[i] == bm[j] {
                    t[(i + 1) * (m + 1) + j + 1] + 1
                } else {
                    t[(i + 1) * (m + 1) + j].max(t[i * (m + 1) + j + 1])
                };
            }
        }
        let (mut i, mut j) = (0, 0);
        while i < n && j < m {
            if am[i] == bm[j] {
                out.push((' ', am[i].to_string()));
                i += 1;
                j += 1;
            } else if t[(i + 1) * (m + 1) + j] >= t[i * (m + 1) + j + 1] {
                out.push(('-', am[i].to_string()));
                i += 1;
            } else {
                out.push(('+', bm[j].to_string()));
                j += 1;
            }
        }
        out.extend(am[i..].iter().map(|l| ('-', l.to_string())));
        out.extend(bm[j..].iter().map(|l| ('+', l.to_string())));
    }
    out.extend(a[a.len() - tail..].iter().map(|l| (' ', l.to_string())));
    out
}

/// The changed lines with three lines of context, as HTML.
fn diff_html(diff: &[(char, String)]) -> String {
    let near: Vec<bool> = (0..diff.len())
        .map(|i| {
            let lo = i.saturating_sub(3);
            let hi = (i + 4).min(diff.len());
            diff[lo..hi].iter().any(|(k, _)| *k != ' ')
        })
        .collect();
    let mut out = String::from("<pre class=\"diff\">");
    let mut skipped = false;
    for (i, (kind, line)) in diff.iter().enumerate() {
        if !near[i] {
            skipped = true;
            continue;
        }
        if skipped {
            out.push_str("<span class=\"skip\">\u{22ef}</span>\n");
            skipped = false;
        }
        let class = match kind {
            '+' => "add",
            '-' => "del",
            _ => "same",
        };
        let _ = writeln!(out, "<span class=\"{class}\">{kind} {}</span>", h(line));
    }
    if skipped {
        out.push_str("<span class=\"skip\">\u{22ef}</span>\n");
    }
    out.push_str("</pre>");
    out
}

/// One approval request, as the approvals table holds it.
#[derive(Debug, Clone)]
struct ApprovalRow {
    id: String,
    created_ms: i64,
    agent: String,
    session: String,
    sql: String,
    rule: String,
    approver: String,
    status: String,
    decided_by: Option<String>,
    note: Option<String>,
    decided_ms: Option<i64>,
}

fn read_approvals(conn: &Connection, from_ms: i64, to_ms: i64) -> Result<Vec<ApprovalRow>, String> {
    if !has_table(conn, "approvals")? {
        return Ok(Vec::new());
    }
    let mut stmt = conn
        .prepare(
            "SELECT id, created_ms, agent, session, sql, rule, approver, status, decided_by, note, decided_ms
             FROM approvals WHERE created_ms >= ?1 AND created_ms < ?2 ORDER BY created_ms, id",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([from_ms, to_ms], |r| {
            Ok(ApprovalRow {
                id: r.get(0)?,
                created_ms: r.get(1)?,
                agent: r.get(2)?,
                session: r.get(3)?,
                sql: r.get(4)?,
                rule: r.get(5)?,
                approver: r.get(6)?,
                status: r.get(7)?,
                decided_by: r.get(8)?,
                note: r.get(9)?,
                decided_ms: r.get(10)?,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}

/// What an approval's record says happened.
fn approval_result(a: &ApprovalRow) -> &'static str {
    match (a.status.as_str(), a.decided_by.as_deref()) {
        ("expired", None) => "timed out",
        ("expired", Some(_)) => "withdrawn",
        ("denied", Some("ariodb")) => "not delivered",
        ("allowed", _) => "allowed",
        ("denied", _) => "denied",
        ("pending", _) => "pending",
        _ => "other",
    }
}

/// Why a decider is not one the approver's definition allows, if it is not.
/// `approver` is the definition in force when the request was made.
pub fn unexpected_decider(
    approver: Option<&crate::approvals::ApproverConfig>,
    approver_name: &str,
    by: &str,
) -> Option<String> {
    use crate::approvals::ApproverKind as K;
    if by == "ariodb" {
        return None;
    }
    let Some(a) = approver else {
        return Some(format!(
            "approver '{approver_name}' is not defined in the config in force, yet {by} decided its request"
        ));
    };
    let person_in_dashboard = by.starts_with("dashboard:") || by.starts_with("sso:");
    let ok = match a.kind {
        K::Llm => by.starts_with("model:") || by.starts_with("ariodb:failed-open:"),
        K::Plugin => by == format!("plugin:{}", a.plugin.as_deref().unwrap_or("")),
        K::Dashboard => person_in_dashboard || by.starts_with("cli:"),
        K::Slack => by.starts_with("slack:") || person_in_dashboard || by.starts_with("cli:"),
        _ => by == "webhook" || person_in_dashboard || by.starts_with("cli:"),
    };
    if !ok {
        return Some(format!(
            "approver '{}' is a {} approver, yet {by} decided its request",
            a.name,
            a.kind.name()
        ));
    }
    if !a.groups.is_empty() && !by.starts_with("sso:") {
        return Some(format!(
            "only members of {} may decide for approver '{}', yet {by} decided its request{}",
            a.groups.join(", "),
            a.name,
            if by.starts_with("cli:") {
                " from the command line, which does not check groups"
            } else {
                ""
            }
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// The report.

pub struct Options {
    pub from_ms: i64,
    pub to_ms: i64,
    pub frameworks: Vec<Framework>,
    pub out: PathBuf,
}

pub struct Summary {
    pub files: usize,
    pub manifest_sha256: String,
    pub decisions: usize,
    pub breaks: Vec<Break>,
    pub exceptions: usize,
}

/// Something to follow up, for the exceptions section.
struct Exception {
    severity: &'static str,
    section: Section,
    at_ms: Option<i64>,
    what: String,
}

#[derive(Default)]
struct AgentActivity {
    outcomes: BTreeMap<String, usize>,
    tables: BTreeSet<String>,
    engines: BTreeSet<String>,
    writes: usize,
    rows: i64,
}

/// A session's changes in the journals.
#[derive(Default)]
struct SessionChanges {
    engine: &'static str,
    agent: String,
    transactions: usize,
    ops: [usize; 4],
    tables: BTreeSet<String>,
    first_ms: i64,
    last_ms: i64,
}

fn op_index(op: Op) -> usize {
    match op {
        Op::Insert => 0,
        Op::Update => 1,
        Op::Delete => 2,
        Op::Truncate => 3,
    }
}

/// Build a pack in `opts.out`, which must not exist or be empty.
pub fn build(config: &Config, config_path: &Path, opts: &Options) -> Result<Summary, String> {
    if opts.from_ms >= opts.to_ms {
        return Err("--from must be before --to".to_string());
    }
    if opts.out.exists()
        && std::fs::read_dir(&opts.out)
            .map_err(|e| format!("{}: {e}", opts.out.display()))?
            .next()
            .is_some()
    {
        return Err(format!(
            "{} is not empty; a pack goes into a new or empty directory",
            opts.out.display()
        ));
    }
    std::fs::create_dir_all(&opts.out).map_err(|e| format!("{}: {e}", opts.out.display()))?;
    let mut pack = Pack {
        dir: opts.out.clone(),
        files: Vec::new(),
    };
    let (from, to) = (opts.from_ms, opts.to_ms);
    let dir = Path::new(&config.journal.dir);
    let store = open_store(dir)?;
    let redact = config.audit.redact_literals;
    let mut exceptions: Vec<Exception> = Vec::new();

    // The decisions log: walk the period, checking every link, and write
    // each entry out as it goes.
    let mut integrity = Integrity::default();
    let mut outcomes: BTreeMap<String, usize> = BTreeMap::new();
    let mut agents: BTreeMap<String, AgentActivity> = BTreeMap::new();
    let mut databases: BTreeSet<(String, String)> = BTreeSet::new();
    let mut refusals: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut rollbacks: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut refused_days: BTreeMap<i64, usize> = BTreeMap::new();
    let mut rollback_days: BTreeMap<i64, usize> = BTreeMap::new();
    let mut entry_deciders: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut failed_open: Vec<(i64, i64, String, String)> = Vec::new();
    {
        let mut csv = pack.create("decisions.csv")?;
        let header = [
            "id",
            "at_utc",
            "at_ms",
            "session",
            "agent",
            "engine",
            "database",
            "kind",
            "tables",
            "outcome",
            "rows",
            "rule",
            "reason",
            "decided_by",
            "latency_ms",
            "sql",
            "prev",
            "hash",
        ];
        csv.write_all(csv_line(&header.map(String::from)).as_bytes())
            .map_err(|e| e.to_string())?;
        let mut json = JsonArray::new(pack.create("decisions.json")?)?;
        if let Some(conn) = &store
            && has_table(conn, "decisions")?
        {
            integrity.oldest_kept = conn
                .query_row(
                    "SELECT id, at_ms FROM decisions ORDER BY id LIMIT 1",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(|e| e.to_string())?;
            let first = one_id(
                conn,
                "SELECT min(id) FROM decisions WHERE at_ms >= ?1",
                from,
            )?;
            let last = one_id(conn, "SELECT max(id) FROM decisions WHERE at_ms < ?1", to)?;
            let (first, last) = match (first, last) {
                (Some(f), Some(l)) if f <= l => (Some(f), Some(l)),
                _ => (None, None),
            };
            integrity.anchor = match first {
                Some(f) => one_id(conn, "SELECT max(id) FROM decisions WHERE id < ?1", f)?,
                None => one_id(conn, "SELECT max(id) FROM decisions WHERE at_ms < ?1", from)?,
            };
            integrity.follower = match last {
                Some(l) => one_id(conn, "SELECT min(id) FROM decisions WHERE id > ?1", l)?,
                None => one_id(conn, "SELECT min(id) FROM decisions WHERE at_ms >= ?1", to)?,
            };
            integrity.first_id = first;
            integrity.last_id = last;
            let lo = integrity.anchor.or(first);
            let hi = integrity.follower.or(last);
            let mut chain = ChainCheck::default();
            if let (Some(lo), Some(hi)) = (lo, hi) {
                crate::audit::walk(conn, lo, hi, |e, intact| {
                    chain.next(&e, intact);
                    let d = &e.decision;
                    let in_period =
                        first.is_some_and(|f| d.id >= f) && last.is_some_and(|l| d.id <= l);
                    if !in_period {
                        return Ok(());
                    }
                    integrity.checked += 1;
                    *outcomes.entry(d.outcome.clone()).or_default() += 1;
                    let a = agents.entry(d.agent.clone()).or_default();
                    *a.outcomes.entry(d.outcome.clone()).or_default() += 1;
                    a.engines.insert(d.engine.clone());
                    databases.insert((d.engine.clone(), d.database.clone()));
                    let day = d.at_ms.div_euclid(86_400_000);
                    let rule = d.rule.clone().unwrap_or_else(|| "policy".to_string());
                    let reason = d.reason.clone().unwrap_or_default();
                    match d.outcome.as_str() {
                        "allowed" => {
                            a.tables.extend(d.tables.iter().cloned());
                            if d.kind.contains("write") {
                                a.writes += 1;
                                a.rows += d.rows.unwrap_or(0);
                            }
                        }
                        "refused" => {
                            *refusals.entry((rule, reason)).or_default() += 1;
                            *refused_days.entry(day).or_default() += 1;
                        }
                        "rolled_back" => {
                            *rollbacks.entry((rule, reason)).or_default() += 1;
                            *rollback_days.entry(day).or_default() += 1;
                        }
                        _ => {}
                    }
                    for by in &d.decided_by {
                        *entry_deciders.entry(decider_kind(by)).or_default() += 1;
                        if by.starts_with("ariodb:failed-open:") {
                            failed_open.push((d.id, d.at_ms, d.agent.clone(), by.clone()));
                        }
                    }
                    let row = [
                        d.id.to_string(),
                        when(d.at_ms),
                        d.at_ms.to_string(),
                        d.session.clone(),
                        d.agent.clone(),
                        d.engine.clone(),
                        d.database.clone(),
                        d.kind.clone(),
                        d.tables.join(" "),
                        d.outcome.clone(),
                        d.rows.map(|r| r.to_string()).unwrap_or_default(),
                        d.rule.clone().unwrap_or_default(),
                        d.reason.clone().unwrap_or_default(),
                        d.decided_by.join(" "),
                        d.latency_ms.map(|r| r.to_string()).unwrap_or_default(),
                        d.sql.clone(),
                        e.prev.clone(),
                        e.hash.clone(),
                    ];
                    csv.write_all(csv_line(&row).as_bytes())
                        .map_err(|e| e.to_string())?;
                    json.push(&serde_json::to_value(&e).map_err(|e| e.to_string())?)
                })?;
            }
            integrity.breaks = chain.breaks;
            integrity.gaps = chain.gaps;
        }
        json.finish()?;
        csv.flush().map_err(|e| e.to_string())?;
    }
    for b in &integrity.breaks {
        exceptions.push(Exception {
            severity: "high",
            section: Section::Integrity,
            at_ms: Some(b.at_ms),
            what: format!("Decisions log chain broken: {}.", b.what),
        });
    }
    for (a, b) in &integrity.gaps {
        exceptions.push(Exception {
            severity: "medium",
            section: Section::Integrity,
            at_ms: None,
            what: format!(
                "Decisions log ids {} to {} are missing, though the entries either side still link.",
                a + 1,
                b - 1
            ),
        });
    }

    // Approvals.
    let approvals = match &store {
        Some(conn) => read_approvals(conn, from, to)?,
        None => Vec::new(),
    };
    let versions_all: Vec<ConfigVersion> = match &store {
        Some(conn) => history::config_versions(conn, to)?,
        None => Vec::new(),
    };
    // The approver definitions in force at a time: from the config history
    // where it reaches back that far, otherwise the config now.
    let parsed: Vec<(i64, Option<Config>)> = versions_all
        .iter()
        .map(|v| (v.at_ms, Config::from_toml(&v.text).ok()))
        .collect();
    let config_at = |ms: i64| -> &Config {
        parsed
            .iter()
            .rev()
            .find(|(at, _)| *at <= ms)
            .and_then(|(_, c)| c.as_ref())
            .unwrap_or(config)
    };
    let mut by_result: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut by_decider: BTreeMap<String, usize> = BTreeMap::new();
    let mut person_waits: Vec<i64> = Vec::new();
    let mut approval_rows = Vec::new();
    let mut approval_json = Vec::new();
    for a in &approvals {
        let result = approval_result(a);
        *by_result.entry(result).or_default() += 1;
        let kind = a
            .decided_by
            .as_deref()
            .map(decider_kind)
            .unwrap_or("nobody");
        if matches!(result, "allowed" | "denied") {
            *by_kind.entry(kind).or_default() += 1;
            if let Some(by) = &a.decided_by {
                *by_decider.entry(by.clone()).or_default() += 1;
            }
            if kind == "person"
                && let Some(d) = a.decided_ms
            {
                person_waits.push(d - a.created_ms);
            }
        }
        if let Some(by) = &a.decided_by {
            let cfg = config_at(a.created_ms);
            let def = cfg.approvers.iter().find(|x| x.name == a.approver);
            if let Some(why) = unexpected_decider(def, &a.approver, by) {
                exceptions.push(Exception {
                    severity: "high",
                    section: Section::Oversight,
                    at_ms: Some(a.created_ms),
                    what: format!("Approval {}: {why}.", a.id),
                });
            } else if by == "webhook" {
                exceptions.push(Exception {
                    severity: "low",
                    section: Section::Oversight,
                    at_ms: Some(a.created_ms),
                    what: format!(
                        "Approval {} was decided through a signed link without signing in, so the person is not identified.",
                        a.id
                    ),
                });
            }
        }
        if result == "not delivered" {
            exceptions.push(Exception {
                severity: "low",
                section: Section::Oversight,
                at_ms: Some(a.created_ms),
                what: format!(
                    "Approval {} could not be delivered to approver '{}' and was refused: {}",
                    a.id,
                    a.approver,
                    a.note.clone().unwrap_or_default()
                ),
            });
        }
        let sql = crate::audit::stored_sql(&a.sql, redact);
        let wait = a.decided_ms.map(|d| d - a.created_ms);
        approval_rows.push(vec![
            a.id.clone(),
            when(a.created_ms),
            a.agent.clone(),
            a.session.clone(),
            a.rule.clone(),
            a.approver.clone(),
            result.to_string(),
            a.decided_by.clone().unwrap_or_default(),
            kind.to_string(),
            a.decided_ms.map(when).unwrap_or_default(),
            wait.map(|w| w.to_string()).unwrap_or_default(),
            a.note.clone().unwrap_or_default(),
            sql.clone(),
        ]);
        approval_json.push(json!({
            "id": a.id, "created_ms": a.created_ms, "agent": a.agent, "session": a.session,
            "rule": a.rule, "approver": a.approver, "status": a.status, "result": result,
            "decided_by": a.decided_by, "decider_kind": kind, "decided_ms": a.decided_ms,
            "wait_ms": wait, "note": a.note, "sql": sql,
        }));
    }
    pack.table(
        "approvals",
        &[
            "id",
            "created_utc",
            "agent",
            "session",
            "rule",
            "approver",
            "result",
            "decided_by",
            "decider_kind",
            "decided_utc",
            "wait_ms",
            "note",
            "sql",
        ],
        &approval_rows,
        &approval_json,
    )?;
    for (id, at, agent, by) in &failed_open {
        exceptions.push(Exception {
            severity: "medium",
            section: Section::Oversight,
            at_ms: Some(*at),
            what: format!(
                "Decision {id} for agent '{agent}' was allowed because a model approver was unavailable and failed open ({by}): no model or person decided it."
            ),
        });
    }

    // The journals: what each session changed, and undo.
    let mut records: Vec<(&'static str, TxnRecord)> = Vec::new();
    records.extend(
        crate::journal::read_all(config)?
            .into_iter()
            .map(|r| ("postgres", r)),
    );
    records.extend(
        crate::mysql_journal::read_all(config)?
            .into_iter()
            .map(|r| ("mysql", r)),
    );
    records.retain(|(_, r)| r.at_ms >= from && r.at_ms < to);
    records.sort_by_key(|(_, r)| r.at_ms);
    let undo_records: Vec<UndoRecord> = match &store {
        Some(conn) => history::undo_records(conn, from, to)?,
        None => Vec::new(),
    };
    let mut sessions: BTreeMap<String, SessionChanges> = BTreeMap::new();
    let mut others = [0usize; 2];
    let mut undos: Vec<(i64, &'static str, String, usize, Option<String>)> = Vec::new();
    let mut change_rows = Vec::new();
    let mut change_json = Vec::new();
    let mut used_undo_records: BTreeSet<i64> = BTreeSet::new();
    let mut undo_transactions = 0;
    for (engine, r) in &records {
        let mut ops = [0usize; 4];
        let mut tables = BTreeSet::new();
        for ch in &r.changes {
            ops[op_index(ch.op)] += 1;
            tables.insert(ch.qualified_table());
        }
        match r.session.as_deref() {
            Some(s) if s.starts_with("undo:") => {
                let session = s.trim_start_matches("undo:").to_string();
                // Who: the undo record for this session nearest in time.
                let by = undo_records
                    .iter()
                    .filter(|u| u.session == session && (u.at_ms - r.at_ms).abs() < 600_000)
                    .min_by_key(|u| (u.at_ms - r.at_ms).abs())
                    .map(|u| {
                        used_undo_records.insert(u.id);
                        u.by.clone()
                    });
                undos.push((r.at_ms, engine, session, r.changes.len(), by));
                undo_transactions += 1;
            }
            Some(s) => {
                let e = sessions.entry(s.to_string()).or_default();
                if e.transactions == 0 {
                    e.first_ms = r.at_ms;
                    e.engine = engine;
                    e.agent = r.agent.clone().unwrap_or_default();
                }
                e.transactions += 1;
                e.last_ms = r.at_ms;
                for (i, n) in ops.iter().enumerate() {
                    e.ops[i] += n;
                }
                e.tables.extend(tables.iter().cloned());
            }
            None => {
                others[0] += 1;
                others[1] += r.changes.len();
            }
        }
        change_rows.push(vec![
            when(r.at_ms),
            engine.to_string(),
            r.xid.to_string(),
            r.lsn_text.clone(),
            r.session.clone().unwrap_or_default(),
            r.agent.clone().unwrap_or_default(),
            tables.iter().cloned().collect::<Vec<_>>().join(" "),
            ops[0].to_string(),
            ops[1].to_string(),
            ops[2].to_string(),
            ops[3].to_string(),
        ]);
        change_json.push(json!({
            "at_ms": r.at_ms, "engine": engine, "xid": r.xid, "position": r.lsn_text,
            "session": r.session, "agent": r.agent, "tables": tables,
            "inserts": ops[0], "updates": ops[1], "deletes": ops[2], "truncates": ops[3],
        }));
    }
    // Undos ariodb recorded but the journal has not (yet) seen.
    for u in undo_records
        .iter()
        .filter(|u| !used_undo_records.contains(&u.id))
    {
        let engine = if u.engine == "mysql" {
            "mysql"
        } else {
            "postgres"
        };
        undos.push((
            u.at_ms,
            engine,
            u.session.clone(),
            u.rows as usize,
            Some(u.by.clone()),
        ));
    }
    undos.sort_by_key(|u| u.0);
    for u in undo_records.iter().filter(|u| !u.intact) {
        exceptions.push(Exception {
            severity: "high",
            section: Section::Change,
            at_ms: Some(u.at_ms),
            what: format!(
                "The record of the undo of session {} was changed, or a record before it removed.",
                u.session
            ),
        });
    }
    for (at, _, session, _, by) in &undos {
        if by.is_none() {
            exceptions.push(Exception {
                severity: "low",
                section: Section::Change,
                at_ms: Some(*at),
                what: format!(
                    "Session {session} was undone, but who undid it is not recorded (an undo from before ariodb recorded them)."
                ),
            });
        }
    }
    pack.table(
        "changes",
        &[
            "committed_utc",
            "engine",
            "xid",
            "position",
            "session",
            "agent",
            "tables",
            "inserts",
            "updates",
            "deletes",
            "truncates",
        ],
        &change_rows,
        &change_json,
    )?;
    let undo_rows: Vec<Vec<String>> = undos
        .iter()
        .map(|(at, engine, s, rows, by)| {
            vec![
                when(*at),
                engine.to_string(),
                s.clone(),
                sessions.get(s).map(|x| x.agent.clone()).unwrap_or_default(),
                rows.to_string(),
                by.clone().unwrap_or_else(|| "not recorded".into()),
            ]
        })
        .collect();
    let undo_json: Vec<Value> = undos
        .iter()
        .map(|(at, engine, s, rows, by)| {
            json!({ "at_ms": at, "engine": engine, "session": s, "rows": rows, "by": by })
        })
        .collect();
    pack.table(
        "undos",
        &["undone_utc", "engine", "session", "agent", "rows", "by"],
        &undo_rows,
        &undo_json,
    )?;

    // Policy changes.
    let baseline = versions_all.iter().rev().find(|v| v.at_ms < from);
    let changes: Vec<&ConfigVersion> = versions_all.iter().filter(|v| v.at_ms >= from).collect();
    for v in versions_all.iter().filter(|v| !v.intact) {
        exceptions.push(Exception {
            severity: "high",
            section: Section::Policy,
            at_ms: Some(v.at_ms),
            what: format!(
                "Config version {} (recorded {}) was changed after it was recorded, or a version before it removed.",
                v.id,
                when(v.at_ms)
            ),
        });
    }
    let version_json: Vec<Value> = baseline
        .into_iter()
        .chain(changes.iter().copied())
        .map(|v| {
            json!({
                "id": v.id, "at_ms": v.at_ms, "in_force_at_start": v.at_ms < from,
                "path": v.path, "source": v.source, "sha256": v.sha256, "intact": v.intact,
                "text": v.text,
            })
        })
        .collect();
    let version_rows: Vec<Vec<String>> = baseline
        .into_iter()
        .chain(changes.iter().copied())
        .map(|v| {
            vec![
                v.id.to_string(),
                when(v.at_ms),
                v.source.clone(),
                v.sha256.clone(),
                v.intact.to_string(),
                v.path.clone(),
            ]
        })
        .collect();
    pack.table(
        "config_versions",
        &["id", "recorded_utc", "source", "sha256", "intact", "path"],
        &version_rows,
        &version_json,
    )?;

    // Spikes.
    for (what, counts) in [("refusals", &refused_days), ("rollbacks", &rollback_days)] {
        for (day, n, median) in spikes(&daily(counts, from, to)) {
            exceptions.push(Exception {
                severity: "medium",
                section: if what == "refusals" {
                    Section::Access
                } else {
                    Section::Change
                },
                at_ms: Some(day * 86_400_000),
                what: format!(
                    "{n} {what} on {}, against a median of {median} a day over the period.",
                    day_of(day * 86_400_000)
                ),
            });
        }
    }
    let retention = config.audit.retention_days;
    if opts.frameworks.contains(&Framework::EuAiAct) && retention > 0 && retention < SIX_MONTHS_DAYS
    {
        exceptions.push(Exception {
            severity: "low",
            section: Section::Integrity,
            at_ms: None,
            what: format!(
                "[audit] retention_days is {retention}: the EU AI Act asks for logs of high-risk AI systems to be kept for at least six months (Articles 19(1) and 26(6))."
            ),
        });
    }
    exceptions.sort_by_key(|e| {
        (
            match e.severity {
                "high" => 0,
                "medium" => 1,
                _ => 2,
            },
            e.at_ms.unwrap_or(0),
        )
    });
    let exception_rows: Vec<Vec<String>> = exceptions
        .iter()
        .map(|e| {
            vec![
                e.severity.to_string(),
                e.section.title().to_string(),
                e.at_ms.map(when).unwrap_or_default(),
                e.what.clone(),
            ]
        })
        .collect();
    let exception_json: Vec<Value> = exceptions
        .iter()
        .map(|e| json!({ "severity": e.severity, "section": e.section.id(), "at_ms": e.at_ms, "what": e.what }))
        .collect();
    pack.table(
        "exceptions",
        &["severity", "section", "at_utc", "what"],
        &exception_rows,
        &exception_json,
    )?;

    // Refusals and rollbacks by rule and reason.
    let grouped = |m: &BTreeMap<(String, String), usize>| -> (Vec<Vec<String>>, Vec<Value>) {
        let mut v: Vec<_> = m.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        (
            v.iter()
                .map(|((rule, reason), n)| vec![rule.clone(), reason.clone(), n.to_string()])
                .collect(),
            v.iter()
                .map(|((rule, reason), n)| json!({ "rule": rule, "reason": reason, "count": n }))
                .collect(),
        )
    };
    let (refusal_rows, refusal_json) = grouped(&refusals);
    pack.table(
        "refusals",
        &["rule", "reason", "count"],
        &refusal_rows,
        &refusal_json,
    )?;
    let (rollback_rows, rollback_json) = grouped(&rollbacks);
    pack.table(
        "rollbacks",
        &["rule", "reason", "count"],
        &rollback_rows,
        &rollback_json,
    )?;

    // Which controls each section gives evidence for.
    let control_rows: Vec<Vec<String>> = Section::ALL
        .iter()
        .flat_map(|s| controls_for(*s, &opts.frameworks))
        .map(|c| {
            vec![
                c.framework.name().to_string(),
                c.id.to_string(),
                c.title.to_string(),
                c.section.title().to_string(),
            ]
        })
        .collect();
    let control_json: Vec<Value> = Section::ALL
        .iter()
        .flat_map(|s| controls_for(*s, &opts.frameworks))
        .map(|c| json!({ "framework": c.framework.key(), "control": c.id, "title": c.title, "section": c.section.id() }))
        .collect();
    pack.table(
        "controls",
        &["framework", "control", "title", "section"],
        &control_rows,
        &control_json,
    )?;

    // Scope.
    let config_text = std::fs::read_to_string(config_path).unwrap_or_default();
    let config_sha = history::sha256_hex(history::mask(&config_text).as_bytes());
    let mut engines: BTreeSet<String> = agents
        .values()
        .flat_map(|a| a.engines.iter().cloned())
        .collect();
    if !config.proxy.listen.is_empty() {
        engines.insert("postgres".into());
    }
    if !config.mysql.listen.is_empty() {
        engines.insert("mysql".into());
    }
    if !config.clickhouse.http_listen.is_empty() || !config.clickhouse.native_listen.is_empty() {
        engines.insert("clickhouse".into());
    }
    let mut agent_names: BTreeSet<String> = config.agents.iter().map(|a| a.name.clone()).collect();
    agent_names.extend(agents.keys().cloned());
    let approvals_decided = by_kind.values().sum::<usize>();
    person_waits.sort();
    let wait_stat = |p: f64| -> Option<i64> {
        (!person_waits.is_empty())
            .then(|| person_waits[((person_waits.len() - 1) as f64 * p).round() as usize])
    };
    let summary = json!({
        "generator": format!("ariodb {}", env!("CARGO_PKG_VERSION")),
        "generated_ms": crate::store::now_ms(),
        "period": { "from_ms": from, "to_ms": to, "from": when(from), "to": when(to) },
        "frameworks": opts.frameworks.iter().map(|f| f.key()).collect::<Vec<_>>(),
        "config": { "path": config_path.display().to_string(), "sha256_masked": config_sha },
        "scope": {
            "agents": agent_names,
            "engines": engines,
            "databases": databases.iter().map(|(e, d)| json!({ "engine": e, "database": d })).collect::<Vec<_>>(),
        },
        "decisions": { "total": integrity.checked, "by_outcome": outcomes },
        "integrity": {
            "intact": integrity.breaks.is_empty(),
            "checked": integrity.checked,
            "first_id": integrity.first_id,
            "last_id": integrity.last_id,
            "anchor_id": integrity.anchor,
            "follower_id": integrity.follower,
            "breaks": integrity.breaks.iter().map(|b| json!({ "id": b.id, "at_ms": b.at_ms, "what": b.what })).collect::<Vec<_>>(),
            "gaps": integrity.gaps.iter().map(|(a, b)| json!([a, b])).collect::<Vec<_>>(),
            "retention_days": retention,
            "oldest_kept_ms": integrity.oldest_kept.map(|o| o.1),
        },
        "approvals": {
            "total": approvals.len(),
            "by_result": by_result,
            "decided_by_kind": by_kind,
            "person_wait_ms": { "median": wait_stat(0.5), "p90": wait_stat(0.9), "max": person_waits.last() },
        },
        "changes": {
            "transactions": records.len(),
            "agent_sessions": sessions.len(),
            "undos": undos.len(),
            "rolled_back": outcomes.get("rolled_back").copied().unwrap_or(0),
            "others_transactions": others[0],
        },
        "policy": { "versions_in_period": changes.len(), "baseline_id": baseline.map(|b| b.id) },
        "exceptions": { "total": exceptions.len() },
    });
    let text = serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?;
    pack.write("summary.json", format!("{text}\n").as_bytes())?;

    // The HTML report.
    let mut html = String::new();
    let section_head = |out: &mut String, s: Section, n: usize| {
        let _ = write!(
            out,
            "<section id=\"{}\"><h2><span class=\"num\">{n}</span> {}</h2>",
            s.id(),
            h(s.title())
        );
        let list = controls_for(s, &opts.frameworks);
        if !list.is_empty() {
            out.push_str("<div class=\"evidence\"><span class=\"label\">Evidence for</span><ul>");
            for c in list {
                let _ = write!(
                    out,
                    "<li><b>{}</b> {} <span class=\"muted\">{}</span></li>",
                    h(c.framework.name()),
                    h(c.id),
                    h(c.title)
                );
            }
            out.push_str("</ul></div>");
        }
    };
    let table = |out: &mut String, header: &[&str], rows: &[Vec<String>], file: &str| {
        if rows.is_empty() {
            out.push_str("<p class=\"none\">None in this period.</p>");
            return;
        }
        out.push_str("<table><thead><tr>");
        for c in header {
            let _ = write!(out, "<th>{}</th>", h(c));
        }
        out.push_str("</tr></thead><tbody>");
        for r in rows.iter().take(MAX_ROWS) {
            out.push_str("<tr>");
            for c in r {
                let _ = write!(out, "<td>{}</td>", h(c));
            }
            out.push_str("</tr>");
        }
        out.push_str("</tbody></table>");
        if rows.len() > MAX_ROWS {
            let _ = write!(
                out,
                "<p class=\"muted\">Showing {MAX_ROWS} of {} rows; all of them are in <code>{}</code>.</p>",
                rows.len(),
                h(file)
            );
        }
    };
    let frameworks_text = opts
        .frameworks
        .iter()
        .map(|f| f.name())
        .collect::<Vec<_>>()
        .join(", ");
    let _ = write!(
        html,
        "<!doctype html><html lang=\"en-GB\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>ariodb compliance report</title><style>{STYLE}</style></head><body>"
    );
    let _ = write!(
        html,
        "<header><p class=\"kicker\">ariodb compliance report</p><h1>{} to {}</h1><p class=\"muted\">Frameworks: {}. Generated {} by ariodb {}.</p><p class=\"disclaimer\">{}</p></header>",
        h(&when(from)),
        h(&when(to)),
        h(&frameworks_text),
        h(&when(crate::store::now_ms())),
        h(env!("CARGO_PKG_VERSION")),
        h(DISCLAIMER)
    );
    html.push_str("<nav><ol>");
    for s in Section::ALL {
        let _ = write!(
            html,
            "<li><a href=\"#{}\">{}</a></li>",
            s.id(),
            h(s.title())
        );
    }
    html.push_str("<li><a href=\"#controls\">Control mappings</a></li><li><a href=\"#verify\">Checking this pack</a></li></ol></nav>");

    // 1. Scope.
    section_head(&mut html, Section::Scope, 1);
    let scope_rows: Vec<(&str, String)> = vec![
        (
            "Period",
            format!("{} to {} (the end is exclusive)", when(from), when(to)),
        ),
        ("ariodb version", env!("CARGO_PKG_VERSION").to_string()),
        (
            "Config file",
            format!(
                "{} (SHA-256 of the masked text: {config_sha})",
                config_path.display()
            ),
        ),
        ("State directory", config.journal.dir.clone()),
        (
            "Agents",
            agent_names.iter().cloned().collect::<Vec<_>>().join(", "),
        ),
        (
            "Engines",
            engines.iter().cloned().collect::<Vec<_>>().join(", "),
        ),
        (
            "Databases used",
            databases
                .iter()
                .map(|(e, d)| format!("{e}: {}", if d.is_empty() { "(default)" } else { d }))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        ("Statements decided", integrity.checked.to_string()),
        ("Approval requests", approvals.len().to_string()),
        ("Journalled transactions", records.len().to_string()),
        (
            "Statements as logged",
            if redact {
                "with literal values replaced by placeholders ([audit] redact_literals)".into()
            } else {
                "with their literal values".to_string()
            },
        ),
    ];
    html.push_str("<table class=\"kv\"><tbody>");
    for (k, v) in &scope_rows {
        let _ = write!(html, "<tr><th>{}</th><td>{}</td></tr>", h(k), h(v));
    }
    html.push_str("</tbody></table></section>");

    // 2. Integrity.
    section_head(&mut html, Section::Integrity, 2);
    let verdict = if integrity.breaks.is_empty() {
        format!(
            "<p class=\"ok\"><b>Intact.</b> All {} entries in the period were recomputed from their contents and each links to the one before it.</p>",
            integrity.checked
        )
    } else {
        format!(
            "<p class=\"bad\"><b>Broken in {} place(s).</b> The entries below were changed or removed after they were written.</p>",
            integrity.breaks.len()
        )
    };
    html.push_str(&verdict);
    let mut notes: Vec<String> = Vec::new();
    match (integrity.first_id, integrity.last_id) {
        (Some(f), Some(l)) => notes.push(format!("The period holds entries {f} to {l}.")),
        _ => notes.push("No entries were written in the period.".to_string()),
    }
    match integrity.anchor {
        Some(a) => notes.push(format!(
            "Its first entry was checked against entry {a}, the last one before the period."
        )),
        None => notes.push(
            "No entry before the period is kept, so the first entry's link backwards cannot be checked."
                .to_string(),
        ),
    }
    match integrity.follower {
        Some(f) => notes.push(format!(
            "Entry {f}, the first after the period, links back to it, so no entry was removed from its end."
        )),
        None => notes.push(
            "No entry follows the period yet, so removal of its last entries would only show once a newer entry is written."
                .to_string(),
        ),
    }
    if retention == 0 {
        notes.push(
            "Retention: [audit] retention_days is 0, so entries are kept indefinitely.".into(),
        );
    } else {
        notes.push(format!(
            "Retention: [audit] retention_days is {retention}; entries older than that are pruned hourly, and the chain is then checked from the oldest entry kept."
        ));
    }
    if let Some((id, at)) = integrity.oldest_kept {
        notes.push(format!(
            "The oldest entry kept is {id}, written {}.",
            when(at)
        ));
        if at > from {
            notes.push(format!(
                "The period starts before that, so entries from before {} are not in this report.",
                when(at)
            ));
        }
    }
    notes.push("The chain is a SHA-256 hash chain without a key: it shows edits and removals, but someone able to rewrite the whole file could rebuild it. Keep a copy elsewhere (for example through an audit-sink plugin) for stronger assurance.".to_string());
    html.push_str("<ul>");
    for n in &notes {
        let _ = write!(html, "<li>{}</li>", h(n));
    }
    html.push_str("</ul>");
    if !integrity.breaks.is_empty() {
        let rows: Vec<Vec<String>> = integrity
            .breaks
            .iter()
            .map(|b| vec![b.id.to_string(), when(b.at_ms), b.what.clone()])
            .collect();
        table(
            &mut html,
            &["Entry", "Written", "What"],
            &rows,
            "summary.json",
        );
    }
    if !integrity.gaps.is_empty() {
        let rows: Vec<Vec<String>> = integrity
            .gaps
            .iter()
            .map(|(a, b)| vec![format!("{} to {}", a + 1, b - 1)])
            .collect();
        html.push_str("<h3>Gaps in entry ids</h3>");
        table(&mut html, &["Missing ids"], &rows, "summary.json");
    }
    html.push_str("</section>");

    // 3. Access control.
    section_head(&mut html, Section::Access, 3);
    html.push_str("<h3>What each agent may do</h3><p class=\"muted\">As the config file sets it now; changes during the period are under Policy changes.</p>");
    let access = |a: Access| match a {
        Access::ReadOnly => "read only",
        Access::ReadWrite => "read and write",
    };
    let access_rows: Vec<Vec<String>> = config
        .agents
        .iter()
        .map(|a| {
            let mut engines = vec![format!(
                "Postgres: {}, tables {}",
                access(a.access),
                a.tables.join(" ")
            )];
            if let Some(ch) = &a.clickhouse {
                engines.push(format!(
                    "ClickHouse: {}, tables {}",
                    access(ch.access),
                    ch.tables.join(" ")
                ));
            }
            if let Some(m) = &a.mysql {
                engines.push(format!(
                    "MySQL: {}, tables {}",
                    access(m.access),
                    m.tables.join(" ")
                ));
            }
            vec![
                a.name.clone(),
                engines.join("; "),
                a.credential
                    .clone()
                    .unwrap_or_else(|| "gateway login".into()),
                a.max_rows_per_write
                    .unwrap_or(config.limits.max_rows_per_write)
                    .to_string(),
            ]
        })
        .collect();
    table(
        &mut html,
        &[
            "Agent",
            "Access and tables",
            "Database login",
            "Row limit per write",
        ],
        &access_rows,
        "summary.json",
    );
    html.push_str("<h3>What each agent did</h3>");
    let activity_rows: Vec<Vec<String>> = agents
        .iter()
        .map(|(name, a)| {
            let n = |o: &str| a.outcomes.get(o).copied().unwrap_or(0).to_string();
            vec![
                name.clone(),
                a.outcomes.values().sum::<usize>().to_string(),
                n("allowed"),
                n("refused"),
                n("rolled_back"),
                n("failed"),
                a.writes.to_string(),
                a.rows.to_string(),
                a.tables.iter().cloned().collect::<Vec<_>>().join(" "),
                a.engines.iter().cloned().collect::<Vec<_>>().join(" "),
            ]
        })
        .collect();
    table(
        &mut html,
        &[
            "Agent",
            "Statements",
            "Allowed",
            "Refused",
            "Rolled back",
            "Failed",
            "Writes",
            "Rows written",
            "Tables used",
            "Engines",
        ],
        &activity_rows,
        "decisions.csv",
    );
    html.push_str("<h3>Refusals by rule and reason</h3><p class=\"muted\">\"policy\" is ariodb's built-in policy; other names are rules from the config.</p>");
    table(
        &mut html,
        &["Rule", "Reason", "Count"],
        &refusal_rows,
        "refusals.csv",
    );
    html.push_str("</section>");

    // 4. Human oversight.
    section_head(&mut html, Section::Oversight, 4);
    let kinds = |k: &str| by_kind.get(k).copied().unwrap_or(0);
    let results = |k: &str| by_result.get(k).copied().unwrap_or(0);
    let _ = write!(
        html,
        "<div class=\"tiles\"><div><b>{}</b>approval requests</div><div><b>{}</b>decided by people</div><div><b>{}</b>by models</div><div><b>{}</b>by plugins</div><div><b>{}</b>timed out</div><div><b>{}</b>withdrawn</div></div>",
        approvals.len(),
        kinds("person"),
        kinds("model"),
        kinds("plugin"),
        results("timed out"),
        results("withdrawn")
    );
    let mut oversight_notes = vec![format!(
        "{} requests were decided ({} allowed, {} denied); {} could not be delivered and were refused; {} were still pending when this report was made.",
        approvals_decided,
        results("allowed"),
        results("denied"),
        results("not delivered"),
        results("pending")
    )];
    if let (Some(m), Some(p), Some(x)) = (wait_stat(0.5), wait_stat(0.9), person_waits.last()) {
        oversight_notes.push(format!(
            "People took {} to decide at the median, {} at the 90th percentile and {} at most.",
            duration(m),
            duration(p),
            duration(*x)
        ));
    }
    oversight_notes.push("Decisions by models and plugins are automated: they are recorded here so they can be told apart from people's, and are not human oversight.".to_string());
    if !failed_open.is_empty() {
        oversight_notes.push(format!(
            "{} statements were let through because a model approver was unavailable and llm_fail_mode is open.",
            failed_open.len()
        ));
    }
    html.push_str("<ul>");
    for n in &oversight_notes {
        let _ = write!(html, "<li>{}</li>", h(n));
    }
    html.push_str("</ul><h3>Who decided</h3>");
    let mut decider_rows: Vec<Vec<String>> = by_decider
        .iter()
        .map(|(by, n)| vec![by.clone(), decider_kind(by).to_string(), n.to_string()])
        .collect();
    decider_rows.sort_by(|a, b| {
        b[2].parse::<usize>()
            .unwrap_or(0)
            .cmp(&a[2].parse::<usize>().unwrap_or(0))
    });
    table(
        &mut html,
        &["Decider", "Kind", "Requests decided"],
        &decider_rows,
        "approvals.csv",
    );
    html.push_str("<h3>Every request</h3>");
    let approval_view: Vec<Vec<String>> = approvals
        .iter()
        .map(|a| {
            vec![
                a.id.clone(),
                when(a.created_ms),
                a.agent.clone(),
                a.rule.clone(),
                a.approver.clone(),
                approval_result(a).to_string(),
                a.decided_by.clone().unwrap_or_default(),
                a.decided_ms
                    .map(|d| duration(d - a.created_ms))
                    .unwrap_or_default(),
                crate::channels::shown_sql(&crate::audit::stored_sql(&a.sql, redact), 300).0,
            ]
        })
        .collect();
    table(
        &mut html,
        &[
            "Request",
            "Asked",
            "Agent",
            "Rule",
            "Approver",
            "Result",
            "Decided by",
            "Time to decide",
            "Statement",
        ],
        &approval_view,
        "approvals.csv",
    );
    html.push_str("</section>");

    // 5. Change control.
    section_head(&mut html, Section::Change, 5);
    let total_writes: usize = agents.values().map(|a| a.writes).sum();
    let total_rows: i64 = agents.values().map(|a| a.rows).sum();
    let rolled = outcomes.get("rolled_back").copied().unwrap_or(0);
    let _ = write!(
        html,
        "<div class=\"tiles\"><div><b>{total_writes}</b>writes committed</div><div><b>{total_rows}</b>rows they changed</div><div><b>{rolled}</b>writes rolled back</div><div><b>{}</b>sessions journalled</div><div><b>{}</b>undos</div></div>",
        sessions.len(),
        undos.len()
    );
    let _ = write!(
        html,
        "<p>Rows counted here are measured inside each write's transaction before it commits. The journals recorded {} transactions in the period: {} from agent sessions, {} undos, and {} by others (people and applications outside ariodb), which undo treats as conflicts rather than overwriting.</p>",
        records.len(),
        sessions.values().map(|s| s.transactions).sum::<usize>(),
        undo_transactions,
        others[0]
    );
    html.push_str("<h3>Writes rolled back</h3>");
    table(
        &mut html,
        &["Rule", "Reason", "Count"],
        &rollback_rows,
        "rollbacks.csv",
    );
    html.push_str("<h3>What agent sessions changed</h3>");
    let session_rows: Vec<Vec<String>> = sessions
        .iter()
        .map(|(id, s)| {
            vec![
                id.clone(),
                s.agent.clone(),
                s.engine.to_string(),
                s.transactions.to_string(),
                s.ops[0].to_string(),
                s.ops[1].to_string(),
                s.ops[2].to_string(),
                s.tables.iter().cloned().collect::<Vec<_>>().join(" "),
                when(s.first_ms),
                when(s.last_ms),
                if undos.iter().any(|u| &u.2 == id) {
                    "yes".into()
                } else {
                    String::new()
                },
            ]
        })
        .collect();
    table(
        &mut html,
        &[
            "Session",
            "Agent",
            "Engine",
            "Transactions",
            "Inserted",
            "Updated",
            "Deleted",
            "Tables",
            "First",
            "Last",
            "Undone",
        ],
        &session_rows,
        "changes.csv",
    );
    html.push_str("<h3>Undo</h3>");
    table(
        &mut html,
        &["Undone", "Engine", "Session", "Agent", "Rows", "By"],
        &undo_rows,
        "undos.csv",
    );
    html.push_str("</section>");

    // 6. Policy changes.
    section_head(&mut html, Section::Policy, 6);
    html.push_str("<p class=\"muted\">ariodb records the config file when it starts and each time it reloads it, with every password, token and secret replaced by <code>***</code>. The full text of each version is in <code>config_versions.json</code>.</p>");
    match baseline {
        Some(b) => {
            let _ = write!(
                html,
                "<p>In force when the period began: version {} recorded {} ({}), SHA-256 <code>{}</code>.</p>",
                b.id,
                h(&when(b.at_ms)),
                h(&b.source),
                h(&b.sha256)
            );
        }
        None if versions_all.is_empty() => html.push_str("<p>No config versions are recorded yet: the history starts when ariodb first starts with config history (or after the versions were pruned).</p>"),
        None => html.push_str("<p>No version is recorded from before the period; the first version below is the earliest kept.</p>"),
    }
    if changes.is_empty() {
        html.push_str("<p class=\"none\">The config did not change in this period.</p>");
    }
    let mut previous = baseline;
    for v in &changes {
        let _ = write!(
            html,
            "<div class=\"change\"><h3>Version {} at {}</h3><p class=\"muted\">Source: {}. SHA-256 <code>{}</code>{}</p>",
            v.id,
            h(&when(v.at_ms)),
            h(&v.source),
            h(&v.sha256),
            if v.intact {
                ""
            } else {
                " <b class=\"bad\">(changed after it was recorded)</b>"
            }
        );
        match previous {
            Some(p) => html.push_str(&diff_html(&diff_lines(&p.text, &v.text))),
            None => {
                let _ = write!(html, "<pre class=\"diff\">{}</pre>", h(&v.text));
            }
        }
        html.push_str("</div>");
        previous = Some(v);
    }
    html.push_str("</section>");

    // 7. Exceptions.
    section_head(&mut html, Section::Exceptions, 7);
    if exceptions.is_empty() {
        html.push_str("<p class=\"ok\">Nothing to follow up: no chain breaks, unexpected deciders, or spikes in refusals or rollbacks.</p>");
    } else {
        let _ = write!(
            html,
            "<p>{} item(s) to follow up, most serious first.</p>",
            exceptions.len()
        );
    }
    html.push_str("<p class=\"muted\">Checked: breaks in the decisions log, the config history and the undo records; approvals decided by someone the approver's definition does not allow; decisions through signed links without a signed-in person; statements let through by a model that failed open; days with at least ")
        ;
    let _ = write!(
        html,
        "{SPIKE_MIN} refusals or rollbacks and {SPIKE_FACTOR} times the period's median day.</p>"
    );
    let exception_view: Vec<Vec<String>> = exceptions
        .iter()
        .map(|e| {
            vec![
                e.severity.to_string(),
                e.section.title().to_string(),
                e.at_ms.map(when).unwrap_or_default(),
                e.what.clone(),
            ]
        })
        .collect();
    if !exceptions.is_empty() {
        table(
            &mut html,
            &["Severity", "Section", "When", "What"],
            &exception_view,
            "exceptions.csv",
        );
    }
    html.push_str("</section>");

    // Mappings and verification.
    html.push_str("<section id=\"controls\"><h2>Control mappings</h2>");
    let _ = write!(html, "<p class=\"disclaimer\">{}</p><ul>", h(DISCLAIMER));
    for f in &opts.frameworks {
        let _ = write!(html, "<li><b>{}</b>: {}.</li>", h(f.name()), h(f.source()));
    }
    html.push_str("</ul>");
    table(
        &mut html,
        &["Framework", "Control", "Summary", "Section"],
        &control_rows,
        "controls.csv",
    );
    html.push_str("</section>");
    html.push_str("<section id=\"verify\"><h2>Checking this pack</h2><p><code>manifest.sha256</code> lists every other file in the pack with its SHA-256. Record the manifest's own hash, which <code>ariodb report</code> printed, when you receive the pack. To check later that nothing was changed, confirm the manifest still has that hash, then check every file against it:</p><pre>sha256sum manifest.sha256\nsha256sum -c manifest.sha256</pre><p>(On macOS: <code>shasum -a 256</code> in place of <code>sha256sum</code>.) The CSV files guard cells that a spreadsheet would run as formulas with a leading <code>'</code>; the JSON files hold the exact values.</p></section>");
    html.push_str("</body></html>\n");
    pack.write("report.html", html.as_bytes())?;

    let manifest = pack.manifest()?;
    Ok(Summary {
        files: pack.files.len(),
        manifest_sha256: manifest,
        decisions: integrity.checked,
        breaks: integrity.breaks,
        exceptions: exceptions.len(),
    })
}

/// `ariodb report`.
pub fn command(
    config: &Config,
    config_path: &Path,
    from: &str,
    to: &str,
    framework: &str,
    out: &Path,
) -> Result<(), String> {
    let opts = Options {
        from_ms: parse_time(from, false)?,
        to_ms: parse_time(to, true)?,
        frameworks: Framework::parse(framework)?,
        out: out.to_path_buf(),
    };
    let s = build(config, config_path, &opts)?;
    println!("wrote {} files to {}", s.files, out.display());
    if s.breaks.is_empty() {
        println!(
            "decisions log: {} entries in the period, chain intact",
            s.decisions
        );
    } else {
        for b in &s.breaks {
            eprintln!("warning: decisions log chain broken: {}", b.what);
        }
        println!(
            "decisions log: {} entries in the period, chain broken in {} place(s)",
            s.decisions,
            s.breaks.len()
        );
    }
    println!("exceptions to follow up: {}", s.exceptions);
    println!("manifest.sha256: {}", s.manifest_sha256);
    Ok(())
}

const STYLE: &str = r#"
:root{--ink:#1b1f24;--muted:#5b6470;--rule:#d7dbe0;--band:#f4f6f8;--accent:#1f4e79;--ok:#256b35;--bad:#a1262c;--warn:#8a5a00}
*{box-sizing:border-box}
html{background:#fff}
body{margin:0 auto;max-width:1040px;padding:32px 24px 64px;color:var(--ink);background:#fff;font:10.5pt/1.5 -apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}
header{border-bottom:2px solid var(--accent);padding-bottom:12px;margin-bottom:16px}
.kicker{margin:0;color:var(--accent);font-weight:600;letter-spacing:.04em;text-transform:uppercase;font-size:9pt}
h1{margin:4px 0 6px;font-size:20pt;line-height:1.2}
h2{font-size:14pt;margin:0 0 10px;color:var(--accent);border-bottom:1px solid var(--rule);padding-bottom:4px}
h2 .num{display:inline-block;min-width:1.4em;color:var(--muted)}
h3{font-size:11pt;margin:18px 0 6px}
section{margin:28px 0}
nav ol{columns:2;margin:0;padding-left:20px}
nav a{color:var(--accent);text-decoration:none}
.muted{color:var(--muted)}
.disclaimer{background:var(--band);border-left:3px solid var(--warn);padding:8px 12px;font-size:9.5pt}
.evidence{background:var(--band);padding:8px 12px;margin:0 0 12px;font-size:9.5pt}
.evidence .label{font-weight:600;color:var(--muted);text-transform:uppercase;font-size:8pt;letter-spacing:.04em}
.evidence ul{margin:4px 0 0;padding-left:18px}
.ok{color:var(--ok)}
.bad{color:var(--bad)}
.none{color:var(--muted);font-style:italic}
table{border-collapse:collapse;width:100%;margin:6px 0 10px;font-size:9pt}
th,td{text-align:left;vertical-align:top;padding:4px 6px;border-bottom:1px solid var(--rule);overflow-wrap:anywhere}
thead th{background:var(--band);font-weight:600}
table.kv th{width:28%;background:none;color:var(--muted);font-weight:600}
thead{display:table-header-group}
tr{break-inside:avoid;page-break-inside:avoid}
code,pre{font:8.5pt/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--band);padding:8px 10px;margin:6px 0}
.diff .add{color:var(--ok);background:#e6f4ea;display:block}
.diff .del{color:var(--bad);background:#fbe9ea;display:block}
.diff .same{display:block}
.diff .skip{display:block;color:var(--muted)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;margin:8px 0 12px}
.tiles div{border:1px solid var(--rule);padding:8px 10px;font-size:9pt;color:var(--muted)}
.tiles b{display:block;font-size:15pt;color:var(--ink)}
@page{size:A4;margin:16mm 14mm}
@media print{body{max-width:none;padding:0}nav{display:none}section{break-before:page;page-break-before:always;margin:0}h2,h3{break-after:avoid;page-break-after:avoid}.change{break-inside:avoid-page}}
@media (max-width:640px){body{padding:16px}nav ol{columns:1}table{font-size:8.5pt}}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn state_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ariodb-report-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn config_text(dir: &Path) -> String {
        format!(
            r#"[database]
url = "postgres://gw:db-pw-not-real@127.0.0.1:5432/app"

[proxy]
listen = "127.0.0.1:6543"

[journal]
enabled = false
dir = "{}"

[[agents]]
name = "coding-agent"
access = "read_write"
tables = ["orders"]
token_env = "NOT_SET_IN_TESTS"

[[approvers]]
name = "ops"
type = "dashboard"
"#,
            dir.join("state").display()
        )
    }

    fn entry<'a>(agent: &'a str, sql: &'a str, outcome: &'a str) -> crate::audit::Entry<'a> {
        crate::audit::Entry {
            session: "s-1",
            agent,
            sql,
            kind: "read".into(),
            tables: &[],
            outcome,
            rows: Some(1),
            reason: None,
            rule: None,
            latency_ms: Some(1),
            engine: "postgres",
            database: "app",
            decided_by: &[],
        }
    }

    fn whole_day() -> (i64, i64) {
        let now = crate::store::now_ms();
        (now - 86_400_000, now + 86_400_000)
    }

    fn read(dir: &Path, name: &str) -> String {
        std::fs::read_to_string(dir.join(name)).unwrap()
    }

    fn summary(dir: &Path) -> Value {
        serde_json::from_str(&read(dir, "summary.json")).unwrap()
    }

    #[test]
    fn dates_and_instants() {
        assert_eq!(parse_time("1970-01-01", false), Ok(0));
        assert_eq!(parse_time("1970-01-01", true), Ok(86_400_000));
        assert_eq!(
            parse_time("2026-10-11", false).map(when),
            Ok("2026-10-11 00:00:00 UTC".into())
        );
        assert_eq!(
            parse_time("2024-02-29T13:05:09Z", false).map(when),
            Ok("2024-02-29 13:05:09 UTC".into())
        );
        assert_eq!(
            parse_time("2026-10-11T08:30Z", true).map(when),
            Ok("2026-10-11 08:30:00 UTC".into())
        );
        for bad in [
            "2026-02-29",
            "2026-13-01",
            "26-10-11",
            "2026-10-11T25:00Z",
            "2026-10-11T10:00",
            "yesterday",
        ] {
            assert!(parse_time(bad, false).is_err(), "{bad}");
        }
        assert_eq!(Framework::parse("all").unwrap().len(), 4);
        assert!(Framework::parse("pci").is_err());
    }

    #[test]
    fn every_section_but_scope_maps_to_controls_in_every_framework_it_should() {
        for f in Framework::ALL {
            assert!(controls_for(Section::Scope, &[f]).is_empty());
            for s in [
                Section::Integrity,
                Section::Oversight,
                Section::Change,
                Section::Exceptions,
            ] {
                assert!(!controls_for(s, &[f]).is_empty(), "{f:?} {s:?}");
            }
        }
        // The EU AI Act says nothing about database access rights or config changes.
        assert!(controls_for(Section::Access, &[Framework::EuAiAct]).is_empty());
        assert!(controls_for(Section::Policy, &[Framework::EuAiAct]).is_empty());
        let ids = |f| {
            CONTROLS
                .iter()
                .filter(|c| c.framework == f)
                .map(|c| c.id)
                .collect::<Vec<_>>()
        };
        let dora = ids(Framework::Dora);
        assert!(
            dora.contains(&"DORA Art. 9(4)(e)") && dora.contains(&"RTS 2024/1774 Art. 12(2)(d)")
        );
        assert!(
            dora.iter()
                .all(|i| i.starts_with("DORA Art. ") || i.starts_with("RTS 2024/1774 Art. "))
        );
        assert!(
            ids(Framework::Soc2)
                .iter()
                .all(|i| ["CC6.", "CC7.", "CC8."].iter().any(|p| i.starts_with(p)))
        );
        let iso = ids(Framework::Iso27001);
        for want in ["A.5.15", "A.8.15", "A.8.16", "A.8.32"] {
            assert!(iso.contains(&want), "{want}");
        }
        assert!(ids(Framework::EuAiAct).iter().all(|i| {
            ["Art. 12", "Art. 14", "Art. 19", "Art. 26"]
                .iter()
                .any(|p| i.starts_with(p))
        }));
        // No control is listed twice for one section.
        for (i, a) in CONTROLS.iter().enumerate() {
            for b in &CONTROLS[i + 1..] {
                assert!(
                    !(a.framework == b.framework && a.section == b.section && a.id == b.id),
                    "{}",
                    a.id
                );
            }
        }
    }

    #[test]
    fn spikes_stand_out_from_the_median() {
        let days: Vec<(i64, usize)> = (0..10).map(|d| (d, 2)).chain([(10, 30), (11, 9)]).collect();
        assert_eq!(spikes(&days), vec![(10, 30, 2)]);
        // A quiet period: small numbers are never spikes.
        assert!(spikes(&[(0, 0), (1, 0), (2, 9)]).is_empty());
        // Busy every day: nothing stands out.
        assert!(spikes(&[(0, 50), (1, 60), (2, 55)]).is_empty());
        assert!(spikes(&[]).is_empty());
    }

    #[test]
    fn diffs_show_what_changed() {
        let a = "a\nb\nc\nd\n";
        let b = "a\nB\nc\nd\ne\n";
        let d = diff_lines(a, b);
        let kinds: String = d.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds, " -+  +");
        assert_eq!(d[2].1, "B");
        assert_eq!(d[5].1, "e");
        let html = diff_html(&diff_lines("x = \"<b>\"\n", "x = \"<i>\"\n"));
        assert!(
            html.contains("- x = &quot;&lt;b&gt;&quot;")
                && html.contains("+ x = &quot;&lt;i&gt;&quot;")
        );
    }

    #[test]
    fn csv_cells_are_quoted_and_formulas_defused() {
        assert_eq!(csv_field("plain"), "plain");
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\"\n"), "\"say \"\"hi\"\"\n\"");
        assert_eq!(csv_field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_field("-- comment"), "'-- comment");
    }

    #[test]
    fn deciders_the_approver_does_not_allow_are_flagged() {
        let config = Config::from_toml(
            "[database]\nurl = \"postgres://localhost/app\"\n\n[[approvers]]\nname = \"ops\"\ntype = \"dashboard\"\n\n[[approvers]]\nname = \"dba\"\ntype = \"dashboard\"\ngroups = [\"dba\"]\n\n[dashboard.oidc]\nissuer = \"https://id.example.test\"\nclient_id = \"ariodb\"\napprover_groups = [\"dba\"]\n\n[[approvers]]\nname = \"judge\"\ntype = \"llm\"\napi_key_env = \"K\"\npolicy = \"Allow reads.\"\n\n[[approvers]]\nname = \"hook\"\ntype = \"webhook\"\nurl = \"https://hooks.example.test/x\"\nhmac_secret_env = \"H\"\n",
        )
        .unwrap();
        let def = |n: &str| config.approvers.iter().find(|a| a.name == n);
        assert_eq!(
            unexpected_decider(def("ops"), "ops", "dashboard:root"),
            None
        );
        assert_eq!(unexpected_decider(def("ops"), "ops", "cli:pat"), None);
        assert_eq!(unexpected_decider(def("ops"), "ops", "ariodb"), None);
        assert!(unexpected_decider(def("ops"), "ops", "model:openai/gpt").is_some());
        assert!(unexpected_decider(def("ops"), "ops", "webhook").is_some());
        assert_eq!(
            unexpected_decider(def("judge"), "judge", "model:anthropic/x"),
            None
        );
        assert!(unexpected_decider(def("judge"), "judge", "dashboard:root").is_some());
        assert_eq!(unexpected_decider(def("hook"), "hook", "webhook"), None);
        assert_eq!(
            unexpected_decider(def("dba"), "dba", "sso:pat@example.test"),
            None
        );
        assert!(unexpected_decider(def("dba"), "dba", "dashboard:root").is_some());
        assert!(
            unexpected_decider(def("dba"), "dba", "cli:pat")
                .unwrap()
                .contains("does not check groups")
        );
        assert!(unexpected_decider(None, "gone", "dashboard:root").is_some());
        assert_eq!(decider_kind("sso:pat@example.test"), "person");
        assert_eq!(decider_kind("ariodb:failed-open:model:x"), "ariodb");
    }

    #[test]
    fn a_pack_verifies_and_reports_a_tampered_period() {
        let root = state_dir("pack");
        let file = root.join("ariodb.toml");
        std::fs::write(&file, config_text(&root)).unwrap();
        let config = Config::load(&file).unwrap();
        let dir = PathBuf::from(&config.journal.dir);
        let log = crate::audit::AuditLog::open(&dir, &config.audit).unwrap();
        let hostile = "<script>alert('agent')</script>";
        for (sql, outcome) in [
            ("SELECT 1", "allowed"),
            ("SELECT '<img src=x onerror=alert(1)>'", "allowed"),
            ("DROP TABLE orders", "refused"),
            ("SELECT 4", "allowed"),
            ("SELECT 5", "allowed"),
        ] {
            log.record(&entry(hostile, sql, outcome));
        }
        history::record_config(&dir, &file, "startup");
        std::fs::write(
            &file,
            config_text(&root).replace("[\"orders\"]", "[\"orders\", \"customers\"]"),
        )
        .unwrap();
        history::record_config(&dir, &file, "reload");
        let db = crate::store::Db::open(&dir).unwrap();
        let now = crate::store::now_ms();
        db.insert_approval(&crate::store::Approval {
            id: "a-<b>1</b>".into(),
            created_ms: now,
            expires_ms: now + 1000,
            agent: hostile.into(),
            session: "s-1".into(),
            sql: "UPDATE orders SET note = '</td><script>x</script>'".into(),
            rule: "ask".into(),
            approver: "ops".into(),
            reason: "r".into(),
            status: "allowed".into(),
            decided_by: Some("model:openai/not-a-person".into()),
            note: None,
            decided_ms: Some(now + 1500),
        })
        .unwrap();

        let (from, to) = whole_day();
        let build_into = |name: &str, frameworks: Vec<Framework>| {
            let out = root.join(name);
            let s = build(
                &config,
                &file,
                &Options {
                    from_ms: from,
                    to_ms: to,
                    frameworks,
                    out: out.clone(),
                },
            )
            .unwrap();
            (out, s)
        };
        let (out, s) = build_into("clean", Framework::ALL.to_vec());
        assert!(s.breaks.is_empty());
        assert_eq!(s.decisions, 5);
        let sum = summary(&out);
        assert_eq!(sum["decisions"]["by_outcome"]["refused"], 1);
        assert_eq!(sum["integrity"]["intact"], true);
        assert_eq!(sum["policy"]["versions_in_period"], 2);

        // The manifest lists every other file with its hash, and the hash
        // printed is the manifest's own.
        let manifest = read(&out, "manifest.sha256");
        assert_eq!(history::sha256_hex(manifest.as_bytes()), s.manifest_sha256);
        let mut listed = Vec::new();
        for line in manifest.lines() {
            let (hash, name) = line.split_once("  ").unwrap();
            assert_eq!(
                hash,
                history::sha256_hex(&std::fs::read(out.join(name)).unwrap()),
                "{name}"
            );
            listed.push(name.to_string());
        }
        let mut present: Vec<String> = std::fs::read_dir(&out)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != "manifest.sha256")
            .collect();
        present.sort();
        assert_eq!(listed, present);
        assert_eq!(s.files, present.len() + 1, "and the manifest");

        // Everything from SQL, names and config is escaped, and secrets are masked.
        let html = read(&out, "report.html");
        assert!(!html.contains("<script>") && !html.contains("<img") && !html.contains("a-<b>"));
        assert!(html.contains("&lt;script&gt;alert(&#39;agent&#39;)&lt;/script&gt;"));
        assert!(!html.contains("<script"), "no scripts at all");
        assert!(html.contains("a-&lt;b&gt;1&lt;/b&gt;"));
        for name in &present {
            assert!(!read(&out, name).contains("db-pw-not-real"), "{name}");
        }
        assert!(html.contains("postgres://gw:***@127.0.0.1:5432/app"));
        assert!(html.contains("+ tables = [&quot;orders&quot;, &quot;customers&quot;]"));
        // A model deciding for a people approver is an exception.
        let exceptions = read(&out, "exceptions.json");
        assert!(
            exceptions.contains("is a dashboard approver, yet model:openai/not-a-person decided"),
            "{exceptions}"
        );
        for section in Section::ALL {
            assert!(
                html.contains(&format!("<section id=\"{}\">", section.id())),
                "{section:?}"
            );
        }
        assert!(html.contains(DISCLAIMER.split('.').next().unwrap()));
        // A non-empty directory is never written into.
        assert!(
            build(
                &config,
                &file,
                &Options {
                    from_ms: from,
                    to_ms: to,
                    frameworks: vec![Framework::Dora],
                    out: out.clone()
                }
            )
            .is_err()
        );

        // One framework names only its own controls.
        let (dora, _) = build_into("dora", vec![Framework::Dora]);
        let html = read(&dora, "report.html");
        assert!(
            html.contains("DORA Art. 9(4)(c)")
                && !html.contains("CC6.1")
                && !html.contains("A.8.15")
        );

        // Edit one entry and remove another: both show, with their ids.
        let conn = Connection::open(dir.join("ariodb.db")).unwrap();
        conn.execute("UPDATE decisions SET sql = 'SELECT 42' WHERE id = 2", [])
            .unwrap();
        conn.execute("DELETE FROM decisions WHERE id = 4", [])
            .unwrap();
        let (tampered, s) = build_into("tampered", Framework::ALL.to_vec());
        let what: Vec<&str> = s.breaks.iter().map(|b| b.what.as_str()).collect();
        assert_eq!(
            what,
            vec![
                "entry 2 was changed after it was written",
                "entries 4 to 4 were removed"
            ]
        );
        assert_eq!(summary(&tampered)["integrity"]["intact"], false);
        assert!(read(&tampered, "report.html").contains("Broken in 2 place(s)"));

        // A period after the last entry still checks nothing was removed
        // from its end: with nothing after it, it says so.
        let (later, s) = {
            let out = root.join("later");
            let s = build(
                &config,
                &file,
                &Options {
                    from_ms: to,
                    to_ms: to + 86_400_000,
                    frameworks: vec![Framework::Soc2],
                    out: out.clone(),
                },
            )
            .unwrap();
            (out, s)
        };
        assert_eq!(s.decisions, 0);
        assert!(read(&later, "report.html").contains("No entries were written in the period."));
        let _ = std::fs::remove_dir_all(&root);
    }
}
