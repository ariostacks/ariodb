//! The dashboard page: one self-contained HTML file, no external resources.
//! All data from agents is inserted with textContent, never as HTML.

pub const PAGE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ariodb</title>
<style>
:root {
  --bg: #f3f5f6; --panel: #ffffff; --ink: #17222b; --muted: #5b6873; --rule: #d7dee2;
  --accent: #0b6870; --accent-ink: #ffffff; --accent-soft: #dcecee;
  --ok: #1d6b3a; --ok-soft: #dff0e5; --warn: #8a5a00; --warn-soft: #f6ead2; --bad: #9a2f2f; --bad-soft: #f5e0e0;
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --sans: system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
@media (prefers-color-scheme: dark) {
  :root { --bg: #0f1518; --panel: #161e22; --ink: #e2e9ed; --muted: #95a3ac; --rule: #2a363c;
    --accent: #5fc0c7; --accent-ink: #0f1518; --accent-soft: #143338;
    --ok: #7fd19a; --ok-soft: #173123; --warn: #e3ab4d; --warn-soft: #3a2c12; --bad: #e08b8b; --bad-soft: #3a1d1d; color-scheme: dark; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 14px/1.5 var(--sans); }
button, input, select, textarea { font: inherit; color: inherit; }
a { color: var(--accent); }
.app { display: grid; grid-template-columns: 210px minmax(0, 1fr); min-height: 100vh; }
nav { background: var(--panel); border-right: 1px solid var(--rule); padding: 18px 12px; display: flex; flex-direction: column; gap: 2px; position: sticky; top: 0; height: 100vh; overflow-y: auto; }
nav .brand { font: 600 17px var(--mono); padding: 4px 10px 16px; letter-spacing: -0.01em; }
nav .brand span { color: var(--accent); }
nav button { all: unset; cursor: pointer; padding: 7px 10px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center; }
nav button:hover { background: var(--bg); }
nav button[aria-current="page"] { background: var(--accent-soft); color: var(--accent); font-weight: 600; }
nav button:focus-visible { outline: 2px solid var(--accent); }
nav .spacer { flex: 1; }
nav .who { color: var(--muted); font-size: 12px; padding: 8px 10px; }
.badge { background: var(--warn); color: var(--panel); border-radius: 10px; padding: 0 7px; font-size: 12px; font-weight: 600; }
.badge[hidden] { display: none; }
main { padding: 24px 28px 48px; min-width: 0; display: grid; gap: 18px; align-content: start; }
h1 { font-size: 20px; margin: 0; }
h2 { font-size: 15px; margin: 0 0 10px; }
.sub { color: var(--muted); margin: 2px 0 0; }
.panel { background: var(--panel); border: 1px solid var(--rule); border-radius: 8px; padding: 16px; min-width: 0; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 12px; }
.tile .n { font: 600 26px var(--mono); }
.tile .l { color: var(--muted); font-size: 13px; }
.row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
input, select, textarea { background: var(--bg); border: 1px solid var(--rule); border-radius: 6px; padding: 6px 9px; }
textarea { width: 100%; font-family: var(--mono); font-size: 13px; }
.btn { border: 1px solid var(--rule); background: var(--panel); border-radius: 6px; padding: 6px 12px; cursor: pointer; }
.btn:hover { border-color: var(--accent); }
.btn.primary { background: var(--accent); color: var(--accent-ink); border-color: var(--accent); }
.btn.danger { color: var(--bad); border-color: var(--bad); }
.btn:disabled { opacity: .5; cursor: not-allowed; }
.btn:focus-visible, input:focus-visible, select:focus-visible, textarea:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.scroll { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
table.wide { min-width: 960px; }
td.stmt { min-width: 300px; }
.btn.sm { padding: 3px 8px; font-size: 12px; white-space: nowrap; }
.actions { display: flex; flex-direction: column; gap: 4px; align-items: stretch; }
th { text-align: left; font-weight: 600; color: var(--muted); font-size: 12px; padding: 6px 8px; border-bottom: 1px solid var(--rule); white-space: nowrap; }
td { padding: 7px 8px; border-bottom: 1px solid var(--rule); vertical-align: top; }
td.num { font-family: var(--mono); text-align: right; white-space: nowrap; }
td.t { white-space: nowrap; color: var(--muted); font-family: var(--mono); font-size: 12px; }
code, .sql { font-family: var(--mono); font-size: 12.5px; }
.sql { white-space: pre-wrap; word-break: break-word; background: var(--bg); border: 1px solid var(--rule); border-radius: 6px; padding: 8px 10px; margin: 6px 0; }
td .sql { margin: 0; padding: 4px 6px; max-height: 6.5em; overflow: hidden; }
.pill { display: inline-block; border-radius: 4px; padding: 1px 7px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.pill.allowed, .pill.allow { background: var(--ok-soft); color: var(--ok); }
.pill.refused, .pill.deny, .pill.denied, .pill.rolled_back { background: var(--bad-soft); color: var(--bad); }
.pill.pending, .pill.approve, .pill.expired, .pill.failed { background: var(--warn-soft); color: var(--warn); }
.card { border: 1px solid var(--rule); border-left: 4px solid var(--warn); border-radius: 8px; padding: 12px 14px; background: var(--panel); display: grid; gap: 6px; }
.meta { color: var(--muted); font-size: 12.5px; }
.msg { padding: 8px 12px; border-radius: 6px; }
.msg.ok { background: var(--ok-soft); color: var(--ok); }
.msg.bad { background: var(--bad-soft); color: var(--bad); }
.empty { color: var(--muted); padding: 10px 0; }
.login { max-width: 360px; margin: 12vh auto; display: grid; gap: 12px; }
.login .brand { font: 600 22px var(--mono); }
.grid2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 18px; }
ul.plain { margin: 6px 0; padding-left: 18px; }
@media (max-width: 760px) {
  .app { grid-template-columns: 1fr; }
  nav { flex-direction: row; flex-wrap: wrap; border-right: 0; border-bottom: 1px solid var(--rule); position: static; height: auto; }
  nav .spacer, nav .who { display: none; }
  main { padding: 16px; }
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
</style>
</head>
<body>
<div id="root"></div>
<script>
"use strict";
let csrf = null, me = null, view = "overview", timer = null;

// Build elements safely: strings become text nodes, never HTML.
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "text") el.textContent = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) if (kid !== null && kid !== undefined && kid !== false) el.append(kid instanceof Node ? kid : String(kid));
  return el;
}
async function api(path, opts = {}) {
  const headers = { "content-type": "application/json" };
  if (csrf) headers["x-ariodb-csrf"] = csrf;
  const res = await fetch(path, { method: opts.method || "GET", headers, body: opts.body ? JSON.stringify(opts.body) : undefined, credentials: "same-origin" });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) { me = null; render(); throw new Error("Log in first."); }
  if (!res.ok) throw new Error(data.error || ("Request failed (" + res.status + ")"));
  return data;
}
const when = ms => new Date(ms).toLocaleString();
const pill = s => h("span", { class: "pill " + s, text: s.replace("_", " ") });
const note = (kind, text) => h("div", { class: "msg " + kind, role: "status", text });

const views = {
  overview: { label: "Overview", draw: drawOverview },
  approvals: { label: "Approvals", draw: drawApprovals },
  decisions: { label: "Decisions", draw: drawDecisions },
  sessions: { label: "Sessions & undo", draw: drawSessions },
  rules: { label: "Rules", draw: drawRules },
  config: { label: "Config", draw: drawConfig },
  settings: { label: "Settings", draw: drawSettings },
};

async function start() {
  const r = await fetch("/api/me", { credentials: "same-origin" }).then(r => r.json());
  if (r.user) { me = r.user; csrf = r.csrf; }
  const hash = location.hash.replace("#", "");
  if (hash.startsWith("approval-")) view = "approvals";
  else if (views[hash]) view = hash;
  render(r.needs_setup);
}

function render(needsSetup) {
  clearInterval(timer);
  const root = document.getElementById("root");
  root.replaceChildren();
  if (!me) { root.append(loginForm(needsSetup)); return; }
  const badge = h("span", { class: "badge", hidden: true, id: "pending-badge" });
  const navItems = Object.entries(views).map(([key, v]) =>
    h("button", { "aria-current": key === view ? "page" : null, onclick: () => { view = key; location.hash = key; render(); } },
      h("span", { text: v.label }), key === "approvals" ? badge : null));
  const main = h("main", { id: "main" });
  root.append(h("div", { class: "app" },
    h("nav", { "aria-label": "Sections" }, h("div", { class: "brand" }, "ario", h("span", { text: "db" })), navItems,
      h("div", { class: "spacer" }), h("div", { class: "who", text: "Signed in as " + me }),
      h("button", { onclick: async () => { await api("/api/logout", { method: "POST" }); me = null; csrf = null; render(); } }, h("span", { text: "Log out" }))),
    main));
  views[view].draw(main);
  const refreshBadge = async () => {
    try { const d = await api("/api/approvals"); badge.hidden = d.approvals.length === 0; badge.textContent = d.approvals.length; } catch (e) {}
  };
  refreshBadge();
  timer = setInterval(() => { refreshBadge(); if (view === "approvals") drawApprovals(main, true); }, 2500);
}

function loginForm(needsSetup) {
  const pw = h("input", { type: "password", id: "pw", autocomplete: needsSetup ? "new-password" : "current-password", required: true });
  const user = h("input", { id: "user", value: "root", autocomplete: "username" });
  const out = h("div");
  const form = h("form", { class: "panel login", onsubmit: async e => {
    e.preventDefault(); out.replaceChildren();
    try {
      const d = await api(needsSetup ? "/api/setup" : "/api/login", { method: "POST", body: { user: user.value, password: pw.value } });
      me = d.user; csrf = d.csrf; render();
    } catch (err) { out.append(note("bad", err.message)); }
  } },
    h("div", { class: "brand", text: "ariodb" }),
    h("p", { class: "sub", text: needsSetup ? "Set the root password (12 characters or more). This works only from the server itself." : "Sign in to review agents' database work." }),
    needsSetup ? null : h("label", { for: "user", text: "User" }), needsSetup ? null : user,
    h("label", { for: "pw", text: "Password" }), pw,
    h("button", { class: "btn primary", type: "submit", text: needsSetup ? "Set password" : "Sign in" }), out);
  return form;
}

function header(title, sub) { return h("header", {}, h("h1", { text: title }), sub ? h("p", { class: "sub", text: sub }) : null); }

async function drawOverview(main) {
  main.replaceChildren(header("Overview", "What agents did in the last 24 hours."));
  try {
    const d = await api("/api/overview");
    const count = o => (d.decisions_24h.find(x => x.outcome === o) || { count: 0 }).count;
    main.append(h("div", { class: "tiles" },
      tile(d.pending_approvals, "waiting for approval"), tile(count("allowed"), "statements allowed"),
      tile(count("refused"), "statements refused"), tile(count("rolled_back"), "writes rolled back"),
      tile(d.sessions_with_changes, "sessions that changed data")));
    main.append(h("section", { class: "panel" }, h("h2", { text: "Agents" }), h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Agent", "Access", "Tables", "Database login", "Token"].map(t => h("th", { text: t })))),
      h("tbody", {}, d.agents.map(a => h("tr", {}, h("td", { text: a.name }), h("td", { text: a.access }),
        h("td", {}, h("code", { text: a.tables.join(", ") })), h("td", { text: a.credential || "default" }),
        h("td", {}, a.token_set ? h("span", { class: "pill allowed", text: "set" }) : h("span", { class: "pill refused", text: "not set" })))))))));
    main.append(h("section", { class: "panel" }, h("h2", { text: "Setup" }), h("ul", { class: "plain" },
      h("li", { text: "Agents connect to " + d.proxy }), h("li", { text: d.rules + " rules" }),
      h("li", { text: "Approvers: " + (d.approvers.map(a => a.name + " (" + a.type + ")").join(", ") || "none") }),
      h("li", { text: "Change journal (needed for undo): " + (d.journal ? "on" : "off") }), h("li", { text: "ariodb " + d.version }))));
  } catch (e) { main.append(note("bad", e.message)); }
}
function tile(n, label) { return h("div", { class: "panel tile" }, h("div", { class: "n", text: n }), h("div", { class: "l", text: label })); }

async function drawApprovals(main, quiet) {
  let d, all;
  try { d = await api("/api/approvals"); all = await api("/api/approvals?all=true"); } catch (e) { if (!quiet) main.replaceChildren(note("bad", e.message)); return; }
  if (quiet && main.dataset.sig === JSON.stringify(d.approvals.map(a => a.id))) return;
  main.dataset.sig = JSON.stringify(d.approvals.map(a => a.id));
  main.replaceChildren(header("Approvals", "Statements held until someone decides. Nothing reaches the database while they wait."));
  const pending = h("section", { class: "panel" }, h("h2", { text: "Waiting" }));
  if (!d.approvals.length) pending.append(h("p", { class: "empty", text: "Nothing is waiting for approval." }));
  for (const a of d.approvals) {
    const noteInput = h("input", { placeholder: "Note for the agent (optional)", "aria-label": "Note", style: "flex:1;min-width:180px" });
    const out = h("div");
    const decide = async verdict => {
      try { await api("/api/approvals/" + encodeURIComponent(a.id), { method: "POST", body: { verdict, note: noteInput.value || null } }); main.dataset.sig = ""; drawApprovals(main); }
      catch (e) { out.replaceChildren(note("bad", e.message)); }
    };
    const left = Math.max(0, Math.round((a.expires_ms - Date.now()) / 1000));
    pending.append(h("div", { class: "card", id: "approval-" + a.id },
      h("div", { class: "row" }, pill("pending"), h("strong", { text: a.agent }), h("span", { class: "meta", text: "rule " + a.rule + " · approver " + a.approver + " · " + left + "s left" })),
      h("div", { text: a.reason }), h("pre", { class: "sql", text: a.sql }),
      h("div", { class: "row" }, noteInput, h("button", { class: "btn primary", onclick: () => decide("allow"), text: "Approve" }), h("button", { class: "btn danger", onclick: () => decide("deny"), text: "Deny" })), out));
  }
  main.append(pending);
  const recent = all.approvals.filter(a => a.status !== "pending").slice(0, 30);
  main.append(h("section", { class: "panel" }, h("h2", { text: "Recent decisions" }), recent.length ? h("div", { class: "scroll" }, h("table", {},
    h("thead", {}, h("tr", {}, ["When", "Status", "Agent", "Rule", "Decided by", "Statement"].map(t => h("th", { text: t })))),
    h("tbody", {}, recent.map(a => h("tr", {}, h("td", { class: "t", text: when(a.created_ms) }), h("td", {}, pill(a.status)), h("td", { text: a.agent }),
      h("td", { text: a.rule }), h("td", { text: (a.decided_by || "") + (a.note ? " — " + a.note : "") }), h("td", {}, h("div", { class: "sql", text: a.sql }))))))) : h("p", { class: "empty", text: "No decisions yet." })));
}

async function drawDecisions(main) {
  main.replaceChildren(header("Decisions", "Every statement agents sent, and what ariodb did with it."));
  const f = { agent: h("input", { placeholder: "Agent", "aria-label": "Agent" }), rule: h("input", { placeholder: "Rule", "aria-label": "Rule" }),
    q: h("input", { placeholder: "Text in statement", "aria-label": "Search statements" }),
    outcome: h("select", { "aria-label": "Outcome" }, ["", "allowed", "refused", "rolled_back", "failed"].map(o => h("option", { value: o, text: o ? o.replace("_", " ") : "Any outcome" }))) };
  const list = h("div");
  const load = async () => {
    const p = new URLSearchParams();
    for (const [k, el] of Object.entries(f)) if (el.value) p.set(k, el.value);
    p.set("limit", "200");
    try { const d = await api("/api/decisions?" + p); list.replaceChildren(decisionTable(d.decisions)); } catch (e) { list.replaceChildren(note("bad", e.message)); }
  };
  main.append(h("form", { class: "panel row", onsubmit: e => { e.preventDefault(); load(); } }, Object.values(f), h("button", { class: "btn primary", type: "submit", text: "Filter" })), h("section", { class: "panel" }, list));
  load();
}
function decisionTable(items) {
  if (!items.length) return h("p", { class: "empty", text: "No decisions match." });
  return h("div", { class: "scroll" }, h("table", { class: "wide" },
    h("thead", {}, h("tr", {}, ["When", "Agent", "Outcome", "Kind", "Rule", "Rows", "ms", "Statement", ""].map(t => h("th", { text: t })))),
    h("tbody", {}, items.map(d => {
      const out = h("div");
      const actions = h("div", { class: "actions" },
        h("button", { class: "btn sm", text: "Block like this", onclick: () => blockLike(d, out) }),
        d.outcome === "allowed" || d.outcome === "refused" ? h("button", { class: "btn sm", text: "Copy as test", onclick: async () => {
          try { const fx = await api("/api/decisions/" + d.id + "/fixture"); await navigator.clipboard.writeText(JSON.stringify(fx, null, 2)); out.replaceChildren(note("ok", "Copied as a test fixture.")); }
          catch (e) { out.replaceChildren(note("bad", e.message)); }
        } }) : null);
      return h("tr", {}, h("td", { class: "t", text: when(d.at_ms) }), h("td", { text: d.agent }), h("td", {}, pill(d.outcome)), h("td", { text: d.kind }),
        h("td", { text: d.rule || "" }), h("td", { class: "num", text: d.rows ?? "" }), h("td", { class: "num", text: d.latency_ms ?? "" }),
        h("td", { class: "stmt" }, h("div", { class: "sql", text: d.sql }), d.reason ? h("div", { class: "meta", text: d.reason }) : null, out), h("td", {}, actions));
    }))));
}
async function blockLike(d, out) {
  try {
    const p = await api("/api/block-like", { method: "POST", body: { decision: d.id, apply: false } });
    const cfg = await api("/api/config");
    const apply = h("button", { class: "btn primary", disabled: !cfg.writable, text: "Add this rule", onclick: async () => {
      try { await api("/api/block-like", { method: "POST", body: { decision: d.id, apply: true } }); out.replaceChildren(note("ok", "Rule " + p.rule + " added and in force.")); }
      catch (e) { out.replaceChildren(note("bad", e.message)); }
    } });
    out.replaceChildren(h("pre", { class: "sql", text: p.snippet.trim() }), h("div", { class: "row" }, apply,
      cfg.writable ? null : h("span", { class: "meta", text: "Config edits are off here; copy this into your config repository." })));
  } catch (e) { out.replaceChildren(note("bad", e.message)); }
}

async function drawSessions(main) {
  main.replaceChildren(header("Sessions & undo", "Every agent session that changed data. Undo reverses exactly one session and leaves everyone else's changes alone."));
  const panel = h("section", { class: "panel" });
  main.append(panel);
  try {
    const d = await api("/api/sessions");
    if (!d.sessions.length) { panel.append(h("p", { class: "empty", text: "No agent has changed data yet." })); return; }
    panel.append(h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Last change", "Session", "Agent", "Transactions", "Rows", "Tables", "Status", ""].map(t => h("th", { text: t })))),
      h("tbody", {}, d.sessions.map(s => {
        const detail = h("tr", { hidden: true }, h("td", { colspan: 8 }));
        const row = h("tr", {}, h("td", { class: "t", text: when(s.last_at_ms) }), h("td", {}, h("code", { text: s.session })), h("td", { text: s.agent }),
          h("td", { class: "num", text: s.transactions }), h("td", { class: "num", text: s.rows }), h("td", { text: s.tables.join(", ") }),
          h("td", {}, s.undone ? h("span", { class: "pill allowed", text: "undone" }) : ""),
          h("td", {}, h("button", { class: "btn", text: "Review undo", onclick: () => showPlan(s, detail) })));
        return [row, detail];
      })))));
  } catch (e) { panel.append(note("bad", e.message)); }
}
async function showPlan(s, detail) {
  const cell = detail.firstChild;
  detail.hidden = false;
  cell.replaceChildren(h("p", { class: "empty", text: "Working out the undo plan…" }));
  try {
    const p = await api("/api/sessions/" + encodeURIComponent(s.session) + "/plan");
    const skip = h("input", { type: "checkbox", id: "skip-" + s.session });
    const out = h("div");
    const run = h("button", { class: "btn danger", disabled: p.already_undone || p.blocked.length > 0, text: "Undo " + p.steps.length + " changes", onclick: async () => {
      if (run.dataset.armed !== "yes") { run.dataset.armed = "yes"; run.textContent = "Click again to undo for real"; return; }
      try { const r = await api("/api/sessions/" + encodeURIComponent(s.session) + "/undo", { method: "POST", body: { skip_conflicts: skip.checked } });
        out.replaceChildren(note("ok", "Undone: " + r.restored + " rows restored in one transaction.")); run.disabled = true; run.textContent = "Undone"; }
      catch (e) { out.replaceChildren(note("bad", e.message)); run.dataset.armed = ""; run.textContent = "Undo " + p.steps.length + " changes"; }
    } });
    cell.replaceChildren(h("div", {},
      p.already_undone ? note("ok", "This session was already undone.") : null,
      h("ul", { class: "plain" }, p.steps.slice(0, 50).map(t => h("li", { text: t })), p.steps.length > 50 ? h("li", { text: "…and " + (p.steps.length - 50) + " more" }) : null),
      p.conflicts.length ? h("div", {}, h("strong", { text: "Changed by someone else since:" }), h("ul", { class: "plain" }, p.conflicts.map(t => h("li", { text: t })))) : null,
      p.blocked.length ? h("div", {}, h("strong", { text: "Cannot be undone:" }), h("ul", { class: "plain" }, p.blocked.map(t => h("li", { text: t })))) : null,
      h("div", { class: "row" }, run, p.conflicts.length ? h("label", { for: "skip-" + s.session }, skip, " Undo the rest and leave conflicting rows alone") : null), out));
  } catch (e) { cell.replaceChildren(note("bad", e.message)); }
}

async function drawRules(main) {
  main.replaceChildren(header("Rules", "Checked on top of each agent's built-in policy. Any matching deny wins; then priority decides between allow and approve."));
  const tryAgent = h("input", { placeholder: "Agent name", "aria-label": "Agent name" });
  const trySql = h("textarea", { rows: 3, placeholder: "SELECT * FROM orders", "aria-label": "Statement to try" });
  const out = h("div");
  main.append(h("form", { class: "panel", onsubmit: async e => { e.preventDefault();
    try { const r = await api("/api/explain", { method: "POST", body: { agent: tryAgent.value, sql: trySql.value } });
      out.replaceChildren(h("p", {}, pill(r.verdict), " decided by ", h("code", { text: r.rule || "no rule (built-in policy allows)" }), r.reason ? " — " + r.reason : "")); }
    catch (err) { out.replaceChildren(note("bad", err.message)); } } },
    h("h2", { text: "Try a statement" }), h("div", { class: "row" }, tryAgent), trySql, h("div", { class: "row" }, h("button", { class: "btn primary", type: "submit", text: "Explain" })), out));
  try {
    const d = await api("/api/rules");
    main.append(h("section", { class: "panel" }, h("h2", { text: d.rules.length + " rules" }), d.rules.length ? h("div", { class: "scroll" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Rule", "Verdict", "Stage", "Priority", "Condition", "Agents"].map(t => h("th", { text: t })))),
      h("tbody", {}, d.rules.map(r => h("tr", {}, h("td", {}, h("strong", { text: r.name }), r.reason ? h("div", { class: "meta", text: r.reason }) : null),
        h("td", {}, pill(r.verdict), r.approve.length ? h("div", { class: "meta", text: r.approve.join(", ") }) : null), h("td", { text: r.stage }),
        h("td", { class: "num", text: r.priority }), h("td", {}, h("div", { class: "sql", text: r.condition || "(always)" })), h("td", { text: r.agents.join(", ") || "all" })))))) : h("p", { class: "empty", text: "No rules; only the built-in policy applies." })));
  } catch (e) { main.append(note("bad", e.message)); }
}

async function drawConfig(main) {
  main.replaceChildren(header("Config", "Changes are checked before they are saved, and take effect at once."));
  try {
    const c = await api("/api/config");
    const text = h("textarea", { rows: 28, spellcheck: "false", "aria-label": "Config file" });
    text.value = c.text;
    const out = h("div");
    main.append(h("section", { class: "panel" }, h("p", { class: "meta", text: c.path }), text, h("div", { class: "row", style: "margin-top:10px" },
      h("button", { class: "btn", text: "Check", onclick: async () => { const r = await api("/api/config/check", { method: "POST", body: { text: text.value } });
        out.replaceChildren(r.ok ? note("ok", "Valid: " + r.agents + " agents, " + r.rules + " rules, " + r.approvers + " approvers.") : note("bad", r.error)); } }),
      h("button", { class: "btn primary", disabled: !c.writable, text: "Save", onclick: async () => {
        try { await api("/api/config", { method: "PUT", body: { text: text.value } }); out.replaceChildren(note("ok", "Saved and in force. The previous file is kept as .bak.")); }
        catch (e) { out.replaceChildren(note("bad", e.message)); } } }),
      c.writable ? null : h("span", { class: "meta", text: "Saving is off (dashboard.config_writes = false). Check here, then commit the change to your config repository." })), out));
  } catch (e) { main.append(note("bad", e.message)); }
}

async function drawSettings(main) {
  main.replaceChildren(header("Settings"));
  const secretsBox = h("section", { class: "panel" }, h("h2", { text: "Secrets" }), h("p", { class: "meta", text: "Encrypted at rest. Values can be replaced but never shown." }));
  const usersBox = h("section", { class: "panel" }, h("h2", { text: "Dashboard users" }));
  const auditBox = h("section", { class: "panel" }, h("h2", { text: "Decisions log" }));
  main.append(h("div", { class: "grid2" }, secretsBox, usersBox), auditBox);
  try {
    const s = await api("/api/secrets");
    const name = h("input", { placeholder: "Name", "aria-label": "Secret name" }), value = h("input", { type: "password", placeholder: "Value", "aria-label": "Secret value", autocomplete: "off" });
    const out = h("div");
    secretsBox.append(h("ul", { class: "plain" }, s.secrets.length ? s.secrets.map(n => h("li", {}, h("code", { text: n }))) : h("li", { class: "empty", text: "None yet" })),
      h("form", { class: "row", onsubmit: async e => { e.preventDefault();
        try { await api("/api/secrets/" + encodeURIComponent(name.value), { method: "POST", body: { value: value.value } }); value.value = ""; drawSettings(main); }
        catch (err) { out.replaceChildren(note("bad", err.message)); } } }, name, value, h("button", { class: "btn primary", type: "submit", text: "Save secret" })), out);
  } catch (e) { secretsBox.append(note("bad", e.message)); }
  try {
    const u = await api("/api/users");
    const name = h("input", { placeholder: "User name", "aria-label": "User name" }), pw = h("input", { type: "password", placeholder: "Password (12+ characters)", "aria-label": "Password", autocomplete: "new-password" });
    const out = h("div");
    usersBox.append(h("ul", { class: "plain" }, u.users.map(n => h("li", { text: n }))),
      h("form", { class: "row", onsubmit: async e => { e.preventDefault();
        try { await api("/api/users", { method: "POST", body: { name: name.value, password: pw.value } }); drawSettings(main); }
        catch (err) { out.replaceChildren(note("bad", err.message)); } } }, name, pw, h("button", { class: "btn primary", type: "submit", text: "Add or reset user" })), out);
  } catch (e) { usersBox.append(note("bad", e.message)); }
  const out = h("div");
  auditBox.append(h("p", { class: "meta", text: "Each entry is chained to the one before it, so edits and deletions show." }),
    h("button", { class: "btn", text: "Check the chain", onclick: async () => { const r = await api("/api/audit/verify");
      out.replaceChildren(r.ok ? note("ok", "Intact: " + r.entries + " entries checked.") : note("bad", r.error)); } }), out);
}

window.addEventListener("hashchange", () => {
  const hash = location.hash.replace("#", "");
  const next = hash.startsWith("approval-") ? "approvals" : hash;
  if (me && views[next] && next !== view) { view = next; render(); }
});
start();
</script>
</body>
</html>
"##;
