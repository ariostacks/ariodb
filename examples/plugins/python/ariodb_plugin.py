#!/usr/bin/env python3
"""An example ariodb plugin with all four capabilities. Standard library only.

ariodb starts it and talks newline-delimited JSON-RPC 2.0 over stdin and
stdout (see docs/plugins.md). Anything for people goes to stderr, which
ariodb copies into its own log.

The example policy: writes are out of hours from 18:00 to 07:00 GMT.

- approver: denies writes out of hours, and anything touching a table on
  the deny list; allows the rest.
- facts: tells rules the hour in GMT, whether it is out of hours, and
  whether there is a change freeze (a file exists), as plugin.<name>.hour_gmt,
  .out_of_hours and .freeze.
- notifier: appends each event to a file as a JSON line (or to stderr).
- audit_sink: appends each decisions-log entry to a file as a JSON line,
  synced to disk before acknowledging it. Declared only when
  ARIODB_EXAMPLE_AUDIT_FILE is set.

Settings, all optional, from the environment ariodb gives it ([[plugins]] env):

  ARIODB_EXAMPLE_START_HOUR     working day starts (GMT), default 7
  ARIODB_EXAMPLE_CUTOFF_HOUR    working day ends (GMT), default 18
  ARIODB_EXAMPLE_DENY_TABLES    comma-separated tables the approver always denies
  ARIODB_EXAMPLE_FREEZE_FILE    while this file exists, facts say freeze = true
  ARIODB_EXAMPLE_EVENTS_FILE    where events go (default: stderr)
  ARIODB_EXAMPLE_AUDIT_FILE     where decisions go; turns on audit_sink
  ARIODB_EXAMPLE_AUDIT_PAUSE_FILE  while this file exists, refuse audit
                                batches (ariodb keeps them and sends them again)
"""

import datetime
import json
import os
import sys

NAME = "ariodb-example"
VERSION = "1.0.0"

START = int(os.environ.get("ARIODB_EXAMPLE_START_HOUR", "7"))
CUTOFF = int(os.environ.get("ARIODB_EXAMPLE_CUTOFF_HOUR", "18"))
DENY_TABLES = {
    t.strip().lower() for t in os.environ.get("ARIODB_EXAMPLE_DENY_TABLES", "").split(",") if t.strip()
}
FREEZE_FILE = os.environ.get("ARIODB_EXAMPLE_FREEZE_FILE", "")
EVENTS_FILE = os.environ.get("ARIODB_EXAMPLE_EVENTS_FILE", "")
AUDIT_FILE = os.environ.get("ARIODB_EXAMPLE_AUDIT_FILE", "")
AUDIT_PAUSE_FILE = os.environ.get("ARIODB_EXAMPLE_AUDIT_PAUSE_FILE", "")


class PluginError(Exception):
    """Answered as a JSON-RPC error; ariodb refuses whatever depended on it."""


def log(text):
    print(f"{NAME}: {text}", file=sys.stderr, flush=True)


def now_gmt():
    return datetime.datetime.now(datetime.timezone.utc)


def out_of_hours(now):
    return not (START <= now.hour < CUTOFF)


def append_line(path, value):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(value, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())


def initialize(params):
    if params.get("protocol_version") != 1:
        raise PluginError(f"this plugin speaks protocol version 1, not {params.get('protocol_version')}")
    log(f"started by ariodb {params.get('ariodb_version')} as '{params.get('name')}'")
    return {
        "name": NAME,
        "version": VERSION,
        "protocol_version": 1,
        "capabilities": {
            "approver": True,
            "facts": True,
            "notifier": True,
            "audit_sink": bool(AUDIT_FILE),
        },
    }


def approve(params):
    statements = params.get("statements", [])
    touched = {t.lower() for s in statements for t in s.get("tables", [])}
    denied = sorted(touched & DENY_TABLES)
    if denied:
        return {"verdict": "deny", "note": f"{', '.join(denied)} may not be touched (deny list)"}
    writes = [s for s in statements if s.get("kind") != "read"]
    now = now_gmt()
    if writes and out_of_hours(now):
        return {
            "verdict": "deny",
            "note": f"writes are allowed {START:02d}:00 to {CUTOFF:02d}:00 GMT; it is {now:%H:%M} GMT",
        }
    return {"verdict": "allow", "note": "within the example policy"}


def facts(params):
    now = now_gmt()
    return {
        "hour_gmt": now.hour,
        "weekday": now.strftime("%a").lower(),
        "out_of_hours": out_of_hours(now),
        "freeze": bool(FREEZE_FILE) and os.path.exists(FREEZE_FILE),
    }


def audit(params):
    entries = params.get("entries", [])
    if not entries:
        raise PluginError("empty batch")
    if params.get("test"):
        # `ariodb plugin test` sends a sample: acknowledge it, store nothing.
        return {"ack": entries[-1]["id"]}
    if AUDIT_PAUSE_FILE and os.path.exists(AUDIT_PAUSE_FILE):
        raise PluginError("paused; send these again later")
    for entry in entries:
        append_line(AUDIT_FILE, entry)
    # Acknowledge only what is safely stored: ariodb resends the rest.
    return {"ack": entries[-1]["id"]}


def event(params):
    if EVENTS_FILE:
        append_line(EVENTS_FILE, params)
    else:
        log(f"event {params.get('event')}: {json.dumps(params.get('details'))}")


METHODS = {"initialize": initialize, "approve": approve, "facts": facts, "audit": audit}
NOTIFICATIONS = {"event": event, "cancel": lambda p: log(f"request {p.get('approval_id')} withdrawn: {p.get('reason')}")}


def answer(msg_id, result=None, error=None):
    reply = {"jsonrpc": "2.0", "id": msg_id}
    if error is None:
        reply["result"] = result
    else:
        reply["error"] = error
    # One JSON value per line; json.dumps never writes a raw newline.
    sys.stdout.write(json.dumps(reply) + "\n")
    sys.stdout.flush()


def main():
    # ariodb closes stdin to stop the plugin, so the loop ends cleanly.
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            log("ignored a line that is not JSON")
            continue
        method, params, msg_id = msg.get("method"), msg.get("params") or {}, msg.get("id")
        if msg_id is None:
            handler = NOTIFICATIONS.get(method)
            if handler:
                try:
                    handler(params)
                except Exception as e:  # a notification has nobody to tell
                    log(f"{method} failed: {e}")
            continue
        handler = METHODS.get(method)
        if handler is None:
            answer(msg_id, error={"code": -32601, "message": f"unknown method {method}"})
            continue
        try:
            answer(msg_id, result=handler(params))
        except PluginError as e:
            answer(msg_id, error={"code": -32000, "message": str(e)})
        except Exception as e:
            answer(msg_id, error={"code": -32603, "message": f"{type(e).__name__}: {e}"})


if __name__ == "__main__":
    main()
