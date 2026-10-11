"""A local stand-in for Splunk's HTTP Event Collector (HEC), so the
end-to-end tests exercise ariodb's Splunk exporter without a Splunk
installation (whose image needs its licence accepted).

It follows Splunk's HEC documentation: the "Authorization: Splunk <token>"
header (or Basic auth with the token as password), JSON events stacked one
after another or in an array, the metadata keys (time, host, source,
sourcetype, index, fields), indexer acknowledgement with channels and
/services/collector/ack, /services/collector/health, and the documented
status codes with their HEC "code" and "text". Unlike Splunk, a request
with one bad event stores none of it.

Tokens come from HEC_STANDIN_TOKENS, a JSON object (never the command
line): {"<token>": {"ack": false, "indexes": ["ariodb"], "disabled": false}}.
An empty or missing "indexes" allows any index.

Every accepted event is appended to <dir>/events.jsonl as
{"channel": ..., "ack_id": ..., "event": <the event object as sent>}, and
every request to <dir>/requests.jsonl as {"path", "status", "code"}. The
token is never written.

<dir>/mode, if present, changes behaviour by its first word:
  busy           events: 503, code 9 "Server is busy"; health unhealthy
  full           events: 429, code 26; health unhealthy
  error          events: 500, code 8 "Internal server error"
  shutting-down  events: 503, code 23 "Server is shutting down"
  ack-slow       acks report indexed only 2 s after the events arrived
  ack-lost       acks never report indexed (as after a lost status cache)

With HEC_STANDIN_CERT and HEC_STANDIN_KEY (PEM files), it serves HTTPS.

Run: python3 -I hec_standin.py <port> <dir>
"""
import base64
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
DIR = sys.argv[2]
TOKENS = json.loads(os.environ.get("HEC_STANDIN_TOKENS", "{}"))
GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
META = {"time", "host", "source", "sourcetype", "index", "fields", "event"}

lock = threading.Lock()
# channel -> next ackID, and channel -> {ackID: time the events arrived}
next_ack = {}
pending_acks = {}


def append(name, entry):
    with lock, open(os.path.join(DIR, name), "a") as f:
        f.write(json.dumps(entry) + "\n")


def mode():
    try:
        with open(os.path.join(DIR, "mode")) as f:
            words = f.read().split()
            return words[0] if words else ""
    except FileNotFoundError:
        return ""


class Reply(Exception):
    """An answer in HEC's form: an HTTP status, a code and a text."""

    def __init__(self, status, code, text, **extra):
        super().__init__(text)
        self.status, self.code, self.text, self.extra = status, code, text, extra


def events_in(body):
    """The events in a request: JSON objects one after another, or an array."""
    text = body.decode("utf-8", "replace").strip()
    if not text:
        raise Reply(400, 5, "No data")
    decoder = json.JSONDecoder()
    out, i, n = [], 0, 0
    while i < len(text):
        try:
            value, end = decoder.raw_decode(text, i)
        except ValueError:
            raise Reply(400, 6, "Invalid data format", **{"invalid-event-number": n})
        out.extend(value if isinstance(value, list) else [value])
        n = len(out)
        i = end
        while i < len(text) and text[i].isspace():
            i += 1
    return out


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send(self, status, payload, code=None):
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=UTF-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        append("requests.jsonl", {"path": self.path.split("?")[0], "status": status, "code": code})

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def token(self, query):
        """The token's settings, or a Reply saying why there are none."""
        auth = self.headers.get("Authorization")
        if auth is None:
            if "token" in query:
                raise Reply(400, 16, "Query string authorization is not enabled")
            raise Reply(401, 2, "Token is required")
        scheme, _, value = auth.partition(" ")
        if scheme == "Splunk":
            token = value.strip()
        elif scheme == "Basic":
            try:
                token = base64.b64decode(value.strip()).decode().split(":", 1)[1]
            except (ValueError, IndexError):
                raise Reply(401, 3, "Invalid authorization")
        else:
            raise Reply(401, 3, "Invalid authorization")
        settings = TOKENS.get(token)
        if settings is None:
            raise Reply(403, 4, "Invalid token")
        if settings.get("disabled"):
            raise Reply(403, 1, "Token disabled")
        return settings

    def channel(self, query):
        channel = self.headers.get("X-Splunk-Request-Channel") or query.get("channel", [None])[0]
        if not channel:
            raise Reply(400, 10, "Data channel is missing")
        if not GUID.match(channel):
            raise Reply(400, 11, "Invalid data channel")
        return channel

    def handle_request(self):
        url = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(url.query)
        path = url.path.rstrip("/")
        body = self.body()
        if path in ("/services/collector/health", "/services/collector/health/1.0"):
            return self.health(query)
        if path in ("/services/collector", "/services/collector/event", "/services/collector/event/1.0"):
            if self.command != "POST":
                raise Reply(405, 404, "Method not allowed")
            return self.event(query, body)
        if path == "/services/collector/ack":
            return self.ack(query, body)
        raise Reply(404, 404, "The requested URL was not found on this server.")

    def health(self, query):
        if "token" in query:
            settings = TOKENS.get(query["token"][0])
            if settings is None:
                raise Reply(400, 21, "Invalid token")
            if settings.get("disabled"):
                raise Reply(400, 22, "Token disabled")
        if mode() in ("busy", "full"):
            raise Reply(503, 18, "HEC is unhealthy, queues are full")
        raise Reply(200, 17, "HEC is healthy")

    def event(self, query, body):
        settings = self.token(query)
        channel = self.channel(query) if settings.get("ack") else None
        m = mode()
        if m == "busy":
            raise Reply(503, 9, "Server is busy")
        if m == "full":
            raise Reply(429, 26, "HEC queue is at capacity and cannot process any more requests")
        if m == "error":
            raise Reply(500, 8, "Internal server error")
        if m == "shutting-down":
            raise Reply(503, 23, "Server is shutting down")
        events = events_in(body)
        allowed = settings.get("indexes") or []
        for n, e in enumerate(events):
            bad = {"invalid-event-number": n}
            if not isinstance(e, dict):
                raise Reply(400, 6, "Invalid data format", **bad)
            if "event" not in e:
                raise Reply(400, 12, "Event field is required", **bad)
            if e["event"] in ("", None):
                raise Reply(400, 13, "Event field cannot be blank", **bad)
            if allowed and "index" in e and e["index"] not in allowed:
                raise Reply(400, 7, "Incorrect index", **bad)
            fields = e.get("fields", {})
            if not isinstance(fields, dict) or any(isinstance(v, dict) for v in fields.values()):
                raise Reply(400, 15, "Error in handling indexed fields", **bad)
            if "time" in e:
                try:
                    float(e["time"])
                except (TypeError, ValueError):
                    raise Reply(400, 6, "Invalid data format", **bad)
            unknown = set(e) - META
            if unknown:
                raise Reply(400, 6, "Invalid data format", **bad)
        ack_id = None
        if channel is not None:
            with lock:
                ack_id = next_ack.get(channel, 0)
                next_ack[channel] = ack_id + 1
                pending_acks.setdefault(channel, {})[ack_id] = time.time()
        for e in events:
            append("events.jsonl", {"channel": channel, "ack_id": ack_id, "event": e})
        if ack_id is not None:
            raise Reply(200, 0, "Success", ackID=ack_id)
        raise Reply(200, 0, "Success")

    def ack(self, query, body):
        settings = self.token(query)
        if not settings.get("ack"):
            raise Reply(400, 14, "ACK is disabled")
        channel = self.channel(query)
        try:
            acks = json.loads(body or b"{}")["acks"]
            ids = [int(a) for a in acks]
        except (ValueError, KeyError, TypeError):
            raise Reply(400, 6, "Invalid data format")
        m = mode()
        status = {}
        with lock:
            known = pending_acks.get(channel, {})
            for i in ids:
                arrived = known.get(i)
                done = arrived is not None and m != "ack-lost" and (
                    m != "ack-slow" or time.time() - arrived >= 2
                )
                if done:
                    # Splunk forgets an ackID once it has said true.
                    del known[i]
                status[str(i)] = done
        self.send(200, {"acks": status})

    def respond(self):
        try:
            self.handle_request()
        except Reply as r:
            self.send(r.status, {"text": r.text, "code": r.code, **r.extra}, r.code)

    do_GET = respond
    do_POST = respond


server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
server.daemon_threads = True
cert, key = os.environ.get("HEC_STANDIN_CERT"), os.environ.get("HEC_STANDIN_KEY")
if cert and key:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
print(f"hec stand-in listening on {PORT}", flush=True)
server.serve_forever()
