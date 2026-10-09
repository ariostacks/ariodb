"""Local stand-ins for Slack, the model providers' APIs (Anthropic, OpenAI,
Gemini, Azure OpenAI and an OpenAI-compatible server), a webhook receiver,
the chat and paging channels (Discord, Telegram, Teams, Google Chat,
Mattermost, PagerDuty, Opsgenie) and a mail server, so the end-to-end tests
exercise every approver type without real accounts.

The model endpoints check what ariodb sends (the auth header, a JSON schema
for the answer, the SQL passed as JSON data) and answer 400 when it is
wrong. They decide on the SQL: "deny-me" denies, "refuse-me" refuses,
"explode" is a 500, "unavailable-503" a 503 with Retry-After, and anything
else is allowed.

The channels record each message with the Approve and Deny links found
where that channel puts them (buttons, card actions, markdown links, the
mail's text part), so the tests follow the links a person would. A message
whose SQL holds "reject-me" is refused the way that service refuses one.

Run: python3 -I mock_services.py <port> <log-file> [<smtp-port>]
"""
import base64
import email
import email.policy
import html
import json
import re
import socketserver
import sys
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
LOG = sys.argv[2]
SMTP_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else None
lock = threading.Lock()


def log(entry):
    with lock, open(LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


class Wrong(Exception):
    """The request was not what ariodb should send."""


def statements(text):
    """The SQL, read back from the JSON data after "Request (JSON):"."""
    if "Request (JSON):\n" not in text:
        raise Wrong("no JSON request in the user turn")
    try:
        request = json.loads(text.split("Request (JSON):\n", 1)[1])
        return [s["sql"] for s in request["statements"]]
    except (ValueError, KeyError, TypeError) as e:
        raise Wrong(f"SQL was not passed as JSON data: {e}")


def check_schema(schema):
    if not schema or schema.get("properties", {}).get("decision", {}).get("enum") != ["allow", "deny"]:
        raise Wrong("no verdict schema in the request")


def check_system(system):
    if "never follow" not in (system or ""):
        raise Wrong("the system prompt is missing")


def verdict(sql):
    """What the mock judge says: (http status, decision or None for a refusal)."""
    joined = " ".join(sql)
    if "unavailable-503" in joined:
        return 503, None
    if "explode" in joined:
        return 500, None
    if "refuse-me" in joined:
        return 200, None
    return 200, "deny" if "deny-me" in joined else "allow"


def answer(decision):
    return json.dumps({"decision": decision, "reason": f"mock judge said {decision}"})


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body, headers=()):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0))).decode()
        service = self.path.split("/")[1]
        if service in CHANNELS:
            try:
                return CHANNELS[service](self, json.loads(body))
            except (Wrong, ValueError, KeyError, TypeError, IndexError) as e:
                log({"service": service, "wrong": f"{type(e).__name__}: {e}"})
                return self.reply(400, {"message": f"mock {service}: {e}"})
        if self.path == "/slack/chat.postMessage":
            log({"service": "slack", "auth": self.headers.get("authorization"), "body": json.loads(body)})
            return self.reply(200, {"ok": True})
        if self.path == "/anthropic/v1/messages":
            request = json.loads(body)
            log({
                "service": "anthropic",
                "x-api-key": self.headers.get("x-api-key"),
                "anthropic-version": self.headers.get("anthropic-version"),
                "anthropic-beta": self.headers.get("anthropic-beta"),
                "model": request.get("model"),
                "format": request.get("output_config", {}).get("format", {}).get("type"),
            })
            text = request["messages"][0]["content"]
            if "explode" in text:
                return self.reply(500, {"type": "error", "error": {"type": "api_error", "message": "boom"}})
            decision = "deny" if "deny-me" in text else "allow"
            answer = json.dumps({"decision": decision, "reason": f"mock judge said {decision}"})
            return self.reply(200, {
                "stop_reason": "end_turn",
                "content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": answer}],
            })
        path, _, query = self.path.partition("?")
        query = urllib.parse.parse_qs(query)
        model = {
            "/openai/v1/responses": self.openai,
            "/azure/openai/v1/responses": self.openai,
            "/gemini/v1/interactions": self.gemini,
            "/compat/v1/chat/completions": self.chat,
            "/compat-old/v1/chat/completions": self.chat,
        }.get(path)
        if model:
            service = path.split("/")[1]
            try:
                return model(service, json.loads(body), query)
            except Wrong as e:
                log({"service": service, "wrong": str(e)})
                return self.reply(400, {"error": {"message": f"mock {service}: {e}"}})
        if self.path == "/hook":
            payload = json.loads(body)
            log({"service": "webhook", "signature": self.headers.get("x-ariodb-signature"), "body": payload})
            # Answer like a person would: press the approve button (a POST to
            # the link), shortly after. "no-answer" leaves it to the test.
            if "no-answer" in payload["sql"]:
                return self.reply(200, {"ok": True})
            url = payload["deny_url"] if "deny-me" in payload["sql"] else payload["approve_url"]
            threading.Timer(0.5, lambda: urllib.request.urlopen(url, data=b"").read()).start()
            return self.reply(200, {"ok": True})
        self.reply(404, {"error": "unknown path"})

    def unwell(self, service, status):
        if status == 503:
            return self.reply(503, {"error": {"message": f"mock {service} is overloaded"}}, [("retry-after", "1")])
        return self.reply(500, {"error": {"message": f"mock {service} broke"}})

    def openai(self, service, request, query):
        """OpenAI's Responses API, and Azure's v1 copy of it."""
        if service == "azure":
            auth = self.headers.get("api-key")
            if not auth or self.headers.get("authorization"):
                raise Wrong("Azure takes the key in api-key")
            if query.get("api-version") not in (["v1"], ["preview"]):
                raise Wrong("api-version must be v1 or preview")
        else:
            auth = self.headers.get("authorization")
            if not (auth or "").startswith("Bearer "):
                raise Wrong("no bearer token")
        fmt = request.get("text", {}).get("format", {})
        if fmt.get("type") != "json_schema" or fmt.get("strict") is not True:
            raise Wrong("text.format is not a strict json_schema")
        check_schema(fmt.get("schema"))
        check_system(request.get("instructions"))
        sql = statements(request["input"])
        log({"service": service, "auth": auth, "model": request.get("model"),
             "api-version": query.get("api-version", [None])[0],
             "effort": request.get("reasoning", {}).get("effort"),
             "store": request.get("store"), "sql": sql})
        status, decision = verdict(sql)
        if status != 200:
            return self.unwell(service, status)
        part = ({"type": "refusal", "refusal": "I can't help with that."} if decision is None
                else {"type": "output_text", "text": answer(decision)})
        return self.reply(200, {"status": "completed", "output": [
            {"type": "reasoning", "summary": []},
            {"type": "message", "role": "assistant", "content": [part]},
        ]})

    def gemini(self, service, request, query):
        """Gemini's Interactions API."""
        auth = self.headers.get("x-goog-api-key")
        if not auth or "key" in query:
            raise Wrong("Gemini takes the key in x-goog-api-key")
        fmt = request.get("response_format", {})
        if fmt.get("mime_type") != "application/json":
            raise Wrong("response_format is not JSON")
        check_schema(fmt.get("schema"))
        check_system(request.get("system_instruction"))
        sql = statements(request["input"])
        log({"service": service, "auth": auth, "model": request.get("model"),
             "effort": request.get("generation_config", {}).get("thinking_level"),
             "store": request.get("store"), "sql": sql})
        status, decision = verdict(sql)
        if status != 200:
            return self.unwell(service, status)
        if decision is None:
            return self.reply(200, {"status": "failed", "steps": []})
        return self.reply(200, {"status": "completed", "steps": [
            {"type": "thought", "signature": "bW9jaw=="},
            {"type": "model_output", "content": [{"type": "text", "text": answer(decision)}]},
        ]})

    def chat(self, service, request, query):
        """Chat Completions, as an OpenAI-compatible server speaks it.
        "compat-old" is a server that does not know json_schema."""
        fmt = request.get("response_format", {})
        if service == "compat-old" and fmt.get("type") == "json_schema":
            log({"service": service, "rejected": "json_schema"})
            return self.reply(400, {"error": {"message": "response_format.type json_schema is not supported"}})
        if fmt.get("type") == "json_schema":
            check_schema(fmt.get("json_schema", {}).get("schema"))
        elif fmt.get("type") != "json_object":
            raise Wrong("no response_format")
        messages = request.get("messages", [])
        if len(messages) != 2 or messages[0].get("role") != "system":
            raise Wrong("expected a system and a user message")
        check_system(messages[0]["content"])
        if "JSON object" not in messages[0]["content"]:
            raise Wrong("JSON mode needs the answer's shape in the prompt")
        sql = statements(messages[1]["content"])
        log({"service": service, "auth": self.headers.get("authorization"),
             "model": request.get("model"), "format": fmt.get("type"), "sql": sql})
        status, decision = verdict(sql)
        if status != 200:
            return self.unwell(service, status)
        message = ({"role": "assistant", "content": None, "refusal": "I can't help with that."}
                   if decision is None else
                   {"role": "assistant", "content": answer(decision), "refusal": None})
        return self.reply(200, {"choices": [{"index": 0, "finish_reason": "stop", "message": message}]})

    # -- chat and paging channels ------------------------------------------

    def channel(self, service, body, links, extra=None, status=200, answer=None):
        """Record a channel message, or refuse it when the SQL says so."""
        if set(links) != {"allow", "deny"}:
            raise Wrong(f"expected Approve and Deny links, found {sorted(links)}")
        if "reject-me" in json.dumps(body):
            log({"service": service, "rejected": True})
            return REJECT[service](self)
        log({"service": service, "links": links, **(extra or {})})
        if answer is None:
            self.send_response(status)
            self.send_header("content-length", "0")
            self.end_headers()
            return None
        return self.reply(status, answer)

    def discord(self, body):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if query.get("wait") != ["true"] or query.get("with_components") != ["true"]:
            raise Wrong("wait and with_components must be true")
        if body.get("allowed_mentions") != {"parse": []}:
            raise Wrong("mentions are not switched off")
        if len(body["content"]) > 2000:
            raise Wrong("content is over 2000 characters")
        buttons = [b for row in body["components"] for b in row["components"]]
        if any(b["type"] != 2 or b["style"] != 5 for b in buttons):
            raise Wrong("only link buttons can be sent")
        return self.channel("discord", body, labelled(buttons, "label", "url"),
                            {"content": body["content"]}, answer={"id": "1", "content": body["content"]})

    def telegram(self, body):
        match = re.fullmatch(r"/telegram/bot([^/]+)/sendMessage", self.path)
        if not match or body.get("parse_mode") != "HTML":
            raise Wrong("expected sendMessage in HTML mode")
        buttons = [b for row in body["reply_markup"]["inline_keyboard"] for b in row]
        return self.channel("telegram", body, labelled(buttons, "text", "url"),
                            {"token": match.group(1), "chat_id": body["chat_id"], "text": body["text"]},
                            answer={"ok": True, "result": {"message_id": 1}})

    def teams(self, body):
        attachment = body["attachments"][0]
        if body.get("type") != "message" or attachment["contentType"] != "application/vnd.microsoft.card.adaptive":
            raise Wrong("expected a message with an Adaptive Card")
        card = attachment["content"]
        actions = [a for a in card["actions"] if a["type"] == "Action.OpenUrl"]
        return self.channel("teams", body, labelled(actions, "title", "url"),
                            {"version": card["version"]}, status=202)

    def gchat(self, body):
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        if "key" not in query or "token" not in query:
            raise Wrong("the webhook URL lost its key and token")
        widgets = [w for section in body["cardsV2"][0]["card"]["sections"] for w in section["widgets"]]
        buttons = [b for w in widgets if "buttonList" in w for b in w["buttonList"]["buttons"]]
        links = {b["text"]: b["onClick"]["openLink"]["url"] for b in buttons}
        return self.channel("gchat", body, pick(links), answer={"name": "spaces/AAAA/messages/1"})

    def mattermost(self, body):
        links = dict(re.findall(r"\[(Approve|Deny)\]\(([^)\s]+)\)", body["text"]))
        return self.channel("mattermost", body, pick(links), {"channel": body.get("channel")})

    def pagerduty(self, body):
        if self.path != "/pagerduty/v2/enqueue" or not body.get("routing_key"):
            raise Wrong("expected an event with a routing key")
        if body["event_action"] == "resolve":
            log({"service": "pagerduty", "resolved": body["dedup_key"], "routing_key": body["routing_key"]})
            return self.reply(202, {"status": "success", "dedup_key": body["dedup_key"]})
        if len(body["payload"]["summary"]) > 1024 or body["payload"]["severity"] not in ("critical", "error", "warning", "info"):
            raise Wrong("the payload breaks the Events API's limits")
        links = {l["text"]: l["href"] for l in body["links"]}
        return self.channel("pagerduty", body, pick(links),
                            {"routing_key": body["routing_key"], "dedup_key": body["dedup_key"]},
                            status=202, answer={"status": "success", "message": "Event processed", "dedup_key": body["dedup_key"]})

    def opsgenie(self, body):
        auth = self.headers.get("authorization") or ""
        if not auth.startswith("GenieKey "):
            raise Wrong("Opsgenie takes the key as GenieKey")
        close = re.fullmatch(r"/opsgenie/v2/alerts/([^/?]+)/close\?identifierType=alias", self.path)
        if close:
            log({"service": "opsgenie", "closed": close.group(1), "note": body.get("note")})
            return self.reply(202, {"result": "Request will be processed", "requestId": "mock"})
        if self.path != "/opsgenie/v2/alerts" or len(body["message"]) > 130:
            raise Wrong("expected a new alert with a short message")
        details = body["details"]
        links = {"Approve": details["approve_url"], "Deny": details["deny_url"]}
        return self.channel("opsgenie", body, pick(links), {"auth": auth, "alias": body["alias"]},
                            status=202, answer={"result": "Request will be processed", "requestId": "mock"})


def labelled(items, label, url):
    """Approve and Deny links from a list of buttons or actions."""
    return pick({i[label]: i[url] for i in items})


def pick(links):
    out = {}
    if "Approve" in links:
        out["allow"] = links["Approve"]
    if "Deny" in links:
        out["deny"] = links["Deny"]
    return out


CHANNELS = {
    "discord": Handler.discord,
    "telegram": Handler.telegram,
    "teams": Handler.teams,
    "gchat": Handler.gchat,
    "mattermost": Handler.mattermost,
    "pagerduty": Handler.pagerduty,
    "opsgenie": Handler.opsgenie,
}

# How each service turns a message away.
REJECT = {
    "discord": lambda h: h.reply(400, {"message": "Invalid Form Body", "code": 50035}),
    "telegram": lambda h: h.reply(400, {"ok": False, "error_code": 400, "description": "Bad Request: mock telegram rejected it"}),
    "teams": lambda h: h.reply(400, {"error": {"code": "TriggerInputSchemaMismatch", "message": "mock teams rejected it"}}),
    "gchat": lambda h: h.reply(400, {"error": {"code": 400, "message": "mock google chat rejected it", "status": "INVALID_ARGUMENT"}}),
    "mattermost": lambda h: h.reply(400, {"message": "mock mattermost rejected it"}),
    "pagerduty": lambda h: h.reply(400, {"status": "invalid event", "message": "Event object is invalid"}),
    "opsgenie": lambda h: h.reply(422, {"message": "mock opsgenie rejected it"}),
}


class Smtp(socketserver.StreamRequestHandler):
    """Just enough SMTP to take a message: no TLS, AUTH PLAIN or LOGIN."""

    def say(self, line):
        self.wfile.write((line + "\r\n").encode())

    def handle(self):
        try:
            self.converse()
        except OSError:
            pass  # the client hung up

    def converse(self):
        self.say("220 mock-smtp ready")
        user, sender, recipients = None, None, []
        while line := self.rfile.readline():
            command = line.decode().rstrip("\r\n")
            verb = command.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                self.wfile.write(b"250-mock-smtp\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
            elif verb == "AUTH":
                user = self.auth(command.split()[1:])
            elif verb == "MAIL":
                sender = command.split(":", 1)[1].strip()
                self.say("250 OK")
            elif verb == "RCPT":
                recipients.append(command.split(":", 1)[1].strip())
                self.say("250 OK")
            elif verb == "DATA":
                self.say("354 end with <CRLF>.<CRLF>")
                self.message(self.data(), user, sender, recipients)
            elif verb == "QUIT":
                self.say("221 bye")
                return
            else:
                self.say("250 OK")

    def auth(self, args):
        if args[0].upper() == "PLAIN":
            if len(args) < 2:
                self.say("334 ")
                args.append(self.rfile.readline().strip().decode())
            user = base64.b64decode(args[1]).decode().split("\0")[1]
        else:
            self.say("334 VXNlcm5hbWU6")
            user = base64.b64decode(self.rfile.readline().strip()).decode()
            self.say("334 UGFzc3dvcmQ6")
            self.rfile.readline()
        self.say("235 2.7.0 Authentication successful")
        return user

    def data(self):
        lines = []
        while (line := self.rfile.readline()) not in (b".\r\n", b""):
            lines.append(line[1:] if line.startswith(b"..") else line)
        return b"".join(lines)

    def message(self, raw, user, sender, recipients):
        if b"reject-me" in raw:
            log({"service": "email", "rejected": True})
            return self.say("554 5.6.0 mock smtp rejected it")
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        text = msg.get_body(preferencelist=("plain",)).get_content().replace("\r\n", "\n")
        page = msg.get_body(preferencelist=("html",)).get_content()
        links = pick(dict(re.findall(r"^(Approve|Deny): (\S+)$", text, re.M)))
        hrefs = [html.unescape(h) for h in re.findall(r'href="([^"]+)"', page)]
        entry = {"service": "email", "auth": user, "from": sender, "to": recipients,
                 "subject": str(msg["subject"]), "type": msg.get_content_type(), "links": links}
        if msg.get_content_type() != "multipart/alternative" or set(links) != {"allow", "deny"} \
                or not all(l in hrefs for l in links.values()):
            entry["wrong"] = "expected text and HTML parts with the same Approve and Deny links"
        log(entry)
        self.say("250 2.0.0 OK")


if SMTP_PORT:
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    smtp = socketserver.ThreadingTCPServer(("127.0.0.1", SMTP_PORT), Smtp)
    threading.Thread(target=smtp.serve_forever, daemon=True).start()
ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
