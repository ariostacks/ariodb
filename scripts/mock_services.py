"""Local stand-ins for Slack, the model providers' APIs (Anthropic, OpenAI,
Gemini, Azure OpenAI and an OpenAI-compatible server) and a webhook
receiver, so the end-to-end tests exercise every approver type without real
accounts.

The model endpoints check what ariodb sends (the auth header, a JSON schema
for the answer, the SQL passed as JSON data) and answer 400 when it is
wrong. They decide on the SQL: "deny-me" denies, "refuse-me" refuses,
"explode" is a 500, "unavailable-503" a 503 with Retry-After, and anything
else is allowed.

Run: python3 -I mock_services.py <port> <log-file>
"""
import json
import sys
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
LOG = sys.argv[2]
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


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
