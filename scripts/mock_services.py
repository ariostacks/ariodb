"""Local stand-ins for Slack, the Anthropic API and a webhook receiver, so
the end-to-end tests exercise every approver type without real accounts.

Run: python3 -I mock_services.py <port> <log-file>
"""
import json
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1])
LOG = sys.argv[2]
lock = threading.Lock()


def log(entry):
    with lock, open(LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
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


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
