"""A minimal Postgres extended-protocol client, so the end-to-end tests can
send message sequences no driver would (closing someone else's statement,
a batch that fails half way).

Run: python3 -I pg_raw.py <port> <user> <token> <message>...

Messages: P:<name>:<sql>  B:<portal>:<statement>  E:<portal>  C:S:<name>
          C:P:<name>  S (Sync). Prints one line per server reply.
"""
import socket
import struct
import sys

port, user, token, *messages = sys.argv[1:]
sock = socket.create_connection(("127.0.0.1", int(port)), timeout=15)


def send(tag, body):
    sock.sendall(tag + struct.pack("!i", len(body) + 4) + body)


def recv_exact(n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise SystemExit("connection closed")
        data += chunk
    return data


def recv():
    tag = recv_exact(1)
    (length,) = struct.unpack("!i", recv_exact(4))
    return tag, recv_exact(length - 4)


def cstr(s):
    return s.encode() + b"\0"


def show(tag, body):
    if tag == b"E":
        fields = dict((f[:1], f[1:].decode()) for f in body.split(b"\0") if f)
        print("ERROR:", fields.get(b"M", "?"))
    elif tag == b"C":
        print("TAG:", body.rstrip(b"\0").decode())
    elif tag == b"Z":
        print("READY", body.decode())
    else:
        print("MSG", tag.decode())


startup = struct.pack("!i", 196608) + cstr("user") + cstr(user) + cstr("database") + cstr("app") + b"\0"
sock.sendall(struct.pack("!i", len(startup) + 4) + startup)
while True:
    tag, body = recv()
    if tag == b"R" and struct.unpack("!i", body[:4])[0] == 3:
        send(b"p", cstr(token))
    elif tag == b"E":
        show(tag, body)
        raise SystemExit(1)
    elif tag == b"Z":
        break

syncs = 0
for m in messages:
    kind, _, rest = m.partition(":")
    if kind == "P":
        name, _, sql = rest.partition(":")
        send(b"P", cstr(name) + cstr(sql) + struct.pack("!h", 0))
    elif kind == "B":
        portal, _, statement = rest.partition(":")
        send(b"B", cstr(portal) + cstr(statement) + struct.pack("!hhh", 0, 0, 0))
    elif kind == "E":
        send(b"E", cstr(rest) + struct.pack("!i", 0))
    elif kind == "C":
        what, _, name = rest.partition(":")
        send(b"C", what.encode() + cstr(name))
    elif kind == "S":
        send(b"S", b"")
        syncs += 1
    else:
        raise SystemExit(f"unknown message {m}")

while syncs:
    tag, body = recv()
    show(tag, body)
    if tag == b"Z":
        syncs -= 1
send(b"X", b"")
