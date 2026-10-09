"""Send a query, then cancel it from a second connection after a delay, the
way psql does on Ctrl-C. Prints the server's error message, if any.

Run: python3 -I pg_cancel.py <port> <user> <token> <sql> <seconds-before-cancel>
"""
import socket
import struct
import sys
import time

port, user, token, sql, delay = sys.argv[1:]
port = int(port)


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise SystemExit("connection closed")
        data += chunk
    return data


def recv(sock):
    tag = recv_exact(sock, 1)
    (length,) = struct.unpack("!i", recv_exact(sock, 4))
    return tag, recv_exact(sock, length - 4)


sock = socket.create_connection(("127.0.0.1", port), timeout=30)
params = b"user\0" + user.encode() + b"\0database\0app\0\0"
sock.sendall(struct.pack("!ii", len(params) + 8, 196608) + params)
key = None
while True:
    tag, body = recv(sock)
    if tag == b"R" and struct.unpack("!i", body[:4])[0] == 3:
        password = token.encode() + b"\0"
        sock.sendall(b"p" + struct.pack("!i", len(password) + 4) + password)
    elif tag == b"K":
        key = body[:8]
    elif tag == b"E":
        raise SystemExit("login failed")
    elif tag == b"Z":
        break

query = sql.encode() + b"\0"
sock.sendall(b"Q" + struct.pack("!i", len(query) + 4) + query)
time.sleep(float(delay))
cancel = socket.create_connection(("127.0.0.1", port), timeout=10)
cancel.sendall(struct.pack("!ii", 16, 80877102) + key)
cancel.close()

while True:
    tag, body = recv(sock)
    if tag == b"E":
        fields = dict((f[:1], f[1:]) for f in body.split(b"\0") if f)
        print("ERROR", fields.get(b"M", b"").decode())
    elif tag == b"Z":
        break
