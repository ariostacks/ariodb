"""Connection limits, seen from the client side, for the end-to-end tests.

Run: python3 -I conn_limits.py <check> <port> ...

  slow <port> <timeout-ms>
      Connect and send nothing (reading whatever the server says first).
      Prints "cut off in time" if ariodb closes the connection within half a
      second either side of the handshake timeout plus scheduling slack.
  pg <port> <agent> <token> <other-agent> <other-token>
      For a listener with max_connections = 3 and max_connections_per_agent
      = 2: fills the agent's places, then the listener's, and prints what
      each refused client was told, and whether an open session still works.
  mysql-full <port> <places>
      Holds <places> connections in their handshake, then prints what the
      next client is told.
  http-full <port> <places>
      Holds <places> idle connections, then prints the status line and body
      of the next request.
"""
import socket
import struct
import sys
import time


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data += chunk
    return data


def connect(port):
    return socket.create_connection(("127.0.0.1", int(port)), timeout=20)


def slow(port, timeout_ms):
    expected = int(timeout_ms) / 1000
    sock = connect(port)
    started = time.monotonic()
    try:
        while sock.recv(4096):
            pass  # a greeting (MySQL speaks first); keep waiting
    except OSError:
        pass
    took = time.monotonic() - started
    if expected - 0.5 <= took <= expected + 2:
        print("cut off in time")
    else:
        print(f"cut off after {took:.1f} s, expected about {expected:.1f} s")


# Postgres -------------------------------------------------------------------

def pg_recv(sock):
    tag = recv_exact(sock, 1)
    (length,) = struct.unpack("!i", recv_exact(sock, 4))
    return tag, recv_exact(sock, length - 4)


def pg_error(body):
    fields = dict((f[:1], f[1:].decode()) for f in body.split(b"\0") if f)
    return f"{fields.get(b'C', '?')} {fields.get(b'M', '?')}"


def pg_login(port, user, token):
    """A logged-in session, or the error that refused it."""
    sock = connect(port)
    params = b"user\0" + user.encode() + b"\0database\0app\0\0"
    sock.sendall(struct.pack("!ii", len(params) + 8, 196608) + params)
    try:
        while True:
            tag, body = pg_recv(sock)
            if tag == b"R" and struct.unpack("!i", body[:4])[0] == 3:
                password = token.encode() + b"\0"
                sock.sendall(b"p" + struct.pack("!i", len(password) + 4) + password)
            elif tag == b"E":
                sock.close()
                return None, pg_error(body)
            elif tag == b"Z":
                return sock, None
    except ConnectionError as e:
        return None, f"closed {e}"


def pg_query(sock, sql):
    query = sql.encode() + b"\0"
    sock.sendall(b"Q" + struct.pack("!i", len(query) + 4) + query)
    value = None
    while True:
        tag, body = pg_recv(sock)
        if tag == b"D":
            (length,) = struct.unpack("!i", body[2:6])
            value = body[6:6 + length].decode()
        elif tag == b"E":
            value = "error " + pg_error(body)
        elif tag == b"Z":
            return value


def pg(port, agent, token, other, other_token):
    first, _ = pg_login(port, agent, token)
    second, _ = pg_login(port, agent, token)
    if not (first and second):
        raise SystemExit("the agent could not open two sessions")
    _, why = pg_login(port, agent, token)
    print(f"third session for {agent}: {why}")
    time.sleep(0.3)  # for ariodb to give that connection's place back
    other_session, why = pg_login(port, other, other_token)
    if not other_session:
        raise SystemExit(f"{other} could not log in: {why}")
    # The listener is full: a burst of clients is refused.
    refusals = [pg_login(port, other, other_token)[1] for _ in range(5)]
    for why in sorted(set(refusals)):
        print(f"burst: {refusals.count(why)} x {why}")
    print(f"open session still works: {pg_query(first, 'SELECT 41 + 1')}")
    for s in (first, second, other_session):
        s.sendall(b"X" + struct.pack("!i", 4))
        s.close()
    time.sleep(0.3)
    again, why = pg_login(port, agent, token)
    print("after closing, a new session logs in" if again else f"after closing: {why}")
    if again:
        again.close()


# MySQL ----------------------------------------------------------------------

def mysql_first_packet(sock):
    head = recv_exact(sock, 4)
    length = head[0] | head[1] << 8 | head[2] << 16
    return recv_exact(sock, length)


def mysql_full(port, places):
    held = []
    for _ in range(int(places)):
        s = connect(port)
        mysql_first_packet(s)  # the handshake: this place is taken
        held.append(s)
    s = connect(port)
    p = mysql_first_packet(s)
    if p[0] == 0xFF:
        code = struct.unpack("<H", p[1:3])[0]
        print(f"ERROR {code} ({p[4:9].decode()}): {p[9:].decode()}")
    else:
        print("handshake: not refused")
    for h in held + [s]:
        h.close()


# HTTP -----------------------------------------------------------------------

def http_full(port, places):
    held = [connect(port) for _ in range(int(places))]
    time.sleep(0.2)
    s = connect(port)
    s.sendall(b"POST / HTTP/1.1\r\nhost: ariodb\r\ncontent-length: 8\r\nconnection: close\r\n\r\nSELECT 1")
    reply = b""
    try:
        while chunk := s.recv(4096):
            reply += chunk
    except OSError:
        pass
    head, _, body = reply.decode(errors="replace").partition("\r\n\r\n")
    print(head.splitlines()[0] if head else "no reply")
    print(body.strip())
    for h in held + [s]:
        h.close()


check, *args = sys.argv[1:]
{"slow": slow, "pg": pg, "mysql-full": mysql_full, "http-full": http_full}[check](*args)
