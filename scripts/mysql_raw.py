"""A minimal MySQL protocol client, so the end-to-end tests can send what the
mysql client does not: prepared statements with parameters, a query
cancelled from a second connection, mysql_native_password logins.

Run: python3 -I mysql_raw.py <port> <user> <token> <action>...

Actions: Q:<sql>           COM_QUERY
         P:<sql>           COM_STMT_PREPARE (the statement becomes "current")
         X[:<param>...]    COM_STMT_EXECUTE the current statement with string parameters
         C                 COM_STMT_CLOSE the current statement
         R                 COM_RESET_CONNECTION
         CANCEL:<secs>:<sql>  COM_QUERY, then KILL QUERY it from a second connection
         S:<secs>          wait, keeping the session open
Prints one line per reply: OK <rows>, ROW <values>, ERROR <code> <message>,
PREPARED <params>, ID <connection id>.
"""
import hashlib
import socket
import struct
import sys
import time

port, user, token, *actions = sys.argv[1:]
port = int(port)

CLIENT_PROTOCOL_41 = 1 << 9
CLIENT_SECURE_CONNECTION = 1 << 15
CLIENT_PLUGIN_AUTH = 1 << 19
CLIENT_CONNECT_WITH_DB = 1 << 3
CLIENT_TRANSACTIONS = 1 << 13
CLIENT_DEPRECATE_EOF = 1 << 24
CAPS = (CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
        | CLIENT_CONNECT_WITH_DB | CLIENT_TRANSACTIONS | CLIENT_DEPRECATE_EOF | 1)


class Conn:
    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=60)
        self.seq = 0

    def recv_exact(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise SystemExit("connection closed")
            data += chunk
        return data

    def read(self):
        head = self.recv_exact(4)
        length = head[0] | head[1] << 8 | head[2] << 16
        self.seq = (head[3] + 1) % 256
        return self.recv_exact(length)

    def send(self, payload, seq=None):
        if seq is not None:
            self.seq = seq
        self.sock.sendall(struct.pack("<I", len(payload))[:3] + bytes([self.seq]) + payload)
        self.seq = (self.seq + 1) % 256

    def login(self):
        hello = self.read()
        version_end = hello.index(b"\0", 1)
        self.thread_id = struct.unpack("<I", hello[version_end + 1:version_end + 5])[0]
        pos = version_end + 5
        nonce = hello[pos:pos + 8]
        pos += 8 + 1 + 2 + 1 + 2 + 2 + 1 + 10
        nonce += hello[pos:pos + 12]
        # mysql_native_password: SHA1(pw) XOR SHA1(nonce + SHA1(SHA1(pw)))
        h1 = hashlib.sha1(token.encode()).digest()
        h3 = hashlib.sha1(nonce + hashlib.sha1(h1).digest()).digest()
        scramble = bytes(a ^ b for a, b in zip(h1, h3))
        body = struct.pack("<IIB", CAPS, 1 << 24, 45) + b"\0" * 23
        body += user.encode() + b"\0" + bytes([len(scramble)]) + scramble
        body += b"app\0mysql_native_password\0"
        self.send(body)
        reply = self.read()
        if reply[0] == 0xFF:
            show_error(reply)
            raise SystemExit(1)

    def command(self, payload):
        self.send(payload, seq=0)


def lenenc(buf, pos):
    first = buf[pos]
    if first < 251:
        return first, pos + 1
    if first == 0xFB:
        return None, pos + 1
    if first == 0xFC:
        return struct.unpack("<H", buf[pos + 1:pos + 3])[0], pos + 3
    if first == 0xFD:
        return int.from_bytes(buf[pos + 1:pos + 4], "little"), pos + 4
    return struct.unpack("<Q", buf[pos + 1:pos + 9])[0], pos + 9


def show_error(p):
    code = struct.unpack("<H", p[1:3])[0]
    print("ERROR", code, p[9:].decode(errors="replace"))


def read_result(c, binary):
    """Print a reply to COM_QUERY or COM_STMT_EXECUTE."""
    p = c.read()
    if p[0] == 0x00:
        rows, _ = lenenc(p, 1)
        print("OK", rows)
        return
    if p[0] == 0xFF:
        show_error(p)
        return
    columns, _ = lenenc(p, 0)
    types = []
    for _ in range(columns):
        col = c.read()
        pos = 0
        for _ in range(6):  # catalog, schema, table, org_table, name, org_name
            n, pos = lenenc(col, pos)
            pos += n
        pos += 1 + 2 + 4  # length of fixed fields, charset, column length
        types.append(col[pos])
    while True:
        p = c.read()
        if p[0] == 0xFE and len(p) < 0xFFFFFF:
            break
        if p[0] == 0xFF:
            show_error(p)
            return
        values = []
        if binary:
            nulls = p[1:1 + (columns + 7 + 2) // 8]
            pos = 1 + len(nulls)
            for i, t in enumerate(types):
                if nulls[(i + 2) // 8] & (1 << ((i + 2) % 8)):
                    values.append("NULL")
                elif t == 8:  # LONGLONG
                    values.append(str(struct.unpack("<q", p[pos:pos + 8])[0]))
                    pos += 8
                elif t == 3:  # LONG
                    values.append(str(struct.unpack("<i", p[pos:pos + 4])[0]))
                    pos += 4
                else:
                    n, pos = lenenc(p, pos)
                    values.append(p[pos:pos + n].decode(errors="replace"))
                    pos += n
        else:
            pos = 0
            while pos < len(p):
                n, pos = lenenc(p, pos)
                if n is None:
                    values.append("NULL")
                else:
                    values.append(p[pos:pos + n].decode(errors="replace"))
                    pos += n
        print("ROW", " | ".join(values))


def query(c, sql):
    c.command(b"\x03" + sql.encode())
    read_result(c, binary=False)


conn = Conn()
conn.login()
print("ID", conn.thread_id)
current = None
params = 0
for action in actions:
    kind, _, rest = action.partition(":")
    if kind == "Q":
        query(conn, rest)
    elif kind == "P":
        conn.command(b"\x16" + rest.encode())
        p = conn.read()
        if p[0] == 0xFF:
            show_error(p)
            continue
        current, columns, params = struct.unpack("<IHH", p[1:9])
        # Parameter and column definitions follow (no EOFs: DEPRECATE_EOF).
        for _ in range(params + columns):
            conn.read()
        print("PREPARED", params)
    elif kind == "X":
        values = rest.split(":") if rest else []
        body = b"\x17" + struct.pack("<IBI", current or 0, 0, 1)
        if params:
            body += b"\0" * ((params + 7) // 8) + b"\x01"
            body += b"\xfe\x00" * params  # all strings
            for v in values:
                data = v.encode()
                body += bytes([len(data)]) + data
        conn.command(body)
        read_result(conn, binary=True)
    elif kind == "C":
        conn.command(b"\x19" + struct.pack("<I", current or 0))
    elif kind == "R":
        conn.command(b"\x1f")
        read_result(conn, binary=False)
    elif kind == "S":
        time.sleep(float(rest))
    elif kind == "CANCEL":
        delay, _, sql = rest.partition(":")
        conn.command(b"\x03" + sql.encode())
        time.sleep(float(delay))
        killer = Conn()
        killer.login()
        killer.command(b"\x03" + f"KILL QUERY {conn.thread_id}".encode())
        read_result(killer, binary=False)
        read_result(conn, binary=False)
    else:
        raise SystemExit(f"unknown action {action}")
conn.command(b"\x01")
