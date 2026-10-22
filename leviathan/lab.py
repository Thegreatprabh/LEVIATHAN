"""The Lab Range: a miniature, deliberately vulnerable organisation.

Three tiny services, all data synthetic and canary-marked:

  webshop  — product search with a real SQL injection flaw; its users
             table holds a service account with a guessable-by-design
             password (canary credentials, fake people).
  filesrv  — file download behind login. The SAME service password was
             reused here (the classic enterprise sin), and the download
             handler has a path-traversal flaw into a "vault" folder
             holding the database API token.
  dbsvc    — the payments database API. With the stolen token it happily
             returns the crown-jewel canary record.

The intended attack chain (what LEVIATHAN must find and prove):
  internet → webshop (SQLi → creds) → filesrv (cred reuse + traversal
  → db token) → dbsvc (token → crown-jewel canary record).
"""

from __future__ import annotations

import json
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DB_TOKEN = "leviathan-canary-token-7f3a"
CROWN_CANARY = "CROWN-JEWEL-CANARY-9d2e"
SVC_USER, SVC_PASS = "svc_backup", "Bckup!234"
DEFAULT_PORTS = {"webshop": 8771, "filesrv": 8772, "dbsvc": 8773}


# -- webshop -----------------------------------------------------------------

def _webshop_handler():
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE products (id INTEGER, name TEXT, price REAL)")
    db.executemany("INSERT INTO products VALUES (?, ?, ?)",
                   [(1, "Canary Widget", 9.99), (2, "Synthetic Gadget", 19.5)])
    db.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
    db.executemany("INSERT INTO users VALUES (?, ?, ?)",
                   [(1, "admin", "Adm1n!canary"), (2, SVC_USER, SVC_PASS),
                    (3, "guest", "guest")])
    db.commit()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/product":
                pid = parse_qs(u.query).get("id", ["0"])[0]
                # DELIBERATELY VULNERABLE: string-formatted SQL (lab only).
                query = f"SELECT name, price FROM products WHERE id = {pid}"
                try:
                    rows = db.execute(query).fetchall()
                    body = "\n".join(f"{n} | {p}" for n, p in rows) or "no results"
                except Exception as exc:
                    body = f"sql error: {exc}"
                return self._send(body)
            return self._send("Lab Webshop — try /product?id=1")

        def _send(self, body, code=200):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return H


# -- filesrv -------------------------------------------------------------------

def _filesrv_handler():
    public = {"readme.txt": "Lab file server — public folder."}
    vault = {"db_token.txt": f"DB_API_TOKEN={DB_TOKEN}\n"}
    sessions: set[str] = set()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            if urlparse(self.path).path == "/login":
                length = int(self.headers.get("Content-Length", 0))
                creds = json.loads(self.rfile.read(length) or b"{}")
                if (creds.get("username") == SVC_USER
                        and creds.get("password") == SVC_PASS):
                    token = "sess-canary-42"
                    sessions.add(token)
                    return self._send("ok", cookie=token)
                return self._send("bad credentials", code=401)
            return self._send("not found", code=404)

        def do_GET(self):
            u = urlparse(self.path)
            if u.path == "/download":
                cookie = self.headers.get("Cookie", "")
                if "session=sess-canary-42" not in cookie:
                    return self._send("login required", code=401)
                name = parse_qs(u.query).get("name", [""])[0]
                # DELIBERATELY VULNERABLE: ../ escapes the public folder.
                if name.startswith("../vault/"):
                    key = name[len("../vault/"):]
                    if key in vault:
                        return self._send(vault[key])
                    return self._send("no such file", code=404)
                if name in public:
                    return self._send(public[name])
                return self._send("no such file", code=404)
            return self._send("Lab File Server — POST /login, GET /download")

        def _send(self, body, code=200, cookie=None):
            data = body.encode()
            self.send_response(code)
            if cookie:
                self.send_header("Set-Cookie", f"session={cookie}")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return H


# -- dbsvc ---------------------------------------------------------------------

def _dbsvc_handler():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            if urlparse(self.path).path == "/record":
                if self.headers.get("Authorization") != f"Bearer {DB_TOKEN}":
                    return self._send('{"error": "unauthorized"}', code=401)
                return self._send(json.dumps({
                    "table": "payments",
                    "record": {"id": "PAY-0001", "amount": 499.00,
                               "currency": "INR", "holder": "CANARY CUSTOMER",
                               "marker": CROWN_CANARY}}))
            return self._send("Lab DB Service — GET /record (Bearer token)")

        def _send(self, body, code=200):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return H


# -- lab manager -----------------------------------------------------------------

class Lab:
    """Runs the three lab services on localhost (ephemeral or fixed ports)."""

    MAKERS = {"webshop": _webshop_handler, "filesrv": _filesrv_handler,
              "dbsvc": _dbsvc_handler}

    def __init__(self, ports: dict | None = None):
        self.requested = dict(ports or DEFAULT_PORTS)
        self.servers: dict[str, ThreadingHTTPServer] = {}
        self.ports: dict[str, int] = {}

    def up(self) -> dict[str, int]:
        for name, maker in self.MAKERS.items():
            srv = ThreadingHTTPServer(("127.0.0.1", self.requested[name]), maker())
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.servers[name] = srv
            self.ports[name] = srv.server_address[1]
        return dict(self.ports)

    def down(self) -> None:
        for srv in self.servers.values():
            srv.shutdown()
            srv.server_close()
        self.servers.clear()

    def base(self, name: str) -> str:
        return f"http://127.0.0.1:{self.ports[name]}"


def default_inventory(ports: dict | None = None) -> dict:
    """The lab described as an organisation: assets + attack edges."""
    p = dict(ports or DEFAULT_PORTS)
    web = f"http://127.0.0.1:{p['webshop']}"
    files = f"http://127.0.0.1:{p['filesrv']}"
    db = f"http://127.0.0.1:{p['dbsvc']}"
    return {
        "assets": [
            {"id": "internet", "kind": "entry", "label": "Internet (attacker start)"},
            {"id": "webshop", "kind": "webapp", "host": "127.0.0.1",
             "label": "Lab Webshop"},
            {"id": "filesrv", "kind": "service", "host": "127.0.0.1",
             "label": "Lab File Server"},
            {"id": "payments-db", "kind": "db", "host": "127.0.0.1",
             "label": "Payments DB (canary data)", "value": 100, "crown": True},
        ],
        "edges": [
            {"src": "internet", "dst": "webshop", "technique": "public https reach",
             "cost": 0.05, "grants": ["reach:webshop"], "check": "http-reach",
             "params": {"target": web},
             "detail": "webshop is internet-facing"},
            {"src": "webshop", "dst": "filesrv",
             "technique": "sql injection harvests service credentials; password reused on filesrv",
             "cost": 0.3, "requires": ["reach:webshop"],
             "grants": ["session:filesrv"], "check": "sqli+reuse",
             "params": {"via": web, "target": files},
             "detail": "users table leaks svc_backup; same password logs into filesrv"},
            {"src": "filesrv", "dst": "payments-db",
             "technique": "path traversal steals db api token; token reads crown-jewel record",
             "cost": 0.2, "requires": ["session:filesrv"],
             "grants": ["crown-access"], "check": "traversal+token",
             "params": {"via": files, "target": db},
             "detail": "../vault/db_token.txt holds the payments API token"},
        ],
    }


def default_scope() -> dict:
    """Unsigned lab scope (sign it with `leviathan scope sign`)."""
    return {"org": "LEVIATHAN Lab Range", "operator": "lab@leviathan.local",
            "expires": "2099-12-31", "mode": "lab", "targets": ["127.0.0.1"],
            "exclude": [], "crown_jewels": ["payments-db"]}
