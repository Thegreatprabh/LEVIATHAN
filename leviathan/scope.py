"""ScopeLock: the signed authorization manifest every action passes through.

A scope is a JSON document:
  {org, operator, expires (YYYY-MM-DD), mode: lab|observe,
   targets: [host | CIDR | host:port ...], exclude: [...],
   crown_jewels: [asset-id ...], signature: <hmac-sha256 hex>}

The signature covers the canonical JSON of every field except itself,
keyed by the operator key (env LEVIATHAN_SCOPE_KEY or an explicit key).
Verification checks signature AND expiry. `authorize()` is the single
choke point: the validator and campaign engine call it before any probe
is constructed; an out-of-scope target raises ScopeViolation — there is
no code path around it.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
from datetime import date


class ScopeViolation(Exception):
    """Raised when an action would leave the signed scope. Hard stop."""


class ScopeError(ValueError):
    """Raised for malformed, unsigned, tampered or expired scopes."""


def _canonical(scope: dict) -> bytes:
    body = {k: v for k, v in scope.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def sign_scope(scope: dict, key: str) -> dict:
    out = dict(scope)
    out["signature"] = hmac.new(key.encode(), _canonical(scope),
                                hashlib.sha256).hexdigest()
    return out


def get_key(explicit: str | None = None) -> str:
    key = explicit or os.environ.get("LEVIATHAN_SCOPE_KEY", "")
    if not key:
        raise ScopeError("no scope key: set LEVIATHAN_SCOPE_KEY or pass --key")
    return key


class Scope:
    def __init__(self, data: dict, key: str):
        self.data = data
        self._key = key

    # -- loading / verification -------------------------------------------

    @classmethod
    def load(cls, path: str, key: str | None = None) -> "Scope":
        with open(path) as fh:
            data = json.load(fh)
        scope = cls(data, get_key(key))
        scope.verify()
        return scope

    def verify(self) -> None:
        data = self.data
        for field in ("org", "operator", "expires", "mode", "targets",
                      "crown_jewels", "signature"):
            if field not in data:
                raise ScopeError(f"scope missing field {field!r}")
        expected = hmac.new(self._key.encode(), _canonical(data),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, str(data["signature"])):
            raise ScopeError("scope signature invalid — tampered or wrong key")
        if data["mode"] not in ("lab", "observe"):
            raise ScopeError(f"unknown scope mode {data['mode']!r}")
        try:
            expires = date.fromisoformat(str(data["expires"]))
        except ValueError:
            raise ScopeError("expires must be YYYY-MM-DD") from None
        if date.today() > expires:
            raise ScopeError(f"scope expired on {data['expires']}")

    # -- authorization choke point ------------------------------------------

    def _matches(self, patterns: list[str], host: str) -> bool:
        for pat in patterns:
            pat = str(pat).strip()
            if pat == host:
                return True
            if "/" in pat:  # CIDR
                try:
                    net = ipaddress.ip_network(pat, strict=False)
                    if ipaddress.ip_address(host) in net:
                        return True
                except ValueError:
                    continue
            if pat.startswith("*.") and host.endswith(pat[1:]):
                return True
        return False

    def authorize(self, host: str) -> None:
        """Raise ScopeViolation unless `host` is in scope and not excluded."""
        host = str(host).split(":")[0]  # strip port
        if self._matches(list(self.data.get("exclude", [])), host):
            raise ScopeViolation(f"{host} is explicitly excluded by scope")
        if not self._matches(list(self.data["targets"]), host):
            raise ScopeViolation(f"{host} is outside the signed scope")

    def allows_asset(self, asset_host: str) -> bool:
        try:
            self.authorize(asset_host)
            return True
        except ScopeViolation:
            return False

    @property
    def mode(self) -> str:
        return str(self.data["mode"])

    @property
    def crown_jewels(self) -> list[str]:
        return list(self.data["crown_jewels"])
