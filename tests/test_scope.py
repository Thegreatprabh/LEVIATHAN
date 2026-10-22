import json

import pytest

from leviathan.scope import Scope, ScopeError, ScopeViolation, sign_scope

KEY = "unit-test-key"
BASE = {"org": "Acme", "operator": "op@acme", "expires": "2099-01-01",
        "mode": "lab", "targets": ["127.0.0.1", "10.0.0.0/24", "*.lab.local"],
        "exclude": ["10.0.0.53"], "crown_jewels": ["payments-db"]}


def signed(**over):
    data = dict(BASE)
    data.update(over)
    return sign_scope(data, KEY)


def test_valid_scope_verifies_and_authorizes():
    s = Scope(signed(), KEY)
    s.verify()
    s.authorize("127.0.0.1")
    s.authorize("127.0.0.1:8771")       # port stripped
    s.authorize("10.0.0.9")            # CIDR
    s.authorize("web.lab.local")       # wildcard


def test_out_of_scope_refused():
    s = Scope(signed(), KEY)
    with pytest.raises(ScopeViolation):
        s.authorize("8.8.8.8")
    with pytest.raises(ScopeViolation):
        s.authorize("evil.com")


def test_excluded_host_refused_even_inside_cidr():
    s = Scope(signed(), KEY)
    with pytest.raises(ScopeViolation):
        s.authorize("10.0.0.53")


def test_tampered_scope_fails_signature():
    data = signed()
    data["targets"] = ["0.0.0.0/0"]     # attacker widens the scope
    with pytest.raises(ScopeError):
        Scope(data, KEY).verify()


def test_wrong_key_fails():
    with pytest.raises(ScopeError):
        Scope(signed(), "another-key").verify()


def test_expired_scope_fails():
    with pytest.raises(ScopeError):
        Scope(signed(expires="2000-01-01"), KEY).verify()


def test_unsigned_scope_fails():
    data = dict(BASE)                   # no signature at all
    with pytest.raises(ScopeError):
        Scope(data, KEY).verify()


def test_load_roundtrip(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(signed()))
    s = Scope.load(str(p), key=KEY)
    assert s.mode == "lab" and s.crown_jewels == ["payments-db"]
