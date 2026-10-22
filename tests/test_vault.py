from leviathan.vault import Vault


def test_chain_verifies(tmp_path):
    v = Vault(str(tmp_path / "v.db"))
    v.add("c1", "plan", {"a": 1})
    v.add("c1", "step-evidence", {"b": 2})
    ok, msg = v.verify()
    assert ok, msg
    assert len(v.records()) == 3 - 1


def test_tamper_breaks_chain(tmp_path):
    path = str(tmp_path / "v.db")
    v = Vault(path)
    v.add("c1", "plan", {"a": 1})
    v.add("c1", "step-evidence", {"b": 2})
    v.db.execute("UPDATE records SET payload = ? WHERE id = 1",
                 ('{"a": 999}',))
    v.db.commit()
    ok, msg = v.verify()
    assert not ok and "tampered" in msg


def test_records_are_campaign_scoped(tmp_path):
    v = Vault(str(tmp_path / "v.db"))
    v.add("c1", "plan", {"a": 1})
    v.add("c2", "plan", {"a": 2})
    assert len(v.records("c1")) == 1 and len(v.records("c2")) == 1
