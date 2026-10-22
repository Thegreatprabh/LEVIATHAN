"""End-to-end: the demo campaign proves the lab chain, unattended."""

import pytest

from leviathan.campaign import run_campaign
from leviathan.graph import Graph
from leviathan.lab import Lab, default_inventory, default_scope
from leviathan.scope import Scope, ScopeViolation, sign_scope
from leviathan.vault import Vault

KEY = "lab-key"


@pytest.fixture()
def lab():
    inst = Lab({"webshop": 0, "filesrv": 0, "dbsvc": 0})
    ports = inst.up()
    yield inst, ports
    inst.down()


def _scope(**over):
    data = default_scope()
    data.update(over)
    return Scope(sign_scope(data, KEY), KEY)


def test_full_chain_proven(lab, tmp_path):
    inst, ports = lab
    graph = Graph.from_inventory(default_inventory(ports))
    vault = Vault(str(tmp_path / "v.db"))
    result = run_campaign(_scope(), graph, vault, campaign_id="cmp-test")
    assert result["reachable"] is True
    assert result["proven"] is True
    assert result["crown_marker"] == "CROWN-JEWEL-CANARY-9d2e"
    proofs = [s["proof"] for s in result["steps"]]
    assert proofs == ["LIKELY", "CONFIRMED", "CONFIRMED"]
    ok, _ = vault.verify()
    assert ok
    assert len(vault.records("cmp-test")) == 5  # plan + 3 steps + result


def test_out_of_scope_campaign_hard_stops(lab, tmp_path):
    inst, ports = lab
    graph = Graph.from_inventory(default_inventory(ports))
    vault = Vault(str(tmp_path / "v.db"))
    evil_scope = _scope(targets=["10.9.9.9"])  # lab hosts NOT in scope
    with pytest.raises(ScopeViolation):
        run_campaign(evil_scope, graph, vault)


def test_wrong_password_lab_would_fail(tmp_path):
    # No lab running at all: step 1 cannot even reach — campaign reports
    # the break honestly instead of claiming proof.
    graph = Graph.from_inventory(default_inventory(
        {"webshop": 1, "filesrv": 2, "dbsvc": 3}))
    vault = Vault(str(tmp_path / "v.db"))
    result = run_campaign(_scope(), graph, vault)
    assert result["proven"] is False
    assert result["steps"][0]["proof"] == "FAILED"
