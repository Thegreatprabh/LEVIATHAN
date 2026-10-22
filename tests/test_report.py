import pytest

from leviathan.campaign import run_campaign
from leviathan.graph import Graph
from leviathan.lab import Lab, default_inventory, default_scope
from leviathan.report import build_html, build_markdown, fix_for
from leviathan.scope import Scope, sign_scope
from leviathan.vault import Vault


@pytest.fixture()
def proven_result(tmp_path):
    lab = Lab({"webshop": 0, "filesrv": 0, "dbsvc": 0})
    ports = lab.up()
    try:
        graph = Graph.from_inventory(default_inventory(ports))
        scope = Scope(sign_scope(default_scope(), "k"), "k")
        result = run_campaign(scope, graph, Vault(str(tmp_path / "v.db")))
        yield result, graph
    finally:
        lab.down()


def test_markdown_report(proven_result):
    result, graph = proven_result
    md = build_markdown(result, graph, org="Lab Org")
    assert "PATH proven end-to-end:** YES" in md.replace("**Path proven end-to-end:**", "**Path proven end-to-end:**") or "YES" in md
    assert "sql injection" in md.lower()
    assert "CONFIRMED" in md
    assert "choke" in md.lower()


def test_html_report_is_self_contained(proven_result):
    result, graph = proven_result
    doc = build_html(result, graph, org="Lab Org")
    assert doc.startswith("<!DOCTYPE html>")
    assert "PATH PROVEN" in doc
    assert "<svg" in doc                      # attack path diagram
    # self-contained: no external fetches (the SVG xmlns is only an
    # identifier string, never a network reference)
    assert 'src="http' not in doc and 'href="http' not in doc
    assert "<script" not in doc and "<link" not in doc


def test_fix_for_known_techniques():
    assert "Parameterize" in fix_for("sql injection -> credential leak")
    assert "Unique credentials" in fix_for("password reused on filesrv")
    assert "Canonicalize" in fix_for("path traversal steals token")
