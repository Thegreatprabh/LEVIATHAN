import pytest

from leviathan.graph import Graph
from leviathan.planner import plan_campaign

# A tiny org: internet -> web -> (sqli) creds -> filesrv -> (token) db (crown)
#                     \-> vpn -> internal -> db (long way)
INV = {
    "assets": [
        {"id": "internet", "kind": "entry"},
        {"id": "web", "kind": "webapp", "host": "127.0.0.1"},
        {"id": "filesrv", "kind": "service", "host": "127.0.0.1"},
        {"id": "vpn", "kind": "service", "host": "127.0.0.1"},
        {"id": "internal", "kind": "host", "host": "127.0.0.1"},
        {"id": "payments-db", "kind": "db", "host": "127.0.0.1",
         "value": 100, "crown": True},
    ],
    "edges": [
        {"src": "internet", "dst": "web", "technique": "https reach",
         "cost": 0.05, "grants": ["reach:web"]},
        {"src": "web", "dst": "filesrv", "technique": "sql injection -> credential leak",
         "cost": 0.3, "requires": ["reach:web"], "grants": ["creds:svc"],
         "check": "sqli-canary"},
        {"src": "filesrv", "dst": "payments-db", "technique": "token reuse",
         "cost": 0.2, "requires": ["creds:svc"], "grants": ["crown-access"],
         "check": "token-canary"},
        {"src": "internet", "dst": "vpn", "technique": "vpn reach",
         "cost": 0.1, "grants": ["reach:vpn"]},
        {"src": "vpn", "dst": "internal", "technique": "weak vpn password",
         "cost": 0.6, "requires": ["reach:vpn"], "grants": ["reach:internal"]},
        {"src": "internal", "dst": "payments-db", "technique": "flat network",
         "cost": 0.5, "requires": ["reach:internal"],
         "grants": ["crown-access"]},
    ],
}


def g():
    return Graph.from_inventory(INV)


def test_best_path_uses_capability_chain():
    p = g().best_path("internet", "payments-db")
    assert p is not None
    assert p.assets == ["internet", "web", "filesrv", "payments-db"]
    assert p.total_cost == pytest.approx(0.55)


def test_capability_gate_blocks_shortcut():
    inv = {"assets": INV["assets"],
           "edges": [e for e in INV["edges"] if e["technique"] != "vpn reach"]}
    p = Graph.from_inventory(inv).best_path("internet", "payments-db")
    assert p.assets == ["internet", "web", "filesrv", "payments-db"]


def test_unreachable_goal_returns_none():
    inv = {"assets": INV["assets"][:2], "edges": INV["edges"][:1]}
    assert Graph.from_inventory(inv).best_path("internet", "payments-db") is None


def test_enumerate_finds_both_routes():
    paths = g().enumerate_paths("internet", "payments-db")
    assert len(paths) == 2
    assert paths[0].total_cost < paths[1].total_cost


def test_blast_radius():
    r = g().blast_radius("web")
    assert "payments-db" in r["crown_jewels_at_risk"]
    assert r["value_at_risk"] == 100
    r2 = g().blast_radius("payments-db")
    assert r2["crown_jewels_at_risk"] == []


def test_choke_points_flag_single_fix():
    # filesrv sits on the cheap path; web is the sole entry to it
    cps = g().choke_points("internet", "payments-db")
    by_asset = {c["asset"]: c for c in cps}
    assert by_asset["web"]["paths_through"] == 1
    assert by_asset["vpn"]["breaks_all_paths"] is False


def test_plan_shape():
    plan = plan_campaign(g())
    assert plan["reachable"] is True
    assert plan["goal"] == "payments-db"
    assert len(plan["steps"]) == 3
    assert plan["risk"]["impact"] == 100
    assert 0 < plan["risk"]["likelihood"] <= 1
    assert len(plan["alternatives"]) == 1


def test_unknown_asset_edge_rejected():
    bad = {"assets": INV["assets"],
           "edges": [{"src": "internet", "dst": "ghost", "technique": "x"}]}
    with pytest.raises(ValueError):
        Graph.from_inventory(bad)
