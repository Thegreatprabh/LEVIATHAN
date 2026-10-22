import json
import os
import subprocess
import sys

import pytest

from leviathan.cli import main
from leviathan.lab import Lab

ROOT = os.path.join(os.path.dirname(__file__), "..")
KEY = "cli-test-key"


def _env():
    return dict(os.environ, LEVIATHAN_SCOPE_KEY=KEY)


def test_cli_help_runs():
    out = subprocess.run([sys.executable, "-m", "leviathan.cli", "--help"],
                         capture_output=True, text=True, cwd=ROOT, timeout=30)
    assert out.returncode == 0 and "campaign" in out.stdout


def test_cli_full_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("LEVIATHAN_SCOPE_KEY", KEY)
    lab = Lab()  # default ports — the shipped inventory points at them
    lab.up()
    try:
        d = str(tmp_path)
        assert main(["lab", "init", "--dir", d]) == 0
        assert main(["scope", "sign", "--scope", f"{d}/scope.json"]) == 0
        assert main(["scope", "verify", "--scope", f"{d}/scope.json"]) == 0
        assert main(["graph", "show", "--inventory", f"{d}/inventory.json"]) == 0
        assert main(["campaign", "plan", "--inventory",
                     f"{d}/inventory.json"]) == 0
        vault = f"{d}/evidence.db"
        rc = main(["campaign", "run", "--scope", f"{d}/scope.json",
                   "--inventory", f"{d}/inventory.json", "--vault", vault])
        assert rc == 0
        assert main(["vault", "verify", "--vault", vault]) == 0
        # find the campaign id from the vault
        from leviathan.vault import Vault
        v = Vault(vault)
        cid = v.records()[0]["campaign"]
        v.close()
        assert main(["report", "build", "--vault", vault, "--campaign", cid,
                     "--inventory", f"{d}/inventory.json",
                     "--scope", f"{d}/scope.json",
                     "--out-md", f"{d}/report.md",
                     "--out-html", f"{d}/report.html"]) == 0
        assert "PATH PROVEN" in open(f"{d}/report.html").read()
    finally:
        lab.down()


def _mcp_session(messages):
    proc = subprocess.run(
        [sys.executable, "-m", "leviathan.mcp_server"],
        input="".join(json.dumps(m) + "\n" for m in messages),
        capture_output=True, text=True, cwd=ROOT, timeout=60)
    return [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]


def test_mcp_initialize_and_tools_list():
    resps = _mcp_session([
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    ])
    assert resps[0]["result"]["serverInfo"]["name"] == "leviathan"
    names = [t["name"] for t in resps[1]["result"]["tools"]]
    assert "campaign_run_lab" in names and "scope_check" in names


def test_mcp_path_find(tmp_path):
    inv = tmp_path / "inv.json"
    from leviathan.lab import default_inventory
    inv.write_text(json.dumps(default_inventory()))
    resps = _mcp_session([
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "path_find",
                    "arguments": {"inventory_path": str(inv)}}},
    ])
    out = json.loads(resps[0]["result"]["content"][0]["text"])
    assert out["reachable"] is True and out["goal"] == "payments-db"
