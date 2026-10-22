"""LEVIATHAN scripted demo — zero setup, proves the whole story:

  1. ScopeLock verifies a signed lab scope
  2. ScopeLock refuses an out-of-scope target (hard stop)
  3. The planner finds the attack path to the crown jewel
  4. The campaign proves every step with canary evidence
  5. The crown-jewel canary record is captured
  6. The evidence vault's hash chain verifies
  7. A tampered scope is rejected
  8. Reports (Markdown + HTML) are generated

Run:  python demo/run_demo.py     (exit 0 = all checks green)
"""

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from leviathan.campaign import run_campaign
from leviathan.graph import Graph
from leviathan.lab import Lab, default_inventory, default_scope
from leviathan.planner import plan_campaign
from leviathan.report import build_html, build_markdown
from leviathan.scope import Scope, ScopeError, ScopeViolation, sign_scope
from leviathan.vault import Vault

KEY = "demo-key"
passed = []


def check(name, cond):
    passed.append(cond)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")


def main() -> int:
    print("🐉 LEVIATHAN — scripted demo")
    lab = Lab({"webshop": 0, "filesrv": 0, "dbsvc": 0})
    ports = lab.up()
    try:
        graph = Graph.from_inventory(default_inventory(ports))
        scope = Scope(sign_scope(default_scope(), KEY), KEY)
        check("signed scope verifies", scope.mode == "lab")
        try:
            scope.authorize("8.8.8.8")
            check("out-of-scope target refused", False)
        except ScopeViolation:
            check("out-of-scope target refused", True)
        plan = plan_campaign(graph)
        check("planner finds the crown-jewel path",
              plan["reachable"] and len(plan["steps"]) == 3)
        with tempfile.TemporaryDirectory() as td:
            vault = Vault(os.path.join(td, "evidence.db"))
            result = run_campaign(scope, graph, vault, campaign_id="demo")
            proofs = [s["proof"] for s in result["steps"]]
            check(f"campaign proves every step {proofs}",
                  result["proven"] and proofs == ["LIKELY", "CONFIRMED", "CONFIRMED"])
            check("crown-jewel canary captured",
                  result["crown_marker"] == "CROWN-JEWEL-CANARY-9d2e")
            ok, _ = vault.verify()
            check("evidence hash chain verifies", ok)
            md = build_markdown(result, graph, org="LEVIATHAN Lab Range")
            doc = build_html(result, graph, org="LEVIATHAN Lab Range")
            check("reports generate (md + self-contained html)",
                  "CONFIRMED" in md and doc.startswith("<!DOCTYPE html>"))
            vault.close()
        tampered = sign_scope(default_scope(), KEY)
        tampered["targets"] = ["0.0.0.0/0"]
        try:
            Scope(tampered, KEY).verify()
            check("tampered scope rejected", False)
        except ScopeError:
            check("tampered scope rejected", True)
    finally:
        lab.down()
    print(f"\n{sum(passed)}/{len(passed)} demo checks passed")
    return 0 if all(passed) else 1


if __name__ == "__main__":
    sys.exit(main())
