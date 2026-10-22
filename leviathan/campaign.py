"""Campaign: plan -> validate step by step -> record everything.

The campaign walks the planner's best path. Before each step it
authorizes the destination asset's host against the scope (a second,
independent choke point — the validator's checks authorize again per
URL). Every step's evidence goes into the vault; the first FAILED step
stops the campaign and the result says exactly where the chain broke.
"""

from __future__ import annotations

import time
import uuid

from .graph import Graph
from .planner import plan_campaign
from .scope import Scope, ScopeViolation
from .validator import CHECKS, Context
from .vault import Vault


def run_campaign(scope: Scope, graph: Graph, vault: Vault,
                 entry: str = "internet", goal: str | None = None,
                 campaign_id: str | None = None) -> dict:
    cid = campaign_id or f"cmp-{uuid.uuid4().hex[:8]}"
    plan = plan_campaign(graph, entry=entry, goal=goal)
    vault.add(cid, "plan", {"plan": plan, "ts": time.time()})
    result = {"campaign": cid, "goal": plan["goal"], "entry": entry,
              "reachable": plan["reachable"], "proven": False,
              "steps": [], "plan": plan}
    if not plan["reachable"]:
        vault.add(cid, "campaign-result", {"proven": False,
                                           "reason": "no path in graph"})
        return result
    ctx = Context(scope)
    proven = True
    for step in plan["steps"]:
        dst = graph.assets[step["to"]]
        if dst.host:
            scope.authorize(dst.host)  # raises ScopeViolation — hard stop
        check_id = step.get("check")
        fn = CHECKS.get(check_id or "")
        if fn is None:
            evidence = {"step": step["n"], "check": check_id,
                        "from": step["from"], "to": step["to"],
                        "technique": step["technique"], "proof": "THEORETICAL",
                        "detail": "no validator check for this step — "
                                  "graph inference only", "artifact": ""}
        else:
            evidence = fn(ctx, step)
        vault.add(cid, "step-evidence", evidence)
        result["steps"].append(evidence)
        if evidence["proof"] == "FAILED":
            proven = False
            break
    result["proven"] = proven and all(
        s["proof"] in ("CONFIRMED", "LIKELY", "THEORETICAL")
        for s in result["steps"])
    result["crown_marker"] = ctx.loot.get("crown")
    vault.add(cid, "campaign-result",
              {"proven": result["proven"], "steps": len(result["steps"]),
               "crown_marker": result["crown_marker"]})
    return result
