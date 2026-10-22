"""Planner: turns the graph into a campaign plan.

Deterministic by design — the same graph always yields the same plan,
so plans are testable and auditable. An optional LLM advisor may re-rank
or explain (roadmap); it never executes anything. Execution belongs to
the validator alone.
"""

from __future__ import annotations

from .graph import Graph


def plan_campaign(graph: Graph, entry: str = "internet",
                  goal: str | None = None, max_alternatives: int = 3) -> dict:
    goals = [goal] if goal else graph.crown_jewels()
    if not goals:
        raise ValueError("no crown jewel defined in the inventory")
    target = goals[0]
    best = graph.best_path(entry, target)
    if best is None:
        return {"entry": entry, "goal": target, "reachable": False,
                "best_path": None, "alternatives": [], "steps": [],
                "risk": {"impact": graph.assets[target].value,
                         "likelihood": 0.0, "score": 0.0},
                "reasoning": [f"no attack path from {entry} to {target} "
                              "exists in the modelled graph"]}
    alts = [p for p in graph.enumerate_paths(entry, target, limit=10)
            if p.assets != best.assets][:max_alternatives]
    steps = []
    reasoning = []
    for i, s in enumerate(best.steps, 1):
        steps.append({
            "n": i, "from": s.edge.src, "to": s.edge.dst,
            "technique": s.edge.technique, "cost": s.edge.cost,
            "requires": list(s.edge.requires), "grants": list(s.edge.grants),
            "check": s.edge.check, "detail": s.edge.detail,
            "params": dict(s.edge.params),
        })
        reasoning.append(
            f"step {i}: {s.edge.src} -> {s.edge.dst} via "
            f"{s.edge.technique} (cost {s.edge.cost})"
            + (f" — needs {', '.join(s.edge.requires)}" if s.edge.requires else "")
            + (f" — gains {', '.join(s.edge.grants)}" if s.edge.grants else ""))
    impact = graph.assets[target].value
    risk_score = round(impact * best.likelihood, 2)
    return {"entry": entry, "goal": target, "reachable": True,
            "best_path": {"assets": best.assets, "total_cost": best.total_cost,
                          "likelihood": best.likelihood},
            "alternatives": [{"assets": p.assets, "total_cost": p.total_cost,
                              "likelihood": p.likelihood} for p in alts],
            "steps": steps,
            "risk": {"impact": impact, "likelihood": best.likelihood,
                     "score": risk_score},
            "reasoning": reasoning}
