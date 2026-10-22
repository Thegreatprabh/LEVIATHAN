"""Attack-graph engine: capability-state path search over an asset graph.

Nodes are assets. Directed edges are attack steps with:
  technique  what the attacker does ("sql injection", "credential reuse")
  cost       effort/difficulty 0..1 (lower = easier for the attacker)
  requires   capabilities needed before the step (e.g. "network-reach")
  grants     capabilities gained after the step (e.g. "creds:svc_backup")
  check      validator check id that can prove this step, or None

Search runs in (asset, capabilities) state space — the classic attack
graph model: the same asset with more capabilities is a different,
stronger position. Dijkstra finds the cheapest path to a crown jewel;
enumeration lists alternatives; blast radius and choke-point analysis
answer "if this falls, what else falls?" and "which single fix breaks
the most paths?".
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field


@dataclass
class Asset:
    id: str
    kind: str
    host: str = ""
    label: str = ""
    value: int = 0          # business value; crown jewels carry the big numbers
    crown: bool = False


@dataclass
class Edge:
    src: str
    dst: str
    technique: str
    cost: float = 0.5
    requires: list = field(default_factory=list)
    grants: list = field(default_factory=list)
    check: str | None = None
    detail: str = ""
    params: dict = field(default_factory=dict)


@dataclass
class Step:
    edge: Edge
    caps_after: frozenset


@dataclass
class Path:
    steps: list
    total_cost: float

    @property
    def assets(self) -> list[str]:
        if not self.steps:
            return []
        seq = [self.steps[0].edge.src]
        seq += [s.edge.dst for s in self.steps]
        return seq

    @property
    def likelihood(self) -> float:
        """Rough success likelihood: product of per-step ease."""
        out = 1.0
        for s in self.steps:
            out *= (1.0 - s.edge.cost)
        return round(out, 4)


class Graph:
    def __init__(self, assets: list[Asset], edges: list[Edge]):
        self.assets = {a.id: a for a in assets}
        self.edges = edges
        self._out: dict[str, list[Edge]] = {}
        for e in edges:
            if e.src not in self.assets or e.dst not in self.assets:
                raise ValueError(f"edge references unknown asset: {e.src}->{e.dst}")
            self._out.setdefault(e.src, []).append(e)

    @classmethod
    def from_inventory(cls, inv: dict) -> "Graph":
        assets = [Asset(id=a["id"], kind=a.get("kind", "host"),
                        host=a.get("host", ""), label=a.get("label", a["id"]),
                        value=int(a.get("value", 0)),
                        crown=bool(a.get("crown", False)))
                  for a in inv["assets"]]
        edges = [Edge(src=e["src"], dst=e["dst"], technique=e["technique"],
                      cost=float(e.get("cost", 0.5)),
                      requires=list(e.get("requires", [])),
                      grants=list(e.get("grants", [])),
                      check=e.get("check"), detail=e.get("detail", ""),
                      params=dict(e.get("params", {})))
                 for e in inv["edges"]]
        return cls(assets, edges)

    def crown_jewels(self) -> list[str]:
        return [a.id for a in self.assets.values() if a.crown]

    # -- path search in capability state space -------------------------------

    def _search(self, entry: str, goals: set[str], start_caps: frozenset,
                banned: frozenset = frozenset()):
        """Dijkstra. Returns (dist, prev) over states."""
        start = (entry, frozenset(start_caps))
        dist = {start: 0.0}
        prev: dict = {}
        pq = [(0.0, entry, frozenset(start_caps))]
        while pq:
            d, node, caps = heapq.heappop(pq)
            state = (node, caps)
            if d > dist.get(state, float("inf")):
                continue
            for e in self._out.get(node, []):
                if e.dst in banned or node in banned:
                    continue
                if not set(e.requires) <= set(caps):
                    continue
                ncaps = frozenset(set(caps) | set(e.grants))
                nstate = (e.dst, ncaps)
                nd = d + e.cost
                if nd < dist.get(nstate, float("inf")):
                    dist[nstate] = nd
                    prev[nstate] = (state, e)
                    heapq.heappush(pq, (nd, e.dst, ncaps))
        return dist, prev

    def best_path(self, entry: str, goal: str,
                  start_caps=frozenset({"external"}),
                  banned: frozenset = frozenset()) -> Path | None:
        dist, prev = self._search(entry, {goal}, start_caps, banned)
        goal_states = [(d, s) for s, d in dist.items() if s[0] == goal]
        if not goal_states:
            return None
        _, gstate = min(goal_states)
        steps = []
        state = gstate
        while state in prev:
            pstate, edge = prev[state]
            steps.append(Step(edge=edge, caps_after=state[1]))
            state = pstate
        steps.reverse()
        return Path(steps=steps, total_cost=round(dist[gstate], 4))

    def enumerate_paths(self, entry: str, goal: str,
                        start_caps=frozenset({"external"}), limit: int = 25,
                        banned: frozenset = frozenset()) -> list[Path]:
        """DFS enumeration of distinct simple attack paths (state-pruned)."""
        results: list[Path] = []

        def dfs(node, caps, steps, cost, seen_states):
            if len(results) >= limit:
                return
            if node == goal and steps:
                results.append(Path(steps=list(steps), total_cost=round(cost, 4)))
                return
            for e in self._out.get(node, []):
                if e.dst in banned or node in banned:
                    continue
                if not set(e.requires) <= set(caps):
                    continue
                ncaps = frozenset(set(caps) | set(e.grants))
                nstate = (e.dst, ncaps)
                if nstate in seen_states:
                    continue
                steps.append(Step(edge=e, caps_after=ncaps))
                seen_states.add(nstate)
                dfs(e.dst, ncaps, steps, cost + e.cost, seen_states)
                seen_states.discard(nstate)
                steps.pop()

        dfs(entry, frozenset(start_caps), [], 0.0, {(entry, frozenset(start_caps))})
        results.sort(key=lambda p: p.total_cost)
        return results

    # -- analysis -----------------------------------------------------------

    def blast_radius(self, asset_id: str) -> dict:
        """If `asset_id` falls, what can an attacker reach from it?
        Capability requirements ignored — this is the worst-case envelope."""
        seen: set[str] = set()
        stack = [asset_id]
        while stack:
            node = stack.pop()
            for e in self._out.get(node, []):
                if e.dst not in seen:
                    seen.add(e.dst)
                    stack.append(e.dst)
        seen.discard(asset_id)
        jewels = sorted(a for a in seen if self.assets[a].crown)
        return {"asset": asset_id, "reachable": sorted(seen),
                "crown_jewels_at_risk": jewels,
                "value_at_risk": sum(self.assets[j].value for j in jewels)}

    def choke_points(self, entry: str, goal: str,
                     start_caps=frozenset({"external"})) -> list[dict]:
        """Rank assets by how many attack paths pass through them, and
        whether removing the asset makes the goal unreachable at all.
        These are the highest-ROI hardening targets."""
        paths = self.enumerate_paths(entry, goal, start_caps, limit=100)
        total = len(paths)
        out = []
        for aid in self.assets:
            if aid in (entry, goal):
                continue
            through = sum(1 for p in paths if aid in p.assets[1:-1])
            if through == 0:
                continue
            still = self.best_path(entry, goal, start_caps,
                                   banned=frozenset({aid}))
            out.append({"asset": aid, "paths_through": through,
                        "of_total": total,
                        "breaks_all_paths": still is None,
                        "share": round(through / total, 3) if total else 0})
        out.sort(key=lambda r: (-r["paths_through"], r["asset"]))
        return out
