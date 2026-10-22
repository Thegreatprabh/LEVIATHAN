"""MCP stdio server: LEVIATHAN tools for AI agents.

Tools: scope_check, graph_summary, path_find, blast_radius,
choke_points, campaign_run_lab. The scope key is read from the
LEVIATHAN_SCOPE_KEY environment variable — keys never travel as tool
arguments. campaign_run_lab executes the validator against the
inventory's targets, which the signed scope must authorize.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

from .campaign import run_campaign
from .graph import Graph
from .planner import plan_campaign
from .scope import Scope
from .vault import Vault

TOOLS = [
    {"name": "scope_check", "description": "Verify a signed scope file (signature + expiry).",
     "inputSchema": {"type": "object", "properties": {"scope_path": {"type": "string"}}, "required": ["scope_path"]}},
    {"name": "graph_summary", "description": "Summarize an inventory: assets, edges, crown jewels.",
     "inputSchema": {"type": "object", "properties": {"inventory_path": {"type": "string"}}, "required": ["inventory_path"]}},
    {"name": "path_find", "description": "Plan the cheapest attack path to a crown jewel.",
     "inputSchema": {"type": "object", "properties": {"inventory_path": {"type": "string"}, "goal": {"type": "string"}}, "required": ["inventory_path"]}},
    {"name": "blast_radius", "description": "If this asset falls, what else falls?",
     "inputSchema": {"type": "object", "properties": {"inventory_path": {"type": "string"}, "asset": {"type": "string"}}, "required": ["inventory_path", "asset"]}},
    {"name": "choke_points", "description": "Rank single fixes that break the most attack paths.",
     "inputSchema": {"type": "object", "properties": {"inventory_path": {"type": "string"}, "goal": {"type": "string"}}, "required": ["inventory_path"]}},
    {"name": "campaign_run_lab", "description": "Run a full validation campaign (scope-checked) and return per-step proofs.",
     "inputSchema": {"type": "object", "properties": {"inventory_path": {"type": "string"}, "scope_path": {"type": "string"}}, "required": ["inventory_path", "scope_path"]}},
]


def _load(path: str):
    with open(path) as fh:
        return json.load(fh)


def call_tool(name: str, args: dict):
    if name == "scope_check":
        s = Scope.load(args["scope_path"])
        return {"org": s.data["org"], "mode": s.mode,
                "targets": s.data["targets"], "expires": s.data["expires"],
                "crown_jewels": s.crown_jewels(), "valid": True}
    if name == "graph_summary":
        g = Graph.from_inventory(_load(args["inventory_path"]))
        return {"assets": len(g.assets), "edges": len(g.edges),
                "crown_jewels": g.crown_jewels(),
                "asset_ids": sorted(g.assets)}
    if name == "path_find":
        g = Graph.from_inventory(_load(args["inventory_path"]))
        return plan_campaign(g, goal=args.get("goal"))
    if name == "blast_radius":
        g = Graph.from_inventory(_load(args["inventory_path"]))
        return g.blast_radius(args["asset"])
    if name == "choke_points":
        g = Graph.from_inventory(_load(args["inventory_path"]))
        goal = args.get("goal") or g.crown_jewels()[0]
        return {"goal": goal, "choke_points": g.choke_points("internet", goal)}
    if name == "campaign_run_lab":
        scope = Scope.load(args["scope_path"])
        g = Graph.from_inventory(_load(args["inventory_path"]))
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
            vault = Vault(tf.name)
            try:
                result = run_campaign(scope, g, vault)
            finally:
                vault.close()
        return {"campaign": result["campaign"], "proven": result["proven"],
                "crown_marker": result["crown_marker"],
                "steps": [{"n": s["step"], "to": s["to"], "proof": s["proof"]}
                          for s in result["steps"]]}
    raise ValueError(f"unknown tool {name}")


def serve(stdin=None, stdout=None) -> None:
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            continue
        method = req.get("method")
        rid = req.get("id")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05",
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "leviathan", "version": "1.0.0"}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = req.get("params", {})
            try:
                out = call_tool(params.get("name", ""), params.get("arguments", {}))
                result = {"content": [{"type": "text",
                                       "text": json.dumps(out)}]}
            except Exception as exc:
                result = {"content": [{"type": "text",
                                       "text": json.dumps({"error": str(exc)})}],
                          "isError": True}
        elif rid is None:
            continue  # notification
        else:
            result = {}
            if method:
                pass
        if rid is not None:
            stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid,
                                     "result": result}) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve()
