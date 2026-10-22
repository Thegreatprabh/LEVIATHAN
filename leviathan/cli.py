"""LEVIATHAN command line.

  leviathan scope init|sign|verify   the ScopeLock workflow
  leviathan lab init|up              the built-in Lab Range
  leviathan graph show               assets, paths, blast radius, choke points
  leviathan campaign plan|run       plan a path / prove it with evidence
  leviathan vault verify             check the evidence hash chain
  leviathan report build             Markdown + HTML from a stored campaign
  leviathan mcp                      MCP stdio server for agents
  leviathan doctor                   environment self-check
"""

from __future__ import annotations

import argparse
import json
import sys

from .campaign import run_campaign
from .graph import Graph
from .lab import DEFAULT_PORTS, Lab, default_inventory, default_scope
from .planner import plan_campaign
from .report import build_html, build_markdown
from .scope import Scope, get_key, sign_scope
from .vault import Vault


def _load_json(path: str):
    with open(path) as fh:
        return json.load(fh)


def _graph(args) -> Graph:
    return Graph.from_inventory(_load_json(args.inventory))


# -- scope ----------------------------------------------------------------------

def cmd_scope_init(args) -> int:
    scope = {"org": args.org, "operator": args.operator, "expires": args.expires,
             "mode": args.mode, "targets": args.targets.split(","),
             "exclude": args.exclude.split(",") if args.exclude else [],
             "crown_jewels": args.crown.split(",") if args.crown else []}
    with open(args.out, "w") as fh:
        json.dump(scope, fh, indent=2)
    print(f"unsigned scope written to {args.out} — sign it: "
          f"leviathan scope sign --scope {args.out}")
    return 0


def cmd_scope_sign(args) -> int:
    key = get_key(args.key)
    signed = sign_scope(_load_json(args.scope), key)
    out = args.out or args.scope
    with open(out, "w") as fh:
        json.dump(signed, fh, indent=2)
    print(f"signed scope written to {out}")
    return 0


def cmd_scope_verify(args) -> int:
    scope = Scope.load(args.scope, key=args.key)
    print(f"scope OK — org={scope.data['org']} mode={scope.mode} "
          f"targets={scope.data['targets']} expires={scope.data['expires']}")
    return 0


# -- lab --------------------------------------------------------------------------

def cmd_lab_init(args) -> int:
    import os
    os.makedirs(args.dir, exist_ok=True)
    with open(f"{args.dir}/inventory.json", "w") as fh:
        json.dump(default_inventory(), fh, indent=2)
    with open(f"{args.dir}/scope.json", "w") as fh:
        json.dump(default_scope(), fh, indent=2)
    print(f"lab files written to {args.dir}/ (inventory.json, scope.json) — "
          "sign the scope, then: leviathan lab up  +  leviathan campaign run")
    return 0


def cmd_lab_up(args) -> int:
    lab = Lab()
    ports = lab.up()
    print("LEVIATHAN Lab Range is up (all data synthetic/canary):")
    for name, port in ports.items():
        print(f"  {name:8} http://127.0.0.1:{port}")
    print("Ctrl+C to stop.")
    try:
        import time
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        lab.down()
        print("\nlab down")
    return 0


# -- graph / campaign ---------------------------------------------------------------

def cmd_graph_show(args) -> int:
    g = _graph(args)
    print(f"assets: {len(g.assets)}  edges: {len(g.edges)}  "
          f"crown jewels: {g.crown_jewels()}")
    for a in g.assets.values():
        print(f"  {a.id:12} {a.kind:8} host={a.host or '-':10} "
              f"value={a.value}{'  👑' if a.crown else ''}")
    plan = plan_campaign(g, goal=args.goal)
    if plan["reachable"]:
        print(f"\ncheapest path to {plan['goal']}: "
              f"{' -> '.join(plan['best_path']['assets'])} "
              f"(cost {plan['best_path']['total_cost']}, "
              f"likelihood {plan['best_path']['likelihood']})")
        for c in g.choke_points(plan["entry"], plan["goal"]):
            print(f"  choke point: {c['asset']} on {c['paths_through']}/"
                  f"{c['of_total']} paths"
                  + (" — breaks ALL paths" if c["breaks_all_paths"] else ""))
    return 0


def cmd_campaign_plan(args) -> int:
    plan = plan_campaign(_graph(args), goal=args.goal)
    print(json.dumps(plan, indent=2))
    return 0


def cmd_campaign_run(args) -> int:
    scope = Scope.load(args.scope, key=args.key)
    g = _graph(args)
    vault = Vault(args.vault)
    try:
        result = run_campaign(scope, g, vault, goal=args.goal)
    finally:
        vault.close()
    for s in result["steps"]:
        print(f"  step {s['step']}: {s['from']} -> {s['to']} "
              f"[{s['proof']}] {s['technique']}")
    print(f"campaign {result['campaign']}: "
          f"{'PATH PROVEN ✅' if result['proven'] else 'NOT PROVEN ❌'}"
          f" — evidence in {args.vault} (leviathan vault verify)")
    return 0 if result["proven"] else 1


# -- vault / report -------------------------------------------------------------------

def cmd_vault_verify(args) -> int:
    vault = Vault(args.vault)
    ok, msg = vault.verify()
    vault.close()
    print(("✅ " if ok else "❌ ") + msg)
    return 0 if ok else 1


def cmd_report_build(args) -> int:
    vault = Vault(args.vault)
    records = vault.records(args.campaign)
    vault.close()
    plan = next(r["payload"]["plan"] for r in records if r["kind"] == "plan")
    steps = [r["payload"] for r in records if r["kind"] == "step-evidence"]
    final = next(r["payload"] for r in records if r["kind"] == "campaign-result")
    result = {"campaign": args.campaign, "goal": plan["goal"],
              "proven": final["proven"], "steps": steps, "plan": plan}
    g = _graph(args)
    org = ""
    if args.scope:
        org = _load_json(args.scope).get("org", "")
    md = build_markdown(result, g, org)
    with open(args.out_md, "w") as fh:
        fh.write(md)
    print(f"markdown report -> {args.out_md}")
    if args.out_html:
        with open(args.out_html, "w") as fh:
            fh.write(build_html(result, g, org))
        print(f"html report     -> {args.out_html}")
    return 0


# -- misc ----------------------------------------------------------------------------

def cmd_mcp(args) -> int:
    from .mcp_server import serve
    serve()
    return 0


def cmd_doctor(args) -> int:
    import platform
    print(f"python {platform.python_version()} — OK")
    print(f"leviathan core: stdlib only — OK")
    for name, port in DEFAULT_PORTS.items():
        import socket
        s = socket.socket()
        free = s.connect_ex(("127.0.0.1", port)) != 0
        s.close()
        print(f"lab port {port} ({name}): {'free' if free else 'IN USE'}")
    print("scope key:", "set" if _key_present() else
          "NOT set — export LEVIATHAN_SCOPE_KEY before signing/verifying")
    return 0


def _key_present() -> bool:
    import os
    return bool(os.environ.get("LEVIATHAN_SCOPE_KEY"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="leviathan",
                                description="Autonomous attack-path engine "
                                            "for authorized infrastructure.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scope").add_subparsers(dest="sub", required=True)
    i = sc.add_parser("init")
    i.add_argument("--org", required=True)
    i.add_argument("--operator", required=True)
    i.add_argument("--expires", default="2099-12-31")
    i.add_argument("--mode", choices=["lab", "observe"], default="lab")
    i.add_argument("--targets", required=True, help="comma-separated hosts/CIDRs")
    i.add_argument("--exclude", default="")
    i.add_argument("--crown", default="")
    i.add_argument("--out", default="scope.json")
    i.set_defaults(fn=cmd_scope_init)
    s2 = sc.add_parser("sign")
    s2.add_argument("--scope", required=True)
    s2.add_argument("--key", default=None)
    s2.add_argument("--out", default=None)
    s2.set_defaults(fn=cmd_scope_sign)
    s3 = sc.add_parser("verify")
    s3.add_argument("--scope", required=True)
    s3.add_argument("--key", default=None)
    s3.set_defaults(fn=cmd_scope_verify)

    lb = sub.add_parser("lab").add_subparsers(dest="sub", required=True)
    li = lb.add_parser("init")
    li.add_argument("--dir", default="labdata")
    li.set_defaults(fn=cmd_lab_init)
    lb.add_parser("up").set_defaults(fn=cmd_lab_up)

    gr = sub.add_parser("graph")
    gs = gr.add_subparsers(dest="sub", required=True).add_parser("show")
    gs.add_argument("--inventory", required=True)
    gs.add_argument("--goal", default=None)
    gs.set_defaults(fn=cmd_graph_show)

    cp = sub.add_parser("campaign").add_subparsers(dest="sub", required=True)
    pl = cp.add_parser("plan")
    pl.add_argument("--inventory", required=True)
    pl.add_argument("--goal", default=None)
    pl.set_defaults(fn=cmd_campaign_plan)
    rn = cp.add_parser("run")
    rn.add_argument("--scope", required=True)
    rn.add_argument("--inventory", required=True)
    rn.add_argument("--vault", default="evidence.db")
    rn.add_argument("--goal", default=None)
    rn.add_argument("--key", default=None)
    rn.set_defaults(fn=cmd_campaign_run)

    vv = sub.add_parser("vault").add_subparsers(dest="sub", required=True)
    vf = vv.add_parser("verify")
    vf.add_argument("--vault", default="evidence.db")
    vf.set_defaults(fn=cmd_vault_verify)

    rb = sub.add_parser("report").add_subparsers(dest="sub", required=True)
    bd = rb.add_parser("build")
    bd.add_argument("--vault", default="evidence.db")
    bd.add_argument("--campaign", required=True)
    bd.add_argument("--inventory", required=True)
    bd.add_argument("--scope", default=None)
    bd.add_argument("--out-md", default="report.md")
    bd.add_argument("--out-html", default="report.html")
    bd.set_defaults(fn=cmd_report_build)

    sub.add_parser("mcp").set_defaults(fn=cmd_mcp)
    sub.add_parser("doctor").set_defaults(fn=cmd_doctor)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
