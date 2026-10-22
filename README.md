# 🐉 LEVIATHAN

**Autonomous attack-path engine for authorized infrastructure.**
*Know your attack paths before an attacker does.*

Security tools list vulnerabilities one by one. Real breaches chain them:
one exposed service → leaked credentials → lateral movement → the
crown-jewel database. No single finding looks critical; **the path is**.
LEVIATHAN models your own infrastructure as an attack graph, plans chained
attack paths the way a red-team operator thinks, and **proves each step
with harmless canary evidence** — before a real attacker finds the same path.

It is scope-locked by construction: no campaign runs without a valid
**signed scope**, no probe touches an out-of-scope target, and nothing is
called *confirmed* without captured evidence in a **hash-chained vault**.

---

## Installation

```bash
git clone https://github.com/Thegreatprabh/LEVIATHAN.git
cd LEVIATHAN
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
```

Zero runtime dependencies — the core is Python 3.10+ standard library only.

**See it work in 30 seconds** (spins up the built-in vulnerable lab and
proves the full attack chain against it, unattended):

```bash
.venv/bin/python demo/run_demo.py
```

```
🐉 LEVIATHAN — scripted demo
  [PASS] signed scope verifies
  [PASS] out-of-scope target refused
  [PASS] planner finds the crown-jewel path
  [PASS] campaign proves every step ['LIKELY', 'CONFIRMED', 'CONFIRMED']
  [PASS] crown-jewel canary captured
  [PASS] evidence hash chain verifies
  [PASS] reports generate (md + self-contained html)
  [PASS] tampered scope rejected

8/8 demo checks passed
```

## The full workflow

```bash
export LEVIATHAN_SCOPE_KEY="your-operator-key"

leviathan lab init --dir labdata        # write the lab's inventory + scope
leviathan scope sign  --scope labdata/scope.json
leviathan lab up                        # terminal 1: run the Lab Range
leviathan campaign run --scope labdata/scope.json \
    --inventory labdata/inventory.json --vault evidence.db
leviathan vault verify --vault evidence.db
leviathan report build --vault evidence.db --campaign <id> \
    --inventory labdata/inventory.json --out-md report.md --out-html report.html
```

## What it does

- **ScopeLock** — a signed authorization manifest (HMAC-SHA256, with expiry).
  Signature and expiry are verified before every campaign; every probe
  passes through a single authorization choke point. A tampered, expired,
  or out-of-scope target is a **hard refusal**, in code and in tests.
- **Attack-Graph Engine** — assets, services, identities and data stores
  as nodes; attack steps as edges carrying technique, cost, required and
  granted *capabilities*. Path search runs in capability-state space.
  Includes **blast-radius** analysis ("if this falls, what else falls?")
  and **choke-point** ranking — the single fixes that break the most paths.
- **Planner** — deterministic, auditable campaign plans: cheapest path,
  alternatives, per-step reasoning, and a risk score (impact × likelihood).
- **Validator** — executes the real technique for each step (SQL
  injection, credential reuse, path traversal, token replay) but only
  ever against **canary** data: synthetic users, canary token files,
  canary records. Proof levels: `CONFIRMED` · `LIKELY` · `THEORETICAL` ·
  `FAILED`, never blurred.
- **Evidence Vault** — append-only SQLite store where every record is
  SHA-256 hash-chained to the previous one. Edit history and
  `leviathan vault verify` catches it.
- **Lab Range** — a miniature vulnerable organisation that ships with the
  tool (SQLi webshop → reused service password → traversal → payments
  API), so the entire story is provable end-to-end with no external target.
- **Reporter** — executive + technical reports in Markdown and a
  self-contained dark HTML dashboard with the attack path drawn as a
  diagram and fixes ranked by ROI.
- **MCP server** — six tools for AI agents (`scope_check`, `graph_summary`,
  `path_find`, `blast_radius`, `choke_points`, `campaign_run_lab`).

## Project inventory

| Area | Contents |
|---|---|
| Core engine | `leviathan/scope.py` (ScopeLock), `graph.py` (attack graph), `planner.py` |
| Validation | `validator.py` (canary checks), `campaign.py` (orchestration), `lab.py` (Lab Range) |
| Evidence & output | `vault.py` (hash-chained evidence), `report.py` (MD + HTML) |
| Interfaces | `cli.py` (10 commands), `mcp_server.py` (6 tools) |
| Verification | 29 pytest tests + an 8-check scripted demo, all green from a fresh clone |

## Safety model — read this

LEVIATHAN is built for **authorized** security validation: your own
infrastructure, or systems you have written authorization to test
(the signed scope *is* that authorization, enforced by the engine).

By construction it will never:

- touch a target outside a valid signed scope,
- run destructive payloads, denial-of-service, persistence, or real
  credential theft — validation is canary-based or observational,
- hide its activity: every action lands in the audit-grade evidence vault,
- claim an unproven path as confirmed.

## Roadmap (stated openly — not launch claims)

- Continuous mode: scheduled campaigns with run-to-run diffing.
- `observe` mode hardening for real estates (read-only posture checks);
  active validation against real assets stays approval-gated by design.
- Recon-import adapters (feed discovered assets straight into the graph).
- Ed25519 scope signatures; optional LLM advisor for plan narration.

## License

MIT. Built for defenders and authorized red teams.
