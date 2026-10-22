"""Evidence Vault: append-only, hash-chained evidence storage.

Every campaign step writes a record: {campaign, kind, payload}. Each
record's hash covers the previous record's hash plus its own canonical
payload — editing or deleting any historical record breaks the chain,
and `verify()` detects it. SQLite (stdlib), one file per deployment.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time

GENESIS = "GENESIS"


def _hash(prev: str, payload_json: str) -> str:
    return hashlib.sha256((prev + payload_json).encode()).hexdigest()


class Vault:
    def __init__(self, path: str):
        self.path = path
        self.db = sqlite3.connect(path)
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS records ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " ts REAL NOT NULL, campaign TEXT NOT NULL, kind TEXT NOT NULL,"
            " payload TEXT NOT NULL, prev_hash TEXT NOT NULL,"
            " hash TEXT NOT NULL)")
        self.db.commit()

    def _tip(self) -> str:
        row = self.db.execute(
            "SELECT hash FROM records ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else GENESIS

    def add(self, campaign: str, kind: str, payload: dict) -> dict:
        payload_json = json.dumps(payload, sort_keys=True)
        prev = self._tip()
        h = _hash(prev, payload_json)
        cur = self.db.execute(
            "INSERT INTO records (ts, campaign, kind, payload, prev_hash, hash)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (time.time(), campaign, kind, payload_json, prev, h))
        self.db.commit()
        return {"id": cur.lastrowid, "campaign": campaign, "kind": kind,
                "hash": h, "prev_hash": prev}

    def records(self, campaign: str | None = None) -> list[dict]:
        q = "SELECT id, ts, campaign, kind, payload, prev_hash, hash FROM records"
        args: tuple = ()
        if campaign:
            q += " WHERE campaign = ?"
            args = (campaign,)
        q += " ORDER BY id"
        return [{"id": r[0], "ts": r[1], "campaign": r[2], "kind": r[3],
                 "payload": json.loads(r[4]), "prev_hash": r[5], "hash": r[6]}
                for r in self.db.execute(q, args)]

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        for r in self.records():
            if r["prev_hash"] != prev:
                return False, f"record {r['id']}: prev_hash mismatch"
            payload_json = json.dumps(r["payload"], sort_keys=True)
            if _hash(prev, payload_json) != r["hash"]:
                return False, f"record {r['id']}: hash mismatch — tampered"
            prev = r["hash"]
        return True, f"chain intact ({len(self.records())} records)"

    def close(self) -> None:
        self.db.close()
