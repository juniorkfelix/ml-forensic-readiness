"""SQLite forensic evidence store (pipeline C).

Append-only by construction: SQLite triggers reject UPDATE and DELETE on
``forensic_events``. This protects against accidental modification. It is NOT
tamper-proof, since anyone with file access can drop the triggers. Tampering is made
*evident* by the hash chain (mlfref.forensic.integrity).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from mlfref.forensic.schema import DDL, HEADER_FIELDS, ForensicEvent


class ForensicEvidenceStore:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(DDL)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> ForensicEvidenceStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def append(self, event: ForensicEvent) -> None:
        placeholders = ",".join("?" for _ in HEADER_FIELDS)
        with self._conn:
            self._conn.execute(
                f"INSERT INTO forensic_events ({','.join(HEADER_FIELDS)}) VALUES ({placeholders})",
                event.as_row(),
            )

    def last_event(self) -> ForensicEvent | None:
        row = self._conn.execute(
            "SELECT * FROM forensic_events ORDER BY sequence_number DESC LIMIT 1"
        ).fetchone()
        return ForensicEvent(**dict(row)) if row else None

    def events(self, event_type: str | None = None) -> list[ForensicEvent]:
        sql = "SELECT * FROM forensic_events"
        args: tuple[Any, ...] = ()
        if event_type:
            sql += " WHERE event_type = ?"
            args = (event_type,)
        rows = self._conn.execute(sql + " ORDER BY sequence_number", args).fetchall()
        return [ForensicEvent(**dict(r)) for r in rows]

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM forensic_events").fetchone()[0])

    def export_jsonl(self, path: str | Path) -> Path:
        """One JSON object per event (metadata parsed), in sequence order."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as fh:
            for ev in self.events():
                d = ev.as_dict()
                d["metadata"] = json.loads(d.pop("metadata_json"))
                fh.write(json.dumps(d, sort_keys=True) + "\n")
        return path

    def size_bytes(self) -> int:
        return self.db_path.stat().st_size if self.db_path.exists() else 0
