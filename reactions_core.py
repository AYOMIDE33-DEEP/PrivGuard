from __future__ import annotations
from pathlib import Path
import json
import sqlite3
from typing import Dict, Optional

APP_DIR = Path(__file__).resolve().parents[1]
DB_PATH = APP_DIR / "privguard.db"


def _conn():
    c = sqlite3.connect(str(DB_PATH))
    c.execute(
        """CREATE TABLE IF NOT EXISTS reactions (
            msg_id TEXT PRIMARY KEY,
            emoji TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )"""
    )
    return c


def set_reaction(msg_id: str, emoji: str) -> None:
    msg_id = (msg_id or "").strip()
    emoji = (emoji or "").strip()
    if not msg_id:
        raise ValueError("Missing msg_id")
    if not emoji:
        # empty => remove reaction
        remove_reaction(msg_id)
        return

    import time
    ts = int(time.time())
    with _conn() as c:
        c.execute(
            "INSERT INTO reactions (msg_id, emoji, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(msg_id) DO UPDATE SET emoji=excluded.emoji, updated_at=excluded.updated_at",
            (msg_id, emoji, ts),
        )
        c.commit()


def remove_reaction(msg_id: str) -> None:
    msg_id = (msg_id or "").strip()
    if not msg_id:
        return
    with _conn() as c:
        c.execute("DELETE FROM reactions WHERE msg_id=?", (msg_id,))
        c.commit()


def get_reaction(msg_id: str) -> Optional[str]:
    msg_id = (msg_id or "").strip()
    if not msg_id:
        return None
    with _conn() as c:
        cur = c.execute("SELECT emoji FROM reactions WHERE msg_id=?", (msg_id,))
        row = cur.fetchone()
        return row[0] if row else None


def get_reactions_map(msg_ids) -> Dict[str, str]:
    ids = [i for i in (msg_ids or []) if i]
    if not ids:
        return {}
    placeholders = ",".join(["?"] * len(ids))
    with _conn() as c:
        cur = c.execute(f"SELECT msg_id, emoji FROM reactions WHERE msg_id IN ({placeholders})", ids)
        return {mid: emo for (mid, emo) in cur.fetchall()}