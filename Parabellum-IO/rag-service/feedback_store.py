"""
Feedback Store — SQLite
Persists human-confirmed NIST CSF mappings for use in RAG retraining.
Each confirmed mapping becomes an additional training document.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "feedback.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the feedback table if it doesn't exist."""
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_text  TEXT    NOT NULL,
                control_id    TEXT    NOT NULL,
                function      TEXT,
                category      TEXT,
                title         TEXT,
                confidence    REAL    DEFAULT 0.0,
                source        TEXT    DEFAULT 'human',
                created_at    TEXT    DEFAULT (datetime('now'))
            )
        """)
        conn.commit()


def store_feedback(
    finding_text: str,
    control_id: str,
    function: str = "",
    category: str = "",
    title: str = "",
    confidence: float = 1.0,
    source: str = "human",
) -> int:
    """
    Store a confirmed finding → NIST CSF control mapping.
    Returns the new row ID.
    """
    with _get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO feedback
               (finding_text, control_id, function, category, title, confidence, source)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (finding_text, control_id, function, category, title, confidence, source),
        )
        conn.commit()
        return cur.lastrowid


def get_all_feedback() -> list[dict]:
    """Return all stored feedback rows as dicts."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM feedback ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_feedback_as_rag_documents() -> list[dict]:
    """
    Convert feedback rows into RAG documents suitable for re-indexing.
    Each document enriches the vector store with confirmed human mappings.
    """
    rows = get_all_feedback()
    docs = []
    for row in rows:
        # Build a descriptive text that mirrors the NIST CSF control format
        text = (
            f"{row['control_id']} {row['function']} {row['category']} "
            f"{row['title']} confirmed mapping for: {row['finding_text']}"
        )
        docs.append({
            "id": str(row["id"]),
            "text": text,
            "metadata": {
                "id": row["control_id"],
                "function": row["function"],
                "category": row["category"],
                "title": row["title"],
            },
        })
    return docs


def get_stats() -> dict:
    """Return aggregate statistics about the feedback store."""
    with _get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
        human = conn.execute(
            "SELECT COUNT(*) FROM feedback WHERE source='human'"
        ).fetchone()[0]
        auto = conn.execute(
            "SELECT COUNT(*) FROM feedback WHERE source='auto'"
        ).fetchone()[0]
        unique_controls = conn.execute(
            "SELECT COUNT(DISTINCT control_id) FROM feedback"
        ).fetchone()[0]
        last_entry = conn.execute(
            "SELECT created_at FROM feedback ORDER BY created_at DESC LIMIT 1"
        ).fetchone()

    return {
        "total_mappings": total,
        "human_confirmed": human,
        "auto_mapped": auto,
        "unique_controls_covered": unique_controls,
        "last_feedback_at": last_entry[0] if last_entry else None,
    }
