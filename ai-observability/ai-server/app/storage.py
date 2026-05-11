import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path
from typing import Any


SQLITE_PATH = os.getenv("SQLITE_PATH", "/tmp/compliance-ai-server.sqlite3")
_LOCK = threading.Lock()
_INITIALIZED = False


def init_db() -> None:
    # SQLite schema is created lazily so tests and local runs need no migration step.
    global _INITIALIZED
    with _LOCK:
        if _INITIALIZED:
            return
        if SQLITE_PATH != ":memory:":
            Path(SQLITE_PATH).parent.mkdir(parents=True, exist_ok=True)
        with _connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS clusters (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    token_hash TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    last_seen_at TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    cluster TEXT,
                    timestamp TEXT,
                    rule TEXT,
                    priority TEXT,
                    severity TEXT,
                    namespace TEXT,
                    pod_name TEXT,
                    container_name TEXT,
                    image TEXT,
                    user_name TEXT,
                    command TEXT,
                    action_taken TEXT,
                    classification_source TEXT,
                    classification_reason TEXT,
                    confidence REAL,
                    resource_manifest TEXT,
                    raw_event_json TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_events_cluster ON events(cluster);
                CREATE INDEX IF NOT EXISTS idx_events_namespace ON events(namespace);
                CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
                """
            )
        _INITIALIZED = True


def save_event(event: dict[str, Any]) -> dict[str, Any]:
    init_db()
    stored = dict(event)
    stored["id"] = stored.get("id") or _new_event_id(stored.get("source", "event"))
    with _LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO events (
                id, source, cluster, timestamp, rule, priority, severity, namespace,
                pod_name, container_name, image, user_name, command, action_taken,
                classification_source, classification_reason, confidence,
                resource_manifest, raw_event_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stored["id"],
                stored.get("source", ""),
                stored.get("cluster", ""),
                stored.get("timestamp", ""),
                stored.get("rule", ""),
                stored.get("priority", ""),
                stored.get("severity", ""),
                stored.get("namespace", ""),
                stored.get("pod_name", ""),
                stored.get("container_name", ""),
                stored.get("image", ""),
                stored.get("user", ""),
                stored.get("command", ""),
                stored.get("action_taken", ""),
                stored.get("classification_source", ""),
                stored.get("classification_reason", ""),
                float(stored.get("confidence", 0) or 0),
                stored.get("resource_manifest", ""),
                json.dumps(stored.get("raw_event", stored), ensure_ascii=False),
            ),
        )
    return stored


def list_events(limit: int = 50, cluster: str = "") -> list[dict[str, Any]]:
    init_db()
    limit = max(1, min(int(limit or 50), 500))
    query = "SELECT * FROM events"
    params: list[Any] = []
    if cluster:
        query += " WHERE cluster = ?"
        params.append(cluster)
    query += " ORDER BY COALESCE(timestamp, created_at) DESC, created_at DESC LIMIT ?"
    params.append(limit)
    with _connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_event(row) for row in rows]


def get_event(event_id: str) -> dict[str, Any] | None:
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        return None
    return _row_to_event(row)


def event_summary() -> dict[str, Any]:
    init_db()
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) AS count FROM events").fetchone()["count"]
        by_severity = _count_by(conn, "severity")
        by_rule = _count_by(conn, "rule")
        by_namespace = _count_by(conn, "namespace")
        by_action = _count_by(conn, "action_taken")
        recent_high = conn.execute(
            """
            SELECT * FROM events
            WHERE severity = 'high'
            ORDER BY COALESCE(timestamp, created_at) DESC, created_at DESC
            LIMIT 10
            """
        ).fetchall()
    return {
        "total_events": total,
        "by_severity": by_severity,
        "by_rule": by_rule,
        "by_namespace": by_namespace,
        "by_action": by_action,
        "recent_high": [_row_to_event(row) for row in recent_high],
    }


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _count_by(conn: sqlite3.Connection, column: str) -> dict[str, int]:
    rows = conn.execute(
        f"""
        SELECT {column} AS key, COUNT(*) AS count
        FROM events
        WHERE {column} IS NOT NULL AND {column} != ''
        GROUP BY {column}
        """
    ).fetchall()
    return {row["key"]: row["count"] for row in rows}


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    raw_event = {}
    try:
        raw_event = json.loads(row["raw_event_json"] or "{}")
    except json.JSONDecodeError:
        raw_event = {}
    return {
        "id": row["id"],
        "source": row["source"],
        "cluster": row["cluster"],
        "timestamp": row["timestamp"],
        "rule": row["rule"],
        "priority": row["priority"],
        "severity": row["severity"],
        "classification_source": row["classification_source"],
        "classification_reason": row["classification_reason"],
        "confidence": row["confidence"],
        "namespace": row["namespace"],
        "pod_name": row["pod_name"],
        "container_name": row["container_name"],
        "image": row["image"],
        "user": row["user_name"],
        "command": row["command"],
        "action_taken": row["action_taken"],
        "resource_manifest": row["resource_manifest"],
        "raw_event": raw_event,
    }


def _new_event_id(source: str) -> str:
    prefix = "evt"
    if source == "gatekeeper":
        prefix = "gk"
    elif source in {"falco-agent", "sidekick"}:
        prefix = "agent"
    return f"{prefix}-{uuid.uuid4().hex[:12]}"
