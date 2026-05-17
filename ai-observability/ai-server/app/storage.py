import json
import os
import secrets
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
                    kind TEXT NOT NULL DEFAULT 'customer',
                    token_hash TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    last_seen_at TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    cluster_id TEXT,
                    cluster TEXT,
                    cluster_kind TEXT NOT NULL DEFAULT 'customer',
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
            _ensure_column(conn, "clusters", "kind", "TEXT NOT NULL DEFAULT 'customer'")
            _ensure_column(conn, "events", "cluster_id", "TEXT")
            _ensure_column(conn, "events", "cluster_kind", "TEXT NOT NULL DEFAULT 'customer'")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_cluster_id ON events(cluster_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_cluster_kind ON events(cluster_kind)")
            _mark_env_demo_clusters(conn)
        _INITIALIZED = True


def save_event(event: dict[str, Any]) -> dict[str, Any]:
    init_db()
    stored = dict(event)
    stored["id"] = stored.get("id") or _new_event_id(stored.get("source", "event"))
    stored["cluster_kind"] = _normalize_cluster_kind(
        stored.get("cluster_kind") or _cluster_kind_for_name(stored.get("cluster", ""))
    )
    with _LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO events (
                id, source, cluster_id, cluster, cluster_kind, timestamp, rule, priority,
                severity, namespace, pod_name, container_name, image, user_name, command, action_taken,
                classification_source, classification_reason, confidence,
                resource_manifest, raw_event_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                stored["id"],
                stored.get("source", ""),
                stored.get("cluster_id", ""),
                stored.get("cluster", ""),
                stored.get("cluster_kind", "customer"),
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


def create_cluster(name: str, kind: str = "customer") -> dict[str, Any]:
    init_db()
    normalized = _normalize_cluster_name(name)
    normalized_kind = _normalize_cluster_kind(kind)
    token = secrets.token_urlsafe(32)
    cluster_id = f"cluster-{uuid.uuid4().hex[:12]}"
    with _LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO clusters (id, name, kind, token_hash, status)
            VALUES (?, ?, ?, ?, 'active')
            """,
            (cluster_id, normalized, normalized_kind, _token_hash(token)),
        )
    cluster = get_cluster(cluster_id)
    assert cluster is not None
    cluster["token"] = token
    return cluster


def list_clusters() -> list[dict[str, Any]]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, name, kind, status, last_seen_at, created_at
            FROM clusters
            ORDER BY created_at DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_cluster(cluster_id: str) -> dict[str, Any] | None:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT id, name, kind, status, last_seen_at, created_at
            FROM clusters
            WHERE id = ?
            """,
            (cluster_id,),
        ).fetchone()
    if row is None:
        return None
    return dict(row)


def update_cluster_kind(cluster_id: str, kind: str) -> dict[str, Any] | None:
    init_db()
    normalized_kind = _normalize_cluster_kind(kind)
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT name FROM clusters WHERE id = ?", (cluster_id,)).fetchone()
        if row is None:
            return None
        cursor = conn.execute(
            "UPDATE clusters SET kind = ? WHERE id = ?",
            (normalized_kind, cluster_id),
        )
        conn.execute(
            "UPDATE events SET cluster_kind = ? WHERE cluster_id = ? OR cluster = ?",
            (normalized_kind, cluster_id, row["name"]),
        )
    return get_cluster(cluster_id)


def rotate_cluster_token(cluster_id: str) -> dict[str, Any] | None:
    init_db()
    token = secrets.token_urlsafe(32)
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            """
            UPDATE clusters
            SET token_hash = ?, status = 'active'
            WHERE id = ?
            """,
            (_token_hash(token), cluster_id),
        )
    if cursor.rowcount == 0:
        return None
    cluster = get_cluster(cluster_id)
    if cluster is not None:
        cluster["token"] = token
    return cluster


def disable_cluster(cluster_id: str) -> dict[str, Any] | None:
    init_db()
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            "UPDATE clusters SET status = 'disabled' WHERE id = ?",
            (cluster_id,),
        )
    if cursor.rowcount == 0:
        return None
    return get_cluster(cluster_id)


def find_cluster_by_token(token: str) -> dict[str, Any] | None:
    init_db()
    token_hash = _token_hash(token)
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT id, name, kind, status, last_seen_at, created_at
            FROM clusters
            WHERE token_hash = ? AND status = 'active'
            """,
            (token_hash,),
        ).fetchone()
    if row is None:
        return None
    return dict(row)


def mark_cluster_seen(cluster_id: str, timestamp: str) -> None:
    init_db()
    with _LOCK, _connect() as conn:
        conn.execute(
            "UPDATE clusters SET last_seen_at = ? WHERE id = ?",
            (timestamp, cluster_id),
        )


def list_events(
    limit: int = 50,
    cluster: str = "",
    cluster_kind: str = "",
    source: str = "",
) -> list[dict[str, Any]]:
    init_db()
    limit = max(1, min(int(limit or 50), 500))
    query = "SELECT * FROM events"
    params: list[Any] = []
    filters: list[str] = []
    if cluster:
        filters.append("cluster = ?")
        params.append(cluster)
    if cluster_kind:
        filters.append("cluster_kind = ?")
        params.append(_normalize_cluster_kind(cluster_kind))
    if source:
        filters.append("source = ?")
        params.append(source)
    if filters:
        query += " WHERE " + " AND ".join(filters)
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
        "cluster_id": row["cluster_id"] or "",
        "cluster": row["cluster"],
        "cluster_kind": row["cluster_kind"] or _cluster_kind_for_name(row["cluster"]),
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


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _mark_env_demo_clusters(conn: sqlite3.Connection) -> None:
    names = _demo_cluster_names()
    if not names:
        return
    conn.executemany(
        "UPDATE clusters SET kind = 'demo' WHERE name = ?",
        [(name,) for name in names],
    )
    conn.executemany(
        "UPDATE events SET cluster_kind = 'demo' WHERE cluster = ?",
        [(name,) for name in names],
    )


def _normalize_cluster_name(name: str) -> str:
    normalized = " ".join(str(name or "").strip().split())
    if not normalized:
        raise ValueError("cluster name is required")
    if len(normalized) > 80:
        raise ValueError("cluster name must be 80 characters or fewer")
    return normalized


def _normalize_cluster_kind(kind: str) -> str:
    normalized = str(kind or "").strip().lower()
    if normalized in {"demo", "test"}:
        return "demo"
    return "customer"


def _cluster_kind_for_name(name: str) -> str:
    if str(name or "").strip() in _demo_cluster_names():
        return "demo"
    return "customer"


def _demo_cluster_names() -> set[str]:
    raw = os.getenv("DEMO_CLUSTER_NAMES", os.getenv("CLUSTER_NAME", ""))
    return {item.strip() for item in raw.split(",") if item.strip()}


def _token_hash(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.encode("utf-8")).hexdigest()
