import json
import os
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
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
                    user_id TEXT,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL DEFAULT 'customer',
                    token_hash TEXT,
                    status TEXT NOT NULL DEFAULT 'active',
                    last_seen_at TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    provider_subject TEXT NOT NULL,
                    email TEXT NOT NULL,
                    name TEXT,
                    picture TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_login_at TEXT,
                    UNIQUE(provider, provider_subject)
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
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
            _ensure_column(conn, "clusters", "user_id", "TEXT")
            _ensure_column(conn, "clusters", "kind", "TEXT NOT NULL DEFAULT 'customer'")
            _ensure_column(conn, "events", "cluster_id", "TEXT")
            _ensure_column(conn, "events", "cluster_kind", "TEXT NOT NULL DEFAULT 'customer'")
            _ensure_cluster_name_scope(conn)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_clusters_user_id ON clusters(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_cluster_id ON events(cluster_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_cluster_kind ON events(cluster_kind)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
            _mark_env_demo_clusters(conn)
        _INITIALIZED = True


def upsert_user(provider: str, provider_subject: str, email: str, name: str = "", picture: str = "") -> dict[str, Any]:
    init_db()
    normalized_provider = str(provider or "").strip().lower()
    normalized_subject = str(provider_subject or "").strip()
    normalized_email = str(email or "").strip().lower()
    if not normalized_provider or not normalized_subject or not normalized_email:
        raise ValueError("provider, provider_subject, and email are required")
    now = _utc_now()
    with _LOCK, _connect() as conn:
        row = conn.execute(
            """
            SELECT id FROM users
            WHERE provider = ? AND provider_subject = ?
            """,
            (normalized_provider, normalized_subject),
        ).fetchone()
        if row is None:
            user_id = f"user-{uuid.uuid4().hex[:12]}"
            conn.execute(
                """
                INSERT INTO users (id, provider, provider_subject, email, name, picture, last_login_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, normalized_provider, normalized_subject, normalized_email, name, picture, now),
            )
        else:
            user_id = row["id"]
            conn.execute(
                """
                UPDATE users
                SET email = ?, name = ?, picture = ?, last_login_at = ?
                WHERE id = ?
                """,
                (normalized_email, name, picture, now, user_id),
            )
    user = get_user(user_id)
    assert user is not None
    return user


def get_user(user_id: str) -> dict[str, Any] | None:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT id, provider, provider_subject, email, name, picture, created_at, last_login_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
    if row is None:
        return None
    return dict(row)


def list_users() -> list[dict[str, Any]]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT users.id, users.provider, users.provider_subject, users.email, users.name,
                   users.picture, users.created_at, users.last_login_at,
                   (
                       SELECT COUNT(*)
                       FROM clusters
                       WHERE clusters.user_id = users.id
                   ) AS cluster_count,
                   (
                       SELECT COUNT(*)
                       FROM clusters
                       WHERE clusters.user_id = users.id AND clusters.status = 'active'
                   ) AS active_cluster_count,
                   (
                       SELECT COUNT(*)
                       FROM clusters
                       WHERE clusters.user_id = users.id AND clusters.status = 'disabled'
                   ) AS disabled_cluster_count,
                   (
                       SELECT COUNT(*)
                       FROM events
                       WHERE events.cluster_id IN (
                           SELECT clusters.id FROM clusters WHERE clusters.user_id = users.id
                       )
                   ) AS event_count,
                   (
                       SELECT MAX(clusters.last_seen_at)
                       FROM clusters
                       WHERE clusters.user_id = users.id
                   ) AS last_seen_at
            FROM users
            ORDER BY COALESCE(users.last_login_at, users.created_at) DESC, users.created_at DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def create_session(user_id: str, ttl_days: int = 30) -> str:
    init_db()
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=max(1, int(ttl_days or 30)))
    with _LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (_token_hash(token), user_id, now.isoformat(), expires_at.isoformat()),
        )
    return token


def get_user_by_session(token: str) -> dict[str, Any] | None:
    init_db()
    if not token:
        return None
    now = _utc_now()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT users.id, users.provider, users.provider_subject, users.email, users.name,
                   users.picture, users.created_at, users.last_login_at
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ? AND sessions.expires_at > ?
            """,
            (_token_hash(token), now),
        ).fetchone()
    if row is None:
        return None
    return dict(row)


def delete_session(token: str) -> None:
    init_db()
    if not token:
        return
    with _LOCK, _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


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


def create_cluster(name: str, kind: str = "customer", user_id: str = "") -> dict[str, Any]:
    init_db()
    normalized = _normalize_cluster_name(name)
    normalized_kind = _normalize_cluster_kind(kind)
    normalized_user_id = str(user_id or "").strip()
    token = secrets.token_urlsafe(32)
    cluster_id = f"cluster-{uuid.uuid4().hex[:12]}"
    with _LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO clusters (id, user_id, name, kind, token_hash, status)
            VALUES (?, ?, ?, ?, ?, 'active')
            """,
            (cluster_id, normalized_user_id or None, normalized, normalized_kind, _token_hash(token)),
        )
    cluster = get_cluster(cluster_id)
    assert cluster is not None
    cluster["token"] = token
    return cluster


def list_clusters(user_id: str = "") -> list[dict[str, Any]]:
    init_db()
    normalized_user_id = str(user_id or "").strip()
    params: list[Any] = []
    where = ""
    if normalized_user_id:
        where = "WHERE clusters.user_id = ?"
        params.append(normalized_user_id)
    with _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT clusters.id, clusters.user_id, clusters.name, clusters.kind, clusters.status,
                   clusters.last_seen_at, clusters.created_at, users.email AS user_email,
                   users.name AS user_name,
                   (
                       SELECT COUNT(*)
                       FROM events
                       WHERE events.cluster_id = clusters.id
                   ) AS event_count
            FROM clusters
            LEFT JOIN users ON users.id = clusters.user_id
            {where}
            ORDER BY clusters.created_at DESC
            """,
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def get_cluster(cluster_id: str) -> dict[str, Any] | None:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT id, user_id, name, kind, status, last_seen_at, created_at
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


def is_demo_cluster_name(name: str) -> bool:
    try:
        normalized = _normalize_cluster_name(name)
    except ValueError:
        return False
    return normalized in _demo_cluster_names()


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
            SELECT id, user_id, name, kind, status, last_seen_at, created_at
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
    user_id: str = "",
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
    if user_id:
        filters.append("cluster_id IN (SELECT id FROM clusters WHERE user_id = ?)")
        params.append(user_id)
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += " ORDER BY COALESCE(timestamp, created_at) DESC, created_at DESC LIMIT ?"
    params.append(limit)
    with _connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [_row_to_event(row) for row in rows]


def get_event(event_id: str, user_id: str = "") -> dict[str, Any] | None:
    init_db()
    params: list[Any] = [event_id]
    user_filter = ""
    if user_id:
        user_filter = " AND cluster_id IN (SELECT id FROM clusters WHERE user_id = ?)"
        params.append(user_id)
    with _connect() as conn:
        row = conn.execute(f"SELECT * FROM events WHERE id = ?{user_filter}", params).fetchone()
    if row is None:
        return None
    return _row_to_event(row)


def event_summary(user_id: str = "") -> dict[str, Any]:
    init_db()
    filters: list[str] = []
    params: list[Any] = []
    if user_id:
        filters.append("cluster_id IN (SELECT id FROM clusters WHERE user_id = ?)")
        params.append(user_id)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    high_where = "WHERE severity = 'high'"
    high_params: list[Any] = []
    if user_id:
        high_where += " AND cluster_id IN (SELECT id FROM clusters WHERE user_id = ?)"
        high_params.append(user_id)
    with _connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS count FROM events {where}", params).fetchone()["count"]
        by_severity = _count_by(conn, "severity", user_id=user_id)
        by_rule = _count_by(conn, "rule", user_id=user_id)
        by_namespace = _count_by(conn, "namespace", user_id=user_id)
        by_action = _count_by(conn, "action_taken", user_id=user_id)
        recent_high = conn.execute(
            f"""
            SELECT * FROM events
            {high_where}
            ORDER BY COALESCE(timestamp, created_at) DESC, created_at DESC
            LIMIT 10
            """,
            high_params,
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


def _count_by(conn: sqlite3.Connection, column: str, user_id: str = "") -> dict[str, int]:
    filters = [f"{column} IS NOT NULL", f"{column} != ''"]
    params: list[Any] = []
    if user_id:
        filters.append("cluster_id IN (SELECT id FROM clusters WHERE user_id = ?)")
        params.append(user_id)
    rows = conn.execute(
        f"""
        SELECT {column} AS key, COUNT(*) AS count
        FROM events
        WHERE {" AND ".join(filters)}
        GROUP BY {column}
        """,
        params,
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


def _ensure_cluster_name_scope(conn: sqlite3.Connection) -> None:
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'clusters'"
    ).fetchone()
    table_sql = row["sql"] if row else ""
    if "name TEXT NOT NULL UNIQUE" in table_sql:
        conn.execute("ALTER TABLE clusters RENAME TO clusters_legacy_unique_name")
        conn.execute(
            """
            CREATE TABLE clusters (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                name TEXT NOT NULL,
                kind TEXT NOT NULL DEFAULT 'customer',
                token_hash TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                last_seen_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO clusters (id, user_id, name, kind, token_hash, status, last_seen_at, created_at)
            SELECT id, user_id, name, kind, token_hash, status, last_seen_at, created_at
            FROM clusters_legacy_unique_name
            """
        )
        conn.execute("DROP TABLE clusters_legacy_unique_name")
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_clusters_user_name
        ON clusters(user_id, name)
        WHERE user_id IS NOT NULL
        """
    )
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_clusters_unowned_name
        ON clusters(name)
        WHERE user_id IS NULL
        """
    )


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


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _token_hash(token: str) -> str:
    import hashlib

    return hashlib.sha256(token.encode("utf-8")).hexdigest()
