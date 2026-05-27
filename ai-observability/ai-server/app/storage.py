import json
import os
import secrets
import sqlite3
import threading
import uuid
import hashlib
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
                    slack_enabled INTEGER NOT NULL DEFAULT 1,
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
                    status TEXT NOT NULL DEFAULT 'active',
                    deleted_at TEXT,
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

                CREATE TABLE IF NOT EXISTS user_slack_settings (
                    user_id TEXT PRIMARY KEY,
                    webhook_url TEXT NOT NULL DEFAULT '',
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );

                CREATE TABLE IF NOT EXISTS slack_notification_state (
                    fingerprint TEXT PRIMARY KEY,
                    first_seen_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    last_notified_at TEXT NOT NULL,
                    count INTEGER NOT NULL DEFAULT 1,
                    last_event_id TEXT NOT NULL DEFAULT ''
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

                CREATE TABLE IF NOT EXISTS policy_apply_history (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    cluster_id TEXT NOT NULL,
                    policy_type TEXT NOT NULL,
                    policy_name TEXT NOT NULL,
                    manifest_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error TEXT NOT NULL DEFAULT '',
                    result_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id),
                    FOREIGN KEY(cluster_id) REFERENCES clusters(id)
                );

                CREATE TABLE IF NOT EXISTS grafana_provisioning (
                    cluster_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    org_id INTEGER NOT NULL,
                    org_name TEXT NOT NULL,
                    datasource_uid TEXT NOT NULL,
                    dashboard_url TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id),
                    FOREIGN KEY(cluster_id) REFERENCES clusters(id)
                );

                CREATE TABLE IF NOT EXISTS auth_login_events (
                    id TEXT PRIMARY KEY,
                    ip_hash TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    email TEXT NOT NULL,
                    result TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id TEXT PRIMARY KEY,
                    actor_user_id TEXT NOT NULL DEFAULT '',
                    actor_email TEXT NOT NULL DEFAULT '',
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT NOT NULL DEFAULT '',
                    before_hash TEXT NOT NULL DEFAULT '',
                    after_hash TEXT NOT NULL DEFAULT '',
                    request_id TEXT NOT NULL DEFAULT '',
                    result TEXT NOT NULL DEFAULT 'success',
                    details_json TEXT NOT NULL DEFAULT '{}',
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
            _ensure_column(conn, "clusters", "slack_enabled", "INTEGER NOT NULL DEFAULT 1")
            _ensure_column(conn, "clusters", "deleted_at", "TEXT")
            _ensure_column(conn, "users", "status", "TEXT NOT NULL DEFAULT 'active'")
            _ensure_column(conn, "users", "deleted_at", "TEXT")
            _ensure_column(conn, "events", "cluster_id", "TEXT")
            _ensure_column(conn, "events", "cluster_kind", "TEXT NOT NULL DEFAULT 'customer'")
            _ensure_cluster_name_scope(conn)
            _ensure_column(conn, "clusters", "slack_enabled", "INTEGER NOT NULL DEFAULT 1")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_clusters_user_id ON clusters(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_cluster_id ON events(cluster_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_cluster_kind ON events(cluster_kind)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_policy_apply_history_user ON policy_apply_history(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_policy_apply_history_cluster ON policy_apply_history(cluster_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_grafana_provisioning_user ON grafana_provisioning(user_id)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_slack_notification_state_last_seen "
                "ON slack_notification_state(last_seen_at)"
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_login_events_ip_time ON auth_login_events(ip_hash, created_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_events_target ON audit_events(target_type, target_id)")
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
            SELECT id, status
            FROM users
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
            status = str(row["status"] or "active")
            if status in {"deleted", "disabled"}:
                raise ValueError(f"{status} user account cannot sign in")
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
            SELECT id, provider, provider_subject, email, name, picture, status, deleted_at, created_at, last_login_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
    if row is None:
        return None
    return dict(row)


def check_auth_account_limit(ip_hash: str, email: str, limit: int = 5, window_hours: int = 24) -> dict[str, Any]:
    init_db()
    normalized_ip_hash = str(ip_hash or "").strip()
    normalized_email = str(email or "").strip().lower()
    if not normalized_ip_hash or not normalized_email:
        return {"allowed": True, "distinct_accounts": 0, "limit": max(1, int(limit or 5))}
    normalized_limit = max(1, int(limit or 5))
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=max(1, int(window_hours or 24)))).isoformat()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT email
            FROM auth_login_events
            WHERE ip_hash = ? AND created_at >= ?
            """,
            (normalized_ip_hash, cutoff),
        ).fetchall()
    emails = {str(row["email"] or "").strip().lower() for row in rows if row["email"]}
    allowed = normalized_email in emails or len(emails) < normalized_limit
    return {
        "allowed": allowed,
        "distinct_accounts": len(emails),
        "limit": normalized_limit,
    }


def record_auth_login_event(ip_hash: str, provider: str, email: str, result: str) -> None:
    init_db()
    normalized_ip_hash = str(ip_hash or "").strip()
    normalized_provider = str(provider or "").strip().lower() or "unknown"
    normalized_email = str(email or "").strip().lower()
    normalized_result = str(result or "").strip().lower() or "unknown"
    if not normalized_ip_hash or not normalized_email:
        return
    with _LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO auth_login_events (id, ip_hash, provider, email, result, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                f"auth-{uuid.uuid4().hex[:12]}",
                normalized_ip_hash,
                normalized_provider,
                normalized_email,
                normalized_result[:32],
                _utc_now(),
            ),
        )


def list_users() -> list[dict[str, Any]]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT users.id, users.provider, users.provider_subject, users.email, users.name,
                   users.picture, users.status, users.deleted_at,
                   users.created_at, users.last_login_at,
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
                       FROM clusters
                       WHERE clusters.user_id = users.id AND clusters.status = 'deleted'
                   ) AS deleted_cluster_count,
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
                   ) AS last_seen_at,
                   COALESCE((
                       SELECT user_slack_settings.webhook_url != ''
                       FROM user_slack_settings
                       WHERE user_slack_settings.user_id = users.id
                   ), 0) AS slack_configured
            FROM users
            ORDER BY COALESCE(users.last_login_at, users.created_at) DESC, users.created_at DESC
            """
        ).fetchall()
    users = [dict(row) for row in rows]
    for user in users:
        user["slack_configured"] = bool(user.get("slack_configured"))
    return users


def get_slack_settings(user_id: str) -> dict[str, Any]:
    init_db()
    normalized_user_id = str(user_id or "").strip()
    if not normalized_user_id:
        return {"webhook_url": "", "configured": False}
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT webhook_url, updated_at
            FROM user_slack_settings
            WHERE user_id = ?
            """,
            (normalized_user_id,),
        ).fetchone()
    webhook_url = row["webhook_url"] if row else ""
    return {
        "webhook_url": webhook_url,
        "configured": bool(webhook_url),
        "updated_at": row["updated_at"] if row else "",
    }


def get_grafana_provisioning(user_id: str, cluster_id: str) -> dict[str, Any] | None:
    init_db()
    normalized_user_id = str(user_id or "").strip()
    normalized_cluster_id = str(cluster_id or "").strip()
    if not normalized_user_id or not normalized_cluster_id:
        return None
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT cluster_id, user_id, org_id, org_name, datasource_uid, dashboard_url, created_at, updated_at
            FROM grafana_provisioning
            WHERE user_id = ? AND cluster_id = ?
            """,
            (normalized_user_id, normalized_cluster_id),
        ).fetchone()
    return dict(row) if row else None


def save_grafana_provisioning(
    user_id: str,
    cluster_id: str,
    org_id: int,
    org_name: str,
    datasource_uid: str,
    dashboard_url: str = "",
) -> dict[str, Any]:
    init_db()
    normalized_user_id = str(user_id or "").strip()
    normalized_cluster_id = str(cluster_id or "").strip()
    normalized_org_name = str(org_name or "").strip()
    normalized_datasource_uid = str(datasource_uid or "").strip()
    if not normalized_user_id or not normalized_cluster_id or not normalized_org_name or not normalized_datasource_uid:
        raise ValueError("user_id, cluster_id, org_name, and datasource_uid are required")
    now = _utc_now()
    with _LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO grafana_provisioning (
                cluster_id, user_id, org_id, org_name, datasource_uid, dashboard_url, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cluster_id) DO UPDATE SET
                user_id = excluded.user_id,
                org_id = excluded.org_id,
                org_name = excluded.org_name,
                datasource_uid = excluded.datasource_uid,
                dashboard_url = excluded.dashboard_url,
                updated_at = excluded.updated_at
            """,
            (
                normalized_cluster_id,
                normalized_user_id,
                int(org_id),
                normalized_org_name,
                normalized_datasource_uid,
                str(dashboard_url or "").strip(),
                now,
            ),
        )
    mapping = get_grafana_provisioning(normalized_user_id, normalized_cluster_id)
    assert mapping is not None
    return mapping


def save_slack_settings(user_id: str, webhook_url: str) -> dict[str, Any]:
    init_db()
    normalized_user_id = str(user_id or "").strip()
    normalized_webhook_url = str(webhook_url or "").strip()
    if not normalized_user_id:
        raise ValueError("user_id is required")
    with _LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO user_slack_settings (user_id, webhook_url, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                webhook_url = excluded.webhook_url,
                updated_at = excluded.updated_at
            """,
            (normalized_user_id, normalized_webhook_url, _utc_now()),
        )
    return get_slack_settings(normalized_user_id)


def create_session(user_id: str, ttl_days: int = 30) -> str:
    init_db()
    user = get_user(user_id)
    if user is None:
        raise ValueError("user account cannot sign in")
    status = str(user.get("status") or "active")
    if status != "active":
        raise ValueError(f"{status} user account cannot sign in")
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
                   users.picture, users.status, users.deleted_at, users.created_at, users.last_login_at
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token_hash = ? AND sessions.expires_at > ? AND users.status = 'active'
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


def delete_user_account(user_id: str) -> dict[str, Any] | None:
    init_db()
    normalized_user_id = str(user_id or "").strip()
    if not normalized_user_id:
        return None
    now = _utc_now()
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT id FROM users WHERE id = ?", (normalized_user_id,)).fetchone()
        if row is None:
            return None
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (normalized_user_id,))
        conn.execute("DELETE FROM user_slack_settings WHERE user_id = ?", (normalized_user_id,))
        conn.execute("DELETE FROM grafana_provisioning WHERE user_id = ?", (normalized_user_id,))
        conn.execute(
            """
            UPDATE clusters
            SET status = 'deleted',
                deleted_at = COALESCE(deleted_at, ?),
                token_hash = ''
            WHERE user_id = ?
            """,
            (now, normalized_user_id),
        )
        conn.execute(
            """
            UPDATE users
            SET status = 'deleted',
                deleted_at = COALESCE(deleted_at, ?)
            WHERE id = ?
            """,
            (now, normalized_user_id),
        )
    return get_user(normalized_user_id)


def restore_user(user_id: str) -> dict[str, Any] | None:
    init_db()
    normalized_user_id = str(user_id or "").strip()
    if not normalized_user_id:
        return None
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET status = 'active',
                deleted_at = NULL
            WHERE id = ? AND status = 'deleted'
            """,
            (normalized_user_id,),
        )
    if cursor.rowcount == 0:
        return None
    return get_user(normalized_user_id)


def disable_user(user_id: str) -> dict[str, Any] | None:
    init_db()
    normalized_user_id = str(user_id or "").strip()
    if not normalized_user_id:
        return None
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT id FROM users WHERE id = ? AND status != 'deleted'", (normalized_user_id,)).fetchone()
        if row is None:
            return None
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (normalized_user_id,))
        conn.execute(
            """
            UPDATE users
            SET status = 'disabled',
                deleted_at = NULL
            WHERE id = ? AND status != 'deleted'
            """,
            (normalized_user_id,),
        )
    return get_user(normalized_user_id)


def enable_user(user_id: str) -> dict[str, Any] | None:
    init_db()
    normalized_user_id = str(user_id or "").strip()
    if not normalized_user_id:
        return None
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            """
            UPDATE users
            SET status = 'active',
                deleted_at = NULL
            WHERE id = ? AND status = 'disabled'
            """,
            (normalized_user_id,),
        )
    if cursor.rowcount == 0:
        return None
    return get_user(normalized_user_id)


_AUDIT_REDACT_KEYS = {
    "access_token",
    "after",
    "api_key",
    "authorization",
    "before",
    "confirm_email",
    "credential",
    "password",
    "secret",
    "session_token",
    "token",
    "token_hash",
    "token_value",
    "webhook_url",
}


def _audit_redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_name = str(key).strip().lower()
            if key_name in _AUDIT_REDACT_KEYS:
                continue
            redacted[key] = _audit_redact_value(item)
        return redacted
    if isinstance(value, list):
        return [_audit_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [_audit_redact_value(item) for item in value]
    return value


def _audit_json(value: Any) -> str:
    return json.dumps(_audit_redact_value(value), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _audit_hash(value: Any) -> str:
    payload = _audit_json(value)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def record_audit_event(
    action: str,
    target_type: str,
    target_id: str = "",
    *,
    actor_user_id: str = "",
    actor_email: str = "",
    before: Any = None,
    after: Any = None,
    request_id: str = "",
    result: str = "success",
    details: dict[str, Any] | None = None,
) -> None:
    init_db()
    normalized_action = str(action or "").strip()
    normalized_target_type = str(target_type or "").strip()
    if not normalized_action or not normalized_target_type:
        return
    normalized_actor_user_id = str(actor_user_id or "").strip()
    normalized_actor_email = str(actor_email or "").strip().lower()
    normalized_target_id = str(target_id or "").strip()
    normalized_request_id = str(request_id or "").strip()
    normalized_result = str(result or "").strip().lower() or "success"
    details_payload = _audit_redact_value(details or {})
    with _LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_events (
                id, actor_user_id, actor_email, action, target_type, target_id,
                before_hash, after_hash, request_id, result, details_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"audit-{uuid.uuid4().hex[:16]}",
                normalized_actor_user_id,
                normalized_actor_email,
                normalized_action,
                normalized_target_type,
                normalized_target_id,
                _audit_hash(before) if before is not None else "",
                _audit_hash(after) if after is not None else "",
                normalized_request_id,
                normalized_result,
                _audit_json(details_payload),
            ),
        )


def _audit_actor_filter(actor_type: str) -> str:
    normalized = str(actor_type or "").strip().lower()
    public_condition = "((actor_user_id = '' AND actor_email = '') OR actor_user_id = 'public' OR actor_email = 'public actor')"
    admin_condition = "(actor_user_id = 'kubeowl-admin' OR actor_email = 'kubeowl-admin@local')"
    if normalized == "public":
        return public_condition
    if normalized == "admin":
        return admin_condition
    if normalized == "login":
        return f"(NOT {public_condition} AND NOT {admin_condition})"
    return ""


def _audit_actor_type(actor_user_id: str, actor_email: str) -> str:
    user_id = str(actor_user_id or "").strip()
    email = str(actor_email or "").strip().lower()
    if (not user_id and not email) or user_id == "public" or email == "public actor":
        return "public"
    if user_id == "kubeowl-admin" or email == "kubeowl-admin@local":
        return "admin"
    return "login"


def _normalize_audit_actor(row: dict[str, Any]) -> dict[str, Any]:
    actor_type = _audit_actor_type(str(row.get("actor_user_id", "")), str(row.get("actor_email", "")))
    row["actor_type"] = actor_type
    if actor_type == "public":
        row["actor_user_id"] = row.get("actor_user_id") or "public"
        row["actor_email"] = row.get("actor_email") or "public actor"
    return row


def list_audit_events(
    limit: int = 100,
    action: str = "",
    target_type: str = "",
    target_id: str = "",
    actor_user_id: str = "",
    actor_type: str = "",
    date_from: str = "",
    date_to: str = "",
) -> list[dict[str, Any]]:
    init_db()
    normalized_limit = max(1, min(int(limit or 100), 500))
    normalized_action = str(action or "").strip()
    normalized_target_type = str(target_type or "").strip()
    normalized_target_id = str(target_id or "").strip()
    normalized_actor_user_id = str(actor_user_id or "").strip()
    normalized_actor_type = str(actor_type or "").strip().lower()
    normalized_date_from = str(date_from or "").strip()
    normalized_date_to = str(date_to or "").strip()
    filters: list[str] = []
    params: list[Any] = []
    if normalized_action:
        filters.append("action = ?")
        params.append(normalized_action)
    if normalized_target_type:
        filters.append("target_type = ?")
        params.append(normalized_target_type)
    if normalized_target_id:
        filters.append("target_id = ?")
        params.append(normalized_target_id)
    if normalized_actor_user_id:
        filters.append("actor_user_id = ?")
        params.append(normalized_actor_user_id)
    actor_type_filter = _audit_actor_filter(normalized_actor_type)
    if actor_type_filter:
        filters.append(actor_type_filter)
    if normalized_date_from:
        filters.append("date(created_at) >= date(?)")
        params.append(normalized_date_from)
    if normalized_date_to:
        filters.append("date(created_at) <= date(?)")
        params.append(normalized_date_to)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    with _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT id, actor_user_id, actor_email, action, target_type, target_id,
                   before_hash, after_hash, request_id, result, details_json, created_at
            FROM audit_events
            {where}
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            [*params, normalized_limit],
        ).fetchall()
    events: list[dict[str, Any]] = []
    for row in rows:
        event = dict(row)
        try:
            event["details"] = json.loads(event.pop("details_json") or "{}")
        except json.JSONDecodeError:
            event["details"] = {}
        events.append(_normalize_audit_actor(event))
    return events


def summarize_audit_events(
    action: str = "",
    target_type: str = "",
    target_id: str = "",
    actor_user_id: str = "",
    actor_type: str = "",
    date_from: str = "",
    date_to: str = "",
) -> dict[str, Any]:
    init_db()
    normalized_action = str(action or "").strip()
    normalized_target_type = str(target_type or "").strip()
    normalized_target_id = str(target_id or "").strip()
    normalized_actor_user_id = str(actor_user_id or "").strip()
    normalized_actor_type = str(actor_type or "").strip().lower()
    normalized_date_from = str(date_from or "").strip()
    normalized_date_to = str(date_to or "").strip()
    filters: list[str] = []
    params: list[Any] = []
    if normalized_action:
        filters.append("action = ?")
        params.append(normalized_action)
    if normalized_target_type:
        filters.append("target_type = ?")
        params.append(normalized_target_type)
    if normalized_target_id:
        filters.append("target_id = ?")
        params.append(normalized_target_id)
    if normalized_actor_user_id:
        filters.append("actor_user_id = ?")
        params.append(normalized_actor_user_id)
    actor_type_filter = _audit_actor_filter(normalized_actor_type)
    if actor_type_filter:
        filters.append(actor_type_filter)
    if normalized_date_from:
        filters.append("date(created_at) >= date(?)")
        params.append(normalized_date_from)
    if normalized_date_to:
        filters.append("date(created_at) <= date(?)")
        params.append(normalized_date_to)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    with _connect() as conn:
        total_row = conn.execute(f"SELECT COUNT(*) AS count FROM audit_events {where}", params).fetchone()
        actor_rows = conn.execute(
            f"""
            SELECT actor_user_id, actor_email, COUNT(*) AS count, MAX(created_at) AS latest_at
            FROM audit_events
            {where}
            GROUP BY actor_user_id, actor_email
            ORDER BY count DESC, latest_at DESC
            LIMIT 6
            """,
            params,
        ).fetchall()
        action_rows = conn.execute(
            f"""
            SELECT action, COUNT(*) AS count
            FROM audit_events
            {where}
            GROUP BY action
            ORDER BY count DESC, action ASC
            LIMIT 6
            """,
            params,
        ).fetchall()
    return {
        "total": int(total_row["count"] or 0),
        "actors": [_normalize_audit_actor(dict(row)) for row in actor_rows],
        "actions": [dict(row) for row in action_rows],
    }


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


def save_policy_apply_history(
    user_id: str,
    cluster_id: str,
    policy_type: str,
    policy_name: str,
    manifest: str,
    status: str,
    error: str = "",
    result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    init_db()
    row = {
        "id": f"policy-apply-{uuid.uuid4().hex[:12]}",
        "user_id": str(user_id or "").strip(),
        "cluster_id": str(cluster_id or "").strip(),
        "policy_type": str(policy_type or "unknown").strip()[:120] or "unknown",
        "policy_name": str(policy_name or "unknown").strip()[:240] or "unknown",
        "manifest_hash": hashlib.sha256(str(manifest or "").encode("utf-8")).hexdigest(),
        "status": str(status or "unknown").strip()[:80] or "unknown",
        "error": str(error or "").strip()[:2000],
        "result_json": json.dumps(result or {}, ensure_ascii=False),
    }
    if not row["user_id"] or not row["cluster_id"]:
        raise ValueError("user_id and cluster_id are required")
    with _LOCK, _connect() as conn:
        conn.execute(
            """
            INSERT INTO policy_apply_history (
                id, user_id, cluster_id, policy_type, policy_name,
                manifest_hash, status, error, result_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                row["id"],
                row["user_id"],
                row["cluster_id"],
                row["policy_type"],
                row["policy_name"],
                row["manifest_hash"],
                row["status"],
                row["error"],
                row["result_json"],
            ),
        )
    return get_policy_apply_history(row["id"]) or row


def get_policy_apply_history(history_id: str) -> dict[str, Any] | None:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT id, user_id, cluster_id, policy_type, policy_name,
                   manifest_hash, status, error, result_json, created_at
            FROM policy_apply_history
            WHERE id = ?
            """,
            (history_id,),
        ).fetchone()
    if row is None:
        return None
    return _row_to_policy_apply_history(row)


def list_policy_apply_history(user_id: str = "", cluster_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
    init_db()
    filters = []
    params: list[Any] = []
    if user_id:
        filters.append("user_id = ?")
        params.append(user_id)
    if cluster_id:
        filters.append("cluster_id = ?")
        params.append(cluster_id)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    params.append(max(1, min(int(limit or 50), 200)))
    with _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT id, user_id, cluster_id, policy_type, policy_name,
                   manifest_hash, status, error, result_json, created_at
            FROM policy_apply_history
            {where}
            ORDER BY created_at DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    return [_row_to_policy_apply_history(row) for row in rows]


def count_policy_apply_history(user_id: str = "", statuses: set[str] | None = None) -> int:
    init_db()
    filters: list[str] = []
    params: list[Any] = []
    if user_id:
        filters.append("user_id = ?")
        params.append(user_id)
    normalized_statuses = sorted(str(status or "").strip() for status in (statuses or set()) if str(status or "").strip())
    if normalized_statuses:
        placeholders = ", ".join("?" for _ in normalized_statuses)
        filters.append(f"status IN ({placeholders})")
        params.extend(normalized_statuses)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    with _connect() as conn:
        row = conn.execute(
            f"SELECT COUNT(DISTINCT manifest_hash) AS count FROM policy_apply_history {where}",
            params,
        ).fetchone()
    return int(row["count"] or 0)


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


def list_clusters(
    user_id: str = "",
    include_deleted: bool = False,
    deleted_only: bool = False,
    status: str = "",
    kind: str = "",
    query: str = "",
) -> list[dict[str, Any]]:
    init_db()
    purge_expired_deleted_clusters()
    normalized_user_id = str(user_id or "").strip()
    normalized_status = str(status or "").strip().lower()
    normalized_kind = str(kind or "").strip().lower()
    normalized_query = str(query or "").strip().lower()
    params: list[Any] = []
    filters: list[str] = []
    if normalized_user_id:
        filters.append("clusters.user_id = ?")
        params.append(normalized_user_id)
    if normalized_status in {"active", "disabled", "deleted"}:
        filters.append("clusters.status = ?")
        params.append(normalized_status)
    elif deleted_only:
        filters.append("clusters.status = 'deleted'")
    elif not include_deleted:
        filters.append("clusters.status != 'deleted'")
    if normalized_kind in {"demo", "customer", "source", "legacy"}:
        filters.append("clusters.kind = ?")
        params.append(normalized_kind)
    if normalized_query:
        filters.append(
            """
            (
                LOWER(clusters.name) LIKE ?
                OR LOWER(COALESCE(users.email, '')) LIKE ?
                OR LOWER(COALESCE(users.name, '')) LIKE ?
                OR LOWER(COALESCE(clusters.status, '')) LIKE ?
                OR LOWER(COALESCE(clusters.kind, '')) LIKE ?
                OR LOWER(COALESCE(clusters.last_seen_at, '')) LIKE ?
            )
            """
        )
        like_query = f"%{normalized_query}%"
        params.extend([like_query, like_query, like_query, like_query, like_query, like_query])
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    with _connect() as conn:
        rows = conn.execute(
            f"""
            SELECT clusters.id, clusters.user_id, clusters.name, clusters.kind, clusters.status,
                   clusters.slack_enabled, clusters.last_seen_at, clusters.deleted_at,
                   clusters.created_at, users.email AS user_email,
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
    clusters = [dict(row) for row in rows]
    for cluster in clusters:
        cluster["slack_enabled"] = bool(cluster.get("slack_enabled"))
    return clusters


def get_cluster(cluster_id: str) -> dict[str, Any] | None:
    init_db()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT id, user_id, name, kind, status, slack_enabled, last_seen_at, deleted_at, created_at
            FROM clusters
            WHERE id = ?
            """,
            (cluster_id,),
        ).fetchone()
    if row is None:
        return None
    cluster = dict(row)
    cluster["slack_enabled"] = bool(cluster.get("slack_enabled"))
    return cluster


def set_cluster_slack_enabled(cluster_id: str, user_id: str, enabled: bool) -> dict[str, Any] | None:
    init_db()
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            """
            UPDATE clusters
            SET slack_enabled = ?
            WHERE id = ? AND user_id = ?
            """,
            (1 if enabled else 0, cluster_id, user_id),
        )
    if cursor.rowcount == 0:
        return None
    return get_cluster(cluster_id)


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
            SET token_hash = ?, status = 'active', deleted_at = NULL
            WHERE id = ? AND status != 'deleted'
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
            "UPDATE clusters SET status = 'disabled' WHERE id = ? AND status != 'deleted'",
            (cluster_id,),
        )
    if cursor.rowcount == 0:
        return None
    return get_cluster(cluster_id)


def enable_cluster(cluster_id: str) -> dict[str, Any] | None:
    init_db()
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            "UPDATE clusters SET status = 'active', deleted_at = NULL WHERE id = ? AND status = 'disabled'",
            (cluster_id,),
        )
    if cursor.rowcount == 0:
        return None
    return get_cluster(cluster_id)


def trash_cluster(cluster_id: str, user_id: str) -> dict[str, Any] | None:
    init_db()
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            """
            UPDATE clusters
            SET status = 'deleted', deleted_at = ?, token_hash = ''
            WHERE id = ? AND user_id = ?
            """,
            (now, cluster_id, user_id),
        )
    if cursor.rowcount == 0:
        return None
    return get_cluster(cluster_id)


def admin_trash_cluster(cluster_id: str) -> dict[str, Any] | None:
    init_db()
    now = datetime.now(timezone.utc).isoformat()
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            """
            UPDATE clusters
            SET status = 'deleted', deleted_at = ?, token_hash = ''
            WHERE id = ? AND status != 'deleted'
            """,
            (now, cluster_id),
        )
    if cursor.rowcount == 0:
        return None
    return get_cluster(cluster_id)


def permanently_delete_cluster(cluster_id: str, user_id: str) -> bool:
    init_db()
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT id FROM clusters WHERE id = ? AND user_id = ? AND status = 'deleted'",
            (cluster_id, user_id),
        ).fetchone()
        if row is None:
            return False
        conn.execute("DELETE FROM policy_apply_history WHERE cluster_id = ?", (cluster_id,))
        conn.execute("DELETE FROM events WHERE cluster_id = ?", (cluster_id,))
        conn.execute("DELETE FROM clusters WHERE id = ? AND user_id = ? AND status = 'deleted'", (cluster_id, user_id))
    return True


def admin_permanently_delete_cluster(cluster_id: str) -> bool:
    init_db()
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT id FROM clusters WHERE id = ? AND status = 'deleted'",
            (cluster_id,),
        ).fetchone()
        if row is None:
            return False
        conn.execute("DELETE FROM policy_apply_history WHERE cluster_id = ?", (cluster_id,))
        conn.execute("DELETE FROM events WHERE cluster_id = ?", (cluster_id,))
        conn.execute("DELETE FROM clusters WHERE id = ? AND status = 'deleted'", (cluster_id,))
    return True


def purge_expired_deleted_clusters(retention_days: int = 3) -> int:
    init_db()
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT id, deleted_at FROM clusters WHERE status = 'deleted' AND deleted_at IS NOT NULL AND deleted_at != ''"
        ).fetchall()
        expired_ids = []
        for row in rows:
            try:
                deleted_at = datetime.fromisoformat(str(row["deleted_at"]))
            except ValueError:
                continue
            if deleted_at.tzinfo is None:
                deleted_at = deleted_at.replace(tzinfo=timezone.utc)
            if deleted_at <= cutoff:
                expired_ids.append(row["id"])
        for cluster_id in expired_ids:
            conn.execute("DELETE FROM policy_apply_history WHERE cluster_id = ?", (cluster_id,))
            conn.execute("DELETE FROM events WHERE cluster_id = ?", (cluster_id,))
            conn.execute("DELETE FROM clusters WHERE id = ?", (cluster_id,))
    return len(expired_ids)


def restore_cluster(cluster_id: str, user_id: str) -> dict[str, Any] | None:
    init_db()
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            """
            UPDATE clusters
            SET status = 'disabled', deleted_at = NULL
            WHERE id = ? AND user_id = ? AND status = 'deleted'
            """,
            (cluster_id, user_id),
        )
    if cursor.rowcount == 0:
        return None
    return get_cluster(cluster_id)


def admin_restore_cluster(cluster_id: str) -> dict[str, Any] | None:
    init_db()
    with _LOCK, _connect() as conn:
        cursor = conn.execute(
            """
            UPDATE clusters
            SET status = 'disabled', deleted_at = NULL
            WHERE id = ? AND status = 'deleted'
            """,
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
            SELECT id, user_id, name, kind, status, slack_enabled, last_seen_at, created_at
            FROM clusters
            WHERE token_hash = ? AND status = 'active'
            """,
            (token_hash,),
        ).fetchone()
    if row is None:
        return None
    cluster = dict(row)
    cluster["slack_enabled"] = bool(cluster.get("slack_enabled"))
    return cluster


def mark_cluster_seen(cluster_id: str, timestamp: str) -> None:
    init_db()
    with _LOCK, _connect() as conn:
        conn.execute(
            """
            UPDATE clusters
            SET last_seen_at = ?
            WHERE id = ? AND (last_seen_at IS NULL OR last_seen_at = '' OR last_seen_at <= ?)
            """,
            (timestamp, cluster_id, timestamp),
        )
        conn.execute(
            """
            UPDATE clusters
            SET last_seen_at = COALESCE(last_seen_at, ?)
            WHERE id = ? AND (last_seen_at IS NULL OR last_seen_at = '')
            """,
            (timestamp, cluster_id),
        )


def list_events(
    limit: int = 50,
    cluster: str = "",
    cluster_kind: str = "",
    source: str = "",
    user_id: str = "",
    exclude_namespaces: set[str] | None = None,
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
    if exclude_namespaces:
        namespaces = sorted(namespace for namespace in exclude_namespaces if namespace)
        placeholders = ", ".join("?" for _ in namespaces)
        filters.append(f"(namespace IS NULL OR namespace = '' OR namespace NOT IN ({placeholders}))")
        params.extend(namespaces)
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


def event_summary(user_id: str = "", cluster: str = "") -> dict[str, Any]:
    init_db()
    normalized_cluster = str(cluster or "").strip()
    filters: list[str] = []
    params: list[Any] = []
    if user_id:
        filters.append("cluster_id IN (SELECT id FROM clusters WHERE user_id = ?)")
        params.append(user_id)
    if normalized_cluster:
        filters.append("cluster = ?")
        params.append(normalized_cluster)
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    high_filters = ["severity = 'high'"]
    high_params: list[Any] = []
    if user_id:
        high_filters.append("cluster_id IN (SELECT id FROM clusters WHERE user_id = ?)")
        high_params.append(user_id)
    if normalized_cluster:
        high_filters.append("cluster = ?")
        high_params.append(normalized_cluster)
    high_where = f"WHERE {' AND '.join(high_filters)}"
    with _connect() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS count FROM events {where}", params).fetchone()["count"]
        recent_24h = conn.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM events
            {where}
            {"AND" if where else "WHERE"} strftime('%s', COALESCE(timestamp, created_at)) >= strftime('%s', 'now', '-1 day')
            """,
            params,
        ).fetchone()["count"]
        latest_event_at = conn.execute(
            f"SELECT MAX(COALESCE(timestamp, created_at)) AS value FROM events {where}",
            params,
        ).fetchone()["value"]
        cluster_where = "WHERE user_id = ? AND status != 'deleted'" if user_id else "WHERE status != 'deleted'"
        cluster_params = [user_id] if user_id else []
        last_seen_at = conn.execute(
            f"SELECT MAX(last_seen_at) AS value FROM clusters {cluster_where}",
            cluster_params,
        ).fetchone()["value"]
        by_severity = _count_by(conn, "severity", user_id=user_id, cluster=normalized_cluster)
        by_rule = _count_by(conn, "rule", user_id=user_id, cluster=normalized_cluster)
        by_namespace = _count_by(conn, "namespace", user_id=user_id, cluster=normalized_cluster)
        by_action = _count_by(conn, "action_taken", user_id=user_id, cluster=normalized_cluster)
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
        "recent_24h": recent_24h,
        "latest_event_at": latest_event_at or "",
        "last_seen_at": last_seen_at or "",
        "by_severity": by_severity,
        "by_rule": by_rule,
        "by_namespace": by_namespace,
        "by_action": by_action,
        "recent_high": [_row_to_event(row) for row in recent_high],
    }


def prometheus_metrics_snapshot() -> dict[str, Any]:
    init_db()
    with _connect() as conn:
        runtime_events_total = conn.execute(
            """
            SELECT events.cluster_id AS cluster_id,
                   clusters.name AS cluster_name,
                   COALESCE(NULLIF(events.severity, ''), 'unknown') AS severity,
                   COALESCE(NULLIF(events.source, ''), 'unknown') AS source,
                   COUNT(*) AS value
            FROM events
            JOIN clusters ON clusters.id = events.cluster_id
            WHERE clusters.status != 'deleted'
            GROUP BY events.cluster_id, clusters.name, severity, source
            ORDER BY clusters.name, severity, source
            """
        ).fetchall()
        runtime_events_recent_24h = conn.execute(
            """
            SELECT events.cluster_id AS cluster_id,
                   clusters.name AS cluster_name,
                   COALESCE(NULLIF(events.severity, ''), 'unknown') AS severity,
                   COUNT(*) AS value
            FROM events
            JOIN clusters ON clusters.id = events.cluster_id
            WHERE clusters.status != 'deleted'
              AND strftime('%s', COALESCE(events.timestamp, events.created_at)) >= strftime('%s', 'now', '-1 day')
            GROUP BY events.cluster_id, clusters.name, severity
            ORDER BY clusters.name, severity
            """
        ).fetchall()
        cluster_last_seen = conn.execute(
            """
            SELECT id AS cluster_id, name AS cluster_name, last_seen_at
            FROM clusters
            WHERE status != 'deleted'
              AND last_seen_at IS NOT NULL
              AND last_seen_at != ''
            ORDER BY name
            """
        ).fetchall()
        active_clusters = conn.execute(
            """
            SELECT COALESCE(NULLIF(kind, ''), 'customer') AS cluster_kind, COUNT(*) AS value
            FROM clusters
            WHERE status = 'active'
            GROUP BY cluster_kind
            ORDER BY cluster_kind
            """
        ).fetchall()
    return {
        "runtime_events_total": [dict(row) for row in runtime_events_total],
        "runtime_events_recent_24h": [dict(row) for row in runtime_events_recent_24h],
        "cluster_last_seen": [dict(row) for row in cluster_last_seen],
        "active_clusters": [dict(row) for row in active_clusters],
    }


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _count_by(conn: sqlite3.Connection, column: str, user_id: str = "", cluster: str = "") -> dict[str, int]:
    filters = [f"{column} IS NOT NULL", f"{column} != ''"]
    params: list[Any] = []
    if user_id:
        filters.append("cluster_id IN (SELECT id FROM clusters WHERE user_id = ?)")
        params.append(user_id)
    normalized_cluster = str(cluster or "").strip()
    if normalized_cluster:
        filters.append("cluster = ?")
        params.append(normalized_cluster)
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


def _row_to_policy_apply_history(row: sqlite3.Row) -> dict[str, Any]:
    result = {}
    try:
        result = json.loads(row["result_json"] or "{}")
    except json.JSONDecodeError:
        result = {}
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "cluster_id": row["cluster_id"],
        "policy_type": row["policy_type"],
        "policy_name": row["policy_name"],
        "manifest_hash": row["manifest_hash"],
        "status": row["status"],
        "error": row["error"],
        "result": result,
        "created_at": row["created_at"],
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
                slack_enabled INTEGER NOT NULL DEFAULT 1,
                last_seen_at TEXT,
                deleted_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO clusters (id, user_id, name, kind, token_hash, status, slack_enabled, last_seen_at, deleted_at, created_at)
            SELECT id, user_id, name, kind, token_hash, status, 1, last_seen_at, NULL, created_at
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
