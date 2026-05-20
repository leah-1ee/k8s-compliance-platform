from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from typing import Any


ADMIN_GRAFANA_COOKIE_NAME = "kubeowl_admin_grafana"


def issue_admin_grafana_token(ttl_seconds: int = 600) -> str:
    secret = _admin_secret()
    if not secret:
        return ""
    payload = {
        "sub": "kubeowl-admin",
        "email": os.getenv("GRAFANA_ADMIN_PROXY_EMAIL", "kubeowl-admin@local"),
        "name": os.getenv("GRAFANA_ADMIN_PROXY_NAME", "KubeOwl Admin"),
        "exp": int(time.time()) + max(60, int(ttl_seconds or 600)),
    }
    encoded_payload = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = _sign(encoded_payload, secret)
    return f"{encoded_payload}.{signature}"


def admin_user_from_token(token: str | None) -> dict[str, Any] | None:
    secret = _admin_secret()
    raw = str(token or "").strip()
    if not secret or "." not in raw:
        return None
    encoded_payload, signature = raw.rsplit(".", 1)
    expected_signature = _sign(encoded_payload, secret)
    if not hmac.compare_digest(signature, expected_signature):
        return None
    try:
        payload = json.loads(_unb64(encoded_payload).decode("utf-8"))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(payload.get("exp") or 0) < int(time.time()):
        return None
    email = str(payload.get("email") or "kubeowl-admin@local").strip()
    name = str(payload.get("name") or "KubeOwl Admin").strip()
    return {
        "id": "kubeowl-admin",
        "email": email,
        "name": name,
        "provider": "admin",
    }


def _admin_secret() -> str:
    return os.getenv("ADMIN_TOKEN", "").strip()


def _sign(value: str, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), value.encode("ascii"), hashlib.sha256).digest()
    return _b64(digest)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
