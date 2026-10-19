"""Common utilities shared across all zones and the Referee."""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel


class TokenPayload(BaseModel):
    """Payload for capability token (signed with HMAC)."""

    token_id: str
    zone: str
    permissions: list[str]
    max_queries: int
    queries_used: int
    issued_at: str  # ISO format
    expires_at: str  # ISO format


def sign_token(payload: TokenPayload, secret: str) -> str:
    """Sign a token payload with HMAC-SHA256."""
    canonical = (
        f"{payload.token_id}|{payload.zone}|{','.join(payload.permissions)}"
        f"|{payload.max_queries}|{payload.queries_used}"
        f"|{payload.issued_at}|{payload.expires_at}"
    )
    return hmac.new(
        secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_token_signature(payload: TokenPayload, signature: str, secret: str) -> bool:
    """Verify a token's HMAC signature."""
    expected = sign_token(payload, secret)
    return hmac.compare_digest(expected, signature)


def compute_timing_bucket(bucket_ms: int) -> float:
    """Return seconds to wait until the next timing bucket boundary."""
    now_ms = int(time.time() * 1000)
    next_bucket = ((now_ms // bucket_ms) + 1) * bucket_ms
    wait_ms = next_bucket - now_ms
    return max(0.0, wait_ms / 1000.0)


def canonical_json(data: dict[str, Any]) -> str:
    """Return canonical JSON string with sorted keys."""
    import json

    return json.dumps(data, sort_keys=True, separators=(",", ":"))