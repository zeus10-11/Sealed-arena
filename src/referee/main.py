"""Sealed Arena Referee — The Blind Mediator.

The Referee is the single trusted component that mediates ALL communication
between Red, Blue, and Model zones. It enforces:

1. Capability tokens — narrowly scoped, short-lived authorisations
2. Commit-reveal — red-team attacks are committed before model sees them
3. Timing shaping — responses released on fixed cadence to close timing channels
4. Audit chain — every event signed into a tamper-evident log
5. Policy enforcement — default-deny, explicit allow via OPA-style rules
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from sealed_arena.audit.bundle import BundleExporter
from sealed_arena.audit.chain import AuditChain
from sealed_arena.audit.merkle import MerkleTree
from sealed_arena.audit.signer import KeyManager
from sealed_arena.audit.verify import verify_bundle
from sealed_arena.canary.mesh import CanaryMesh, LeakageReport, Zone as CanaryZone
from sealed_arena.config import settings
from sealed_arena.models import (
    AuditEntry,
    BundleMetadata,
    CapabilityToken,
    Commitment,
    Message,
    PolicyDecision,
    VerdictBundle,
    Zone,
)
from src.common import (
    TokenPayload,
    canonical_json,
    compute_timing_bucket,
    sign_token,
    verify_token_signature,
)


# ═══════════════════════════════════════════════════════════════════════════
# Request/Response Models
# ═══════════════════════════════════════════════════════════════════════════


class SendMessageRequest(BaseModel):
    """Request to send a message through the Referee."""

    token: str = Field(..., description="Capability token")
    target_zone: Zone = Field(..., description="Destination zone")
    content: str = Field(..., description="Message payload")
    commitment_hash: str | None = Field(
        None, description="Optional commit-reveal commitment hash"
    )


class SendMessageResponse(BaseModel):
    """Response from sending a message."""

    message_id: str
    content_hash: str
    status: str = "accepted"
    timing_bucket_ms: int


class CommitRequest(BaseModel):
    """Submit a commitment (commit-reveal protocol)."""

    token: str
    attacker_id: str
    hash_value: str


class CommitResponse(BaseModel):
    commitment_id: str
    status: str = "recorded"


class RevealRequest(BaseModel):
    """Reveal a committed payload."""

    token: str
    commitment_id: str
    nonce: str
    payload: str


class RevealResponse(BaseModel):
    commitment_id: str
    verified: bool
    status: str


class TokenRequest(BaseModel):
    """Request a capability token."""

    zone: Zone
    permissions: list[str]
    max_queries: int = 50
    ttl_seconds: int = 300


class TokenResponse(BaseModel):
    token: str
    token_id: str
    expires_at: str
    max_queries: int


class HealthResponse(BaseModel):
    status: str = "healthy"
    referee_version: str = "0.1.0"
    audit_entries: int = 0
    commitments_pending: int = 0
    tokens_active: int = 0


class VerifyBundleRequest(BaseModel):
    bundle_path: str


# ═══════════════════════════════════════════════════════════════════════════
# Referee State
# ═══════════════════════════════════════════════════════════════════════════


class RefereeState:
    """Central state for the Referee service."""

    def __init__(self) -> None:
        # Core components
        self.audit_chain = AuditChain()
        self.key_manager = KeyManager()
        self.canary_mesh = CanaryMesh()

        # Runtime state
        self._commitments: dict[str, Commitment] = {}
        self._active_tokens: dict[str, CapabilityToken] = {}
        self._token_queries: dict[str, int] = {}  # token_id -> queries_used
        self._message_queue: dict[str, asyncio.Queue] = {}  # zone -> queue
        self._lock = asyncio.Lock()

        # Timing
        self._timing_bucket_ms = settings.TIMING_BUCKET_MS

        # Load or generate signing key
        self._init_keys()

        # Plant initial canaries for each zone
        self._plant_initial_canaries()

    def _init_keys(self) -> None:
        """Load or generate Ed25519 signing keys."""
        key_path = Path(settings.SIGNING_KEY_PATH)
        if key_path.exists():
            self.key_manager.load_keypair(key_path)
        else:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            self.key_manager.generate_keypair(private_key_path=key_path)

    def _plant_initial_canaries(self) -> None:
        """Plant canaries in each zone's state."""
        for zone in ["red", "blue", "model", "referee"]:
            self.canary_mesh.plant_canaries(zone, count=3)

    # ----------------------------------------------------------------------
    # Capability Token Management
    # ----------------------------------------------------------------------

    def issue_token(self, request: TokenRequest) -> TokenResponse:
        """Issue a new capability token."""
        token_id = secrets.token_urlsafe(16)
        issued_at = datetime.now(timezone.utc)
        expires_at = issued_at + timedelta(seconds=request.ttl_seconds)

        payload = TokenPayload(
            token_id=token_id,
            zone=request.zone.value,
            permissions=request.permissions,
            max_queries=request.max_queries,
            queries_used=0,
            issued_at=issued_at.isoformat(),
            expires_at=expires_at.isoformat(),
        )
        signature = sign_token(payload, settings.TOKEN_SECRET)

        token = CapabilityToken(
            token_id=token_id,
            zone=request.zone,
            permissions=request.permissions,
            max_queries=request.max_queries,
            queries_used=0,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=signature,
        )

        self._active_tokens[token_id] = token
        self._token_queries[token_id] = 0

        # Audit log
        self.audit_chain.append(
            "token_issued",
            {
                "token_id": token_id,
                "zone": request.zone.value,
                "permissions": request.permissions,
                "max_queries": request.max_queries,
                "expires_at": expires_at.isoformat(),
            },
        )

        return TokenResponse(
            token=f"{token_id}.{signature}",
            token_id=token_id,
            expires_at=expires_at.isoformat(),
            max_queries=request.max_queries,
        )

    def verify_token(
        self, token_str: str, required_permission: str
    ) -> tuple[bool, CapabilityToken | None, str]:
        """Verify a capability token and check permission.

        Returns: (allowed, token, reason)
        """
        # Parse token (format: token_id.signature)
        parts = token_str.split(".", 1)
        if len(parts) != 2:
            self._log_policy(token_str, required_permission, "unknown", False, "Malformed token")
            return False, None, "Malformed token format"

        token_id, signature = parts

        token = self._active_tokens.get(token_id)
        if token is None:
            self._log_policy(token_id, required_permission, "unknown", False, "Token not found")
            return False, None, "Token not found or revoked"

        if token.is_expired():
            self._log_policy(token_id, required_permission, token.zone.value, False, "Token expired")
            return False, token, "Token expired"

        if not token.has_queries_remaining():
            self._log_policy(token_id, required_permission, token.zone.value, False, "Query budget exhausted")
            return False, token, "Query budget exhausted"

        if not token.has_permission(required_permission):
            self._log_policy(token_id, required_permission, token.zone.value, False, "Permission denied")
            return False, token, f"Permission '{required_permission}' not granted"

        # Verify signature
        payload = TokenPayload(
            token_id=token.token_id,
            zone=token.zone.value,
            permissions=token.permissions,
            max_queries=token.max_queries,
            queries_used=0,  # Signature is computed at creation with queries_used=0
            issued_at=token.issued_at.isoformat(),
            expires_at=token.expires_at.isoformat(),
        )
        if not verify_token_signature(payload, token.signature, settings.TOKEN_SECRET):
            self._log_policy(token_id, required_permission, token.zone.value, False, "Invalid signature")
            return False, token, "Invalid token signature"

        # Increment query count
        token.queries_used += 1
        self._token_queries[token_id] = token.queries_used

        self._log_policy(token_id, required_permission, token.zone.value, True, "Allowed")
        return True, token, "Allowed"

    def _log_policy(
        self, token_id: str, action: str, resource: str, allowed: bool, reason: str
    ) -> None:
        """Log a policy decision to the audit chain."""
        self.audit_chain.append(
            "policy_decision",
            {
                "token_id": token_id,
                "action": action,
                "resource": resource,
                "allowed": allowed,
                "reason": reason,
            },
        )

    # ----------------------------------------------------------------------
    # Message Mediation
    # ══════════════════════════════════════════════════════════════════════════

    async def send_message(
        self, source_zone: Zone, request: SendMessageRequest
    ) -> SendMessageResponse:
        """Mediate a message from source_zone to target_zone."""
        # Verify token with send_prompt permission
        allowed, token, reason = self.verify_token(request.token, "send_prompt")
        if not allowed:
            raise HTTPException(status_code=403, detail=f"Token verification failed: {reason}")

        # Verify token belongs to source zone
        if token.zone != source_zone:
            raise HTTPException(
                status_code=403, detail=f"Token zone {token.zone} != source zone {source_zone}"
            )

        # Create message
        message = Message(
            source_zone=source_zone,
            target_zone=request.target_zone,
            content=request.content,
        )

        # If this is a commit-reveal flow, verify commitment
        if request.commitment_hash:
            await self._verify_commitment(request.commitment_hash, message.content)

        # Enqueue for target zone
        target = request.target_zone.value
        if target not in self._message_queue:
            self._message_queue[target] = asyncio.Queue()
        await self._message_queue[target].put(message)

        # Apply timing bucket delay
        wait_s = compute_timing_bucket(self._timing_bucket_ms)
        if wait_s > 0:
            await asyncio.sleep(wait_s)

        # Audit log
        self.audit_chain.append(
            "message",
            {
                "message_id": message.id,
                "source_zone": source_zone.value,
                "target_zone": request.target_zone.value,
                "content_hash": message.content_hash,
                "has_commitment": request.commitment_hash is not None,
            },
        )

        # Check for canary leakage in the message content
        self.canary_mesh.check_for_leakage(message.content, source_zone.value)

        return SendMessageResponse(
            message_id=message.id,
            content_hash=message.content_hash,
            timing_bucket_ms=self._timing_bucket_ms,
        )

    async def receive_messages(
        self, zone: Zone, token: str, max_messages: int = 10
    ) -> list[Message]:
        """Receive messages for a zone (long-polling style)."""
        # Verify token with read_results permission
        allowed, _, reason = self.verify_token(token, "read_results")
        if not allowed:
            raise HTTPException(status_code=403, detail=reason)

        queue = self._message_queue.get(zone.value, asyncio.Queue())
        messages = []

        # Drain up to max_messages
        for _ in range(max_messages):
            try:
                msg = queue.get_nowait()
                messages.append(msg)
            except asyncio.QueueEmpty:
                break

        return messages

    # ----------------------------------------------------------------------
    # Commit-Reveal
    # ----------------------------------------------------------------------

    async def commit(self, request: CommitRequest) -> CommitResponse:
        """Record a commitment from red team."""
        allowed, _, reason = self.verify_token(request.token, "commit_attack")
        if not allowed:
            raise HTTPException(status_code=403, detail=reason)

        commitment = Commitment(
            id=secrets.token_urlsafe(12),
            attacker_id=request.attacker_id,
            hash_value=request.hash_value,
        )
        self._commitments[commitment.id] = commitment

        self.audit_chain.append(
            "commitment",
            {
                "commitment_id": commitment.id,
                "attacker_id": request.attacker_id,
                "hash_value": request.hash_value,
            },
        )

        return CommitResponse(commitment_id=commitment.id)

    async def reveal(self, request: RevealRequest) -> RevealResponse:
        """Reveal a committed payload."""
        allowed, _, reason = self.verify_token(request.token, "reveal_attack")
        if not allowed:
            raise HTTPException(status_code=403, detail=reason)

        commitment = self._commitments.get(request.commitment_id)
        if commitment is None:
            raise HTTPException(status_code=404, detail="Commitment not found")

        if commitment.nonce is not None:
            raise HTTPException(status_code=400, detail="Commitment already revealed")

        commitment.nonce = request.nonce
        commitment.payload = request.payload
        commitment.revealed_at = datetime.now(timezone.utc)

        verified = commitment.verify()

        self.audit_chain.append(
            "reveal",
            {
                "commitment_id": request.commitment_id,
                "attacker_id": commitment.attacker_id,
                "verified": verified,
            },
        )

        return RevealResponse(
            commitment_id=request.commitment_id, verified=verified, status="revealed"
        )

    async def _verify_commitment(self, commitment_hash: str, content: str) -> bool:
        """Verify that content matches a recorded commitment."""
        for commitment in self._commitments.values():
            if commitment.hash_value == commitment_hash and commitment.payload:
                computed = hashlib.sha256(
                    (commitment.nonce + commitment.payload).encode("utf-8")
                ).hexdigest()
                return computed == commitment_hash
        return False

    # ----------------------------------------------------------------------
    # Bundle Creation & Verification
    # ----------------------------------------------------------------------

    def create_bundle(
        self,
        arena_id: str,
        model_snapshot_id: str,
        seeds: list[str],
    ) -> Path:
        """Create a signed verdict bundle."""
        metadata = BundleMetadata(
            arena_id=arena_id,
            model_snapshot_id=model_snapshot_id,
            seeds=seeds,
            created_at=datetime.now(timezone.utc),
        )

        exporter = BundleExporter(self.audit_chain, self.key_manager, metadata)

        # Add revealed payloads
        for commitment in self._commitments.values():
            if commitment.nonce and commitment.payload:
                exporter.add_revealed_payload(
                    commitment.hash_value, commitment.payload, commitment.nonce
                )

        output_path = Path(f"verdict_{arena_id}.zip")
        return exporter.export(output_path)

    def get_canary_report(self) -> LeakageReport:
        """Get the current canary leakage report."""
        return self.canary_mesh.get_leakage_report()

    def get_audit_summary(self) -> dict[str, Any]:
        """Get audit chain summary for health check."""
        return {
            "entries": self.audit_chain.length,
            "head_hash": self.audit_chain.head.entry_hash if self.audit_chain.head else None,
            "commitments_pending": len(
                [c for c in self._commitments.values() if c.nonce is None]
            ),
            "tokens_active": len(self._active_tokens),
        }


# Global referee state (single instance)
_referee_state: RefereeState | None = None


def get_referee() -> RefereeState:
    """Get the global referee state instance."""
    global _referee_state
    if _referee_state is None:
        _referee_state = RefereeState()
    return _referee_state


# ═══════════════════════════════════════════════════════════════════════════
# FastAPI Application
# ═══════════════════════════════════════════════════════════════════════════


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup
    referee = get_referee()
    print(f"[Referee] Started on {settings.REFEREE_HOST}:{settings.REFEREE_PORT}")
    print(f"[Referee] Timing bucket: {referee._timing_bucket_ms}ms")
    print(f"[Referee] Audit key: {referee.key_manager.get_public_key_hex()[:16]}...")
    yield
    # Shutdown
    print("[Referee] Shutting down...")


app = FastAPI(
    title="Sealed Arena Referee",
    description="Blind mediator for adversarial AI safety testing",
    version="0.1.0",
    lifespan=lifespan,
)


# ═══════════════════════════════════════════════════════════════════════════
# Middleware
# ═══════════════════════════════════════════════════════════════════════════


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    """Log all API calls to audit chain."""
    start = time.time()
    response = await call_next(request)
    duration_ms = int((time.time() - start) * 1000)

    referee = get_referee()
    referee.audit_chain.append(
        "api_call",
        {
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": duration_ms,
        },
    )
    return response


# ═══════════════════════════════════════════════════════════════════════════
# Endpoints
# ═══════════════════════════════════════════════════════════════════════════


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Health check endpoint."""
    referee = get_referee()
    summary = referee.get_audit_summary()
    return HealthResponse(
        audit_entries=summary["entries"],
        commitments_pending=summary["commitments_pending"],
        tokens_active=summary["tokens_active"],
    )


# ---- Capability Tokens ----

@app.post("/tokens", response_model=TokenResponse)
async def issue_token(request: TokenRequest) -> TokenResponse:
    """Issue a new capability token."""
    referee = get_referee()
    return referee.issue_token(request)


# ---- Message Passing ----

@app.post("/zones/red/messages", response_model=SendMessageResponse)
async def red_send(request: SendMessageRequest) -> SendMessageResponse:
    """Red zone sends a message."""
    referee = get_referee()
    return await referee.send_message(Zone.RED, request)


@app.post("/zones/blue/messages", response_model=SendMessageResponse)
async def blue_send(request: SendMessageRequest) -> SendMessageResponse:
    """Blue zone sends a message."""
    referee = get_referee()
    return await referee.send_message(Zone.BLUE, request)


@app.post("/zones/model/messages", response_model=SendMessageResponse)
async def model_send(request: SendMessageRequest) -> SendMessageResponse:
    """Model zone sends a message."""
    referee = get_referee()
    return await referee.send_message(Zone.MODEL, request)


@app.get("/zones/red/messages")
async def red_receive(
    token: str = Header(..., alias="X-Capability-Token"),
    max_messages: int = 10,
) -> list[Message]:
    """Red zone receives messages."""
    referee = get_referee()
    return await referee.receive_messages(Zone.RED, token, max_messages)


@app.get("/zones/blue/messages")
async def blue_receive(
    token: str = Header(..., alias="X-Capability-Token"),
    max_messages: int = 10,
) -> list[Message]:
    """Blue zone receives messages."""
    referee = get_referee()
    return await referee.receive_messages(Zone.BLUE, token, max_messages)


@app.get("/zones/model/messages")
async def model_receive(
    token: str = Header(..., alias="X-Capability-Token"),
    max_messages: int = 10,
) -> list[Message]:
    """Model zone receives messages."""
    referee = get_referee()
    return await referee.receive_messages(Zone.MODEL, token, max_messages)


# ---- Commit-Reveal ----

@app.post("/commit", response_model=CommitResponse)
async def create_commitment(request: CommitRequest) -> CommitResponse:
    """Submit a commitment (commit-reveal protocol)."""
    referee = get_referee()
    return await referee.commit(request)


@app.post("/reveal", response_model=RevealResponse)
async def reveal_commitment(request: RevealRequest) -> RevealResponse:
    """Reveal a committed payload."""
    referee = get_referee()
    return await referee.reveal(request)


# ---- Canary Mesh ----

@app.get("/canary/report")
async def canary_report() -> LeakageReport:
    """Get the current canary leakage detection report."""
    referee = get_referee()
    return referee.get_canary_report()


@app.post("/canary/check/{zone}")
async def canary_check(zone: Zone, content: str) -> list:
    """Check content for foreign canaries (for zone agents to call)."""
    referee = get_referee()
    events = referee.canary_mesh.check_for_leakage(content, zone.value)
    return [
        {
            "canary_fingerprint": e.canary.fingerprint,
            "owner_zone": e.canary.owner_zone,
            "found_in_zone": e.found_in_zone,
            "severity": e.severity,
            "snippet": e.content_snippet,
        }
        for e in events
    ]


# ---- Verdict Bundles ----

class BundleCreateRequest(BaseModel):
    """Request to create a verdict bundle."""
    arena_id: str
    model_snapshot_id: str
    seeds: list[str] = []


@app.post("/bundle/create")
async def create_bundle(request: BundleCreateRequest) -> dict[str, str]:
    """Create a signed verdict bundle for the session."""
    referee = get_referee()
    path = referee.create_bundle(request.arena_id, request.model_snapshot_id, request.seeds)
    return {"bundle_path": str(path), "status": "created"}


@app.post("/bundle/verify")
async def verify_bundle_endpoint(request: VerifyBundleRequest) -> dict:
    """Verify a verdict bundle offline."""
    result = verify_bundle(request.bundle_path)
    return {
        "bundle_path": result.bundle_path,
        "overall_valid": result.overall_valid,
        "checks": [
            {"name": c.name, "passed": c.passed, "detail": c.detail}
            for c in result.checks
        ],
    }


# ---- Audit Log Access ----

@app.get("/audit/entries")
async def get_audit_entries(start: int = 0, end: int | None = None) -> list[dict]:
    """Get audit log entries (for debugging/dashboard)."""
    referee = get_referee()
    entries = referee.audit_chain.get_entries(start, end)
    return [e.model_dump() for e in entries]


@app.get("/audit/verify")
async def verify_audit_chain() -> dict:
    """Verify the integrity of the audit chain."""
    referee = get_referee()
    valid, broken_at = referee.audit_chain.verify_chain()
    return {
        "valid": valid,
        "broken_at": broken_at,
        "total_entries": referee.audit_chain.length,
    }