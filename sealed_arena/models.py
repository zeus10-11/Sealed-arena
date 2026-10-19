"""
Shared Pydantic models for the Sealed Arena.

Every data structure exchanged between zones, the Referee, the audit log,
and the Leak-Lab is defined here so there is a single source of truth for
serialisation / validation across the entire system.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, computed_field


# ═══════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════


class Zone(str, Enum):
    """Logical isolation zone recognised by the Referee.

    * **RED**   — the attacker / red-team agent.
    * **BLUE**  — the defender / blue-team agent.
    * **MODEL** — the model under test.
    """

    RED = "red"
    BLUE = "blue"
    MODEL = "model"


# ═══════════════════════════════════════════════════════════════════════════
# Core message type
# ═══════════════════════════════════════════════════════════════════════════


class Message(BaseModel):
    """A single message transiting through the Referee.

    The ``content_hash`` is automatically derived from ``content`` using
    SHA-256, providing an integrity check that can be verified against the
    audit log without revealing the content itself.
    """

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique message identifier (UUID v4).",
    )
    source_zone: Zone = Field(
        ...,
        description="Zone that originated this message.",
    )
    target_zone: Zone = Field(
        ...,
        description="Zone this message is addressed to.",
    )
    content: str = Field(
        ...,
        description="Plain-text message payload.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the message was created.",
    )

    @computed_field  # type: ignore[misc]
    @property
    def content_hash(self) -> str:
        """SHA-256 hex digest of ``content``."""
        return hashlib.sha256(self.content.encode("utf-8")).hexdigest()


# ═══════════════════════════════════════════════════════════════════════════
# Commitment scheme (commit-reveal for red-team attacks)
# ═══════════════════════════════════════════════════════════════════════════


class Commitment(BaseModel):
    """Cryptographic commitment used in the commit-reveal protocol.

    The red-team agent first publishes ``hash_value`` (the commitment).
    After the model responds, the red-team reveals ``nonce`` and ``payload``
    so auditors can verify ``SHA-256(nonce || payload) == hash_value``.
    """

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique commitment identifier.",
    )
    attacker_id: str = Field(
        ...,
        description="Identifier of the committing red-team agent.",
    )
    hash_value: str = Field(
        ...,
        description="SHA-256 hex digest that constitutes the commitment.",
    )
    nonce: Optional[str] = Field(
        default=None,
        description="Random nonce revealed after model response.",
    )
    payload: Optional[str] = Field(
        default=None,
        description="Attack payload revealed after model response.",
    )
    committed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the commitment was recorded.",
    )
    revealed_at: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp when the reveal occurred (None until revealed).",
    )

    def verify(self) -> bool:
        """Return ``True`` if the revealed nonce+payload match the commitment hash.

        Raises:
            ValueError: If the commitment has not been revealed yet.
        """
        if self.nonce is None or self.payload is None:
            raise ValueError("Commitment has not been revealed yet.")
        computed = hashlib.sha256(
            (self.nonce + self.payload).encode("utf-8")
        ).hexdigest()
        return computed == self.hash_value


# ═══════════════════════════════════════════════════════════════════════════
# Capability token (JWT-like, HMAC-signed)
# ═══════════════════════════════════════════════════════════════════════════


class CapabilityToken(BaseModel):
    """A capability token that authorises a zone to perform specific actions.

    Tokens are signed with an HMAC secret held by the Referee so that
    tampered tokens can be detected immediately.
    """

    token_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique token identifier.",
    )
    zone: Zone = Field(
        ...,
        description="The zone this token authorises.",
    )
    permissions: list[str] = Field(
        ...,
        description=(
            "List of permitted actions, e.g. 'send_prompt', 'read_results', "
            "'read_own_results'."
        ),
    )
    max_queries: int = Field(
        default=50,
        ge=1,
        description="Maximum number of queries this token allows.",
    )
    queries_used: int = Field(
        default=0,
        ge=0,
        description="Number of queries consumed so far.",
    )
    issued_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the token was issued.",
    )
    expires_at: datetime = Field(
        ...,
        description="UTC timestamp after which the token is no longer valid.",
    )
    signature: str = Field(
        default="",
        description="HMAC-SHA256 hex signature over the token payload.",
    )

    def is_expired(self) -> bool:
        """Return ``True`` if the token has passed its expiration time."""
        return datetime.now(timezone.utc) >= self.expires_at

    def has_queries_remaining(self) -> bool:
        """Return ``True`` if the token still has unused queries."""
        return self.queries_used < self.max_queries

    def has_permission(self, action: str) -> bool:
        """Check whether the token grants a specific permission."""
        return action in self.permissions


# ═══════════════════════════════════════════════════════════════════════════
# Policy engine decision record
# ═══════════════════════════════════════════════════════════════════════════


class PolicyDecision(BaseModel):
    """Record of a single policy evaluation made by the Referee.

    Every time a capability token is checked against a requested action,
    one of these records is emitted into the audit log.
    """

    token_id: str = Field(
        ...,
        description="ID of the capability token being evaluated.",
    )
    action: str = Field(
        ...,
        description="The action the caller is requesting (e.g. 'send_prompt').",
    )
    resource: str = Field(
        ...,
        description="The resource being accessed (e.g. a zone name or endpoint).",
    )
    allowed: bool = Field(
        ...,
        description="Whether the policy engine allowed the action.",
    )
    reason: str = Field(
        default="",
        description="Human-readable explanation for the decision.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the policy decision.",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Append-only audit log
# ═══════════════════════════════════════════════════════════════════════════


class AuditEntry(BaseModel):
    """A single entry in the append-only, hash-chained audit log.

    Each entry contains a back-pointer (``previous_hash``) to the preceding
    entry, forming a tamper-evident chain analogous to a blockchain.
    ``entry_hash`` is ``SHA-256(index || previous_hash || event_type || event_data || timestamp)``.
    """

    index: int = Field(
        ...,
        ge=0,
        description="Zero-based sequence number in the audit log.",
    )
    previous_hash: str = Field(
        ...,
        description="SHA-256 hex digest of the previous entry (genesis uses '0' * 64).",
    )
    event_type: str = Field(
        ...,
        description="Category label, e.g. 'message', 'policy_decision', 'commitment'.",
    )
    event_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary JSON-serialisable payload for the event.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the entry was appended.",
    )
    entry_hash: str = Field(
        default="",
        description="SHA-256 hex digest of this entry (computed on creation).",
    )

    def compute_hash(self) -> str:
        """Compute the expected hash for this entry (for verification)."""
        import json

        canonical_data = json.dumps(self.event_data, sort_keys=True, separators=(",", ":"))
        canonical = (
            f"{self.index}|{self.previous_hash}|{self.event_type}"
            f"|{canonical_data}"
            f"|{self.timestamp.isoformat()}"
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify_hash(self) -> bool:
        """Verify that the stored entry_hash matches the computed hash."""
        return self.entry_hash == self.compute_hash()


def _deterministic_dict(d: dict[str, Any]) -> str:
    """Return a deterministic string representation of a dict for hashing.

    Keys are sorted, values are recursively stringified. This is intentionally
    simple — sufficient for our hashing needs without pulling in a canonical
    JSON library.
    """
    parts: list[str] = []
    for key in sorted(d.keys()):
        value = d[key]
        if isinstance(value, dict):
            parts.append(f"{key}:{_deterministic_dict(value)}")
        elif isinstance(value, (list, tuple)):
            items = ",".join(
                _deterministic_dict(v) if isinstance(v, dict) else str(v)
                for v in value
            )
            parts.append(f"{key}:[{items}]")
        else:
            parts.append(f"{key}:{value}")
    return "{" + ",".join(parts) + "}"


# ═══════════════════════════════════════════════════════════════════════════
# Merkle tree node
# ═══════════════════════════════════════════════════════════════════════════


class MerkleNode(BaseModel):
    """Node in a binary Merkle tree built over audit entries.

    Leaf nodes store the ``entry_hash`` of an :class:`AuditEntry`.
    Internal nodes store ``SHA-256(left.hash_value || right.hash_value)``.
    """

    hash_value: str = Field(
        ...,
        description="SHA-256 hex digest for this node.",
    )
    left: Optional["MerkleNode"] = Field(
        default=None,
        description="Left child (None for leaf nodes).",
    )
    right: Optional["MerkleNode"] = Field(
        default=None,
        description="Right child (None for leaf nodes).",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Merkle proof structures
# ═══════════════════════════════════════════════════════════════════════════


class MerkleProofStep(BaseModel):
    """A single step in a Merkle inclusion proof."""

    hash: str = Field(..., description="Sibling hash at this level.")
    direction: str = Field(
        ..., description="Whether the sibling is 'left' or 'right' of the current hash."
    )


class MerkleProof(BaseModel):
    """Merkle inclusion proof for a single leaf."""

    leaf_index: int = Field(..., description="Index of the leaf in the original list.")
    leaf_hash: str = Field(..., description="Hash of the leaf being proven.")
    siblings: list[MerkleProofStep] = Field(
        default_factory=list, description="Ordered list of sibling hashes from leaf to root."
    )
    root: str = Field(..., description="Expected Merkle root hash.")


# ═══════════════════════════════════════════════════════════════════════════
# Bundle metadata
# ═══════════════════════════════════════════════════════════════════════════


class BundleMetadata(BaseModel):
    """Metadata for a verdict bundle."""

    arena_id: str = Field(..., description="Unique arena session identifier.")
    model_snapshot_id: str = Field(..., description="Model checkpoint identifier.")
    seeds: list[str] = Field(default_factory=list, description="Random seeds used.")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Bundle creation timestamp.",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Verification result structures
# ═══════════════════════════════════════════════════════════════════════════


class CheckResult(BaseModel):
    """Result of a single verification check."""

    name: str = Field(..., description="Name of the check.")
    passed: bool = Field(..., description="Whether the check passed.")
    detail: str = Field(default="", description="Human-readable detail.")


class VerificationResult(BaseModel):
    """Overall result of bundle verification."""

    bundle_path: str = Field(..., description="Path to the verified bundle.")
    overall_valid: bool = Field(..., description="Whether all checks passed.")
    checks: list[CheckResult] = Field(default_factory=list, description="Individual check results.")


# ═══════════════════════════════════════════════════════════════════════════
# Verdict bundle (final signed output of an arena session)
# ═══════════════════════════════════════════════════════════════════════════


class VerdictBundle(BaseModel):
    """Immutable, signed bundle produced at the end of an arena session.

    Contains the full audit trail, the Merkle root over all entries, and an
    Ed25519 signature from the Referee so that any third party can verify
    the session was conducted faithfully.
    """

    arena_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this arena session.",
    )
    entries: list[AuditEntry] = Field(
        default_factory=list,
        description="Ordered list of all audit entries in the session.",
    )
    merkle_root: str = Field(
        default="",
        description="SHA-256 Merkle root over all entry hashes.",
    )
    signature: str = Field(
        default="",
        description="Ed25519 signature (hex) over the merkle_root.",
    )
    model_snapshot_id: str = Field(
        default="",
        description="Identifier / hash of the model checkpoint used.",
    )
    seeds: list[str] = Field(
        default_factory=list,
        description="Random seeds used during the session for reproducibility.",
    )
    revealed_payloads: list[str] = Field(
        default_factory=list,
        description="Attack payloads revealed during the commit-reveal phase.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the bundle was finalised.",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Leak-Lab models
# ═══════════════════════════════════════════════════════════════════════════


class LeakageResult(BaseModel):
    """Result of a single leakage probe within Leak-Lab.

    A probe tests whether a specific piece of zone-private information
    can be inferred from observable outputs (model responses, timing, etc.).
    """

    probe_name: str = Field(
        ...,
        description="Short identifier for the probe (e.g. 'timing_oracle').",
    )
    setup: str = Field(
        ...,
        description="Description of the experimental setup for this probe.",
    )
    leaked: bool = Field(
        ...,
        description="Whether the probe detected information leakage.",
    )
    details: str = Field(
        default="",
        description="Human-readable details about the finding.",
    )
    bits_leaked: float = Field(
        default=0.0,
        ge=0.0,
        description="Estimated number of bits leaked (0.0 = none).",
    )
    confidence_interval: tuple[float, float] = Field(
        default=(0.0, 0.0),
        description="95%% confidence interval for ``bits_leaked`` as (lower, upper).",
    )


class LeakageScore(BaseModel):
    """Aggregate leakage score for a particular experimental setup.

    Groups multiple :class:`LeakageResult` probes run under the same
    conditions and computes a normalised score.
    """

    setup_name: str = Field(
        ...,
        description="Name of the overall test setup.",
    )
    total_probes: int = Field(
        default=0,
        ge=0,
        description="Total number of probes executed.",
    )
    probes_leaked: int = Field(
        default=0,
        ge=0,
        description="Number of probes that detected leakage.",
    )
    score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Normalised leakage score in [0, 1]. 0 = no leakage.",
    )
    results: list[LeakageResult] = Field(
        default_factory=list,
        description="Individual probe results that contribute to this score.",
    )


# ═══════════════════════════════════════════════════════════════════════════
# Canary tokens for cross-zone leak detection
# ═══════════════════════════════════════════════════════════════════════════


class CanaryToken(BaseModel):
    """A canary token planted in one zone to detect cross-zone leaks.

    If the canary ``value`` is observed in a zone other than ``owner_zone``,
    the Referee records it as a confirmed leak.
    """

    token_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this canary token.",
    )
    owner_zone: Zone = Field(
        ...,
        description="Zone where this canary was planted.",
    )
    value: str = Field(
        ...,
        description="The canary string to watch for in other zones.",
    )
    planted_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the canary was planted.",
    )
    found_in_zone: Optional[Zone] = Field(
        default=None,
        description="Zone where the canary was unexpectedly found (None = not leaked).",
    )
    found_at: Optional[datetime] = Field(
        default=None,
        description="UTC timestamp when the canary was detected outside its zone.",
    )
