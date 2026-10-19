"""
Global configuration for the Sealed Arena.

Uses Pydantic Settings so every value can be overridden via environment
variables prefixed with ``SEALED_ARENA_`` (e.g. ``SEALED_ARENA_REFEREE_PORT=9000``).
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import ClassVar

from pydantic import Field
from pydantic_settings import BaseSettings


class ArenaSettings(BaseSettings):
    """Central configuration for all Sealed Arena components.

    Attributes:
        REFEREE_HOST: Hostname the Referee HTTP service binds to.
        REFEREE_PORT: Port the Referee HTTP service binds to.
        SIGNING_KEY_PATH: Filesystem path to the Ed25519 private key (PEM).
        AUDIT_LOG_PATH: Filesystem path where the append-only audit log is stored.
        TIMING_BUCKET_MS: Quantisation bucket for timing side-channel mitigation.
            All responses are delayed to the next multiple of this value.
        MAX_QUERIES_PER_TOKEN: Hard cap on how many queries a single capability
            token may perform before it is revoked.
        CANARY_LENGTH: Length (in characters) of planted canary tokens used for
            leak detection.
        TOKEN_TTL_SECONDS: Default time-to-live for newly issued capability tokens.
        TOKEN_SECRET: HMAC secret used to sign capability tokens.  Generated
            randomly at startup when not supplied via the environment.
        ZONES: The three logical zones recognised by the Referee.
    """

    # ── Referee service ─────────────────────────────────────────────────
    REFEREE_HOST: str = Field(
        default="127.0.0.1",
        description="Hostname the Referee HTTP service binds to.",
    )
    REFEREE_PORT: int = Field(
        default=8400,
        description="Port the Referee HTTP service listens on.",
    )

    # ── Cryptographic material ──────────────────────────────────────────
    SIGNING_KEY_PATH: Path = Field(
        default=Path("keys/referee.pem"),
        description="Path to the Ed25519 private key in PEM format.",
    )
    AUDIT_LOG_PATH: Path = Field(
        default=Path("audit/arena.log"),
        description="Path for the append-only JSON-lines audit log.",
    )

    # ── Side-channel mitigation ─────────────────────────────────────────
    TIMING_BUCKET_MS: int = Field(
        default=500,
        ge=1,
        description=(
            "Quantisation bucket in milliseconds.  Every Referee response is "
            "padded to the next multiple of this value to mitigate timing "
            "side-channels."
        ),
    )

    # ── Capability tokens ───────────────────────────────────────────────
    MAX_QUERIES_PER_TOKEN: int = Field(
        default=50,
        ge=1,
        description="Maximum number of queries allowed per capability token.",
    )
    TOKEN_TTL_SECONDS: int = Field(
        default=300,
        ge=1,
        description="Default TTL (in seconds) for newly minted capability tokens.",
    )
    TOKEN_SECRET: str = Field(
        default_factory=lambda: secrets.token_hex(32),
        description=(
            "Hex-encoded HMAC secret for capability token signatures.  "
            "A random value is generated at startup if not provided."
        ),
    )

    # ── Canary / leak detection ─────────────────────────────────────────
    CANARY_LENGTH: int = Field(
        default=32,
        ge=8,
        description="Character length of planted canary tokens.",
    )

    # ── Zone definitions ────────────────────────────────────────────────
    ZONES: ClassVar[list[str]] = ["red", "blue", "model"]

    model_config = {
        "env_prefix": "SEALED_ARENA_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


# ---------------------------------------------------------------------------
# Module-level singleton — import ``settings`` wherever config is needed.
# ---------------------------------------------------------------------------

settings = ArenaSettings()
"""Module-level singleton of :class:`ArenaSettings`.

Usage::

    from sealed_arena.config import settings
    print(settings.REFEREE_PORT)
"""
