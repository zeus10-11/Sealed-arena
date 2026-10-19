"""Model Zone Server — LLM Inference Endpoint.

The Model Zone hosts the LLM under test. It communicates ONLY with the
Referee via the model-net network.

Key defenses active in this zone:
- KV-cache salting: per-tenant cache namespace prevents timing side-channels
- Clean-Model Guarantee: state is snapshotted and reset between runs
- Canary strings: detect contamination across sessions
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import sys
import time
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from rich.console import Console

console = Console()


class ModelConfig(BaseModel):
    """Model configuration."""

    model_name: str = "demo-model"
    cache_salt: str = ""
    max_tokens: int = 512
    temperature: float = 0.7
    reset_between_runs: bool = True


class PromptRequest(BaseModel):
    """Incoming prompt from Referee."""

    message_id: str
    content: str
    source_zone: str
    commitment_hash: str | None = None


class PromptResponse(BaseModel):
    """Model response to Referee."""

    message_id: str
    response: str
    tokens_generated: int
    processing_time_ms: float
    cache_salt_used: str


class ModelServer:
    """LLM inference server with Sealed Arena defenses."""

    def __init__(self, config: ModelConfig) -> None:
        self.config = config
        self.request_count = 0
        self.canary_strings: list[str] = []
        self._generate_canaries()

    def _generate_canaries(self) -> None:
        """Generate canary strings for contamination detection."""
        for i in range(3):
            canary = f"CANARY-MODEL-{secrets.token_hex(16)}"
            self.canary_strings.append(canary)
        console.print(f"[green]Generated {len(self.canary_strings)} model canaries[/]")

    def _get_cache_salt(self, tenant_id: str = "default") -> str:
        """Get the KV-cache salt for a tenant (prevents cross-tenant cache timing)."""
        if self.config.cache_salt:
            return hashlib.sha256(
                f"{self.config.cache_salt}:{tenant_id}".encode()
            ).hexdigest()[:16]
        return "default"

    def _check_canaries(self, text: str) -> list[str]:
        """Check if any canary strings appear in text (contamination detection)."""
        found = []
        for canary in self.canary_strings:
            if canary in text:
                found.append(canary)
        return found

    def _reset_state(self) -> None:
        """Reset model state between runs (Clean-Model Guarantee)."""
        self.request_count = 0
        self._generate_canaries()
        console.print("[yellow]Model state reset (Clean-Model Guarantee)[/]")

    async def generate(self, prompt: str, tenant_id: str = "default") -> PromptResponse:
        """Generate a response for the given prompt."""
        start = time.time()
        self.request_count += 1

        # Check for canary contamination in input
        leaked = self._check_canaries(prompt)
        if leaked:
            console.print(f"[red]⚠️ CANARY LEAK DETECTED IN INPUT:[/] {leaked}")

        # Simulate model inference with cache salt
        cache_salt = self._get_cache_salt(tenant_id)

        # In a real implementation, this would call vLLM/llama.cpp
        # For demo, we generate a deterministic response based on prompt hash
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:8]
        response = (
            f"[Model:{self.config.model_name}] Response to prompt #{self.request_count} "
            f"(hash: {prompt_hash}). Cache salt: {cache_salt}. "
            f"Temperature: {self.config.temperature}. "
            f"Max tokens: {self.config.max_tokens}. "
        )

        # Add canary to response for cross-zone leak detection
        if self.canary_strings:
            response += f" {self.canary_strings[0]}"

        processing_time = (time.time() - start) * 1000

        # Check for canary contamination in output
        leaked_out = self._check_canaries(response)
        if leaked_out:
            console.print(f"[red]⚠️ CANARY LEAK DETECTED IN OUTPUT:[/] {leaked_out}")

        return PromptResponse(
            message_id=secrets.token_urlsafe(8),
            response=response,
            tokens_generated=len(response.split()),
            processing_time_ms=processing_time,
            cache_salt_used=cache_salt,
        )


# Global model server instance
_model_server: ModelServer | None = None


def get_model_server() -> ModelServer:
    global _model_server
    if _model_server is None:
        config = ModelConfig(
            model_name=os.getenv("MODEL_NAME", "demo-model"),
            cache_salt=os.getenv("CACHE_SALT", secrets.token_hex(16)),
            max_tokens=int(os.getenv("MAX_TOKENS", "512")),
            temperature=float(os.getenv("TEMPERATURE", "0.7")),
            reset_between_runs=os.getenv("MODEL_RESET_BETWEEN_RUNS", "true").lower()
            == "true",
        )
        _model_server = ModelServer(config)
    return _model_server


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan."""
    server = get_model_server()
    console.print(f"[bold]🤖 Model Zone Server Starting[/]")
    console.print(f"  Model: {server.config.model_name}")
    console.print(f"  Cache Salt Enabled: {bool(server.config.cache_salt)}")
    console.print(f"  Reset Between Runs: {server.config.reset_between_runs}")
    yield
    console.print("[bold]🤖 Model Zone Server Shutting Down[/]")


app = FastAPI(
    title="Sealed Arena Model Zone",
    description="LLM inference with KV-cache salting and Clean-Model Guarantee",
    version="0.1.0",
    lifespan=lifespan,
)


# Referee client for sending responses back
_referee_client: httpx.AsyncClient | None = None


async def get_referee_client() -> httpx.AsyncClient:
    global _referee_client
    if _referee_client is None:
        referee_url = os.getenv("REFEREE_URL", "http://referee:8000")
        _referee_client = httpx.AsyncClient(base_url=referee_url, timeout=30.0)
    return _referee_client


@app.get("/health")
async def health() -> dict[str, Any]:
    """Health check."""
    server = get_model_server()
    return {
        "status": "healthy",
        "model": server.config.model_name,
        "requests_served": server.request_count,
        "cache_salt_active": bool(server.config.cache_salt),
        "canaries_active": len(server.canary_strings),
    }


@app.post("/generate")
async def generate_endpoint(
    request: PromptRequest,
    x_capability_token: str = Header(..., alias="X-Capability-Token"),
) -> PromptResponse:
    """Generate a response for a prompt from the Referee."""
    server = get_model_server()

    # In a real implementation, verify the capability token with Referee
    # For now, we trust the Referee to have validated it

    # Determine tenant from source zone (for cache salting)
    tenant_id = request.source_zone

    # Generate response
    response = await server.generate(request.content, tenant_id)

    # Send response back to Referee (targeting the source zone)
    try:
        client = await get_referee_client()
        await client.post(
            "/zones/model/messages",
            headers={"X-Capability-Token": x_capability_token},
            json={
                "token": x_capability_token,
                "target_zone": request.source_zone,
                "content": response.response,
            },
        )
    except Exception as e:
        console.print(f"[yellow]Warning: Failed to send response to Referee: {e}[/]")

    return response


@app.post("/reset")
async def reset_endpoint(
    x_capability_token: str = Header(..., alias="X-Capability-Token"),
) -> dict[str, str]:
    """Reset model state (Clean-Model Guarantee)."""
    server = get_model_server()
    server._reset_state()
    return {"status": "reset", "model": server.config.model_name}


@app.get("/canaries")
async def get_canaries() -> dict[str, list[str]]:
    """Get current canary strings (for debugging)."""
    server = get_model_server()
    return {"canaries": server.canary_strings}


async def main() -> None:
    """Run the Model Zone server directly (for testing without Docker)."""
    import uvicorn

    port = int(os.getenv("PORT", "8001"))
    config = uvicorn.Config(
        "src.zones.model.server:app",
        host="0.0.0.0",
        port=port,
        log_level="info",
        reload=False,
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())