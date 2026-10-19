"""Sealed Arena CLI — Command-line interface for the arena."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="sealed-arena")
def cli() -> None:
    """Sealed Arena — Adversarial AI Safety Testing Infrastructure.

    Red, Blue, and the Model fight in the same room, and none of them
    can see through the walls. Every verdict is cryptographically provable.
    """
    pass


@cli.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8000, help="Port to bind to")
@click.option("--reload/--no-reload", default=False, help="Enable auto-reload")
def referee(host: str, port: int, reload: bool) -> None:
    """Start the Referee service."""
    import uvicorn

    os.environ["REFEREE_HOST"] = host
    os.environ["REFEREE_PORT"] = str(port)

    console.print(f"[bold]🏁 Starting Referee on {host}:{port}[/]")
    uvicorn.run(
        "src.referee.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


@cli.command()
@click.option("--referee-url", default="http://localhost:8000", help="Referee URL")
@click.option("--zone", default="red", help="Zone name")
def red(referee_url: str, zone: str) -> None:
    """Run the Red Zone agent (attacker)."""
    os.environ["REFEREE_URL"] = referee_url
    os.environ["ZONE_NAME"] = zone

    from src.zones.red.agent import main as red_main

    asyncio.run(red_main())


@cli.command()
@click.option("--referee-url", default="http://localhost:8000", help="Referee URL")
@click.option("--zone", default="blue", help="Zone name")
@click.option("--duration", default=60, help="Defense loop duration (seconds)")
def blue(referee_url: str, zone: str, duration: int) -> None:
    """Run the Blue Zone agent (defender)."""
    os.environ["REFEREE_URL"] = referee_url
    os.environ["ZONE_NAME"] = zone
    os.environ["DEFENSE_DURATION"] = str(duration)

    from src.zones.blue.agent import main as blue_main

    asyncio.run(blue_main())


@cli.command()
@click.option("--referee-url", default="http://localhost:8000", help="Referee URL")
@click.option("--port", default=8001, help="Model server port")
@click.option("--model-name", default="demo-model", help="Model name")
def model(referee_url: str, port: int, model_name: str) -> None:
    """Run the Model Zone server (LLM inference)."""
    os.environ["REFEREE_URL"] = referee_url
    os.environ["PORT"] = str(port)
    os.environ["MODEL_NAME"] = model_name

    from src.zones.model.server import main as model_main

    asyncio.run(model_main())


@cli.command()
@click.option("--referee-url", default="http://localhost:8000", help="Referee URL")
@click.option("--sealed-tokens", help="JSON file with Sealed Arena tokens")
@click.option("--shared-tokens", help="JSON file with shared sandbox tokens")
def leaklab(referee_url: str, sealed_tokens: str | None, shared_tokens: str | None) -> None:
    """Run Leak-Lab probes against arena setups."""
    os.environ["REFEREE_URL"] = referee_url

    from sealed_arena.leaklab import LeakLab, main as leaklab_main

    if sealed_tokens or shared_tokens:
        import json

        sealed = json.loads(Path(sealed_tokens).read_text()) if sealed_tokens else {}
        shared = json.loads(Path(shared_tokens).read_text()) if shared_tokens else {}

        async def run() -> None:
            lab = LeakLab(referee_url)
            sealed_score, shared_score = await lab.compare_setups(sealed, shared or None)
            lab.print_comparison(sealed_score, shared_score)

        asyncio.run(run())
    else:
        asyncio.run(leaklab_main())


@cli.command()
@click.argument("bundle_path", type=click.Path(exists=True, path_type=Path))
def verify(bundle_path: Path) -> None:
    """Verify a verdict bundle offline."""
    from sealed_arena.audit.verify import verify_bundle

    console.print(f"[bold]🔍 Verifying bundle:[/] {bundle_path}")
    result = verify_bundle(bundle_path)

    for check in result.checks:
        status = "[green]✅ PASS[/]" if check.passed else "[red]❌ FAIL[/]"
        console.print(f"  {status} {check.name}: {check.detail}")

    if result.overall_valid:
        console.print("\n[bold green]✅ Bundle is VALID — all checks passed.[/]")
        sys.exit(0)
    else:
        console.print("\n[bold red]❌ Bundle is INVALID — one or more checks failed.[/]")
        sys.exit(1)


@cli.command()
@click.option("--referee-url", default="http://localhost:8000", help="Referee URL")
@click.option("--arena-id", default="demo", help="Arena session ID")
@click.option("--model-snapshot", default="model-v1", help="Model snapshot ID")
@click.option("--seeds", default="", help="Comma-separated random seeds")
def bundle(referee_url: str, arena_id: str, model_snapshot: str, seeds: str) -> None:
    """Create a verdict bundle from the Referee."""
    import httpx

    seed_list = [s.strip() for s in seeds.split(",") if s.strip()]

    async def create() -> None:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{referee_url}/bundle/create",
                json={
                    "arena_id": arena_id,
                    "model_snapshot_id": model_snapshot,
                    "seeds": seed_list,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            console.print(f"[green]Bundle created:[/] {data['bundle_path']}")

    asyncio.run(create())


@cli.command()
@click.option("--referee-url", default="http://localhost:8000", help="Referee URL")
def canary(referee_url: str) -> None:
    """Get the canary leakage report from the Referee."""
    import httpx

    async def get_report() -> None:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{referee_url}/canary/report")
            resp.raise_for_status()
            report = resp.json()

            console.print("[bold]📊 Canary Leakage Report[/]")
            console.print(f"  Leakage Score: {report['leakage_score']}/100")
            console.print(f"  Total Canaries: {report['total_canaries']}")
            console.print(f"  Compromised: {report['compromised_canaries']}")

            if report["events"]:
                console.print("\n  [red]Leakage Events:[/]")
                for event in report["events"]:
                    console.print(
                        f"    {event['canary']['owner_zone']} -> "
                        f"{event['found_in_zone']} ({event['severity']})"
                    )
            else:
                console.print("\n  [green]No leakage detected[/]")

    asyncio.run(get_report())


@cli.command()
@click.option("--referee-url", default="http://localhost:8000", help="Referee URL")
def health(referee_url: str) -> None:
    """Check Referee health."""
    import httpx

    async def check() -> None:
        async with httpx.AsyncClient(timeout=5.0) as client:
            try:
                resp = await client.get(f"{referee_url}/health")
                if resp.status_code == 200:
                    data = resp.json()
                    console.print("[green]✅ Referee is healthy[/]")
                    console.print(f"  Entries: {data['audit_entries']}")
                    console.print(f"  Pending Commitments: {data['commitments_pending']}")
                    console.print(f"  Active Tokens: {data['tokens_active']}")
                else:
                    console.print(f"[red]❌ Referee unhealthy: {resp.status_code}[/]")
                    sys.exit(1)
            except Exception as e:
                console.print(f"[red]❌ Failed to connect: {e}[/]")
                sys.exit(1)

    asyncio.run(check())


@cli.command()
def demo() -> None:
    """Run a full Sealed Arena demo (requires Docker Compose)."""
    console.print("[bold]🚀 Sealed Arena Demo[/]")
    console.print("This command starts the full stack via Docker Compose.")
    console.print("Run manually: cd deploy && docker compose up --build")
    console.print("\nThen in separate terminals:")
    console.print("  sealed-arena red")
    console.print("  sealed-arena blue")
    console.print("  sealed-arena leaklab")
    console.print("  sealed-arena verify verdict_*.zip")


if __name__ == "__main__":
    cli()