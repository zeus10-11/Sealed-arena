# Sealed Arena — Deployment Guide

## Prerequisites

| Requirement | Minimum Version | Purpose |
|---|---|---|
| Docker Engine | 24.0+ | Container runtime |
| Docker Compose | 2.20+ | Multi-service orchestration |
| Python | 3.14 | Local development and verification |
| Git | 2.40+ | Source control |

> [!IMPORTANT]
> Docker must be configured to support the `deploy.resources` section. If running
> in Docker Desktop, enable resource limits in Settings → Resources.

---

## Quick Start

### 1. Build all containers

```bash
cd deploy/
docker compose build
```

### 2. Start the arena

```bash
docker compose up -d
```

### 3. Verify services are healthy

```bash
docker compose ps
```

All four services should show `healthy` status:

```
NAME                    STATUS              PORTS
sealed-arena-referee    Up (healthy)        0.0.0.0:8000->8000/tcp
sealed-arena-red        Up (healthy)
sealed-arena-blue       Up (healthy)
sealed-arena-model      Up (healthy)
```

### 4. Access the Referee API

```bash
curl http://localhost:8000/health
```

### 5. Stop the arena

```bash
docker compose down
```

To also remove audit log volumes:

```bash
docker compose down -v
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    HOST MACHINE                      │
│                                                      │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐        │
│  │ RED ZONE │   │BLUE ZONE │   │MODEL ZONE│        │
│  │          │   │          │   │          │        │
│  │ No inet  │   │ No inet  │   │ No inet  │        │
│  │ No vols  │   │ No vols  │   │ tmpfs    │        │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘        │
│       │              │              │               │
│   red-net         blue-net       model-net          │
│  (internal)      (internal)     (internal)          │
│       │              │              │               │
│       └──────────────┼──────────────┘               │
│                      │                              │
│              ┌───────┴───────┐                      │
│              │   REFEREE     │                      │
│              │               │                      │
│              │  :8000 (API)  │──── audit-logs vol   │
│              └───────────────┘                      │
│                      │                              │
│               Host port 8000                        │
└─────────────────────────────────────────────────────┘
```

---

## Network Isolation

Three Docker networks enforce the Blind Referee pattern:

| Network | Subnet | Connected Services | Internet |
|---|---|---|---|
| `red-net` | 172.28.1.0/24 | red-zone, referee | ❌ Blocked |
| `blue-net` | 172.28.2.0/24 | blue-zone, referee | ❌ Blocked |
| `model-net` | 172.28.3.0/24 | model-zone, referee | ❌ Blocked |

**Key guarantee:** Red cannot reach Blue. Blue cannot reach Model. No zone can reach the internet. The Referee is the sole mediator.

### Verify network isolation

```bash
# From inside the red zone, try to reach blue zone (should fail):
docker exec sealed-arena-red ping -c 1 blue-zone
# Expected: Name or service not known

# From inside the red zone, reach the referee (should succeed):
docker exec sealed-arena-red python -c \
  "import urllib.request; print(urllib.request.urlopen('http://referee:8000/health').read())"
```

---

## Security Hardening

Every container runs with:

| Control | Setting | Purpose |
|---|---|---|
| Read-only rootfs | `read_only: true` | Prevents filesystem modifications |
| No new privileges | `no-new-privileges: true` | Blocks privilege escalation |
| All caps dropped | `cap_drop: ALL` | Minimal Linux capabilities |
| Seccomp profile | `seccomp-profile.json` | Syscall allowlist (default deny) |
| Non-root user | `USER arena` | Process runs unprivileged |
| tmpfs for /tmp | `noexec,nosuid` | Temp space without persistence |
| Resource limits | 512MB / 0.5 CPU | Prevents resource exhaustion |

### Seccomp Profile

The included `seccomp-profile.json` uses a **default-deny** policy:

- **Allowed:** Core process lifecycle, memory management, file I/O, networking (TCP/UDP), signals, threading, time
- **Blocked:** `mount`, `umount`, `ptrace`, `reboot`, `kexec_load`, `bpf`, `io_uring_*`, `unshare`, `setns`, and 30+ other dangerous syscalls

---

## Volumes

| Volume | Mounted In | Purpose |
|---|---|---|
| `audit-logs` | Referee at `/app/audit` | Tamper-evident audit chain |

> [!WARNING]
> Zone containers have **no persistent volumes**. This is intentional — it prevents
> filesystem-based information leakage between zones.

---

## Environment Variables

### Referee

| Variable | Default | Description |
|---|---|---|
| `REFEREE_HOST` | `0.0.0.0` | Bind address |
| `REFEREE_PORT` | `8000` | API port |
| `AUDIT_LOG_DIR` | `/app/audit` | Audit chain storage |
| `TIMING_BUCKET_MS` | `500` | Fixed response cadence (timing closure) |
| `MAX_QUERIES_PER_TOKEN` | `50` | Query budget per capability token |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

### Zones (Red, Blue, Model)

| Variable | Default | Description |
|---|---|---|
| `ZONE_NAME` | (required) | Zone identifier: `red`, `blue`, `model` |
| `REFEREE_URL` | `http://referee:8000` | Referee API endpoint |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

### Model Zone (additional)

| Variable | Default | Description |
|---|---|---|
| `CACHE_SALT_ENABLED` | `true` | Per-tenant KV-cache namespacing |
| `MODEL_RESET_BETWEEN_RUNS` | `true` | Clean-Model Guarantee |

---

## Production Hardening Checklist

- [ ] Generate Ed25519 signing keys and store securely (not in container image)
- [ ] Enable key rotation schedule
- [ ] Configure TLS between host and Referee (reverse proxy or cert mount)
- [ ] Set up log shipping for audit chain (append-only external store)
- [ ] Enable rootless Docker or Podman for additional isolation
- [ ] Consider gVisor (`runsc`) runtime for stronger sandbox boundary
- [ ] Review and tune seccomp profile for your specific Python version
- [ ] Set up monitoring and alerting on container health checks
- [ ] Configure Docker log rotation in production

---

## Troubleshooting

### Container fails with "permission denied"

The containers run with read-only root filesystem. Ensure your application writes only to `/tmp` (tmpfs) or mounted volumes.

### Health check fails

Check that the Referee is starting correctly:

```bash
docker compose logs referee
```

### Seccomp blocks a syscall

If a container crashes with "operation not permitted," a needed syscall may be blocked. Debug with:

```bash
docker run --security-opt seccomp=unconfined <image> <command>
```

Then identify the missing syscall with `strace` and add it to `seccomp-profile.json`.

### Network connectivity issues

Verify networks exist:

```bash
docker network ls | grep sealed
```

Inspect a specific network:

```bash
docker network inspect deploy_red-net
```
