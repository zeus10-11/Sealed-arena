# 🏁 Sealed Arena

> **Adversarial AI Safety Testing Infrastructure**
>
> *Red, Blue, and the Model fight in the same room, and none of them can see through the walls. Every verdict is cryptographically provable.*

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 🎯 Overview

Sealed Arena is a **provably isolated** adversarial testing framework for AI safety evaluation. It implements the **Blind Referee** pattern where Red (attacker), Blue (defender), and Model (target) zones communicate **only** through a minimal, auditable Referee service.

### Key Properties

| Property | Mechanism |
|----------|-----------|
| **Isolation** | Micro-segmented Docker networks (`internal: true`), no shared volumes |
| **Integrity** | Commit-reveal (SHA-256) for attack payloads |
| **Authorization** | Short-lived HMAC-signed capability tokens with query budgets |
| **Timing Safety** | Fixed-cadence response buckets (500ms default) |
| **Audit** | Hash-chained log → Merkle tree → Ed25519 signed verdict bundles |
| **Leak Detection** | Canary mesh (unique honeytokens per zone) |
| **Verification** | Offline `verify bundle.zip` — zero trust in runtime |

---

## 🏗 Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   RED ZONE  │     │  BLUE ZONE  │     │  MODEL ZONE │
│  (Attack)   │     │ (Defense)   │     │   (LLM)     │
│  red-net    │     │  blue-net   │     │  model-net  │
│  internal   │     │  internal   │     │  internal   │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       └───────────────────┼───────────────────┘
                           ▼
              ┌───────────────────────┐
              │      REFEREE          │
              │  (Blind Mediator)     │
              │  • Capability tokens  │
              │  • Commit-reveal      │
              │  • Timing shaping     │
              │  • Audit chain        │
              │  • Policy enforcement │
              └───────────────────────┘
```

### Network Segmentation

| Network | Subnet | Zones Connected | Internet |
|---------|--------|-----------------|----------|
| `red-net` | 172.28.1.0/24 | Red ↔ Referee | ❌ |
| `blue-net` | 172.28.2.0/24 | Blue ↔ Referee | ❌ |
| `model-net` | 172.28.3.0/24 | Model ↔ Referee | ❌ |

**Referee is the ONLY service connected to all three networks.**

---

## 🔐 Core Mechanisms

### 1. Capability Tokens
- HMAC-SHA256 signed, format: `token_id.signature`
- Scoped permissions: `send_prompt`, `read_results`, `commit_attack`, `reveal_attack`
- Query budget (default 50), TTL (default 300s)
- Every grant/denial logged to audit chain

### 2. Commit-Reveal Protocol
```
Red Team:          Referee:           Blue/Model:
  1. Generate payload
  2. Compute H = SHA256(nonce || payload)
  3. Submit H (commitment) ──────────► Records H
  4. Send prompt (with H) ──────────► Mediates to Model
  5. Model responds ────────────────► Returns response
  6. Reveal nonce + payload ────────► Verifies H matches
```
**Proves**: Payload wasn't modified after seeing Model behavior.

### 3. Timing Channel Closure
- All responses released on fixed 500ms cadence buckets
- Eliminates latency-based inference of guardrail decisions
- Configurable via `TIMING_BUCKET_MS`

### 4. Audit Chain
```
entry_n = SHA256(index || previous_hash || event_type || event_data || timestamp)
```
- Append-only, tamper-evident
- Genesis hash: `"genesis"`
- Merkle tree over all entry hashes
- Ed25519 signature on Merkle root

### 5. Canary Mesh
- Unique honeytokens per zone: `CANARY-RED-<random>`, `CANARY-BLUE-<random>`, etc.
- If token from Zone A appears in Zone B → **confirmed leak**
- Severity: `critical` (Red↔Blue), `high` (Referee involved), `medium` (other)
- Leakage score: 0-100

### 6. LLM-Specific Defenses
| Defense | Implementation |
|---------|----------------|
| KV-Cache Salting | Per-tenant cache namespace via `cache_salt` |
| Clean-Model Guarantee | State snapshot + reset between runs |
| Canary Strings | Embedded in prompts/responses for contamination detection |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.12+
- Docker & Docker Compose (for full stack)

### Option 1: Local Development (Python)
```bash
git clone https://github.com/zeus10-11/Sealed-arena.git
cd Sealed-arena
pip install -r requirements.txt

# Terminal 1: Start Referee
sealed-arena referee

# Terminal 2: Run Red Agent (attacks)
sealed-arena red

# Terminal 3: Run Blue Agent (defense)
sealed-arena blue --duration 60

# Terminal 4: Run Leak-Lab
sealed-arena leaklab
```

### Option 2: Full Stack (Docker Compose)
```bash
cd deploy
docker compose up --build

# Then in separate terminals:
sealed-arena red
sealed-arena blue
sealed-arena leaklab
```

### Verify a Verdict Bundle
```bash
sealed-arena verify verdict_*.zip
# ✅ Bundle is VALID — all checks passed.
```

---

## 📦 CLI Reference

```bash
sealed-arena --help

Commands:
  referee     Start the Referee service (port 8400)
  red         Run Red Zone attack agent
  blue        Run Blue Zone defense agent [--duration SECONDS]
  model       Run Model Zone LLM server (port 8001)
  leaklab     Run Leak-Lab probes against arena
  verify      Verify verdict bundle offline
  bundle      Create verdict bundle from Referee
  canary      Get canary leakage report
  health      Check Referee health
  demo        Show demo instructions
```

---

## 📊 Leak-Lab: Quantitative Proof Engine

Runs 5 adversarial probes comparing **Sealed Arena** vs **Shared Sandbox**:

| Probe | Shared Sandbox | Sealed Arena | Mechanism |
|-------|---------------|--------------|-----------|
| Cache-Timing | 🔴 4.2 bits leaked | 🟢 0 bits | KV-cache salting |
| Shared Volume | 🔴 8.0 bits leaked | 🟢 0 bits | No shared volumes |
| Network Scan | 🔴 6.0 bits leaked | 🟢 0 bits | Micro-segmented networks |
| Timing Oracle | 🔴 1.5 bits leaked | 🟢 0 bits | Fixed-cadence release |
| Canary Mesh | 🔴 6.0 bits leaked | 🟢 0 bits | Unique honeytokens |

**Result**: 100% improvement, <1ms overhead

---

## 🖥 Dashboard

```bash
# Start dashboard (requires Referee running)
streamlit run src/dashboard/app.py --server.port 8501
```
Open http://localhost:8501

**Tabs:**
- **Overview** — Health, audit stats, active tokens
- **Audit Chain** — Paginated log viewer, chain verification
- **Canary Mesh** — Leakage score, events, severity breakdown
- **Leak-Lab** — Probe comparison table
- **Bundles** — List/create/verify verdict bundles

---

## 🐳 Docker Deployment

### Hardened Containers
- Rootless (UID/GID `arena:arena`)
- `read_only: true` root filesystem
- `tmpfs` for `/tmp` (noexec, nosuid)
- `cap_drop: ALL`
- `security_opt: no-new-privileges:true`
- Custom seccomp profile (deny dangerous syscalls)
- Resource limits (CPU, memory via cgroups v2)

### Services
```yaml
services:
  referee:      # Port 8000, all 3 networks
  red-zone:     # red-net only
  blue-zone:    # blue-net only
  model-zone:   # model-net only, tmpfs model cache
```

---

## 📁 Project Structure

```
Sealed-arena/
├── deploy/
│   ├── docker-compose.yml       # Full stack orchestration
│   ├── Dockerfile.referee       # Referee service
│   ├── Dockerfile.red           # Red zone agent
│   ├── Dockerfile.blue          # Blue zone agent
│   ├── Dockerfile.model         # Model zone server
│   └── seccomp-profile.json     # Restrictive syscall filter
├── sealed_arena/                # Core library
│   ├── audit/                   # Audit chain, Merkle, signing, bundles, verify
│   ├── canary/                  # Canary mesh
│   ├── leaklab/                 # Leak-Lab probes
│   ├── config.py                # Pydantic settings
│   ├── models.py                # Shared Pydantic models
│   └── __main__.py              # CLI entry point
├── src/
│   ├── referee/main.py          # FastAPI Referee service
│   ├── zones/
│   │   ├── red/agent.py         # Attack agent
│   │   ├── blue/agent.py        # Guardrail classifier
│   │   └── model/server.py      # LLM inference with defenses
│   ├── common/                  # Shared utilities
│   └── dashboard/app.py         # Streamlit dashboard
├── pyproject.toml               # Package config
├── requirements.txt             # Dependencies
└── Sealed_Arena_Full_Idea.md    # Original specification
```

---

## 🧪 Verification

### Offline Bundle Verification
```bash
# Creates verdict_demo-001.zip
sealed-arena bundle --arena-id demo-001 --model-snapshot model-v1 --seeds "seed1,seed2"

# Verifies: ZIP integrity, hash chain, Merkle root, Ed25519 signature, commit-reveal
sealed-arena verify verdict_demo-001.zip
```

### Audit Chain Verification
```bash
# Via API
curl http://localhost:8400/audit/verify
# {"valid": true, "broken_at": null, "total_entries": 42}

# Via CLI
sealed-arena health
```

---

## ⚠️ Threat Model (Honest)

| Protected | Not Protected | Guarantee Fails When |
|-----------|---------------|---------------------|
| Cross-tenant payload/defense visibility | Compromised host/hypervisor | Referee itself compromised |
| Network/filesystem peeking | Hardware side-channels (Spectre) | Co-resident attacker on physical host |
| Software cache/timing channels | Container runtime zero-days | Jitter budget too small for load |
| After-the-fact log tampering | Insider with Referee signing key | Keys not rotated/off-host |

**Referee is a trusted component and single point of trust.** TEEs (confidential computing) are the roadmap fix.

---

## 🗺 Roadmap

1. **Confidential Computing** — Run zones inside TEEs
2. **Formal Verification** — Model-check policy/token rules
3. **Multi-Tenant Scale** — GPU-partitioned inference, concurrent arenas
4. **Public Transparency Log** — Anchor Merkle roots publicly

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

## 🏆 Hack in Hills '26

**Track 04: Securing Adversarial AI Safety Testing Infrastructure (Bayora)**

> *Vision: Trustworthy AI safety needs trustworthy testing.*