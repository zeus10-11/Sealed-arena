# SEALED ARENA: Full Idea Detail

**Hack in Hills '26 | Track 04: Securing Adversarial AI Safety Testing Infrastructure (Bayora)**

> *Red, blue, and the model fight in the same room, and none of them can see through the walls. Every verdict is cryptographically provable.*

---

## 1. The Core Insight

Bayora's problem isn't "run three containers." It's that **a safety finding is only as trustworthy as the isolation behind it**. If red's payload leaks to blue, blue can overfit its defense. If blue's logic leaks to red, the attack is no longer blind. If the model is contaminated, the result isn't reproducible. Any of these makes the verdict meaningless.

So Sealed Arena treats isolation as something you **measure and prove**, not just configure. That's the angle most teams will miss.

---

## 2. The Architecture: The Blind Referee

Red, blue and the model never communicate directly. Everything goes through one small, auditable **Referee** service.

```
 RED ZONE ──┐                         ┌── MODEL ZONE
 (attacks)  ├──► BLIND REFEREE ◄──────┤   (client LLM)
 BLUE ZONE ─┘   token check · OPA     └───
 (defense)      commit-reveal · timing shaper
                signed audit chain
```

The Referee has only four jobs:

1. Check capability tokens and policy.
2. Mediate every message between zones.
3. Shape timing on responses.
4. Sign every event into the audit chain.

Keeping it small matters because it is the one component you have to trust, so its code and attack surface should be easy to review.

**Design point worth stating on stage:** blue's defense (for example a guardrail classifier) has to see prompts to filter them. So blue logic runs as a **sealed plugin inside the Referee's execution path**. Blue's *team and tooling* never see live traffic. They get only aggregate results after the test concludes. The same logic applies in reverse: red sees only the outcomes it is allowed to see.

---

## 3. The Mechanisms in Detail

### A. Commit-reveal for attacks
- Before a test, red submits `H = SHA-256(payload || nonce)` to the Referee.
- Blue and the audit log see only `H`.
- After the test concludes, red reveals `payload` and `nonce`. Anyone can recompute `H`.
- **What it proves:** the payload wasn't swapped or tuned after seeing blue's behavior.
- **What it does not do:** it doesn't hide the payload by itself. Hiding comes from network and policy isolation. Say this clearly in the pitch.

### B. Capability tokens
- Each tenant gets short-lived, narrowly scoped tokens, such as "send up to 50 prompts to the model" or "read own results."
- There is no token for "read blue's weights" in red's hands, or "read attack repo" in blue's.
- Policy is enforced by an OPA policy engine, or a small FastAPI service if time is short.
- Every grant and denial is logged.

### C. Micro-segmented network
- Three isolated Docker networks (red, blue, model), all `internal: true` with no outbound internet.
- The only route between zones is through the Referee.
- Default deny. Anything else is a logged violation.

### D. Hardened sandboxes
- Rootless containers, seccomp profiles, all capabilities dropped, read-only root filesystems, no shared volumes.
- Per-tenant cgroups for CPU, memory and I/O limits.
- gVisor (`runsc`) as an optional extra boundary. It needs no special hardware.

### E. Tamper-evident audit chain
- Every event (prompt hash, response hash, policy decision, token grant) is appended as `entry_n = H(entry_{n-1} || event || timestamp)`.
- Entries are batched into a Merkle tree, and each root is signed with Ed25519.
- The export is a **Verdict Bundle** containing the log, roots, signatures, revealed payloads, model snapshot ID and seeds.
- `verify bundle.zip` checks everything offline. If anyone edits one line, verification fails.

---

## 4. The LLM-Specific Defenses (Your Differentiators)

### F. KV-cache salting
Inference servers reuse cached computation for shared prompt prefixes. A second tenant can detect a cache hit by timing, which reveals what another tenant sent.
- **Defense:** give each tenant a separate cache namespace (a per-tenant salt), so prefixes never match across tenants.
- **Implementation note:** recent vLLM versions have a cache-salt option for this. Check your version. If it isn't available, prefix a per-tenant token or disable cross-tenant prefix caching and accept the performance cost.

### G. Timing-channel closure
Response latency can reveal whether a defense blocked or allowed a prompt.
- **Defense:** release responses on a fixed cadence (for example, in time buckets) with bounded padding. Overhead is the trade-off, so measure p95 latency and show it.

### H. Query budgets and coarse feedback
Red could try to reconstruct blue's classifier by probing it.
- **Defense:** cap queries per token and return coarse outcomes only. This limits how much blue logic can be inferred.

### I. Clean-Model Guarantee
- Snapshot the model and its serving state, and reset between runs.
- Seed the session with canary strings to detect contamination across sessions.

---

## 5. The Three Extra Innovations

| Idea | How it works | Why it's strong |
|---|---|---|
| **Canary Mesh** | Plant unique honeytokens in each tenant's state (payload store, classifier config, context). Monitor for any canary appearing outside its owner's zone. | A sighting is concrete, provable leakage rather than a suspicion. |
| **Replay Court** | Pin the model snapshot and seeds, and record every input. An auditor re-runs the finding in a fresh sandbox and compares verdicts. | Findings become reproducible by a third party, not just logged. |
| **Leakage in Bits** | Leak-Lab runs many probe trials and estimates mutual information between a secret (for example, a payload property) and what the attacker observed. | Turns "secure" into a number you can compare between setups. |

**Honesty note on Leakage in Bits:** estimating mutual information from limited samples is noisy. Report confidence intervals, and describe it as an estimate of observable leakage for the tested probes, not a proof of zero leakage.

---

## 6. Leak-Lab: Your Proof Engine

A built-in adversary attacks your own arena with the same probes against two setups: a naive shared sandbox and Sealed Arena.

| Probe | Shared sandbox (expected) | Sealed Arena (target) |
|---|---|---|
| Cache-timing | Recovers payload prefix | No shared cache hit |
| Shared volume peek | Reads red payloads | Denied and logged |
| Network scan | Reaches other tenants | Only Referee reachable |
| Timing side channel | Latency reveals block/allow | Fixed-cadence release |
| Canary check | Canary crosses tenants | Zero crossings |

The output is a **Leakage Score** for each setup, plus the latency overhead. These table values are design targets until you measure them.

---

## 7. Demo Script (3 Minutes)

1. **Baseline:** run Leak-Lab on the shared sandbox and show it recovering red's payload. Leakage Score is high.
2. **Switch on Sealed Arena:** rerun the same probes. They fail, and the dashboard lights up with policy violations.
3. **Tamper test:** change one line in the audit log. The verifier fails loudly.
4. **Offline verify:** run `verify bundle.zip` on a clean log and it prints verified.
5. **Overhead:** show the latency chart to prove the results stay valid.

Rehearse this. A reliable 3-minute demo beats a broader but flaky one.

---

## 8. Threat Model (Say This Honestly)

| Protected | Not Protected | Guarantee Fails When |
|---|---|---|
| Cross-tenant payload and defense visibility | Compromised host or hypervisor | The Referee itself is compromised |
| Network and filesystem peeking | Hardware side channels (Spectre-class, DRAM) | A co-resident attacker shares the physical host |
| Software-level cache and timing channels | Container-runtime zero-days (reduced, not removed, by gVisor) | Jitter budget is too small for the load |
| After-the-fact log tampering | Insider holding the Referee's signing key | Keys are not rotated or kept off-host |

The Referee is a trusted component and a single point of trust. Say so, and point to TEEs (confidential computing) as the roadmap fix. Judges reward this because Objective 06 asks for exactly this.

---

## 9. Tech Stack

- **Runtime:** Docker Compose, rootless Podman or gVisor, seccomp, cgroups v2
- **Referee and policy:** FastAPI plus OPA
- **Crypto:** Ed25519, SHA-256 hash chain, Merkle tree (Python `cryptography` or PyNaCl)
- **Model:** a small local model on vLLM or llama.cpp
- **Data:** JailbreakBench, AdvBench and HarmBench for red prompts, and a simple classifier for blue
- **Dashboard:** Streamlit or React with a leakage meter and audit timeline

---

## 10. Build Order and Team Split

1. Network segmentation plus the Referee proxy.
2. Capability tokens and commit-reveal.
3. Audit chain and verifier CLI.
4. Model isolation and cache salting.
5. Leak-Lab and the Leakage Score.
6. Dashboard, threat-model slide and demo rehearsal.

**Suggested split for 4 people:**
- Person 1: isolation and networking
- Person 2: crypto and audit
- Person 3: LLM serving and Leak-Lab
- Person 4: dashboard, deck and demo

**If time runs short, cut in this order:** Replay Court, then Canary Mesh, then gVisor.
**Never cut:** the Referee, the audit chain with its verifier, and Leak-Lab. Those three carry the whole story.

---

## 11. Mapping to Bayora's Evaluation Objectives

| Objective | How Sealed Arena answers it |
|---|---|
| 01 Isolate without breaking function | Referee mediation plus measured p95 latency overhead |
| 02 Prevent information leakage | Segmented networks, capability tokens, cache salting, timing closure |
| 03 Guarantee audit integrity | Hash chain, Merkle roots, Ed25519 signatures, Verdict Bundle, offline verifier |
| 04 Build for deployability | Docker Compose, standard runtimes, no special hardware |
| 05 Address LLM-native threats | KV-cache salting, Clean-Model Guarantee, canary strings |
| 06 Quantify residual risk | Threat model table plus Leakage in Bits with confidence intervals |

---

## 12. Likely Judge Questions

- **"Isn't the Referee a single point of failure?"**
  Yes. It is small and auditable, and the TEE roadmap removes the host from the trust base.
- **"Does commit-reveal hide the payload?"**
  No. It proves integrity. Isolation provides secrecy.
- **"What's the latency cost?"**
  Show the measured p95 overhead from your chart.
- **"Can you prove zero leakage?"**
  No. We measure observable leakage with confidence intervals and state the limits.

---

## 13. Roadmap

1. **Confidential computing:** run zones inside TEEs to close the malicious-host gap.
2. **Formal verification:** prove policy and token rules correct with model checking.
3. **Multi-tenant scale:** GPU-partitioned inference and many concurrent arenas.
4. **Public transparency log:** anchor Merkle roots publicly so verdicts are third-party checkable.

> **Vision:** Trustworthy AI safety needs trustworthy testing.
