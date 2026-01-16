# Asupersync

<div align="center">

```
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║     ┌─────────────────────────────────────────────────────┐   ║
    ║     │  REGION                                             │   ║
    ║     │    ┌───────┐  ┌───────┐  ┌───────┐                 │   ║
    ║     │    │ Task  │──│ Task  │──│ Task  │  ← owned        │   ║
    ║     │    └───┬───┘  └───┬───┘  └───────┘                 │   ║
    ║     │        │          │                                 │   ║
    ║     │        ▼          ▼                                 │   ║
    ║     │    ┌───────┐  ┌───────┐                            │   ║
    ║     │    │ SUB   │  │ SUB   │  ← nested                  │   ║
    ║     │    │REGION │  │REGION │                            │   ║
    ║     │    └───────┘  └───────┘                            │   ║
    ║     └─────────────────────────────────────────────────────┘   ║
    ║                         │                                     ║
    ║                         ▼ close                               ║
    ║                   ┌───────────┐                               ║
    ║                   │QUIESCENCE │  ← guaranteed                 ║
    ║                   └───────────┘                               ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
```

**Spec-first, cancel-correct, capability-secure async for Rust**

[![Status: Design Phase](https://img.shields.io/badge/Status-Design%20Phase-yellow)](https://github.com/Dicklesworthstone/asupersync)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

</div>

---

## TL;DR

**The Problem**: Rust's async ecosystem (tokio, async-std) gives you *tools* but not *guarantees*. Cancellation silently drops data. Spawned tasks can orphan. Cleanup is best-effort. Testing concurrent code is non-deterministic. You write correct code by convention, and discover bugs in production.

**The Solution**: Asupersync is an async runtime where **correctness is structural, not conventional**. Tasks are owned by regions that close to quiescence. Cancellation is a protocol with bounded cleanup. Effects require capabilities. The lab runtime makes concurrency deterministic and replayable.

### Why Asupersync?

| Guarantee | What It Means |
|-----------|---------------|
| **No orphan tasks** | Every spawned task is owned by a region; region close waits for all children |
| **Cancel-correctness** | Cancellation is request → drain → finalize, never silent data loss |
| **Bounded cleanup** | Cleanup budgets are *sufficient conditions*, not hopes |
| **No silent drops** | Two-phase effects (reserve/commit) make data loss impossible for primitives |
| **Deterministic testing** | Lab runtime: virtual time, deterministic scheduling, trace replay |
| **Capability security** | All effects flow through explicit `Cx`; no ambient authority |

---

## The Core Idea

Most async runtimes are "spawn and pray":

```rust
// Tokio: what happens when this scope exits?
tokio::spawn(async { /* orphaned? cancelled? who knows */ });
```

Asupersync enforces structured concurrency:

```rust
// Asupersync: scope guarantees quiescence
scope.region(|sub| async {
    sub.spawn(task_a);
    sub.spawn(task_b);
    // ← region close: waits for BOTH tasks, runs finalizers, resolves obligations
}).await;
// ← guaranteed: nothing from inside is still running
```

**Cancellation works as a protocol, not a flag:**

```
Running → CancelRequested → Cancelling → Finalizing → Completed(Cancelled)
            ↓                    ↓             ↓
         (bounded)          (cleanup)    (finalizers)
```

Every step is explicit, budgeted, and driven to completion.

---

## Design Philosophy

### 1. Structured Concurrency by Construction

Tasks don't float free. Every task is owned by a region. Regions form a tree. When a region closes, it *guarantees* all children are complete, all finalizers have run, all obligations are resolved. This is the "no orphans" invariant, enforced by the type system and runtime rather than by discipline.

### 2. Cancellation as a First-Class Protocol

Cancellation operates as a multi-phase protocol, not a silent `drop`:
- **Request**: propagates down the tree
- **Drain**: tasks run to cleanup points (bounded by budgets)
- **Finalize**: finalizers run (masked, budgeted)
- **Complete**: outcome is `Cancelled(reason)`

Primitives publish *cancellation responsiveness bounds*. Budgets are sufficient conditions for completion.

### 3. Two-Phase Effects Prevent Data Loss

Anywhere cancellation could lose data, Asupersync uses reserve/commit:

```rust
let permit = tx.reserve(cx).await?;  // ← cancel-safe: nothing committed yet
permit.send(message);                 // ← linear: must happen or abort
```

Dropping a permit aborts cleanly. Message never partially sent.

### 4. Capability Security (No Ambient Authority)

All effects flow through explicit capability tokens:

```rust
async fn my_task(cx: &mut Cx<'_>) {
    cx.spawn(...);        // ← need spawn capability
    cx.sleep_until(...);  // ← need time capability
    cx.trace(...);        // ← need trace capability
}
```

Swap `Cx` to change interpretation: production vs. lab vs. distributed.

### 5. Deterministic Testing is Default

The lab runtime provides:
- **Virtual time**: sleeps complete instantly, time is controlled
- **Deterministic scheduling**: same seed → same execution
- **Trace capture/replay**: debug production issues locally
- **Schedule exploration**: DPOR-class coverage of interleavings

Concurrency bugs become reproducible test failures.

---

## How Asupersync Compares

| Feature | Asupersync | tokio | async-std | smol |
|---------|------------|-------|-----------|------|
| **Structured concurrency** | ✅ Enforced | ❌ Manual | ❌ Manual | ❌ Manual |
| **Cancel-correctness** | ✅ Protocol | ⚠️ Drop-based | ⚠️ Drop-based | ⚠️ Drop-based |
| **No orphan tasks** | ✅ Guaranteed | ❌ spawn detaches | ❌ spawn detaches | ❌ spawn detaches |
| **Bounded cleanup** | ✅ Budgeted | ❌ Best-effort | ❌ Best-effort | ❌ Best-effort |
| **Deterministic testing** | ✅ Built-in | ❌ External tools | ❌ External tools | ❌ External tools |
| **Obligation tracking** | ✅ Linear tokens | ❌ None | ❌ None | ❌ None |
| **Ecosystem** | ❌ New | ✅ Massive | ⚠️ Medium | ⚠️ Small |
| **Maturity** | ❌ Design phase | ✅ Production | ✅ Production | ✅ Production |

**When to use Asupersync:**
- Internal applications where correctness > ecosystem
- Systems where cancel-correctness is non-negotiable (financial, medical, infrastructure)
- Projects that need deterministic concurrency testing
- Distributed systems with structured shutdown requirements

**When Asupersync might not be ideal:**
- You need tokio ecosystem compatibility today
- Rapid prototyping where guarantees don't matter yet
- Projects that can't wait for implementation

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              EXECUTION TIERS                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   FIBERS    │  │    TASKS    │  │   ACTORS    │  │   REMOTE    │        │
│  │             │  │             │  │             │  │             │        │
│  │ • Borrow-   │  │ • Parallel  │  │ • Long-     │  │ • Named     │        │
│  │   friendly  │  │ • Send      │  │   lived     │  │   compute   │        │
│  │ • Same-     │  │ • Work-     │  │ • Super-    │  │ • Leases    │        │
│  │   thread    │  │   stealing  │  │   vised     │  │ • Idempotent│        │
│  │ • Region-   │  │ • Region    │  │ • Region-   │  │ • Saga      │        │
│  │   pinned    │  │   heap      │  │   owned     │  │   cleanup   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
│         │                │                │                │                │
│         └────────────────┴────────────────┴────────────────┘                │
│                                   │                                         │
│                                   ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         REGION TREE                                  │   │
│  │                                                                      │   │
│  │    Root Region ──┬── Child Region ──┬── Task                        │   │
│  │                  │                  ├── Task                        │   │
│  │                  │                  └── Subregion ── Task           │   │
│  │                  └── Child Region ── Actor                          │   │
│  │                                                                      │   │
│  │    Invariant: close(region) → quiescence(all descendants)           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│                                   ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                      OBLIGATION REGISTRY                             │   │
│  │                                                                      │   │
│  │    SendPermit ──→ send() or abort()                                 │   │
│  │    Ack        ──→ commit() or nack()                                │   │
│  │    Lease      ──→ renew() or expire()                               │   │
│  │    IoOp       ──→ complete() or cancel()                            │   │
│  │                                                                      │   │
│  │    Invariant: region_close requires all obligations resolved        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                   │                                         │
│                                   ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         SCHEDULER                                    │   │
│  │                                                                      │   │
│  │    Cancel Lane ──→ Timed Lane (EDF) ──→ Ready Lane                  │   │
│  │         ↑                                                            │   │
│  │    (priority)     Lyapunov-guided: V(Σ) must decrease               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Mathematical Foundations

Asupersync has formal semantics backing its engineering.

| Concept | Math | Payoff |
|---------|------|--------|
| **Outcomes** | Severity lattice: `Ok < Err < Cancelled < Panicked` | Monotone aggregation, no "recovery" from worse states |
| **Concurrency** | Near-semiring: `join (⊗)` and `race (⊕)` with laws | Lawful rewrites, DAG optimization |
| **Budgets** | Tropical semiring: `(ℝ∪{∞}, min, +)` | Critical path computation, budget propagation |
| **Obligations** | Linear logic: resources used exactly once | No leaks, static checking possible |
| **Traces** | Mazurkiewicz equivalence (partial orders) | Optimal DPOR, stable replay |
| **Cancellation** | Two-player game with budgets | Completeness theorem: sufficient budgets guarantee termination |

See [`asupersync_v4_formal_semantics.md`](./asupersync_v4_formal_semantics.md) for the complete operational semantics.

---

## Documentation

| Document | Purpose |
|----------|---------|
| [`asupersync_plan_v4.md`](./asupersync_plan_v4.md) | **Design Bible**: Complete specification, invariants, philosophy |
| [`asupersync_v4_formal_semantics.md`](./asupersync_v4_formal_semantics.md) | **Operational Semantics**: Small-step rules, TLA+ sketch |
| [`asupersync_v4_api_skeleton.rs`](./asupersync_v4_api_skeleton.rs) | **API Skeleton**: Rust types and signatures |
| [`AGENTS.md`](./AGENTS.md) | **AI Guidelines**: Rules for AI coding agents |

---

## Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| **Phase 0** | Single-thread deterministic kernel | 🔜 Next |
| Phase 1 | Parallel scheduler + region heap | Planned |
| Phase 2 | I/O integration | Planned |
| Phase 3 | Actors + session types | Planned |
| Phase 4 | Distributed structured concurrency | Planned |
| Phase 5 | DPOR + TLA+ tooling | Planned |

---

## Limitations

### Current State: Design Phase

Asupersync is currently a **specification**, not an implementation. The design documents are complete; code does not yet exist.

### Honest Trade-offs

| Limitation | Why It Exists | Mitigation |
|------------|---------------|------------|
| **No ecosystem** | New runtime, incompatible with tokio | Internal use cases don't need ecosystem |
| **Ergonomics tax** | Explicit capabilities, two-phase patterns | Macros can reduce boilerplate |
| **Learning curve** | New mental model (regions, obligations) | Comprehensive documentation |
| **Performance unknown** | No implementation to benchmark | Design prioritizes correctness; optimize later |

### What Asupersync Does NOT Do

- **Magically cancel arbitrary futures**: Non-cooperative futures can still stall; escalation boundaries are explicit
- **Exactly-once distributed execution**: We provide *idempotency + leases*; exactly-once is a system property
- **Compiler-level guarantees**: No language changes; relies on runtime + conventions

---

## FAQ

### Why "Asupersync"?

"A super sync": structured concurrency done right.

### Why not just use tokio with careful conventions?

Conventions don't compose. The 100th engineer on your team will spawn a detached task. The library you depend on will drop a future holding a lock. Asupersync makes incorrect code unrepresentable (or at least detectable).

### Is this vaporware?

The specification is complete and detailed enough to implement. Implementation is the next phase. The design has been refined through multiple iterations with formal semantics.

### How does this compare to structured concurrency in other languages?

Similar goals to Kotlin coroutines, Swift structured concurrency, and Java's Project Loom. Asupersync goes further with:
- Formal operational semantics
- Two-phase effects for cancel-safety
- Obligation tracking (linear resources)
- Deterministic lab runtime

### Can I use this with existing async Rust code?

Not directly. Asupersync is a new runtime with its own `Future` polling and capability system. Interop would require adapters at the boundary.

### When will it be usable?

Phase 0 (single-thread kernel) is the next milestone. No timeline; this is a correctness-first project.

---

## Contributing

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

MIT (pending final decision)
