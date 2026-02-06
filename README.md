<p align="center">
  <img src="asupersync_illustration.webp" alt="Asupersync - Spec-first, cancel-correct async for Rust" width="800">
</p>

# Asupersync

<div align="center">

<img src="asupersync_diagram.webp" alt="Asupersync Architecture - Regions, Tasks, and Quiescence" width="700">

[![CI](https://github.com/Dicklesworthstone/asupersync/actions/workflows/ci.yml/badge.svg)](https://github.com/Dicklesworthstone/asupersync/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange.svg)](https://www.rust-lang.org/)
[![Status: Active Development](https://img.shields.io/badge/Status-Active%20Development-brightgreen)](https://github.com/Dicklesworthstone/asupersync)

**Spec-first, cancel-correct, capability-secure async for Rust**

<h3>Quick Install</h3>

```bash
cargo add asupersync --git https://github.com/Dicklesworthstone/asupersync
```

</div>

---

## TL;DR

**The Problem**: Rust's async ecosystem gives you *tools* but not *guarantees*. Cancellation silently drops data. Spawned tasks can orphan. Cleanup is best-effort. Testing concurrent code is non-deterministic. You write correct code by convention, and discover bugs in production.

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

## Quick Example

```rust
use asupersync::{Cx, Scope, Outcome, Budget};

// Structured concurrency: scope guarantees quiescence
async fn main_task(cx: &mut Cx) -> Outcome<(), Error> {
    cx.region(|scope| async {
        // Spawn owned tasks - they cannot orphan
        scope.spawn(worker_a);
        scope.spawn(worker_b);

        // When scope exits: waits for BOTH tasks,
        // runs finalizers, resolves obligations
    }).await;

    // Guaranteed: nothing from inside is still running
    Outcome::ok(())
}

// Cancellation is a protocol, not a flag
async fn worker_a(cx: &mut Cx) -> Outcome<(), Error> {
    loop {
        // Checkpoint for cancellation - explicit, not implicit
        cx.checkpoint()?;

        // Two-phase send: cancel-safe
        let permit = tx.reserve(cx).await?;  // Can cancel here
        permit.send(message);                 // Linear: must happen
    }
}

// Lab runtime: deterministic testing
#[test]
fn test_cancellation_is_bounded() {
    let lab = LabRuntime::new(LabConfig::default().seed(42));

    lab.run(|cx| async {
        // Same seed = same execution = reproducible bugs
        cx.region(|scope| async {
            scope.spawn(task_under_test);
        }).await
    });

    // Oracles verify invariants
    assert!(lab.obligation_leak_oracle().is_ok());
    assert!(lab.quiescence_oracle().is_ok());
}
```

---

## Design Philosophy

### 1. Structured Concurrency by Construction

Tasks don't float free. Every task is owned by a region. Regions form a tree. When a region closes, it *guarantees* all children are complete, all finalizers have run, all obligations are resolved. This is the "no orphans" invariant, enforced by the type system and runtime rather than by discipline.

```rust
// Typical executors: what happens when this scope exits?
spawn(async { /* orphaned? cancelled? who knows */ });

// Asupersync: scope guarantees quiescence
scope.region(|sub| async {
    sub.spawn(task_a);
    sub.spawn(task_b);
}).await;
// ← guaranteed: nothing from inside is still running
```

### 2. Cancellation as a First-Class Protocol

Cancellation operates as a multi-phase protocol, not a silent `drop`:

```
Running → CancelRequested → Cancelling → Finalizing → Completed(Cancelled)
            ↓                    ↓             ↓
         (bounded)          (cleanup)    (finalizers)
```

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
async fn my_task(cx: &mut Cx) {
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

## "Alien Artifact" Quality Algorithms

Asupersync deliberately uses mathematically rigorous machinery where it buys real correctness, determinism, and debuggability. The goal is not "cleverness"; it's to make concurrency properties *structural*, so both humans and coding agents can trust the system under cancellation, failures, and schedule perturbations.

### Formal Semantics (and a Lean Skeleton) for the Runtime Kernel

The runtime design is backed by a small-step operational semantics (`asupersync_v4_formal_semantics.md`) with an accompanying Lean mechanization scaffold (`formal/lean/Asupersync.lean`).

One example: the cancellation/cleanup **budget** composes as a semiring-like object (componentwise `min`, with priority as `max`), which makes "who constrains whom?" algebraic instead of ad-hoc:

```text
combine(b1, b2) =
  deadline   := min(b1.deadline,   b2.deadline)
  pollQuota  := min(b1.pollQuota,  b2.pollQuota)
  costQuota  := min(b1.costQuota,  b2.costQuota)
  priority   := max(b1.priority,   b2.priority)
```

This is the kind of structure that lets us reason about cancellation protocols and bounded cleanup with proof-friendly, compositional rules.

### DPOR-Style Schedule Exploration (Mazurkiewicz Traces, Foata Fingerprints)

The Lab runtime includes a DPOR-style schedule explorer (`src/lab/explorer.rs`) that treats executions as traces modulo commutation of independent events (Mazurkiewicz equivalence). Instead of "run it 10,000 times and pray", it tracks coverage by equivalence class fingerprints and can prioritize exploration based on trace topology.

The net effect: deterministic, replayable concurrency debugging with *coverage semantics* rather than vibes.

### Anytime-Valid Invariant Monitoring via e-processes

Oracles can run repeatedly during an execution without invalidating significance, using **e-processes** (`src/lab/oracle/eprocess.rs`). The key property is Ville's inequality (anytime validity):

```text
P_H0(∃ t : E_t ≥ 1/α) ≤ α
```

So you can "peek" after every scheduling step and still control type-I error, which is exactly what you want in a deterministic scheduler + oracle setting.

### Distribution-Free Conformal Calibration for Lab Metrics

For lab metrics that benefit from calibrated prediction sets, Asupersync uses split conformal calibration (`src/lab/conformal.rs`) with finite-sample, distribution-free guarantees (under exchangeability):

```text
P(Y ∈ C(X)) ≥ 1 − α
```

This is used to keep alerting and invariant diagnostics robust without baking in fragile distributional assumptions.

### Explainable Evidence Ledgers (Bayes Factors, Galaxy-Brain Diagnostics)

When a run violates an invariant (or conspicuously does not), Asupersync can produce a structured evidence ledger (`src/lab/oracle/evidence.rs`) using Bayes factors and log-likelihood contributions. The goal is agent-friendly debugging: equations + substitutions + one-line intuitions, so you can see *exactly why* the system believes "task leak" (or "clean close") is happening.

### Deterministic Algorithms in the Hot Path (Not Just in Tests)

Determinism is treated as a first-class algorithmic constraint across the codebase:

- A deterministic virtual time wheel (`src/lab/virtual_time_wheel.rs`) with explicit tie-breaking.
- Deterministic consistent hashing (`src/distributed/consistent_hash.rs`) for stable assignment without iteration-order landmines.
- Trace canonicalization and race analysis hooks integrated into the lab runtime (`src/lab/runtime.rs`, `src/trace/dpor`).

The point is simple: "same seed, same behavior" should be true end-to-end, not just for a demo scheduler.

---

## How Asupersync Compares

| Feature | Asupersync | async-std | smol |
|---------|------------|-----------|------|
| **Structured concurrency** | ✅ Enforced | ❌ Manual | ❌ Manual |
| **Cancel-correctness** | ✅ Protocol | ⚠️ Drop-based | ⚠️ Drop-based |
| **No orphan tasks** | ✅ Guaranteed | ❌ spawn detaches | ❌ spawn detaches |
| **Bounded cleanup** | ✅ Budgeted | ❌ Best-effort | ❌ Best-effort |
| **Deterministic testing** | ✅ Built-in | ❌ External tools | ❌ External tools |
| **Obligation tracking** | ✅ Linear tokens | ❌ None | ❌ None |
| **Ecosystem** | 🔜 Growing | ⚠️ Medium | ⚠️ Small |
| **Maturity** | 🔜 Active dev | ✅ Production | ✅ Production |

**When to use Asupersync:**
- Internal applications where correctness > ecosystem
- Systems where cancel-correctness is non-negotiable (financial, medical, infrastructure)
- Projects that need deterministic concurrency testing
- Distributed systems with structured shutdown requirements

**When to consider alternatives:**
- You need broad ecosystem library compatibility (we're building native equivalents)
- Rapid prototyping where correctness guarantees aren't yet critical

---

## Installation

### From Git (Recommended)

```bash
# Add to Cargo.toml
cargo add asupersync --git https://github.com/Dicklesworthstone/asupersync

# Or manually add:
# [dependencies]
# asupersync = { git = "https://github.com/Dicklesworthstone/asupersync" }
```

### From Source

```bash
git clone https://github.com/Dicklesworthstone/asupersync.git
cd asupersync
cargo build --release
```

### Minimum Supported Rust Version

Asupersync requires **Rust 1.75+** and uses Edition 2021.

---

## Core Types Reference

### Outcome — Four-Valued Result

```rust
pub enum Outcome<T, E> {
    Ok(T),                    // Success
    Err(E),                   // Application error
    Cancelled(CancelReason),  // External cancellation
    Panicked(PanicPayload),   // Task panicked
}

// Severity lattice: Ok < Err < Cancelled < Panicked
// HTTP mapping: Ok→200, Err→4xx/5xx, Cancelled→499, Panicked→500
```

### Budget — Resource Constraints

```rust
pub struct Budget {
    pub deadline: Option<Time>,   // Absolute deadline
    pub poll_quota: u32,          // Max poll calls
    pub cost_quota: Option<u64>,  // Abstract cost units
    pub priority: u8,             // Scheduling priority (0-255)
}

// Semiring: meet(a, b) = tighter constraint wins
let effective = outer_budget.meet(inner_budget);
```

### CancelReason — Structured Context

```rust
pub enum CancelKind {
    User,             // Explicit cancellation
    Timeout,          // Deadline exceeded
    FailFast,         // Sibling failed
    RaceLost,         // Lost a race
    ParentCancelled,  // Parent region cancelled
    Shutdown,         // Runtime shutdown
}

// Severity: User < Timeout < FailFast < ParentCancelled < Shutdown
// Cleanup budgets scale inversely with severity
```

### Cx — Capability Context

```rust
pub struct Cx { /* ... */ }

impl Cx {
    pub fn spawn<F>(&self, f: F) -> TaskHandle;
    pub fn checkpoint(&self) -> Result<(), Cancelled>;
    pub fn mask(&self) -> MaskGuard;  // Defer cancellation
    pub fn trace(&self, event: TraceEvent);
    pub fn budget(&self) -> Budget;
    pub fn is_cancel_requested(&self) -> bool;
}
```

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

### Scheduler Priority Lanes

| Lane | Purpose | Priority |
|------|---------|----------|
| **Cancel Lane** | Tasks in cancellation states | 200-255 (highest) |
| **Timed Lane** | Deadline-driven tasks (EDF) | Based on deadline |
| **Ready Lane** | Normal runnable tasks | Default priority |

---

## Spork (OTP Mental Model)

Spork is an OTP-style layer built on Asupersync's kernel guarantees: regions
(structured concurrency), obligations (linearity), explicit cancellation, and the
deterministic lab runtime.

### OTP Mapping (Conceptual)

| OTP Concept | Spork / Asupersync Interpretation |
|------------|-----------------------------------|
| Process | A region-owned task/actor (cannot orphan) |
| Supervisor | A compiled, deterministic restart topology over regions |
| Link | Failure propagation rule (sibling/parent coupling; deterministic) |
| Monitor + DOWN | Observation without coupling: deterministic notifications |
| Registry | Names as lease obligations: reserve/commit or abort (no stale names) |
| call/cast | Request/response and mailbox protocols with bounded drain on cancel |

### Why Spork Is Strictly Stronger (When We Finish It)

- Determinism: the lab runtime makes OTP-style debugging reproducible (seeded schedules, trace capture/replay, schedule exploration).
- Cancel-correctness: cancellation is a protocol (request -> drain -> finalize), so OTP-style shutdown has explicit budgets and bounded cleanup.
- No silent leaks: regions cannot close with live children or unresolved obligations (permits/acks/leases), so "forgot to reply" and "stale name" become structural failures (or test-oracle failures), not production mysteries.

### Where To Look In The Repo

- Supervisor compilation/runtime: `src/supervision.rs`
- Name leases + registry plumbing: `src/cx/registry.rs`
- Deterministic ordering contracts (Spork): `docs/spork_deterministic_ordering.md`
- Spork glossary + invariants: `docs/spork_glossary_invariants.md`
- Crash artifacts + canonical traces: `src/trace/crashpack.rs`

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

## "Alien Artifact" Quality Algorithms

Asupersync is intentionally "math-forward": it uses advanced math and theory-grade CS where it buys real guarantees (determinism, cancel-correctness, bounded cleanup, and reproducible concurrency debugging). This is not aspirational; the mechanisms below are implemented in the codebase today.

### Mazurkiewicz Trace Monoid + Foata Normal Form (DPOR Equivalence Classes)

Instead of treating traces as opaque linear logs, Asupersync factors out *pure commutations* of independent events via trace theory. Two traces that differ only by swapping adjacent independent events are considered equivalent, and canonicalized to a unique representative (Foata normal form). See `src/trace/canonicalize.rs`.

$$
M(\\Sigma, I) = \\Sigma^* / \\equiv_I
$$

Payoff: canonical fingerprints for schedule exploration and stable replay across "same behavior, different interleaving" runs.

### Geodesic Schedule Normalization (A* / Beam Search Over Linear Extensions)

Given a dependency DAG (trace poset), Asupersync constructs a valid linear extension that minimizes "owner switches" (a proxy for context-switch entropy) using deterministic heuristics and an exact bounded A* solver. See `src/trace/geodesic.rs` and `src/trace/event_structure.rs`.

Payoff: smaller, more canonical traces that are easier to diff, replay, and minimize.

### DPOR Race Detection + Happens-Before (Vector Clocks)

Asupersync includes DPOR-style race detection and backtracking point extraction, using a minimal happens-before relation (vector clocks per task) plus resource-footprint conflicts. See `src/trace/dpor.rs` and `src/trace/independence.rs`.

Payoff: systematic interleaving exploration that targets truly different behaviors instead of brute-force schedule fuzzing.

### Persistent Homology of Trace Commutation Complexes (GF(2) Boundary Reduction)

Schedule exploration is prioritized using topological signals from a square cell complex built out of commuting diamonds: edges are causality edges, squares represent valid commutations, and Betti numbers/persistence quantify "non-trivial scheduling freedom". The implementation uses deterministic GF(2) bitset linear algebra and boundary-matrix reduction. See `src/trace/boundary.rs`, `src/trace/gf2.rs`, and `src/trace/scoring.rs`.

Payoff: an evidence-ledger, structure-aware notion of "interesting schedules" that tends to surface rare concurrency behaviors earlier.

### Sheaf-Theoretic Consistency Checks for Distributed Sagas

In distributed obligation tracking, pairwise lattice merges can hide *global* inconsistency (phantom commits). Asupersync models this as a sheaf-style gluing problem and detects obstructions where no global assignment explains all local observations. See `src/trace/distributed/sheaf.rs`.

Payoff: catches split-brain-style saga states that evade purely pairwise conflict checks.

### Anytime-Valid Invariant Monitoring (E-Processes, Ville's Inequality)

The lab runtime can continuously monitor invariants (task leaks, obligation leaks, region quiescence) using e-processes: a supermartingale-based, anytime-valid testing framework that supports optional stopping without "peeking penalties". See `src/lab/oracle/eprocess.rs` and `src/obligation/eprocess.rs`.

Payoff: turn long-running exploration into statistically sound monitoring, with deterministic, explainable rejection thresholds.

### Distribution-Free Conformal Calibration for Oracle Metrics

Oracle anomaly thresholds are calibrated using split conformal prediction, giving finite-sample, distribution-free coverage guarantees under exchangeability assumptions across deterministic schedule seeds. See `src/lab/conformal.rs`.

Payoff: stable false-alarm behavior under workload drift, without hand-tuned magic constants.

### Algebraic Law Sheets + Rewrite Engines With Side-Condition Lattices

Asupersync's concurrency combinators come with an explicit law sheet (severity lattices, budget semirings, race/join laws, etc.) and a rewrite engine guarded by conservative static analyses (obligation-safety and cancel-safety lattices; deadline min-plus reasoning). See `src/combinator/laws.rs`, `src/plan/rewrite.rs`, and `src/plan/analysis.rs`.

Payoff: principled plan optimization without silently breaking cancel/drain/quiescence invariants.

### TLA+ Export for Model Checking

Traces can be exported as TLA+ behaviors with spec skeletons for bounded TLC model checking of core invariants (no orphans, obligation linearity, quiescence). See `src/trace/tla_export.rs`.

Payoff: bridge from deterministic runtime traces to model-checking workflows when you need "prove it", not "it passed tests".

---

## Using Asupersync as a Dependency

### Cargo.toml

```toml
[dependencies]
# Git dependency until crates.io publish
asupersync = { git = "https://github.com/Dicklesworthstone/asupersync", version = "0.1" }
```

### Feature Flags

Asupersync is feature-light by default; the lab runtime is available without flags.

| Feature | Description | Default |
|---------|-------------|---------|
| `test-internals` | Expose test-only helpers (not for production) | No |
| `metrics` | OpenTelemetry metrics provider | No |
| `tracing-integration` | Tracing spans/logging integration | No |
| `proc-macros` | `scope!`, `spawn!`, `join!`, `race!` proc macros | No |
| `tower` | Tower `Service` adapter support | No |
| `trace-compression` | LZ4 compression for trace files | No |
| `debug-server` | Debug HTTP server for runtime inspection | No |
| `config-file` | TOML config file loading for `RuntimeBuilder` | No |
| `io-uring` | Linux io_uring reactor (kernel 5.1+) | No |
| `tls` | TLS support via rustls | No |
| `tls-native-roots` | TLS with native root certs | No |
| `tls-webpki-roots` | TLS with webpki root certs | No |
| `cli` | CLI tools (trace inspection) | No |

### Minimum Supported Rust Version

Rust **1.75+** (Edition 2021).

### Semver Policy

- **0.x.y**: Breaking changes may ship in **0.(x+1).0**
- **1.x.y**: Breaking changes only in **(1+1).0.0**

See `docs/api_audit.md` for the current public API audit and stability notes.

### Core Exports

```rust
use asupersync::{
    // Capability context
    Cx, Scope,

    // Outcome types (four-valued result)
    Outcome, OutcomeError, PanicPayload, Severity, join_outcomes,

    // Cancellation
    CancelKind, CancelReason,

    // Resource management
    Budget, Time,

    // Error handling
    Error, ErrorKind, Recoverability,

    // Identifiers
    RegionId, TaskId, ObligationId,

    // Testing
    LabConfig, LabRuntime,

    // Policy
    Policy,
};
```

### Wrapping Cx for Frameworks

Framework authors (e.g., HTTP servers) should wrap `Cx`:

```rust
/// Framework-specific request context
pub struct RequestContext<'a> {
    cx: &'a Cx,
    request_id: u64,
}

impl<'a> RequestContext<'a> {
    pub fn is_cancelled(&self) -> bool {
        self.cx.is_cancel_requested()
    }

    pub fn budget(&self) -> Budget {
        self.cx.budget()
    }

    pub fn checkpoint(&self) -> Result<(), asupersync::Error> {
        self.cx.checkpoint()
    }
}
```

### HTTP Status Mapping

```rust
// Recommended HTTP status mapping:
// - Outcome::Ok(_)        → 200 OK
// - Outcome::Err(_)       → 4xx/5xx based on error type
// - Outcome::Cancelled(_) → 499 Client Closed Request
// - Outcome::Panicked(_)  → 500 Internal Server Error
```

---

## Configuration

### Lab Runtime Configuration

```rust
let config = LabConfig::default()
    // Seed for deterministic scheduling (same seed = same execution)
    .seed(42)

    // Maximum steps before timeout (prevents infinite loops)
    .max_steps(100_000)

    // Enable futurelock detection (tasks holding obligations without progress)
    .futurelock_max_idle_steps(1000)

    // Enable trace capture for replay
    .capture_trace(true);

let lab = LabRuntime::new(config);
```

### Budget Configuration

```rust
// Request timeout with poll budget
let request_budget = Budget::new()
    .with_deadline_secs(30)       // 30 second timeout
    .with_poll_quota(10_000)      // Max 10k polls
    .with_priority(100);          // Normal priority

// Cleanup budget (tighter for faster shutdown)
let cleanup_budget = Budget::new()
    .with_deadline_secs(5)
    .with_poll_quota(500);
```

---

## Troubleshooting

### "ObligationLeak detected"

Your task completed while holding an obligation (permit, ack, lease).

```rust
// Wrong: permit dropped without send/abort
let permit = tx.reserve(cx).await?;
return Outcome::ok(());  // Leak!

// Right: always resolve obligations
let permit = tx.reserve(cx).await?;
permit.send(message);  // Resolved
```

### "RegionCloseTimeout"

A region is stuck waiting for children that won't complete.

```rust
// Check for: infinite loops without checkpoints
loop {
    cx.checkpoint()?;  // Add checkpoints in loops
    // ... work ...
}
```

### "FuturelockViolation"

A task is holding obligations but not making progress.

```rust
// Check for: awaiting something that will never resolve
// while holding a permit/lock
let permit = tx.reserve(cx).await?;
other_thing.await;  // If this blocks forever → futurelock
permit.send(msg);
```

### Deterministic test failures

Same seed should give same execution. If not:

```rust
// Check for: time-based operations
// WRONG: uses wall-clock time
let now = std::time::Instant::now();

// RIGHT: uses virtual time through Cx
let now = cx.now();
```

Also check for ambient randomness:

```rust
// WRONG: ambient entropy breaks determinism
let id = rand::random::<u64>();

// RIGHT: use capability-based entropy
let id = cx.random_u64();
```

To enforce deterministic collections in lab code, consider a clippy rule that
disallows `std::collections::HashMap/HashSet` in favor of `util::DetHashMap/DetHashSet`.

---

## Limitations

### Current Phase (0-1) Constraints

| Capability | Current State | Planned |
|------------|---------------|---------|
| Multi-threaded runtime | 🔜 In progress | Phase 1 |
| I/O reactor integration | ❌ Not yet | Phase 2 |
| Actor supervision | ❌ Planned | Phase 3 |
| Distributed runtime | ❌ Designed | Phase 4 |
| DPOR exploration | ⚠️ Hooks exist | Phase 5 |

### What Asupersync Doesn't Do

- **Cooperative cancellation only**: Non-cooperative code requires explicit escalation boundaries
- **Not a drop-in replacement for other runtimes**: Different API, different guarantees
- **No ecosystem compatibility**: Can't directly use runtime-specific libraries (adapters planned)

### Design Trade-offs

| Choice | Trade-off |
|--------|-----------|
| Explicit checkpoints | More verbose, but cancellation is observable |
| Capability tokens | Extra parameter threading, but testable and auditable |
| Two-phase effects | More complex primitives, but no data loss |
| Region ownership | Can't detach tasks, but no orphans |

---

## Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| **Phase 0** | Single-thread deterministic kernel | ✅ Complete |
| **Phase 1** | Parallel scheduler + region heap | 🔜 In Progress |
| **Phase 2** | I/O integration | Planned |
| **Phase 3** | Actors + session types | Planned |
| **Phase 4** | Distributed structured concurrency | Planned |
| **Phase 5** | DPOR + TLA+ tooling | Planned |

---

## FAQ

### Why "Asupersync"?

"A super sync": structured concurrency done right.

### Why not just use existing runtimes with careful conventions?

Conventions don't compose. The 100th engineer on your team will spawn a detached task. The library you depend on will drop a future holding a lock. Asupersync makes incorrect code unrepresentable (or at least detectable).

### How does this compare to structured concurrency in other languages?

Similar goals to Kotlin coroutines, Swift structured concurrency, and Java's Project Loom. Asupersync goes further with:
- Formal operational semantics
- Two-phase effects for cancel-safety
- Obligation tracking (linear resources)
- Deterministic lab runtime

### Can I use this with existing async Rust code?

Asupersync has its own runtime with explicit capabilities. For code that needs to interop with external async libraries, we provide boundary adapters that preserve our cancel-correctness guarantees.

### Is this production-ready?

Phase 0 (single-threaded deterministic kernel) is complete and tested. Phase 1 (multi-threaded) is in progress. Use for internal applications where correctness matters more than ecosystem breadth.

### How do I report bugs?

Open an issue at https://github.com/Dicklesworthstone/asupersync/issues

---

## Documentation

| Document | Purpose |
|----------|---------|
| [`asupersync_plan_v4.md`](./asupersync_plan_v4.md) | **Design Bible**: Complete specification, invariants, philosophy |
| [`asupersync_v4_formal_semantics.md`](./asupersync_v4_formal_semantics.md) | **Operational Semantics**: Small-step rules, TLA+ sketch |
| [`asupersync_v4_api_skeleton.rs`](./asupersync_v4_api_skeleton.rs) | **API Skeleton**: Rust types and signatures |
| [`docs/integration.md`](./docs/integration.md) | **Integration Docs**: Architecture, API orientation, tutorials |
| [`docs/macro-dsl.md`](./docs/macro-dsl.md) | **Macro DSL**: scope!/spawn!/join!/race! usage, patterns, examples |
| [`docs/cancellation-testing.md`](./docs/cancellation-testing.md) | **Cancellation Testing**: deterministic injection + oracles |
| [`docs/replay-debugging.md`](./docs/replay-debugging.md) | **Replay Debugging**: Record/replay for debugging async bugs |
| [`docs/security_threat_model.md`](./docs/security_threat_model.md) | **Security Review**: Threat model and security invariants |
| [`TESTING.md`](./TESTING.md) | **Testing Guide**: unit, conformance, E2E, fuzzing, CI |
| [`AGENTS.md`](./AGENTS.md) | **AI Guidelines**: Rules for AI coding agents |

---

## Contributing

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

MIT
