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

[![Status: Active Development](https://img.shields.io/badge/Status-Active%20Development-brightgreen)](https://github.com/Dicklesworthstone/asupersync)
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
| **Ecosystem** | ✅ Growing | ✅ Massive | ⚠️ Medium | ⚠️ Small |
| **Maturity** | ✅ Active development | ✅ Production | ✅ Production | ✅ Production |

**When to use Asupersync:**
- Internal applications where correctness > ecosystem
- Systems where cancel-correctness is non-negotiable (financial, medical, infrastructure)
- Projects that need deterministic concurrency testing
- Distributed systems with structured shutdown requirements

**When to consider alternatives:**
- You need tokio ecosystem library compatibility (we're building native equivalents)
- Rapid prototyping where correctness guarantees aren't yet critical

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

## Using Asupersync as a Dependency

Asupersync is designed to be used as a library by other Rust crates. Here's how to integrate it into your project.

### Adding the Dependency

```toml
[dependencies]
asupersync = { git = "https://github.com/Dicklesworthstone/asupersync" }
```

### Core Types for External Crates

The following types are re-exported at the crate root for convenient access:

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

Framework authors (e.g., HTTP servers) should wrap `Cx` rather than expose it directly:

```rust
use asupersync::{Cx, Budget};

/// Framework-specific request context
pub struct RequestContext<'a> {
    cx: &'a Cx,
    request_id: u64,
    // framework-specific fields
}

impl<'a> RequestContext<'a> {
    pub fn new(cx: &'a Cx, request_id: u64) -> Self {
        Self { cx, request_id }
    }

    /// Check if the request should be cancelled
    pub fn is_cancelled(&self) -> bool {
        self.cx.is_cancel_requested()
    }

    /// Get remaining budget (for timeout handling)
    pub fn budget(&self) -> Budget {
        self.cx.budget()
    }

    /// Checkpoint for cancellation (returns error if cancelled)
    pub fn checkpoint(&self) -> Result<(), asupersync::Error> {
        self.cx.checkpoint()
    }
}
```

### Using Outcome for HTTP Handlers

Map `Outcome` variants to HTTP status codes:

```rust
use asupersync::Outcome;

async fn handler(ctx: RequestContext<'_>) -> Outcome<Response, ApiError> {
    // Check cancellation
    ctx.checkpoint()?;

    // Do work
    let data = fetch_data().await?;

    Outcome::ok(Response::json(data))
}

// Recommended HTTP status mapping:
// - Outcome::Ok(_)        -> 200 OK (or custom success code)
// - Outcome::Err(_)       -> 4xx/5xx based on error type
// - Outcome::Cancelled(_) -> 499 Client Closed Request
// - Outcome::Panicked(_)  -> 500 Internal Server Error
```

### Budget for Request Timeouts

Use `Budget` to implement request timeouts:

```rust
use asupersync::{Budget, Time};

fn create_request_budget(timeout_secs: u64) -> Budget {
    Budget::new()
        .with_deadline(Time::from_secs(timeout_secs))
        .with_poll_quota(10_000)  // Limit poll iterations
}
```

### API Stability

Asupersync is in early development (Phase 0). The public API may change. Key guarantees:

- **Stable exports**: Types listed above will remain exported
- **Semantic versioning**: Breaking changes will increment the major version once 1.0 is reached
- **Deprecation policy**: Deprecated items will be marked before removal

---

## CLI Tooling Guidelines (Future)

Asupersync is a library/runtime, but when we add CLI tools (trace viewer, lab runner, test
runner, benchmark runner), they must be **agent-friendly**, **deterministic**, and **safe
for automation**. These are *guidelines*, not a promise of current implementation.

### Principles
- **Dual-mode output**: human-readable by default on TTY; machine-readable when piped or in CI.
- **Structured errors**: parseable error objects with type, title, detail, suggestion, and exit code.
- **Progressive disclosure**: terse by default; `--verbose` or `--json` for details.
- **Determinism**: stable ordering, no time-based nondeterminism unless explicitly requested.
- **Graceful cancellation**: handle SIGINT/SIGTERM; first signal requests cancel, second exits.

### Environment & Flags
- `--format human|json|jsonl|tsv` (and `--json` shorthand) for machine-friendly output.
- `ASUPERSYNC_OUTPUT_FORMAT` and `CI` select defaults for automation.
- `NO_COLOR` disables ANSI; `CLICOLOR_FORCE` enables ANSI.
- `ASUPERSYNC_NO_PROMPT` disables interactive prompts.

### Structured Error Example (JSON line)
```json
{"type":"invalid_argument","title":"Invalid argument: --foo","detail":"--foo expects an integer","suggestion":"Try --foo 123","exit_code":1}
```

### Semantic Exit Codes (baseline)
- `0`: success
- `1`: user error (invalid input/args)
- `2`: runtime error (invariant/test failure)
- `3`: internal error (tool bug)
- `4`: cancelled (signal/timeout)
- `10+`: tool-specific (e.g., determinism/trace mismatch)

### References
- Command Line Interface Guidelines: https://clig.dev/
- RFC 9457 (Problem Details): https://www.rfc-editor.org/rfc/rfc9457
- NO_COLOR: https://no-color.org/

---

## Roadmap

| Phase | Focus | Status |
|-------|-------|--------|
| **Phase 0** | Single-thread deterministic kernel | ✅ In Progress |
| **Phase 1** | Parallel scheduler + region heap | 🔜 Next |
| **Phase 2** | I/O integration | Planned |
| **Phase 3** | Actors + session types | Planned |
| **Phase 4** | Distributed structured concurrency | Planned |
| **Phase 5** | DPOR + TLA+ tooling | Planned |

---

## Design Trade-offs

### Intentional Choices

| Choice | Rationale | Benefit |
|--------|-----------|---------|
| **Explicit capabilities** | All effects through `Cx` | Testable, auditable, capability-secure |
| **Two-phase patterns** | Reserve/commit for cancel-safety | Zero data loss during cancellation |
| **Region ownership** | Tasks owned by regions | Guaranteed quiescence, no orphans |
| **Structured cancellation** | Protocol, not flag | Bounded cleanup, predictable shutdown |

### Scope Boundaries

- **Cooperative cancellation**: Non-cooperative code requires explicit escalation boundaries
- **Idempotency + leases**: Exactly-once is a system property built on our primitives
- **Runtime enforcement**: Guarantees via runtime and API design, not language changes

---

## FAQ

### Why "Asupersync"?

"A super sync": structured concurrency done right.

### Why not just use tokio with careful conventions?

Conventions don't compose. The 100th engineer on your team will spawn a detached task. The library you depend on will drop a future holding a lock. Asupersync makes incorrect code unrepresentable (or at least detectable).

### How does this compare to structured concurrency in other languages?

Similar goals to Kotlin coroutines, Swift structured concurrency, and Java's Project Loom. Asupersync goes further with:
- Formal operational semantics
- Two-phase effects for cancel-safety
- Obligation tracking (linear resources)
- Deterministic lab runtime

### Can I use this with existing async Rust code?

Asupersync has its own runtime with explicit capabilities. For code that needs to interop with external async libraries, we provide boundary adapters that preserve our cancel-correctness guarantees.

---

## Contributing

> *About Contributions:* Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## License

MIT (pending final decision)
