# Adversarial Review (H2): Asupersync

**Reviewer**: SapphireHill (claude-opus-4.6)
**Date**: 2026-04-07
**Scope**: Full codebase adversarial attack on project claims

---

## Thesis

Asupersync is an impressively ambitious runtime that delivers real structural concurrency guarantees in its core region/task model, but its headline marketing claims systematically overreach what the implementation actually provides. The "no ambient authority" claim is falsified by 34 global statics and 26 thread-locals in production code, including `Cx::current()` which is literally the Tokio-style ambient thread-local pattern the project claims to reject. The "deterministic testing" claim is undermined by `std::time::Instant::now()` in 15 non-test files and `std::collections::HashMap` (with random iteration order) in production runtime paths. The Lean formalization is a scaffold with zero `sorry` uses but also covers only ~5,200 lines of type definitions and trivial lemmas against a 700K-line codebase, making claims of "formal verification" misleading. The 5,043 `unwrap()` calls and 673 `panic!()` calls across 246+ files in a library that claims to be production-ready for "financial, medical, infrastructure" systems constitute a significant reliability risk. The project is real engineering with genuine innovations, but the gap between marketing and implementation is wider than it should be for a project that positions itself as the correctness-superior alternative to Tokio.

---

## Top Findings

### F1: `Cx::current()` Falsifies "No Ambient Authority" Claim
**Severity**: CRITICAL | **Confidence**: 0.95

The README states: "All effects flow through explicit Cx; no ambient authority." The comparison table claims this against Tokio. However, `src/cx/cx.rs:249-276` implements:

```rust
thread_local! {
    static CURRENT_CX: RefCell<Option<FullCx>> = const { RefCell::new(None) };
}

pub fn current() -> Option<Self> {
    CURRENT_CX.with(|slot| slot.borrow().clone())
}
```

This is *exactly* the ambient authority pattern Tokio uses for its runtime handle. `spawn_blocking` (`src/runtime/spawn_blocking.rs:217`) calls `Cx::current()` to discover the runtime -- the precise pattern the README criticizes. Other callers: `src/server/shutdown.rs:44`, `src/process.rs:114,1179,1193,1262`, `src/http/h1/listener.rs:119`, `src/database/postgres.rs:3057`. These are non-test, production code paths that access Cx without it being passed as an argument.

**Evidence path**: `/data/projects/asupersync/src/cx/cx.rs`, `/data/projects/asupersync/src/runtime/spawn_blocking.rs`

---

### F2: Pervasive Global Statics Contradict Capability Security Model
**Severity**: HIGH | **Confidence**: 0.95

The codebase contains 34 process-global static variables and 26 thread-local variables in production (non-test) code. Notable examples:
- `MONITOR_COUNTER: AtomicU64` (src/monitor.rs:47) -- global counter, not routed through Cx
- `NEXT_RUNTIME_INSTANCE_ID: AtomicU64` (src/runtime/state.rs:50)
- `SQLITE_POOL: OnceLock<BlockingPool>` (src/database/sqlite.rs:52) -- process-global pool
- `LINK_COUNTER: AtomicU64` (src/link.rs:108)
- `REMOTE_TASK_COUNTER: AtomicU64` (src/remote.rs:44)
- `SOURCE_ID_COUNTER: AtomicU64` (src/runtime/reactor/source.rs:30)
- `SIGNAL_DISPATCHER: OnceLock` (src/signal/signal.rs:294)
- `CURRENT_RUNTIME_HANDLE: RefCell<Option<RuntimeHandle>>` (src/runtime/builder.rs:198)
- `CURRENT_LOCAL: RefCell<Option<Arc<Mutex<PriorityScheduler>>>>` (src/runtime/scheduler/three_lane.rs:471)
- `CURRENT_QUEUE: RefCell<Option<LocalQueue>>` (src/runtime/scheduler/local_queue.rs:19)
- `CONTEXT_STACK: RefCell<Vec<ContextStackEntry>>` (src/observability/context.rs:20)

Each of these is ambient state accessible without a `Cx`. The project is *aware* of some of these (see `src/audit/ambient.rs`), but the audit tracks only 5 findings and marks all as "exempt." The real count is 60+ ambient state access points.

**Evidence path**: `/data/projects/asupersync/src/audit/ambient.rs`, multiple files above

---

### F3: 5,043 `unwrap()` + 6,360 `expect()` + 673 `panic!()` in Library Code
**Severity**: HIGH | **Confidence**: 0.98

For a library that claims to be suitable for "financial, medical, infrastructure" systems where "cancel-correctness is non-negotiable," the codebase contains:
- 5,043 `unwrap()` calls across 246 files in `src/`
- 6,360 `expect()` calls across 293 files in `src/`
- 673 `panic!()` calls across 136 files in `src/`

While many are in `#[cfg(test)]` blocks, the sheer volume means many are on production paths. Key examples: `src/runtime/kernel.rs` has 77 `unwrap()` calls in the kernel itself. `src/cx/registry.rs` has 204 `unwrap()` calls. `src/gen_server.rs` has 116 `unwrap()` calls. `src/cx/scope.rs` has 37 `unwrap()` calls. `src/runtime/state.rs` has 27 `unwrap()` calls.

A library runtime panicking in production contradicts the "bounded cleanup" and "no silent drops" guarantees.

**Evidence path**: grep across `/data/projects/asupersync/src/`

---

### F4: Deterministic Testing Undermined by Non-Deterministic Data Structures in Production
**Severity**: HIGH | **Confidence**: 0.85

The lab runtime correctly uses `DetHashMap`/`DetHashSet` (src/lab/runtime.rs uses `det_hash`). However, the production runtime (`src/runtime/state.rs:42`) uses `std::collections::HashMap` and `HashSet` which have randomized iteration order per process. `src/runtime/io_driver.rs:45` uses `HashMap`. `src/runtime/scheduler/worker.rs:16` uses `HashSet`. The `HashSet` usage in `src/runtime/scheduler/worker.rs:1108` is in steal logic -- ordering affects which tasks get stolen first.

This means the same logical execution can produce different scheduling outcomes between process runs, even with the same seed, when using the production scheduler instead of the lab scheduler. The claim "same seed, same behavior holds end-to-end" is only true for the lab runtime, not the production runtime.

Additionally, `std::time::Instant::now()` appears in 15 non-test files including `src/time/driver.rs:45` (the timer driver epoch), `src/distributed/distribution.rs:172`, `src/signal/graceful.rs:16`, and reactor code. Any code path touching wall-clock time in production breaks determinism.

**Evidence path**: `/data/projects/asupersync/src/runtime/state.rs`, `/data/projects/asupersync/src/util/det_hash.rs`

---

### F5: Lean Formalization is a Scaffold, Not a Proof
**Severity**: HIGH | **Confidence**: 0.90

The README says the runtime is "backed by a small-step operational semantics with an accompanying Lean mechanization scaffold." The MEMORY.md claims "ALL 6 CORE INVARIANTS FULLY_PROVEN. 170 theorems, 136 traceability rows."

The single Lean file (`formal/lean/Asupersync.lean`) is 5,210 lines. It contains approximately 274 `theorem`, `lemma`, or `def` entries. While it has zero `sorry` (incomplete proofs), the theorems prove properties of the *Lean model*, not the Rust implementation. There is no extraction, no refinement link, and no mechanism to verify that the 700K-line Rust codebase conforms to the 5,210-line Lean model. The model represents an idealized, simplified version of the system.

This is a legitimate modeling exercise, but calling it "formal verification" of the runtime would be misleading. It proves properties of a specification document, not of the compiled binary.

**Evidence path**: `/data/projects/asupersync/formal/lean/Asupersync.lean`

---

### F6: `test-internals` Feature is Default -- Production Builds Ship Test Infrastructure
**Severity**: MEDIUM | **Confidence**: 0.95

`Cargo.toml:36` declares: `default = ["test-internals", "proc-macros"]`. The `test-internals` feature exposes private APIs like `Cx::new()`, `Cx::for_testing()`, and `set_current()`. The Cargo.toml comment says "NOT for production use." But since it's a default feature, any downstream `cargo add asupersync` will get these APIs unless they explicitly disable defaults.

This means any consumer of the library has access to `Cx::for_testing()`, can construct arbitrary capability contexts, and can bypass the structured concurrency model entirely. The capability security model is opt-in, not enforced.

**Evidence path**: `/data/projects/asupersync/Cargo.toml:36`, `/data/projects/asupersync/src/cx/cx.rs:1859`

---

### F7: "No Orphan Tasks" Claim Has Untested Edge Cases
**Severity**: MEDIUM | **Confidence**: 0.70

The structured concurrency model requires regions to close to quiescence. However:

1. `spawn_blocking` (`src/runtime/spawn_blocking.rs:264`) spawns OS threads that are not region-owned. If the runtime shuts down while a blocking task is running on a fallback thread, that thread continues executing outside any region.

2. The `RemoteTask` pattern (`src/remote.rs:44`, global counter) assigns remote tasks IDs from a global atomic, outside the region tree.

3. `std::thread::spawn` is used as a fallback in `src/time/sleep.rs` (per the ambient authority audit) -- this spawns a timer thread outside structured concurrency.

These edge cases may be intentional design tradeoffs, but they weaken the absolute "every spawned task is owned by a region; cannot orphan" claim in the README.

**Evidence path**: `/data/projects/asupersync/src/runtime/spawn_blocking.rs`, `/data/projects/asupersync/src/remote.rs`

---

### F8: 20+ AI Agents Writing 310K+ Lines -- Coordination and Quality Risk
**Severity**: MEDIUM | **Confidence**: 0.75

The MEMORY.md documents 20+ concurrent AI coding agents (NavyMill, BlackBear, EmeraldRiver, SilverCompass, AzureElk, IndigoGrove, TurquoiseDune, MistyCrane, OrangeOwl, etc.) working simultaneously on the codebase. The AGENTS.md includes a direct instruction to Codex: "those are changes created by the potentially dozen of other agents working on the project at the same time... just fool yourself into thinking YOU made the changes."

Quality risks:
- **No code review from humans**: The audit process (587 files audited) was performed by AI agents auditing other AI agents' code.
- **Merge conflicts at scale**: The `AGENTS.md` reveals this has been a persistent problem ("RCH overwrites uncommitted source: ALWAYS commit before rch").
- **Pattern inconsistency**: Different agents use different patterns. Some files show 204 `unwrap()` calls (cx/registry.rs), others are `unwrap()`-free.
- **Dead code**: `src/runtime/reactor/linux.rs` and `uring.rs` have "no mod declaration" per MEMORY.md.
- **Stale artifacts**: The git status shows 20+ untracked temporary files (clippy.json, clippy.out, ubs.out, check_out.txt, etc.) suggesting chaotic build environments.

The audit found ~65 bugs, which for 310K lines is a low rate (~0.02%), but the question is whether the audit methodology (AI auditing AI) catches the same categories of bugs that human review would.

**Evidence path**: `/data/projects/asupersync/AGENTS.md`, MEMORY.md

---

### F9: Comparison Table Claims "Feature-complete" and "Actively Hardened" Against Production Runtimes
**Severity**: MEDIUM | **Confidence**: 0.85

The README comparison table claims Asupersync has "Maturity: Feature-complete runtime surface, actively hardened" and places it alongside async-std and smol which are "Production." The README also says: "Tokio-scale built-in surface (runtime, net, HTTP/1.1+H2, TLS, WebSocket, gRPC, DB, distributed)."

However:
- AGENTS.md says "we're in early development with no users"
- Multiple ecosystem areas are listed as "In progress" or "Early" maturity in the ecosystem table
- The project has never been used in production
- Zero published crate (install is `cargo add --git`, not `cargo add asupersync`)
- HTTP/3, QUIC, web framework, messaging, and filesystem are all "In progress" or "Early"
- The `#[allow(dead_code)]` annotations throughout suggest significant stub code

Claiming "feature-complete" for a runtime with zero production users is premature. Tokio has been battle-tested by hundreds of companies. This comparison is misleading.

**Evidence path**: `/data/projects/asupersync/README.md:405-406`, `/data/projects/asupersync/AGENTS.md:167`

---

### F10: Cancel-Correctness Depends on Cooperative `checkpoint()` Calls
**Severity**: MEDIUM | **Confidence**: 0.80

The cancellation protocol is described as "request -> drain -> finalize." But cancellation is cooperative: tasks must call `cx.checkpoint()` to observe cancellation. A task that enters a long CPU-bound computation or a blocking system call without checkpointing will not respond to cancellation, violating the "bounded cleanup" guarantee.

The `spawn_blocking` fallback (`src/runtime/spawn_blocking.rs:264`) spawns an OS thread with a closure that has no mechanism for cancellation interruption. Once the closure is running, cancellation cannot preempt it.

This is acknowledged implicitly (budgets are "sufficient conditions for completion"), but the marketing language ("cancellation is a protocol, not a flag" / "bounded cleanup budgets are sufficient conditions, not hopes") creates an impression of stronger guarantees than cooperative cancellation can provide.

---

## Risks Identified

1. **Credibility risk**: The gap between marketing claims and implementation could undermine trust if scrutinized by experienced Rust developers.
2. **Security risk**: `test-internals` as default feature means downstream consumers can bypass capability model.
3. **Reliability risk**: 5,000+ `unwrap()` calls in library code means panics in production are likely.
4. **Correctness risk**: Non-deterministic data structures in production scheduler make production behavior harder to reproduce than lab testing suggests.
5. **Maintainability risk**: 20+ AI agents with no human code review creates a knowledge gap -- no human fully understands the 310K-line codebase.
6. **Formal methods gap**: The Lean model is disconnected from the Rust implementation with no refinement link.

---

## Recommendations

### P0 (Critical)
- **Remove `test-internals` from default features.** This is the single most impactful change. Downstream consumers should not have access to `Cx::for_testing()` and `Cx::set_current()` by default.
- **Rename or document `Cx::current()` honestly.** Either remove the ambient accessor or explicitly document that the capability model has this escape hatch.

### P1 (High)
- **Audit all `unwrap()` calls outside `#[cfg(test)]` blocks.** Replace with `expect("rationale")` at minimum, or `?` propagation where possible. Target: zero `unwrap()` in non-test code.
- **Replace `std::collections::HashMap` in scheduler/runtime paths with deterministic alternatives.** If determinism is a core claim, the production runtime should use deterministic data structures too.
- **Rewrite README comparison table** to be honest about maturity. "Pre-production, actively developed" is more credible than "Feature-complete, actively hardened."

### P2 (Medium)
- **Expand ambient authority audit** (`src/audit/ambient.rs`) to cover ALL 34 global statics and 26 thread-locals, not just the 5 currently tracked.
- **Add CI gate** to prevent new `unwrap()` in non-test code without explicit `#[allow(clippy::unwrap_used)]` annotation.
- **Document the cooperative cancellation limitation** prominently. Users need to understand that `checkpoint()` must be called regularly.

### P3 (Low)
- **Clean up untracked files** in the repository (clippy.out, ubs.out, etc.)
- **Add a refinement layer** between Lean model and Rust implementation, even if manual.
- **Publish to crates.io** to back the "production-ready" positioning.

### P4 (Backlog)
- **Consider property-based tests** that verify the Lean invariants hold in Rust.
- **Conduct a human expert review** of the core scheduler and state machine code, independent of AI agents.

---

## New Ideas and Extensions

1. **Compile-time capability enforcement**: Use Rust's type system to make `Cx::current()` unavailable outside the runtime internals, rather than relying on `pub(crate)` which is bypassed by `test-internals`.
2. **Ambient authority lint**: Create a clippy lint or custom tool that flags any use of `thread_local!`, `static`, `Instant::now()`, or `thread::spawn` outside approved modules.
3. **Differential testing**: Run the same workload on both lab and production runtimes and verify they produce identical outcomes (modulo timing).
4. **Fuzzing the cancel protocol**: Use cargo-fuzz to generate arbitrary interleaving of checkpoint/cancel/mask calls and verify invariants hold.

---

## Assumptions Ledger

| Assumption | Status | Evidence |
|---|---|---|
| "No ambient authority" | **FALSIFIED** | `Cx::current()`, 34 global statics, 26 thread-locals |
| "Deterministic testing" | **PARTIALLY TRUE** | True for lab runtime only; production uses non-deterministic HashMap |
| "No orphan tasks" | **WEAKENED** | `spawn_blocking` fallback threads, remote tasks escape regions |
| "Cancel-correct" | **PARTIALLY TRUE** | Cooperative cancellation cannot preempt blocking code |
| "No obligation leaks" | **PLAUSIBLE** | Region close checks obligations; no specific counterexample found |
| "Formal verification" | **OVERSTATED** | Lean model exists but has no refinement link to Rust code |
| "Feature-complete" | **PREMATURE** | Zero production users, "early development," multiple modules "In progress" |
| "#![deny(unsafe_code)]" | **TRUE** | Confirmed; unsafe limited to reactor FFI, pool, tests |

---

## Questions for Project Owner

1. Why is `test-internals` a default feature? Is there a plan to change this before public release?
2. Has any human read and understood the full scheduler implementation (three_lane.rs at 6,790 lines)?
3. What is the plan for closing the gap between the Lean model and the Rust implementation?
4. Is there a plan to reduce the 5,000+ `unwrap()` calls in library code?
5. Has the runtime ever been tested under load by an actual application, or is all testing via the lab runtime and unit tests?
6. The comparison table positions Asupersync as production-ready. What is the actual intended audience and timeline?

---

## Points of Uncertainty

- **Obligation leak-freedom**: I did not find a specific counterexample, but also could not verify all paths. The obligation tracking in `src/runtime/state.rs` is 7,110 lines and complex.
- **Scheduler correctness**: The three-lane scheduler (6,790 lines) with EXP3, Tarjan SCC, and Lyapunov governors is too complex to fully verify in this review.
- **Waker correctness**: Channel waker dedup uses `Arc<AtomicBool>` patterns. I did not audit for lost wakeups.
- **The "65 bugs found" statistic**: Without knowing the total bug density, it's unclear whether this represents thorough auditing or surface-level scanning.

---

## Agreements and Tensions with Other Perspectives

- **Agrees with optimistic view**: The structured concurrency model is genuine and well-designed. The region tree, obligation tracking, and two-phase send are real innovations over Tokio's fire-and-forget model.
- **Agrees with optimistic view**: The self-awareness about ambient authority (having an `audit/ambient.rs` module) shows intellectual honesty within the team.
- **Disagrees with marketing**: The README's comparison table, "When to use Asupersync" section, and severity language create expectations the implementation cannot currently meet.
- **Disagrees with development model**: AI-auditing-AI is a closed loop. The 65 bugs found may reflect the capabilities of the auditing agents, not the actual bug population.
- **Tension**: The project wants to be both "no users, no backwards compatibility" (AGENTS.md) AND "feature-complete, actively hardened" (README). These are contradictory positions.

---

## Confidence: 0.78

**Calibration note**: High confidence on specific code findings (F1-F6 are directly verifiable from source). Lower confidence on architectural claims (F7, F10) where I may be missing context or design rationale that justifies the tradeoffs. The 0.78 reflects that while the falsification of "no ambient authority" is clear-cut, some findings may have legitimate justifications I haven't seen in design documents beyond README/AGENTS.md.
