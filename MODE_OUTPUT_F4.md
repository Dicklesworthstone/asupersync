# MODE F4: Failure Mode and Effects Analysis (FMEA) -- Asupersync

## Thesis

Asupersync is a 310K+ line Rust async runtime that replaces convention-based correctness with structural enforcement: regions own tasks, obligations track resources linearly, cancellation follows a protocol, and the lab runtime enables deterministic replay. The architecture addresses many classical async failure modes through invariants enforced at the type level and runtime level. However, the sheer surface area of the system -- 42 modules, multi-worker scheduling, hierarchical cancellation trees, obligation ledgers, and a deterministic test oracle -- creates emergent failure modes at subsystem boundaries. This analysis systematically enumerates what can fail, assesses severity via FMEA scoring (Severity x Occurrence x Detection = Risk Priority Number), and identifies gaps in the existing mitigation matrix.

---

## Top Findings

### F1: EXP3 Adaptive Cancel Streak Divergence Under Adversarial Workload

**Evidence:** `src/runtime/scheduler/three_lane.rs:267-384` -- The `AdaptiveCancelStreakPolicy` uses EXP3 (Exponential-weight algorithm for Exploration and Exploitation) with gamma=0.07. The reward function (`reward_against`, line 235-264) mixes four terms (Lyapunov drop, deadline penalty, fairness penalty, fallback penalty) with hard-coded weights (0.5, -0.2, -0.2, -0.1). Weight clamping at `[1e-30, 1e30]` (line 367) prevents NaN/inf, but the reward signal can degenerate under workloads where all arms produce near-identical rewards, causing entropy collapse to a single arm.

**Failure Mode:** Under sustained mixed workloads where cancel and ready pressure oscillate, the EXP3 policy may lock onto a suboptimal arm (e.g., cancel_streak_limit=4) that causes excessive fairness violations, or lock onto limit=64 that delays ready-lane dispatch. The `e_process_log` monitoring (line 369) tracks deviation but has no automatic corrective action -- it only logs.

**FMEA:** S=5 (ready-lane starvation causes latency spikes but not data loss), O=3 (requires specific adversarial pattern), D=4 (e_process_log and metrics exist but no alert threshold). **RPN = 60**

**Severity:** MEDIUM  
**Confidence:** 0.7

---

### F2: Region That Never Reaches Quiescence Due to Async Finalizer Deadlock

**Evidence:** `src/runtime/state.rs:2457-2470` -- When `advance_region_state` encounters a `Finalizing` region, it runs sync finalizers, but if an async finalizer is found, it pushes it back and `break`s (line 2470). The async finalizer must be polled to completion by the scheduler. If the async finalizer itself awaits a resource owned by a task in the same region (or a child region already closed), it will deadlock -- the region cannot complete close until the finalizer finishes, and the finalizer cannot finish because the resource it needs is gone.

**Failure Mode:** A region stuck in `Finalizing` state permanently. The parent region cannot close either (line 2535-2544 cascades parent advancement only after child close completes). This propagates upward, potentially stalling the entire region tree.

**FMEA:** S=8 (entire application can hang), O=3 (requires finalizer that depends on same-region resources), D=5 (lab runtime's `StuckBailout` detection at 1000 iterations exists but only in test mode, not production). **RPN = 120**

**Severity:** HIGH  
**Confidence:** 0.8

---

### F3: Lock Ordering Enforcement Only Active in debug_assertions

**Evidence:** `src/runtime/sharded_state.rs:737-798` -- The `lock_order` module uses `debug_assert!` (line 753) and is gated behind `#[cfg(debug_assertions)]` at call sites (lines 356-363). In release builds, the lock ordering checker is completely compiled out. If a new code path acquires locks in wrong order (e.g., Tasks before Regions), it will deadlock silently in production with no diagnostic.

**Failure Mode:** A previously undetected lock ordering violation causes deadlock in production under specific contention patterns. The `ContendedMutex` uses `std::sync::Mutex` which does not detect deadlocks.

**FMEA:** S=9 (production deadlock, total hang), O=2 (code is well-audited and ordering is documented), D=7 (no runtime detection in release builds). **RPN = 126**

**Severity:** HIGH  
**Confidence:** 0.75

---

### F4: Obligation Leak Handling Reentrance Guard Bypass on Panic Unwind

**Evidence:** `src/runtime/state.rs:1190-1291` -- The `handling_leaks` boolean guard prevents reentrant calls. When the response policy is `Panic`, the code resets `handling_leaks = false` before calling `panic_any` (lines 1246-1248). However, if `mark_obligation_leaked` (called at line 1225) itself triggers `advance_region_state` which discovers more leaks, the guard will suppress those -- they are silently lost. Additionally, if the `Recover` path's `abort_obligation` (line 1274) triggers further region state changes that discover new leaks during the same call, those are also suppressed.

**Failure Mode:** Cascading obligation leaks during recovery are silently dropped, leaving the runtime in an inconsistent state where leaked obligations are not properly accounted for. The `leak_count` counter may undercount.

**FMEA:** S=5 (silent data inconsistency in leak tracking, not data loss), O=3 (requires multi-obligation leaks in same region with Recover policy), D=6 (the `handling_leaks` guard itself is the detection mechanism, and it suppresses reporting). **RPN = 90**

**Severity:** MEDIUM  
**Confidence:** 0.8

---

### F5: Channel SendPermit Reserve-But-Never-Send (Phantom Slot Consumption)

**Evidence:** `src/channel/mpsc.rs:92-118` -- The `ChannelInner` tracks `reserved` slots separately from `queue.len()`, and `used_slots()` (line 141) counts both. A `SendPermit` that is dropped without calling `.send()` should release the reservation. If the `SendPermit::drop` impl fails to decrement `reserved` (or if it decrements but fails to wake the next sender waiter), the channel permanently loses one slot of capacity.

**Failure Mode:** Under cancellation storms where many `reserve()` futures are cancelled mid-flight, accumulated phantom reservations could reduce effective channel capacity to zero, causing all subsequent `reserve()` calls to block forever.

**FMEA:** S=7 (channel becomes permanently unusable), O=2 (two-phase design is specifically built to handle this; RAII drop on permit exists), D=3 (channel capacity monitoring would detect, and tests cover this path). **RPN = 42**

**Severity:** LOW-MEDIUM (mitigated by design)  
**Confidence:** 0.6

---

### F6: TokenSlab Generation Wraparound Causing Stale Waker Dispatch

**Evidence:** `src/runtime/reactor/token.rs:36-131` -- `SlabToken` uses a `u32` generation counter (line 47-48). On 32-bit targets, `MAX_GENERATION` is only 0xFF (255, line 121). After 256 reuses of the same slab slot, the generation wraps to 0, and a stale token from generation 0 will match the new allocation. This causes the reactor to dispatch events to the wrong task's waker.

**Failure Mode:** On 32-bit targets (including WASM32), after heavy fd churn (256+ reuses of a single slot), stale tokens match new registrations. This causes spurious wakeups to wrong tasks and potentially missed wakeups for the correct task.

**FMEA:** S=6 (wrong task woken, potential data corruption if acted on), O=3 (requires 256 reuses of same slot on 32-bit; moderate for long-running WASM apps), D=7 (no generation overflow detection or logging). **RPN = 126**

**Severity:** HIGH  
**Confidence:** 0.85

---

### F7: Tarjan SCC Deadlock Detector O(N^2) Blowup Under Large Task Graphs

**Evidence:** `src/runtime/scheduler/three_lane.rs:567-696` -- `wait_graph_signals_from_state` builds a full adjacency list (`vec![Vec::new(); tasks.len()]`) and runs Tarjan's SCC on every invocation. For a runtime with 10K+ concurrent tasks, this is O(V+E) where E can be O(V^2) in dense wait graphs. The function is called from the spectral health monitor path, which runs periodically.

**Failure Mode:** Under high task counts, the deadlock detector itself becomes a bottleneck, consuming significant CPU and holding the RuntimeState lock for the duration of the O(V+E) traversal. This can trigger the very latency spikes it is designed to detect.

**FMEA:** S=4 (performance degradation, not correctness), O=4 (any high-task-count application), D=3 (performance profiling would catch this). **RPN = 48**

**Severity:** MEDIUM  
**Confidence:** 0.8

---

### F8: Browser WASM Single-Threaded Event Loop Starvation

**Evidence:** `src/runtime/reactor/browser.rs:22-39` -- The BrowserReactor explicitly notes "Browser Event Model: Unlike native epoll/kqueue/IOCP, the browser has no blocking poll." The `max_events_per_poll` (default 64) bounds batch size, but if a single task runs a long synchronous computation between checkpoints, it monopolizes the browser event loop, freezing the UI.

**Failure Mode:** The browser poll model is cooperative. A task that performs CPU-intensive work without yielding (no `cx.checkpoint()` call) starves both the scheduler and the browser event loop. Unlike native backends, there is no preemptive time-slicing. The `browser_ready_handoff_limit` (line 80 of three_lane.rs, default 0 = disabled) would need to be enabled for mitigation.

**FMEA:** S=6 (browser tab becomes unresponsive, user-visible), O=5 (common for compute-heavy WASM tasks), D=4 (visible to user but no internal detection mechanism). **RPN = 120**

**Severity:** HIGH  
**Confidence:** 0.85

---

### F9: Multi-Agent Development Process -- Concurrent Edit Conflicts

**Evidence:** Git status shows 20+ agents (`MEMORY.md` lists NavyMill, BlackBear, EmeraldRiver, SilverCompass, AzureElk, IndigoGrove, TurquoiseDune, MistyCrane, etc.). The `.rch-*` directories in the repo root indicate multiple remote compilation helper sessions. The `handling_leaks` fix at line 1247 (`self.handling_leaks = false` before panic) was specifically documented as a bug fix -- the kind of subtle state-management issue that concurrent agents can introduce and that may not be caught by per-file auditing.

**Failure Mode:** Two agents modify the same critical path (e.g., `advance_region_state`) simultaneously, creating merge conflicts or -- worse -- clean merges that produce incorrect behavior. The beads system provides advisory locking but is explicitly noted as "heavily contended during multi-agent sessions" (`MEMORY.md`). An agent may `rch` (remote compile) overwriting uncommitted changes.

**FMEA:** S=7 (regression introduction in critical path), O=5 (20+ agents, documented contention issues), D=4 (CI and audits exist but lag behind rapid commits). **RPN = 140**

**Severity:** HIGH  
**Confidence:** 0.9

---

### F10: Lab Runtime False Positive Oracle Under Non-Deterministic Seed Interaction

**Evidence:** `src/lab/runtime.rs:112-118` -- `LabRunReport` uses `LabConfig::new(42)` with seed-driven determinism. The `trace_fingerprint` (line 133) uses Foata/Mazurkiewicz canonicalization. However, if any code path uses `std::time::Instant::now()` or system entropy instead of the lab's `DetRng`, the trace diverges between runs, and the oracle may declare a violation when the program is actually correct (false positive), or may miss a real bug because the non-deterministic interleaving was not explored (false negative).

**Failure Mode:** A new module added by an agent uses `OsEntropy` directly instead of the Cx-threaded `DetEntropy`, breaking lab determinism. The conformal oracle (`src/lab/conformal.rs`, 53KB) and e-process monitor silently produce unreliable results because their statistical guarantees assume identical execution traces across seeds.

**FMEA:** S=6 (oracle becomes unreliable, bugs slip through), O=4 (new code from any of 20+ agents may forget to use DetEntropy), D=5 (trace fingerprint comparison would detect divergence, but only if you run the same seed twice). **RPN = 120**

**Severity:** HIGH  
**Confidence:** 0.75

---

### F11: Cancel Storm Cascade Amplification

**Evidence:** `src/cancel/symbol_cancel.rs:206-252` -- `SymbolCancelToken::cancel()` propagates to all children (line 244-251) synchronously in a loop. In a deep hierarchy (e.g., region tree depth 100+ with multiple tokens per level), the recursive cancellation traversal amplifies into O(N*D) where N is total tokens and D is tree depth. Each cancellation also acquires the `children` write lock (line 245) and `listeners` write lock (line 227).

**Failure Mode:** A cancel request at the root of a deep token tree causes a cascade that holds multiple RwLock write guards simultaneously, blocking all concurrent readers. With large fan-out (e.g., broadcast channel with 1000 subscribers each having cancel tokens), the cascade can take milliseconds, during which all other tasks trying to check cancellation status are blocked.

**FMEA:** S=5 (latency spike during cancellation), O=3 (requires deep/wide cancel tree), D=4 (metrics track cancellation time but no timeout on cascade). **RPN = 60**

**Severity:** MEDIUM  
**Confidence:** 0.7

---

### F12: MaskedFinalizer Mask Depth Saturation Silently Disables Cancellation Observation

**Evidence:** `src/runtime/state.rs:172-194` -- When `mask_depth >= MAX_MASK_DEPTH`, the code logs an error but **returns without masking** (line 189). This means the finalizer runs without cancellation masking, which is the opposite of the intended behavior -- the finalizer should be shielded from cancellation so it can complete cleanup, but instead it runs unmasked and can be interrupted by cancellation.

**Failure Mode:** If `MAX_MASK_DEPTH` is exceeded (a logic error in nesting), the finalizer runs without protection. Cancellation during the finalizer can cause partial cleanup, leaking resources that the finalizer was supposed to release.

**FMEA:** S=6 (partial cleanup, resource leak), O=2 (MAX_MASK_DEPTH would need to be exhausted), D=4 (error log exists but no metric or alert). **RPN = 48**

**Severity:** MEDIUM  
**Confidence:** 0.75

---

### F13: Recently-Closed Region Tombstone Eviction Race

**Evidence:** `src/runtime/state.rs:2557-2568` -- `remember_closed_region` uses a bounded HashSet (capacity 4096) with FIFO eviction. If more than 4096 regions close before external handles check their status, the tombstone is evicted and the handle sees "never existed" instead of "closed and cleaned up." The comment at line 376-379 explicitly acknowledges this risk.

**Failure Mode:** Under sustained high region churn (e.g., per-request regions in a web server), the tombstone set fills rapidly. `AppHandle` or other external references that outlive their region will get incorrect status, potentially leading to retry loops or error-handling divergence.

**FMEA:** S=4 (incorrect status query, not data loss), O=4 (web server with per-request regions easily exceeds 4096), D=5 (no monitoring of tombstone eviction rate). **RPN = 80**

**Severity:** MEDIUM  
**Confidence:** 0.8

---

### F14: Poisoned Mutex Recovery Masks Bugs

**Evidence:** `src/runtime/scheduler/local_queue.rs:37-46` and `src/runtime/scheduler/three_lane.rs:862-863` -- Both use `unwrap_or_else(std::sync::PoisonError::into_inner)` to recover from mutex poisoning. This is documented as intentional (the runtime should not abort on a single task panic), but it means that if a panic leaves the internal data structure in an inconsistent state (e.g., half-updated task arena), the poison recovery silently continues with corrupted data.

**FMEA:** S=7 (data structure corruption leading to UB-like behavior within safe Rust), O=2 (panic during a critical section is rare; data structures are designed for crash-safety), D=6 (corrupted state may manifest as later logic errors, hard to trace back). **RPN = 84**

**Severity:** MEDIUM  
**Confidence:** 0.7

---

## Risks Identified

| ID | Risk | S | O | D | RPN | Priority |
|----|------|---|---|---|-----|----------|
| F9 | Multi-agent concurrent edit conflicts introducing regressions | 7 | 5 | 4 | 140 | P0 |
| F3 | Lock ordering enforcement absent in release builds | 9 | 2 | 7 | 126 | P0 |
| F6 | TokenSlab generation wraparound on 32-bit/WASM targets | 6 | 3 | 7 | 126 | P1 |
| F2 | Async finalizer deadlock blocks region tree indefinitely | 8 | 3 | 5 | 120 | P1 |
| F8 | Browser WASM event loop starvation from long tasks | 6 | 5 | 4 | 120 | P1 |
| F10 | Lab oracle false positive from non-deterministic entropy | 6 | 4 | 5 | 120 | P1 |
| F4 | Obligation leak handling suppresses cascading leaks | 5 | 3 | 6 | 90 | P2 |
| F14 | Poisoned mutex recovery masks data corruption | 7 | 2 | 6 | 84 | P2 |
| F13 | Tombstone eviction gives wrong region status | 4 | 4 | 5 | 80 | P2 |
| F1 | EXP3 cancel streak policy entropy collapse | 5 | 3 | 4 | 60 | P3 |
| F11 | Cancel storm cascade amplification | 5 | 3 | 4 | 60 | P3 |
| F7 | Tarjan SCC detector O(V+E) blowup | 4 | 4 | 3 | 48 | P3 |
| F12 | MaskedFinalizer depth saturation disables masking | 6 | 2 | 4 | 48 | P3 |
| F5 | Phantom slot consumption from cancelled reserves | 7 | 2 | 3 | 42 | P4 |

---

## Recommendations

### P0 -- Critical (address before production)

1. **R1 (F3): Add lightweight lock ordering validation in release builds.** Replace the `debug_assert!` in `lock_order::before_lock` with a conditional check that is always active but cheap -- e.g., a thread-local `u8` tracking the highest held lock order, checked against the next acquisition. Overhead: one thread-local read per lock acquire. File: `src/runtime/sharded_state.rs:749-761`.

2. **R2 (F9): Implement mandatory file reservation for critical-path files.** The agent-mail `file_reservation_paths` mechanism should be enforced (not advisory) for files in `src/runtime/state.rs`, `src/runtime/scheduler/three_lane.rs`, and `src/runtime/sharded_state.rs`. A pre-commit hook should reject commits to reserved files by non-holder agents.

### P1 -- High (address in next sprint)

3. **R3 (F6): Add generation overflow detection and re-registration in TokenSlab.** When generation reaches `MAX_GENERATION - 1`, either: (a) mark the slot as permanently unusable and allocate a fresh slot, or (b) log a warning and reset with a nonce. File: `src/runtime/reactor/token.rs`.

4. **R4 (F2): Add async finalizer timeout.** In `advance_region_state` (line 2460), when an async finalizer is spawned, associate a deadline. If the finalizer does not complete within the deadline, escalate to `mark_obligation_leaked` for any obligations it holds and force-close the region. File: `src/runtime/state.rs`.

5. **R5 (F8): Enable `browser_ready_handoff_limit` by default for WASM targets.** Set the default to a non-zero value (e.g., 32) when `target_arch = "wasm32"`. Document that WASM tasks must yield cooperatively. File: `src/runtime/scheduler/three_lane.rs:80`.

6. **R6 (F10): Add lint/test that all entropy sources in spawned tasks are routed through Cx.** A lab-mode test that runs the same seed twice and asserts trace fingerprint equality would catch any non-deterministic entropy leaks. File: new test in `tests/`.

### P2 -- Medium (schedule for hardening phase)

7. **R7 (F4): Replace the `handling_leaks` boolean with a stack-depth counter.** Allow recursive leak handling up to depth 2, so cascading leaks from `mark_obligation_leaked` -> `advance_region_state` -> `collect_obligation_leaks` are still processed. Cap at depth 2 to prevent infinite recursion. File: `src/runtime/state.rs:1190-1291`.

8. **R8 (F14): Log a diagnostic on mutex poison recovery.** When `PoisonError::into_inner` is used, emit a structured warning with the poisoning location. This preserves the no-abort policy while making corruption visible. File: `src/runtime/scheduler/local_queue.rs`, `three_lane.rs`.

9. **R9 (F13): Make tombstone capacity configurable.** For web servers with per-request regions, 4096 tombstones may be inadequate. Expose via `RuntimeBuilder`. Add a metric for tombstone eviction rate. File: `src/runtime/state.rs:434`.

### P3 -- Low (backlog)

10. **R10 (F1): Add EXP3 arm diversity monitor.** When normalized entropy drops below 0.2 for 10 consecutive epochs, force a uniform reset of weights. File: `src/runtime/scheduler/three_lane.rs:311-331`.

11. **R11 (F11): Implement breadth-first cancel propagation with a shared work queue.** Replace the synchronous recursive cancel cascade with an iterative BFS that bounds lock hold time per batch. File: `src/cancel/symbol_cancel.rs:206-252`.

12. **R12 (F7): Add task count guard for Tarjan SCC.** Skip the full graph analysis when task count exceeds a threshold (e.g., 5000) and use a sampling heuristic instead. File: `src/runtime/scheduler/three_lane.rs:649`.

---

## New Ideas and Extensions

1. **Probabilistic lock ordering verification in release builds.** Rather than checking every lock acquire, sample 1% of acquisitions. This gives statistical coverage with near-zero overhead.

2. **Region close progress meter.** Expose a per-region progress estimate (ratio of completed tasks to total tasks + obligations) for observability. This would make F2 (stuck finalizer) visible before the stuck-bailout timeout.

3. **Cancel cascade circuit breaker.** If a single cancel propagation touches more than N tokens (e.g., 10,000), pause and yield to the scheduler before continuing. This converts F11 from a latency spike into bounded overhead.

4. **Dual-write tombstone journal.** Instead of an in-memory bounded set, write closed region IDs to a ring buffer backed by a memory-mapped file. This survives process crashes and eliminates the 4096-entry limit.

5. **WASM cooperative yield quota.** Instrument `cx.checkpoint()` calls with a budget counter that forces a yield after N polls in WASM mode, even if the task has not explicitly yielded.

---

## Assumptions Ledger

| # | Assumption | Impact if Wrong |
|---|-----------|-----------------|
| A1 | Lock ordering tests adequately cover all production code paths | F3 is worse than assessed -- real ordering violations may exist |
| A2 | `SendPermit::drop` correctly releases the reserved slot | F5 is actually not a risk |
| A3 | The 20+ agents listed in MEMORY.md are representative of peak concurrency | F9 may be higher or lower severity |
| A4 | WASM32 is a primary deployment target | F6 and F8 may be deprioritized if WASM is demo-only |
| A5 | The lab runtime oracle is used as a primary quality gate | F10 is critical if true, low if oracle is supplementary |
| A6 | `MAX_MASK_DEPTH` is set to a reasonable value (e.g., 8+) | F12 may be effectively impossible |
| A7 | Production workloads have <1000 concurrent tasks | F7 is not a real concern at that scale |

---

## Questions for Project Owner

1. **Is WASM32 a production deployment target or demonstration-only?** This determines priority of F6 (generation wraparound) and F8 (event loop starvation).

2. **What is the expected peak concurrent task count?** This affects F7 (Tarjan blowup) and F13 (tombstone capacity).

3. **Is the lab oracle the primary quality gate, or is it supplementary to integration tests?** This determines severity of F10.

4. **Has lock ordering ever been violated in release builds?** If yes, R1 becomes P0; if no historical incidents, it may be P1.

5. **What is `MAX_MASK_DEPTH` set to?** This bounds the practical exploitability of F12.

6. **Are there plans to reduce the number of concurrent agents, or is the 20+ agent model the intended steady state?** This affects F9 severity and whether R2 is sufficient.

7. **What is the policy for async finalizers -- are they expected to be fast (sub-ms) or can they involve I/O?** This determines whether F2 requires a timeout or whether it is a user-education issue.

---

## Points of Uncertainty

- **P1:** The `handling_leaks` guard (F4) may have been intentionally designed to suppress cascading leaks. The code comment does not clarify whether suppression or recursion is the desired behavior. Confidence in this being a bug: 0.6.

- **P2:** The EXP3 policy (F1) has been audited and is noted as SOUND in the audit index. The entropy collapse scenario may be prevented by the `refresh_probs` normalization. More analysis of the gamma=0.07 parameter against theoretical regret bounds would be needed. Confidence: 0.5.

- **P3:** The `SendPermit` drop path (F5) was explicitly designed for cancel safety and has been audited. The failure mode is theoretical. Confidence it is actually exploitable: 0.3.

- **P4:** Whether the browser reactor's `max_events_per_poll=64` is sufficient to prevent event starvation versus causing batch-processing latency. Both too-low and too-high values have failure modes. Confidence in current default: 0.6.

---

## Agreements and Tensions with Other Perspectives

**Agrees with security/audit perspective:**
- The lock ordering enforcement gap (F3) is a cross-cutting concern that any security audit would flag.
- The poison recovery pattern (F14) is a known security/reliability tension in Rust async runtimes.

**Agrees with performance perspective:**
- The Tarjan SCC overhead (F7) is a classic algorithmic scaling concern.
- The cancel cascade amplification (F11) is a performance-under-load issue.

**Tension with developer experience perspective:**
- The recommendation to enforce file reservations (R2) adds process overhead that may slow down the agent swarm. The DX perspective would argue for better merge tooling instead of access control.

**Tension with "ship fast" perspective:**
- Many of these failure modes are low-occurrence (O=2-3). A pragmatic "ship and monitor" approach would defer P2 and P3 items. However, the lock ordering gap (F3) and agent conflict (F9) are process risks that compound over time.

**Complements the formal verification perspective:**
- The Lean proofs (170 theorems per MEMORY.md) cover core invariants but not emergent multi-subsystem interactions like F2 (finalizer deadlock) or F4 (leak handling reentrancy). FMEA fills the gap between what is formally proven and what can go wrong in practice.

---

## Confidence: 0.78

Calibration note: High confidence in the structural analysis of each failure mode (the code paths are verified against source). Moderate confidence in occurrence ratings, which are based on architectural reasoning rather than production telemetry. The 20+ agents and 65+ historical bugs found during audit provide strong evidence that this codebase surface area is prone to emergent interaction bugs. The FMEA scores are conservative -- several failure modes rated O=2 may be O=3-4 in practice under sustained production load.
