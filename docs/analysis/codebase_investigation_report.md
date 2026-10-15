# Codebase Investigation Report: Asupersync

## 1. Project Overview
**Asupersync** is a spec-first, capability-secure async runtime for Rust, prioritizing correctness, structured concurrency, and deterministic testing. It distinguishes itself by enforcing "no orphan tasks" and "cancel-correctness" through a strict region-based ownership model and a multi-phase cancellation protocol.

## 2. Architecture & Key Concepts
*   **Structured Concurrency**: Work is organized into a tree of **Regions**. Every task belongs to a region. A region cannot close until all children (tasks/sub-regions) are complete (quiescence).
*   **Cancellation**: Implemented as a protocol (`Request` -> `Drain` -> `Finalize` -> `Complete`) rather than a silent drop. This ensures resources are cleaned up and no data is lost.
*   **Cx (Capability Context)**: A context object passed to all tasks, providing capabilities (spawning, time, tracing) without ambient authority.
*   **Obligations**: Linear resources (Permits, Acks, Leases) that must be explicitly resolved (committed/aborted) before a region can close, preventing leaks.
*   **Phases**:
    *   **Phase 0**: Single-threaded deterministic kernel (Marked as complete).
    *   **Phase 1**: Parallel scheduler + region heap (In progress).

## 3. Implementation Status & Findings

### Phase 0 vs Phase 1
*   **Phase 0 (Single-threaded)**: The core runtime structure (`RuntimeState`, `TaskRecord`, `RegionRecord`) is in place.
*   **Phase 1 (Parallel Scheduler)**: I found substantial implementation in `src/runtime/scheduler/three_lane.rs`, `global_injector.rs`, and `stealing.rs`. This indicates Phase 1 is well underway, implementing a "Multi-worker 3-lane scheduler with work stealing."

### Key Discrepancy: Missing Nested Regions
The `README.md` and `asupersync_v4_api_skeleton.rs` describe a `Scope::region` method for creating nested regions (Tier 3):

```rust
// From README example
scope.region(|sub| async { ... }).await;
```

However, my analysis of **`src/cx/scope.rs`** confirms this method is **missing**. The `Scope` struct implements `spawn`, `spawn_task`, `spawn_local`, and combinators like `join`/`race`, but lacks the API to create child regions. This is a significant gap in the "Structured Concurrency" promise for the current implementation.

### Testing Infrastructure
*   **Lab Runtime**: Located in `src/lab`, providing deterministic testing capabilities (`seed`, `virtual_time`).
*   **Environment Issue**: Attempting to run `cargo test` failed with **Signal 1 (SIGHUP)**. This matches your memory that the environment kills long-running shell commands. I must rely on static analysis and file operations, as running the test suite is currently not possible.

## 4. Next Steps Recommendation
Since I cannot run tests to verify behavior, I recommend we focus on:
1.  **Implementing the missing `Scope::region` method** in `src/cx/scope.rs` to fulfill the structured concurrency promise.
2.  **Connecting the Phase 1 Scheduler** if it's not yet fully integrated.
3.  **Using `ubs` (Ultimate Bug Scanner)** or manual analysis for verification, given the `cargo test` instability.