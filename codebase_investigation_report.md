# Asupersync Codebase Investigation Report

## 1. Project Overview
**Asupersync** is a spec-first, cancel-correct, capability-secure async runtime for Rust. It prioritizes structural correctness over convention, ensuring no orphan tasks, bounded cleanup during cancellation, and no resource leaks via obligation tracking.

**Current Phase:** Phase 0 (Single-threaded deterministic kernel) is complete. Phase 1 (Multi-threaded scheduler) is in progress.

## 2. Core Primitives & Architecture

### 2.1 Capability Context (`Cx`)
- **Location:** `src/cx/cx.rs`
- **Purpose:** A token passed to every async operation. It grants access to capabilities (Time, IO, Spawn, Trace) and prevents ambient authority.
- **Key Features:**
  - `checkpoint()`: Explicitly checks for cancellation (cooperative).
  - `trace()`: Emits events for deterministic replay.
  - Carries `RegionId` and `TaskId` for identity.

### 2.2 Structured Concurrency (`Scope` & Regions)
- **Location:** `src/cx/scope.rs`, `src/record/region.rs`
- **Purpose:** Ensures every task belongs to a region. A region cannot close until all children (tasks and sub-regions) are complete.
- **Lifecycle:** `Open` → `Closing` → `Draining` → `Finalizing` → `Closed`.
- **Tiers:**
  - **Fiber Tier (Phase 0):** `spawn_local` (borrow-friendly, pinned to thread).
  - **Task Tier (Phase 1):** `spawn` (Send bounds, migratable).

### 2.3 Runtime State (Σ)
- **Location:** `src/runtime/state.rs`
- **Purpose:** The "God Object" holding the global system state.
- **Components:**
  - `regions`: Arena of `RegionRecord`.
  - `tasks`: Arena of `TaskRecord`.
  - `obligations`: Arena of `ObligationRecord`.
  - `stored_futures`: Map of `TaskId` → `StoredTask` (the actual futures).
  - `io_driver` / `timer_driver`: Interfaces to the reactor.

### 2.4 Obligations
- **Location:** `src/obligation/mod.rs`, `src/runtime/state.rs`
- **Purpose:** Linear tracking of resources (locks, permits) to prevent leaks.
- **Mechanism:**
  - `create_obligation`: Registers a resource.
  - `commit_obligation`: Marks successful use.
  - `abort_obligation`: Marks cleanup on cancellation.
  - **Leak Detection:** Runtime checks on task completion; static analysis tools available.

## 3. Scheduling & Execution

### 3.1 Phase 0 Execution (Single-Threaded)
- **Entry Point:** `Runtime::block_on` (`src/runtime/builder.rs`).
- **Mechanism:**
  - Uses `run_future_with_budget` to poll the main future on the current thread.
  - **Cooperative Loop:** Polls → Checks Budget → Yields (`thread::yield_now`) → Parks if pending.
  - Does *not* use the complex scheduler for the main blocking task, but spawned tasks are stored in `RuntimeState` and polled.

### 3.2 Phase 1 Execution (Multi-Threaded)
- **Scheduler:** `WorkStealingScheduler` wrapping `ThreeLaneScheduler` (`src/runtime/scheduler/`).
- **Lanes:**
  1. **Cancel Lane:** High priority (cleanup/shutdown).
  2. **Timed Lane:** Earliest Deadline First (EDF).
  3. **Ready Lane:** Standard FIFO/LIFO work.
- **Status:**
  - `RuntimeInner` initializes `ThreeLaneScheduler`.
  - Worker threads are spawned if `worker_threads > 0`.
  - Integration is visible in `RuntimeInner::new` but `block_on` remains simple.

## 4. Key Invariants & Safety

- **Quiescence:** `RuntimeState::is_quiescent` ensures no live tasks, pending obligations, or registered I/O before shutdown.
- **Cancel-Correctness:** Cancellation is a protocol (Request → Drain → Finalize). Tasks must explicitly `checkpoint()` or handle cancellation signals.
- **Determinism:** The "Lab Runtime" (`src/lab/`) wraps the core state to provide seed-based deterministic execution for testing.

## 5. Next Steps for Phase 1
- **Scheduler Integration:** Fully migrate `block_on` to use the `ThreeLaneScheduler` for all tasks, or clearly separate the "main thread" role from workers.
- **Blocking Pool:** `src/runtime/blocking_pool.rs` is implemented but needs robust integration for Phase 1 I/O.
- **Migration:** Ensure `spawn` (Task Tier) correctly pushes to the global injection queue or local worker queues.
