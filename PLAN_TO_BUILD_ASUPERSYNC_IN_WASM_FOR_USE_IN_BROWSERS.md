# PLAN_TO_BUILD_ASUPERSYNC_IN_WASM_FOR_USE_IN_BROWSERS

## Document Header

- Version: `v4`
- Status: `Execution Blueprint`
- Scope: Browser/wasm adaptation of the most useful Asupersync subset with TS/React/Next developer product
- Intent: maximize correctness, adoption, and long-term architecture quality without stalling delivery

---

## 0. Program Charter

### 0.1 Mission

Build a browser-native Asupersync runtime product that preserves core semantic guarantees while becoming easy to integrate in modern frontend stacks.

### 0.2 Program outcomes

1. `wasm32-unknown-unknown` target compiles and runs a useful Asupersync subset.
2. Cancellation and structured concurrency semantics remain first-class and test-proven.
3. First-party JS/TS API is ergonomic and production-usable.
4. React and Next.js integration is straightforward and well-documented.
5. Deterministic replay/diagnostics become a flagship capability.

### 0.3 What success looks like

A frontend team can install `@asupersync/browser`, orchestrate complex async workflows with explicit cancellation trees, and replay concurrency incidents deterministically from production traces.

---

## 1. Non-Negotiable Constraints

1. Preserve Asupersync invariants:
   - structured ownership
   - cancel protocol (`request -> drain -> finalize`)
   - obligation accounting
   - region close => quiescence
2. Keep Tokio out of core runtime semantics.
3. Maintain deterministic mode reproducibility.
4. Keep capability boundaries explicit and auditable.
5. Do not ship a wasm artifact that weakens semantics for convenience.

---

## 2. Verified Baseline and Facts

## 2.1 Documentation review completed

Read fully:

1. `AGENTS.md`
2. `README.md`

## 2.2 Build blocker evidence (verified)

Probe:

```bash
rch exec -- cargo check -p asupersync --target wasm32-unknown-unknown --no-default-features
```

Observed dependency failure chain:

```text
errno
└── signal-hook-registry
    └── signal-hook
        └── asupersync
```

Root cause:

```text
target OS "unknown" unsupported by errno
```

## 2.3 Source scale (verified)

From `src/**/*.rs`:

1. Files: `517`
2. LOC: `475,394`

Largest areas by LOC:

| Area | LOC |
|---|---:|
| runtime | 48,834 |
| lab | 37,796 |
| trace | 36,326 |
| obligation | 28,260 |
| net | 26,261 |
| http | 23,082 |
| raptorq | 18,615 |
| combinator | 17,573 |
| cli | 17,089 |
| plan | 13,337 |
| types | 12,257 |
| cx | 11,911 |
| sync | 11,636 |
| observability | 11,600 |
| transport | 10,846 |
| channel | 10,108 |

## 2.4 Native API hotspot profile (verified)

Pattern hits for native/platform-bound symbols by module:

| Area | Hit Count |
|---|---:|
| runtime | 244 |
| net | 146 |
| fs | 75 |
| sync | 41 |
| server | 39 |
| signal | 35 |
| channel | 13 |
| http | 12 |
| time | 11 |

High-risk files include:

1. `src/runtime/reactor/macos.rs`
2. `src/net/unix/stream.rs`
3. `src/fs/uring.rs`
4. `src/runtime/reactor/io_uring.rs`
5. `src/runtime/reactor/epoll.rs`

## 2.5 Manifest-level blocker set (verified)

Current direct dependencies requiring platform-specific surgery for wasm closure:

1. `signal-hook`
2. `nix`
3. `libc`
4. `socket2`
5. `polling`
6. `tempfile`
7. `tokio` direct dependency present and must be policy-reviewed for closure compliance

---

## 3. Strategic Positioning and Product Thesis

## 3.1 Strategic thesis

Do not frame this as “Rust compiled to wasm.”

Frame it as:

**A frontend concurrency reliability runtime with deterministic replay and structural cancellation guarantees.**

## 3.2 Differentiation vectors

1. Structured concurrency in UI/client workflows.
2. Explicit cancellation protocol semantics.
3. Deterministic replay and invariant-aware diagnostics.
4. Capability-secure effect boundaries.
5. Unified Rust semantics and TS ergonomics.

## 3.3 Initial market wedge

Target teams with painful async complexity:

1. realtime dashboards
2. collaborative apps
3. route-heavy Next.js applications
4. SDK/platform teams shipping browser clients

---

## 4. Architecture Option Analysis

## 4.1 Options

### Option A: Stay monolithic, gate heavily

1. keep current crate shape
2. add cfg/feature fencing
3. add browser backend in-place

### Option B: Immediate full split

1. split to `core/native/wasm/bindings` before feature work

### Option C: Hybrid staged split

1. immediate gating + seam abstraction in current crate
2. incremental extraction of stable core
3. complete split after parity is proven

## 4.2 Weighted decision matrix

Scoring: `1-5` (higher is better)

| Criterion | Weight | A | B | C |
|---|---:|---:|---:|---:|
| Time to first usable alpha | 20 | 5 | 1 | 4 |
| Long-term maintainability | 20 | 2 | 5 | 4 |
| Migration risk control | 15 | 3 | 2 | 5 |
| Invariant regression risk | 15 | 3 | 4 | 5 |
| Team parallelizability | 10 | 3 | 4 | 5 |
| Adoption feedback speed | 10 | 5 | 2 | 4 |
| Refactor overhead | 10 | 5 | 1 | 4 |

Weighted score:

1. Option A: `3.65`
2. Option B: `2.55`
3. Option C: `4.45`

### Decision

Adopt **Option C: Hybrid staged split**.

---

## 5. Target End-State Architecture

## 5.1 Rust crate topology

1. `asupersync-core`
   - semantic kernel (types, cancellation, obligations, region logic, scheduler semantics interfaces)
2. `asupersync-native`
   - native backends (threads, reactor, sockets, fs, process, signal)
3. `asupersync-wasm-core`
   - browser scheduler/timer/io backends
4. `asupersync-wasm-bindings`
   - wasm-bindgen API boundary
5. `asupersync`
   - facade crate for feature-profile composition and migration continuity

## 5.2 JS package topology

1. `@asupersync/browser-core`
2. `@asupersync/browser`
3. `@asupersync/react`
4. `@asupersync/next`

## 5.3 Layer model

### Layer 1: Semantic kernel

1. deterministic state machine behavior
2. no platform assumptions

### Layer 2: Backend adapters

1. scheduler backend
2. timer backend
3. io backend
4. trace sink backend

### Layer 3: Interop

1. wasm exports
2. TS wrappers

### Layer 4: Framework product

1. React hooks
2. Next helpers

---

## 6. Module Portability Ledger

Portability classes:

1. `G` green: low platform coupling
2. `A` amber: moderate coupling, abstraction needed
3. `R` red: strong native coupling, gate or replace

| Area | LOC | Class | v1 Action |
|---|---:|---|---|
| types | 12k | G | move/retain in core |
| cancel | 4k+ | G | core |
| obligation | 28k | G/A | core with backend seams |
| combinator | 17k | G/A | core |
| channel | 10k | G/A | core with wake abstraction |
| sync | 11k | A | refactor runtime coupling |
| cx | 12k | A | backend handle abstraction |
| time | 8k | A | backend-specific timer implementations |
| trace | 36k | G/A | core + browser sink adapters |
| lab | 38k | A | deterministic browser profile adaptation |
| runtime | 49k | A/R | split semantic scheduler vs native workers |
| net | 26k | R | gate native stack; build browser adapters |
| fs | 4k+ | R | gate out for browser v1 |
| signal | 1.8k | R | gate out for browser v1 |
| process | 1.4k | R | gate out for browser v1 |
| server | 1.8k | R | gate out for browser v1 |

---

## 7. Invariant Preservation Program

## 7.1 Invariant mapping

| Invariant | Browser implementation plan | Validation method |
|---|---|---|
| No orphan tasks | preserve region-owned task graph and closure checks | region oracle + leak oracle |
| Region close => quiescence | identical region close state machine | quiescence oracle |
| Cancel protocol | identical phase machine with JS capsule bridge | phase transition trace tests |
| Losers drained | preserve race loser-drain semantics | race drain suite |
| No obligation leaks | preserve obligation table lifecycle | obligation leak oracle |
| Determinism (mode) | virtual clock + deterministic tick scheduler | trace fingerprint parity tests |

## 7.2 Proof obligation template (mandatory per PR)

Each PR touching semantic paths must document:

1. invariants impacted
2. tests/oracles proving preservation
3. trace events proving expected transitions
4. residual risk and follow-up tasks

## 7.3 Oracle parity matrix

Run both native deterministic and wasm deterministic modes against same scenario corpus and compare:

1. terminal outcome class
2. leak counts
3. quiescence status
4. trace equivalence fingerprint

---

## 8. Browser Runtime Engine Design

## 8.1 Runtime profiles

1. `live-main-thread`
2. `live-worker`
3. `deterministic`

## 8.2 Scheduler algorithm

Per tick:

1. consume cancel-lane budget slice
2. consume timed-lane due slice
3. consume ready-lane slice
4. run finalize/drain micro-pass
5. emit telemetry snapshot as configured
6. schedule next tick if work remains

## 8.3 Wake strategy

1. microtask wake for low latency
2. macrotask fallback to avoid starvation and ensure yielding
3. explicit backpressure on repeated wake storms

## 8.4 Fairness guarantees

1. enforce bounded cancel streak
2. guarantee ready-lane service after limit
3. per-tick poll budget controls

## 8.5 Deterministic mode specifics

1. no wall clock reads
2. explicit virtual-time advancement
3. deterministic queue ordering and event tie-breakers

---

## 9. Browser I/O Capability Architecture

## 9.1 Foreign Operation Capsule model

All JS async operations are represented as capsules with explicit lifecycle:

1. `Created`
2. `Submitted`
3. `CancelRequested`
4. `Draining`
5. `Finalizing`
6. `Completed`

## 9.2 Fetch adapter

1. creation registers operation/obligation
2. cancel request maps to `AbortController`
3. completion commits or aborts obligation deterministically
4. trace lifecycle events emitted

## 9.3 WebSocket adapter

1. explicit protocol states (`connecting/open/closing/closed`)
2. send/recv operations checkpoint-aware
3. close handshake mapped to finalize semantics
4. terminal mapping to typed outcomes

## 9.4 Future extensions

1. Streams API bridges
2. WebTransport adapter
3. Service Worker channel adapter

---

## 10. Build and Dependency Surgery Plan

## 10.1 Dependency closure actions

1. move `signal-hook` behind non-wasm target cfg
2. move `nix`, `libc`, `socket2`, `polling` out of wasm closure
3. move `tempfile` out of unconditional runtime closure
4. add wasm deps:
   - `wasm-bindgen`
   - `js-sys`
   - `web-sys`
   - `wasm-bindgen-futures`
5. resolve direct `tokio` dependency policy and closure impact

## 10.2 Feature profile design

Proposed profiles:

1. `native-runtime`
2. `wasm-runtime`
3. `browser-io`
4. `deterministic-mode`
5. `browser-trace`

## 10.3 Feature compatibility enforcement

| Feature | Native | wasm |
|---|---|---|
| native-runtime | allowed | forbidden |
| wasm-runtime | optional | required |
| browser-io | no-op/forbidden | allowed |
| cli | allowed | forbidden |
| tls/sqlite/postgres/mysql/kafka | allowed | forbidden |

Implement compile-time guardrails for invalid combinations.

---

## 11. JS/TS API Product Design

## 11.1 API principles

1. explicit lifecycle
2. typed outcomes
3. explicit cancellation
4. no ambient global runtime by default

## 11.2 Runtime API sketch

```ts
export type RuntimeMode = "live" | "deterministic";

export interface RuntimeOptions {
  mode?: RuntimeMode;
  seed?: number;
  pollBudget?: number;
  worker?: "main" | "dedicated";
  trace?: { enabled: boolean; capacity?: number };
}

export interface RuntimeHandle {
  close(): Promise<void>;
  createScope(label?: string): ScopeHandle;
  createCancelToken(reason?: string): CancelTokenHandle;
  io: BrowserIo;
  channels: ChannelFactory;
  tracing: TraceApi;
}
```

## 11.3 Outcome contract

Use discriminated union:

1. `{ kind: "ok", value: T }`
2. `{ kind: "err", error: RuntimeError }`
3. `{ kind: "cancelled", cancel: CancelInfo }`
4. `{ kind: "panicked", panic: PanicInfo }`

## 11.4 Handle safety

1. opaque IDs
2. generation checks
3. invalidation on runtime close
4. explicit lifecycle errors for stale handles

---

## 12. React Integration Plan

## 12.1 Hook package

1. `useAsupersyncRuntime`
2. `useAsupersyncScope`
3. `useAsupersyncTask`
4. `useAsupersyncChannel`
5. `useAsupersyncCancellationTree`

## 12.2 Lifecycle mapping

1. component mount -> scope registration
2. component unmount -> cancellation request + structured drain
3. stale update prevention after close/cancel terminal states

## 12.3 Required sample apps

1. route transition orchestration
2. realtime websocket dashboard
3. optimistic mutation rollback
4. deterministic test harness integration

---

## 13. Next.js Integration Plan

## 13.1 Constraints

1. runtime usage in client components only
2. strict SSR boundary enforcement
3. dynamic import and chunk splitting support

## 13.2 Helper APIs

1. `createClientRuntime()`
2. `withAsupersyncClientBoundary()`
3. `createWorkerRuntime()`

## 13.3 Validation matrix

1. App Router usage
2. route transitions
3. hydration safety
4. worker mode integration

---

## 14. Deterministic Replay Program

## 14.1 Artifact schema

Trace artifact fields:

1. runtime profile metadata
2. seed and clock mode
3. event stream and ordering metadata
4. cancellation and obligation events
5. schema version + optional compression metadata

## 14.2 Replay workflows

1. browser capture -> local replay
2. CI replay of archived traces
3. regression replay pack for known bug classes

## 14.3 Operator outputs

1. failure summary
2. invariant violations
3. cause-chain explanation
4. remediation hints

---

## 15. Security and Capability Hardening

## 15.1 Threat model focus

1. stale/forged handle usage
2. runtime isolation boundary violations
3. trace tampering
4. cancellation abuse patterns

## 15.2 Controls

1. handle registry with generation checks
2. runtime capability gating at API boundary
3. signed or checksummed trace artifacts for integrity checks (optional mode)
4. strict close semantics and handle invalidation

## 15.3 Security test cases

1. stale handle invocation
2. invalid handle id fuzzing
3. cancellation storm behavior
4. malformed trace import handling

---

## 16. Performance and Size Engineering

## 16.1 Budget categories

1. initialization latency
2. per-tick scheduler overhead
3. cancellation response latency
4. memory overhead baseline
5. compressed wasm artifact sizes by package tier

## 16.2 Tiered packaging

1. `core-min`
2. `core-trace`
3. `full-dev`

## 16.3 CI gates

1. size regression checks
2. browser perf smoke tests
3. failure on budget breach beyond threshold

---

## 17. Testing and Quality Gates

## 17.1 Rust-side matrix

1. native build/test
2. wasm build/test
3. clippy across active profiles
4. deterministic parity tests between native and wasm deterministic modes

## 17.2 JS/TS-side matrix

1. unit tests
2. browser integration tests (Playwright)
3. React hook lifecycle tests
4. Next integration e2e tests

## 17.3 Invariant gate suite

1. no orphan tasks
2. no obligation leaks
3. region-close quiescence
4. loser-drain correctness
5. deterministic trace fingerprint stability

---

## 18. Program Execution Model

## 18.1 Parallel tracks

1. platform/dependency track
2. core/runtime track
3. browser backend/bindings track
4. framework integration track
5. replay/qa track

## 18.2 Ownership model

1. architecture lead
2. runtime/backend engineers
3. frontend platform engineer
4. qa/infra engineer

## 18.3 Cadence

1. weekly architecture checkpoint
2. bi-weekly milestone gate
3. invariant dashboard review each cycle

---

## 19. Phase Plan with Entry/Exit Gates

## Phase 0: Baseline and ADR lock

Entry:

1. current baseline identified

Exit:

1. wasm CI lane active
2. blocker report stable
3. ADRs approved

## Phase 1: Dependency closure repair

Exit:

1. wasm profile reaches crate compilation stage

## Phase 2: Surface gating

Exit:

1. wasm path excludes native-only surfaces cleanly

## Phase 3: Semantic seam extraction

Exit:

1. backend interfaces wired
2. native parity preserved

## Phase 4: Browser scheduler/time alpha

Exit:

1. scheduler and timer suites pass in browser harness

## Phase 5: Browser I/O alpha

Exit:

1. fetch/websocket cancel semantics verified

## Phase 6: Bindings and TS alpha

Exit:

1. strict TS integration green

## Phase 7: React/Next beta

Exit:

1. example apps and framework e2e suites green

## Phase 8: Replay beta

Exit:

1. deterministic reproduction of real trace bug demonstrated

## Phase 9: Hardening + GA

Exit:

1. all GA criteria satisfied

---

## 20. First 40 PR Rollout Playbook

### Foundation PRs

1. PR-001 wasm CI lane
2. PR-002 dependency blocker report tool
3. PR-003 dependency cfg gating pass
4. PR-004 feature compatibility compile-fail checks
5. PR-005 platform availability docs

### Surface and seam PRs

6. PR-006 `src/lib.rs` export fencing
7. PR-007 scheduler backend trait
8. PR-008 timer backend trait
9. PR-009 io backend trait
10. PR-010 trace sink backend trait
11. PR-011 runtime builder backend wiring
12. PR-012 sleep fallback refactor for wasm path
13. PR-013 deterministic tick interface
14. PR-014 backend parity test harness

### Browser runtime PRs

15. PR-015 browser scheduler initial loop
16. PR-016 microtask/macrotask wake strategy
17. PR-017 fairness and streak controls
18. PR-018 backpressure and queue caps
19. PR-019 deterministic browser mode implementation
20. PR-020 browser runtime telemetry API

### Browser I/O PRs

21. PR-021 fetch capsule
22. PR-022 fetch cancellation bridge
23. PR-023 websocket adapter
24. PR-024 websocket close/finalize mapping
25. PR-025 browser I/O trace events

### Bindings and package PRs

26. PR-026 wasm bindings runtime class
27. PR-027 task and cancellation handles
28. PR-028 channel handle bindings
29. PR-029 `@asupersync/browser-core` package
30. PR-030 `@asupersync/browser` ergonomic wrapper
31. PR-031 strict TS type tests

### Framework and replay PRs

32. PR-032 `@asupersync/react` hooks package
33. PR-033 `@asupersync/next` helpers package
34. PR-034 React demo app
35. PR-035 Next demo app
36. PR-036 trace export/import API
37. PR-037 replay harness CLI/web tool
38. PR-038 replay oracle report integration
39. PR-039 performance/size CI gates
40. PR-040 GA release automation

---

## 21. Timeline (Aggressive 12-Week Program)

1. Week 1: baseline and ADR lock
2. Weeks 2-3: dependency and surface gating
3. Weeks 4-6: core seam extraction + browser scheduler/time
4. Weeks 7-8: browser I/O + bindings
5. Weeks 9-10: React/Next productization
6. Weeks 11-12: replay hardening + GA candidate

---

## 22. Risk Register

| Risk | Trigger | Impact | Mitigation |
|---|---|---|---|
| dependency regression | unguarded native dep added | wasm build breaks | dependency CI gate |
| semantic drift | backend divergence | invariant regressions | parity matrix + oracle gates |
| UI jank | oversized tick work | poor UX | budget/yield/worker mode |
| weak binding semantics | lifecycle leaks | correctness issues | capsule model + handle safety |
| size creep | feature accretion | adoption friction | package tiers + size gates |
| security issues | stale/forged handle usage | runtime misuse | generation checks + fuzz tests |

---

## 23. Immediate Next 10 Working Days

### Day 1

1. lock ADRs and program owners

### Days 2-3

1. wasm CI lane and blocker artifact
2. dependency cfg gating initial pass

### Days 4-5

1. feature compatibility checks
2. `src/lib.rs` platform fencing

### Days 6-7

1. scheduler/timer backend interfaces
2. sleep fallback path refactor kickoff

### Days 8-9

1. browser scheduler alpha
2. deterministic mode tick driver alpha

### Day 10

1. minimal wasm runtime binding and smoke demo

---

## 24. GA Definition of Done

1. wasm and native pipelines both green
2. invariant parity suite green
3. TS/React/Next integration suites green
4. deterministic replay workflow proven
5. size/perf/security gates green
6. release automation for Rust and npm artifacts operational

---

## 25. Post-v1 Innovation Roadmap

1. WebTransport backend
2. Service Worker orchestration profile
3. cross-tab region coordination
4. durable trace/obligation snapshots in IndexedDB
5. browser devtools panel with runtime graph and cancel-chain visualizer
6. differential replay between app versions for regression triage

---

## 26. Strategic Why

This plan intentionally pairs deep semantic rigor with aggressive productization.

- Rigor without adoption yields an elegant but unused runtime.
- Adoption without rigor yields a popular but fragile abstraction.

The objective is both: **correctness you can trust** and **developer experience teams will actually adopt**.

