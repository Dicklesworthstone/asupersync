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

### 1.1 ADR Governance Contract (WASM Program)

This program is governed by a formal ADR series. Any browser-facing semantic decision that can affect invariants, determinism, cancellation behavior, capability boundaries, or interoperability must land through this process.

Compatibility stance:

1. Browser adaptation is correctness-first, not compatibility-first.
2. Backwards compatibility is not guaranteed during this phase; semantic correctness is mandatory.
3. Any compatibility concession is allowed only when invariant-preserving and explicitly documented in an ADR with expiration criteria.

### 1.2 ADR Index (program baseline)

| ADR ID | Title | Status | Primary Owner | Scope |
|---|---|---|---|---|
| `WASM-ADR-001` | Browser Semantic Contract Boundary | accepted | runtime-core | Defines what semantic behavior must remain identical to native mode |
| `WASM-ADR-002` | Platform Seam Taxonomy | accepted | runtime-core | Defines scheduler/time/io/authority seam model and responsibilities |
| `WASM-ADR-003` | Runtime Profile Model (`live-main-thread`, `live-worker`, `deterministic`) | accepted | runtime-core | Defines supported execution profiles and constraints |
| `WASM-ADR-004` | Capability Authority Envelope for Browser APIs | proposed | security/runtime | Defines explicit authority boundaries for fetch/storage/worker APIs |
| `WASM-ADR-005` | Deterministic Replay Artifact Contract for Browser Mode | proposed | trace/lab | Defines browser trace/replay schema guarantees |
| `WASM-ADR-006` | Deferred Native Surface Register Policy | accepted | architecture | Defines gate/defer criteria for native-only modules |
| `WASM-ADR-007` | Versioned WASM ABI and Break Policy | proposed | bindings/api | Defines ABI stability, versioning, and break handling rules |
| `WASM-ADR-008` | CI Gating and Evidence Promotion Rules | proposed | qa/ci | Defines evidence required for merge/release gates |

### 1.3 Explicitly Rejected Alternatives

These alternatives are intentionally rejected and must not be reintroduced without a superseding ADR:

1. Silent semantic weakening for browser convenience (for example: best-effort cancellation that can leak obligations).
2. Ambient authority wrappers around browser globals (`window`, `fetch`, timers) without explicit capability paths.
3. "Compile-only parity" acceptance criteria that skip deterministic replay/evidence requirements.
4. Ad-hoc per-feature policy exceptions without decision records and expiry.

### 1.4 ADR Decision Template (required for each browser-semantic decision)

```markdown
# WASM-ADR-XXX: <Title>

- Status: proposed | accepted | superseded | deprecated
- Date: YYYY-MM-DD
- Owners: <team/people>
- Related beads: <ids>
- Supersedes: <optional ADR IDs>

## Context
- What exact semantic/runtime problem is being solved?
- Which invariants are at risk if this is done incorrectly?
- Which alternatives were considered and why rejected?

## Decision
- Concrete decision statement (normative language: MUST/SHOULD/MAY).
- Exact surfaces affected (modules, feature flags, API boundaries).

## Allowed Tradeoffs
- Tradeoffs accepted for this decision (explicit, bounded, testable).

## Forbidden Compromises
- Explicitly disallowed shortcuts that would violate invariants.

## Invariant Impact Checklist
- [ ] Structured ownership preserved
- [ ] Cancel protocol preserved (`request -> drain -> finalize`)
- [ ] Loser-drain preserved
- [ ] No obligation leaks introduced
- [ ] Region-close quiescence preserved
- [ ] Deterministic profile reproducibility preserved
- [ ] Capability boundaries remain explicit

## Required Evidence
- Unit evidence:
- Conformance/e2e evidence:
- Replay/trace evidence:
- CI gate evidence:

## Rollout + Rollback
- Rollout plan:
- Rollback trigger conditions:
- Rollback execution path:

## Compatibility Statement
- Explicitly state compatibility impact and migration obligations.
```

### 1.5 Review Protocol and Sign-Off

Any ADR marked `accepted` requires:

1. One runtime-core approver.
2. One invariants/testing approver.
3. One integration/security approver when capability or boundary surfaces are touched.

Required review checklist:

1. Decision is scoped to named surfaces and is testable.
2. Rejected alternatives are explicit and technically justified.
3. Invariant impact checklist is complete with linked evidence.
4. CI/replay artifacts are reproducible with pinned commands.
5. Failure/rollback criteria are concrete and operational.

Promotion gates:

1. `proposed` -> `accepted`: requires evidence links + sign-off checklist complete.
2. `accepted` -> implemented rollout: requires bead links and CI pass on required lanes.
3. superseding/deprecating an ADR: must reference old/new IDs and migration obligations.

### 1.6 Cadence and Audit Rules

1. ADR index is reviewed weekly during browser program triage.
2. Every merged PR that changes browser semantic behavior must link an ADR ID.
3. Any semantic drift discovered in replay/conformance must file:
   - a corrective bead,
   - an ADR amendment (or superseding ADR),
   - and a root-cause note in the affected ADR.

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

### 6.1 Census Method (Deterministic, Reproducible)

The module census below is generated from crate surfaces declared in `src/lib.rs` and measured against live source using stable `rg` queries.

```bash
rg --no-filename '^pub mod [a-z_]+' src/lib.rs
rg -n "crate::<module>(::|;)" src -g '*.rs'              # fan-in
rg -o "crate::[a-z_]+" src/<module>{.rs,/} -g '*.rs'     # fan-out
rg -n "std::os::|libc|nix::|socket2|polling::|io_uring|kqueue|epoll|std::fs|std::net|signal" \
  src/<module>{.rs,/} -g '*.rs'                           # implicit OS assumptions
```

Snapshot timestamp: `2026-02-28`.

### 6.2 Public Module-by-Module Census (src/lib.rs surface)

Disposition semantics:

1. `required`: in browser-v1 semantic subset (or required to keep deterministic correctness workflow intact).
2. `optional`: not required for browser-v1 core path, but portable enough for later browser expansion.
3. `out-of-scope`: native-first surface gated out for browser-v1.

| Module | Surface Kind | Browser v1 Disposition | Fan-in | Fan-out | Native Hits | Implicit OS Assumptions |
|---|---|---|---:|---:|---:|---|
| actor | public module | optional | 4 | 12 | 1 | light native OS coupling |
| app | public module | optional | 14 | 10 | 0 | no explicit OS primitive coupling |
| audit | public module | optional | 0 | 0 | 9 | light native OS coupling |
| bytes | public module | required | 39 | 28 | 0 | no explicit OS primitive coupling |
| cancel | public module | required | 0 | 6 | 0 | no explicit OS primitive coupling |
| channel | public module | required | 66 | 59 | 19 | light native OS coupling |
| cli | public module | out-of-scope | 0 | 33 | 112 | strong native OS coupling |
| codec | public module | optional | 24 | 21 | 0 | no explicit OS primitive coupling |
| combinator | public module | required | 45 | 30 | 0 | no explicit OS primitive coupling |
| config | public module | optional | 12 | 3 | 2 | light native OS coupling |
| conformance | public module | optional | 2 | 4 | 0 | no explicit OS primitive coupling |
| console | public module | optional | 9 | 5 | 0 | no explicit OS primitive coupling |
| cx | public module | required | 300 | 33 | 5 | light native OS coupling |
| database | public module | out-of-scope | 0 | 14 | 5 | light native OS coupling |
| decoding | public module | optional | 3 | 10 | 0 | no explicit OS primitive coupling |
| distributed | public module | optional | 9 | 36 | 0 | no explicit OS primitive coupling |
| encoding | public module | optional | 5 | 4 | 0 | no explicit OS primitive coupling |
| epoch | public module | optional | 0 | 11 | 0 | no explicit OS primitive coupling |
| error | public module | required | 109 | 2 | 0 | no explicit OS primitive coupling |
| evidence | public module | optional | 12 | 5 | 8 | light native OS coupling |
| evidence_sink | public module | optional | 15 | 2 | 0 | no explicit OS primitive coupling |
| fs | public module | out-of-scope | 33 | 58 | 141 | strong native OS coupling |
| gen_server | public module | optional | 5 | 15 | 1 | light native OS coupling |
| grpc | public module | out-of-scope | 4 | 48 | 2 | light native OS coupling |
| http | public module | out-of-scope | 31 | 52 | 52 | moderate native OS coupling |
| io | public module | out-of-scope | 49 | 49 | 2 | light native OS coupling |
| lab | public module | optional | 122 | 186 | 9 | light native OS coupling |
| link | public module | optional | 2 | 2 | 73 | moderate native OS coupling |
| messaging | public module | out-of-scope | 1 | 16 | 2 | light native OS coupling |
| migration | public module | optional | 0 | 2 | 0 | no explicit OS primitive coupling |
| monitor | public module | optional | 23 | 2 | 0 | no explicit OS primitive coupling |
| net | public module | out-of-scope | 45 | 121 | 161 | strong native OS coupling |
| obligation | public module | required | 49 | 89 | 10 | light native OS coupling |
| observability | public module | required | 29 | 36 | 22 | moderate native OS coupling |
| plan | public module | required | 19 | 20 | 0 | no explicit OS primitive coupling |
| process | public module | out-of-scope | 0 | 7 | 29 | moderate native OS coupling |
| raptorq | public module | optional | 48 | 33 | 2 | light native OS coupling |
| record | public module | required | 177 | 34 | 0 | no explicit OS primitive coupling |
| remote | public module | optional | 20 | 6 | 0 | no explicit OS primitive coupling |
| runtime | public module | required | 253 | 223 | 406 | strong native OS coupling |
| security | public module | optional | 64 | 7 | 0 | no explicit OS primitive coupling |
| server | public module | out-of-scope | 4 | 18 | 198 | strong native OS coupling |
| service | public module | optional | 4 | 32 | 2 | light native OS coupling |
| session | public module | optional | 0 | 7 | 0 | no explicit OS primitive coupling |
| signal | public module | out-of-scope | 3 | 24 | 167 | strong native OS coupling |
| spork | public module | optional | 1 | 13 | 1 | light native OS coupling |
| stream | public module | required | 40 | 120 | 0 | no explicit OS primitive coupling |
| supervision | public module | optional | 32 | 10 | 0 | no explicit OS primitive coupling |
| sync | public module | required | 32 | 45 | 16 | light native OS coupling |
| test_logging | public module | optional | 6 | 6 | 17 | light native OS coupling |
| test_ndjson | public module | optional | 1 | 4 | 6 | light native OS coupling |
| test_utils | public module | optional | 265 | 7 | 0 | no explicit OS primitive coupling |
| time | public module | required | 85 | 52 | 0 | no explicit OS primitive coupling |
| tls | public module | out-of-scope | 14 | 18 | 2 | light native OS coupling |
| trace | public module | required | 142 | 80 | 28 | moderate native OS coupling |
| tracing_compat | public module | optional | 67 | 5 | 0 | no explicit OS primitive coupling |
| transport | public module | optional | 32 | 46 | 7 | light native OS coupling |
| types | public module | required | 666 | 27 | 2 | light native OS coupling |
| util | public module | required | 149 | 2 | 0 | no explicit OS primitive coupling |
| web | public module | optional | 38 | 13 | 2 | light native OS coupling |

### 6.3 Internal Runtime Surface Census (non-lib.rs seams)

| Internal Surface | Browser v1 Disposition | Fan-in/Fan-out Role | Implicit OS Assumptions |
|---|---|---|---|
| `runtime/scheduler/three_lane.rs` | required (semantic core), with backend seam extraction | very high fan-in scheduler hub | currently assumes multi-worker parking/unparking and native thread model |
| `runtime/sharded_state.rs` | required | high fan-in state-mutation hub | lock-strategy assumptions; no hard OS syscall coupling required |
| `runtime/region_heap.rs` | required | medium fan-in allocator/state substrate | no direct syscall assumptions; deterministic handle semantics portable |
| `runtime/reactor/*` | out-of-scope for browser-v1 native path | high fan-out to IO stack | explicit epoll/kqueue/io_uring/FD token assumptions |
| `runtime/io_driver.rs` | out-of-scope for browser-v1 native path | hub between scheduler and reactor | evented FD readiness and OS reactor wake assumptions |
| `runtime/blocking_pool.rs` | out-of-scope for browser-v1 | medium fan-in for sync bridge | native thread creation/parking assumptions |
| `runtime/local.rs` | required (adapted) | low fan-in local-task pinning layer | currently thread-local storage assumptions; must map to browser worker identity model |
| `runtime/deadline_monitor.rs` | optional for v1 live profile, required for deterministic diagnostics profile | medium fan-in observability path | wall-clock fallback assumptions need browser monotonic timer substitution |

### 6.4 Workspace Crate Census

| Workspace Crate | Surface Kind | Browser v1 Disposition | Dependency Fan-in/Fan-out | Implicit OS Assumptions |
|---|---|---|---|---|
| `asupersync` | primary runtime library surface | required | fan-in: highest; fan-out: depends on macros + FrankenSuite crates (+ feature-gated tooling) | mixed; strong native assumptions concentrated in gated modules |
| `asupersync-macros` | proc-macro compile-time surface | optional (ergonomics) | fan-in: consumed by `asupersync` when `proc-macros` enabled | none (compile-time syntax transformation only) |
| `asupersync-conformance` | test/conformance surface | optional for shipping runtime; required for CI quality gates | fan-in: validation-only; fan-out: serde/tempfile | light filesystem assumptions via test tooling |
| `franken-kernel` | shared type substrate | required (transitively used by runtime decision/evidence surfaces) | fan-in: `asupersync`, `franken-decision` | no OS coupling |
| `franken-evidence` | evidence ledger schema | required for evidence pipeline | fan-in: `asupersync`, `franken-decision` | no OS coupling |
| `franken-decision` | decision-contract runtime | required for scheduler decision-contract path | fan-in: `asupersync` | no OS coupling |
| `frankenlab` | deterministic harness CLI/package | optional for browser runtime artifact; required for replay/forensics workflows | fan-in: operator/testing workflows, depends on `asupersync` | mostly tooling assumptions (CLI/file outputs), not runtime-core OS dependency |

### 6.5 Browser-v1 Subset Summary (from census)

Required semantic set:

1. `types`, `error`, `cancel`, `obligation`, `record`
2. `cx`, `runtime` (semantic slice only), `time`
3. `channel`, `combinator`, `sync`, `stream`
4. `trace`, `plan`, `observability`, `util`, `bytes`

Out-of-scope native set (gated in browser-v1):

1. `net`, `fs`, `process`, `signal`, `server`
2. `io` (native reactor path), `http`, `grpc`, `tls`
3. `database`, `messaging`, `cli`

Critical implicit OS assumptions requiring explicit seam replacement before browser execution:

1. Reactor/event-loop assumptions (`epoll`, `kqueue`, `io_uring`, tokenized FD readiness).
2. Threading and parking assumptions (`Parker`, worker unparks, TLS task pinning).
3. Filesystem/process/signal assumptions in runtime-adjacent tooling and native integrations.

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

Canonical browser build profiles (normative):

| Profile ID | Profile name | Intended use | Required features | Allowed optional features | Forbidden features/surfaces | Promotion gate |
|---|---|---|---|---|---|---|
| `FP-BR-DEV` | `wasm-browser-dev` | local dev, fast iteration, diagnostics | `wasm-runtime`, `browser-io` | `browser-trace`, `tracing-integration`, `test-internals` | `native-runtime`, `cli`, `tls`, `sqlite`, `postgres`, `mysql`, `kafka`, any tokio-backed surface | must compile on `wasm32-unknown-unknown` and pass browser smoke suite |
| `FP-BR-PROD` | `wasm-browser-prod` | production browser package | `wasm-runtime`, `browser-io` | `browser-trace` (bounded), `trace-compression` | `test-internals`, `native-runtime`, `cli`, database/network-native stacks, any tokio-backed surface | size/perf/security gates + invariant parity suite green |
| `FP-BR-DET` | `wasm-browser-deterministic` | replay, incident forensics, CI deterministic checks | `wasm-runtime`, `deterministic-mode`, `browser-trace` | `trace-compression` | `native-runtime`, ambient-time shortcuts, non-deterministic entropy/time sources without capture hooks | deterministic replay matrix green for pinned traces |
| `FP-BR-MIN` | `wasm-browser-minimal` | minimal embed footprint | `wasm-runtime` | none by default | `browser-io`, `browser-trace`, all non-essential integrations | compiles clean and passes core scheduler/cancel invariants |

Profile normalization rules:

1. Browser targets MUST select exactly one `FP-BR-*` canonical profile.
2. `FP-BR-PROD` is the default release profile; all others are explicit opt-in.
3. Any new browser feature must declare:
   - which `FP-BR-*` profiles permit it,
   - expected size/perf impact,
   - deterministic-mode impact (`FP-BR-DET`).
4. Any profile deviation requires ADR reference and expiration criteria.

## 10.3 Feature compatibility enforcement

| Feature/surface | Native target | wasm browser target | Enforcement mode |
|---|---|---|---|
| `native-runtime` | allowed | forbidden | compile-time `cfg` + compile-fail tests |
| `wasm-runtime` | optional | required | profile validator + CI gate |
| `browser-io` | no-op/forbidden | allowed in `FP-BR-DEV/PROD` | feature-compat matrix tests |
| `deterministic-mode` | allowed | required for `FP-BR-DET` | deterministic lane gate |
| `browser-trace` | optional | required for `FP-BR-DET`; optional bounded for PROD | artifact schema + replay gates |
| `cli` | allowed | forbidden | target-gated manifest + compile-fail tests |
| `tls/sqlite/postgres/mysql/kafka` | allowed by profile | forbidden for browser profiles | manifest policy checks |
| tokio-backed surface | forbidden in core semantics | forbidden | dependency closure audit + deny-list |

Enforcement implementation requirements:

1. Add profile validation checks that fail build on illegal feature combinations.
2. Keep a committed compatibility matrix artifact and diff it in CI.
3. Require per-profile reproducible commands in gate docs (all heavy checks run via `rch exec -- ...`).

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

## 17.4 Verification taxonomy (WASM-17 test fabric baseline)

Test layers:

1. `L0-unit`: deterministic unit tests for one semantic unit (single module/state machine)
2. `L1-integration`: cross-module runtime flow tests (scheduler + cancel + obligation + adapters)
3. `L2-e2e`: browser user-path tests (vanilla, React, Next) with artifact capture
4. `L3-replay`: deterministic replay assertions from captured traces and seeded scenario fixtures

Risk tiers:

1. `R0-critical`: cancellation, quiescence, obligation closure, authority boundaries
2. `R1-high`: scheduler fairness, timer semantics, io capsule lifecycle, trace integrity
3. `R2-medium`: framework binding correctness, packaging boundaries, docs-linked UX flows

Rule: every retained browser feature/invariant must map to at least one `L0-unit` test and one higher-level test (`L1/L2/L3`).

## 17.5 Feature and invariant traceability matrix

| Trace ID | Retained feature/invariant | Risk | Implementation loci (authoritative surfaces) | Required L0 unit coverage | Required higher-level coverage | Required evidence artifacts | Deterministic replay required | Owner |
|---|---|---|---|---|---|---|---|---|
| `WVT-001` | Structured task ownership (no orphan tasks) | R0-critical | `src/runtime/state.rs`, `src/runtime/region_table.rs`, `src/cx/scope.rs` | region tree ownership + close checks | L1 region close integration; L2 unmount-driven scope teardown | `EV-WVT-001-L0`, `EV-WVT-001-L1`, `RP-REGION-001` | yes (`RP-REGION-001`) | Runtime backend owner |
| `WVT-002` | Region close implies quiescence | R0-critical | `src/runtime/state.rs`, `src/record/region.rs`, `src/lab/runtime.rs` | region final-state machine tests | L1 quiescence oracle parity native vs wasm | `EV-WVT-002-L0`, `EV-WVT-002-L1`, `RP-QUIESCE-001` | yes (`RP-QUIESCE-001`) | Runtime backend owner |
| `WVT-003` | Cancel protocol `request -> drain -> finalize` | R0-critical | `src/cancel/*`, `src/runtime/state.rs`, `src/types/cancel.rs` | cancel phase transition tables | L1 cancel-drain integration under deadlines; L2 route-transition cancel flow | `EV-WVT-003-L0`, `EV-WVT-003-L1`, `RP-CANCEL-001`, `RP-CANCEL-002` | yes (`RP-CANCEL-001`, `RP-CANCEL-002`) | Cancellation + runtime owner |
| `WVT-004` | Loser drain after race | R0-critical | `src/combinator/race.rs`, `src/combinator/select.rs`, `src/cancel/*` | race combinator loser-drain unit suite | L1 concurrent race integration with obligation accounting | `EV-WVT-004-L0`, `EV-WVT-004-L1`, `RP-RACE-001` | yes (`RP-RACE-001`) | Combinator owner |
| `WVT-005` | No obligation leaks (permit/ack/lease) | R0-critical | `src/obligation/*`, `src/runtime/obligation_table.rs`, `src/runtime/state.rs` | obligation table lifecycle tests | L1 leak oracle across fetch/websocket capsules | `EV-WVT-005-L0`, `EV-WVT-005-L1`, `RP-OBL-001` | yes (`RP-OBL-001`) | Obligation owner |
| `WVT-006` | Deterministic mode parity | R0-critical | `src/lab/runtime.rs`, `src/time/*`, `src/trace/canonicalize.rs` | virtual clock + tie-break ordering tests | L1 seed parity native/wasm; L3 fingerprint equivalence | `EV-WVT-006-L0`, `EV-WVT-006-L1`, `RP-DET-001` | yes (`RP-DET-001`) | Determinism owner |
| `WVT-007` | Browser scheduler fairness and cancel streak bounds | R1-high | `src/runtime/scheduler/three_lane.rs`, `src/runtime/scheduler/priority.rs` | lane budget and streak limit tests | L1 scheduler stress integration; L2 UI latency smoke | `EV-WVT-007-L0`, `EV-WVT-007-L1`, `RP-SCHED-001` | yes (`RP-SCHED-001`) | Runtime backend owner |
| `WVT-008` | Browser timer semantics and deadlines | R1-high | `src/time/driver.rs`, `src/time/wheel.rs`, `src/runtime/timer.rs` | timer wheel/tick conversion tests | L1 timeout propagation integration in wasm profile | `EV-WVT-008-L0`, `EV-WVT-008-L1`, `RP-TIME-001` | yes (`RP-TIME-001`) | Time subsystem owner |
| `WVT-009` | Fetch capsule authority + cancellation bridge | R0-critical | `src/cx/cx.rs`, `src/io/*`, browser adapter seam layer | capability check + lifecycle transition tests | L1 fetch abort integration; L2 framework data-load cancel path | `EV-WVT-009-L0`, `EV-WVT-009-L1`, `RP-FETCH-001` | yes (`RP-FETCH-001`) | Browser IO owner |
| `WVT-010` | WebSocket capsule close/finalize mapping | R1-high | `src/net/websocket/*`, `src/cancel/*`, browser adapter seam layer | websocket state transition tests | L1 socket close/drain integration | `EV-WVT-010-L0`, `EV-WVT-010-L1`, `RP-WS-001` | yes (`RP-WS-001`) | Browser IO owner |
| `WVT-011` | wasm handle generation safety (stale handle rejection) | R0-critical | `src/runtime/region_heap.rs`, bindings handle registry layer | handle registry and generation mismatch tests | L2 browser API misuse scenarios | `EV-WVT-011-L0`, `EV-WVT-011-L2`, `RP-HANDLE-001` | yes (`RP-HANDLE-001`) | Bindings owner |
| `WVT-012` | Trace schema integrity and replay import/export | R1-high | `src/trace/*`, `src/lab/replay.rs`, schema contract docs | schema encode/decode unit tests | L1 artifact contract validation; L3 replay consistency | `EV-WVT-012-L0`, `EV-WVT-012-L1`, `RP-TRACE-001` | yes (`RP-TRACE-001`) | Replay + observability owner |
| `WVT-013` | React integration lifecycle correctness | R2-medium | `@asupersync/react`, `src/web/*` bindings boundary | hook state-machine tests | L2 React integration e2e | `EV-WVT-013-L0`, `EV-WVT-013-L2`, `RP-REACT-001` | optional (`RP-REACT-001`) | Framework owner |
| `WVT-014` | Next.js App Router boundary correctness | R2-medium | `@asupersync/next`, route/runtime boundary helpers | boundary helper unit tests | L2 Next integration e2e/hydration safety | `EV-WVT-014-L0`, `EV-WVT-014-L2`, `RP-NEXT-001` | optional (`RP-NEXT-001`) | Framework owner |

## 17.6 Coverage targets and pass/fail thresholds

Coverage targets (minimum; per PR touching mapped surface):

1. `R0-critical` rows: line >= 92%, branch >= 88%, mutation kill >= 80%
2. `R1-high` rows: line >= 88%, branch >= 82%, mutation kill >= 70%
3. `R2-medium` rows: line >= 80%, branch >= 72%
4. Every traceability row must have at least one `L0-unit` and one higher-layer test reference in CI artifacts.

Pass/fail gates:

1. Any missing `L0-unit` or missing higher-layer mapping for a touched `WVT-*` row fails CI.
2. Any `R0-critical` scenario without replay pointer (`RP-*`) fails CI.
3. Deterministic parity suites must match outcome class and fingerprint class for required rows.
4. Structured log validation must confirm required fields: `trace_id`, `scenario_id`, `seed`, `runtime_profile`, `artifact_uri`, `outcome_class`.

## 17.7 Critical scenario catalog (must stay replayable)

1. `RP-CANCEL-001`: cancel during reserve before commit (no data loss, no leak)
2. `RP-CANCEL-002`: parent cancel fanout with mixed child phases (all children drained/finalized)
3. `RP-RACE-001`: race winner commit with loser drain completion guarantee
4. `RP-OBL-001`: permit/ack/lease closure under timeout and explicit user cancel
5. `RP-QUIESCE-001`: region close under concurrent finalizers reaches quiescence
6. `RP-DET-001`: same seed and profile produce equivalent fingerprint class
7. `RP-FETCH-001`: fetch abort bridge preserves cancel reason mapping and cleanup
8. `RP-HANDLE-001`: stale handle and forged id paths rejected with deterministic errors
9. `RP-TRACE-001`: trace export/import roundtrip preserves replay determinism

## 17.8 Ownership and maintenance cadence

Ownership roles:

1. Runtime backend owner: `WVT-001/002/007`
2. Cancellation/runtime owner: `WVT-003`
3. Combinator owner: `WVT-004`
4. Obligation owner: `WVT-005`
5. Determinism owner: `WVT-006`
6. Browser IO owner: `WVT-009/010`
7. Bindings owner: `WVT-011`
8. Replay/observability owner: `WVT-012`
9. Framework owner: `WVT-013/014`

Cadence:

1. On every PR: update touched `WVT-*` mappings and attach artifact links.
2. Weekly: review coverage deltas and stale replay fixtures.
3. Per milestone gate: full matrix audit across native/wasm and framework lanes.
4. Before GA: zero unmapped retained features/invariants, zero stale `RP-*` pointers.

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

### 19.1 Phase-gate operating contract

1. Gates are ordered and monotonic (`PG-0` through `PG-9`); no skipping and no parallel promotion.
2. A gate is only promotable when all exit evidence links are present and replayable.
3. Any kill criterion is a stop-the-line event: freeze forward work on affected tracks until disposition is documented.
4. Every rollback must pin:
   - rollback trigger ID,
   - last known-good gate,
   - exact revert scope (PRs/beads),
   - deterministic repro bundle (`RP-*`, `EV-*`).
5. Promotion authority is triad approval: runtime owner + invariants/testing owner + integration/security owner (for capability/interop gates).

### 19.2 Gate matrix: entry, exit, kill, rollback

| Gate | Phase | Entry | Exit | Kill criteria (stop-the-line) | Rollback trigger and target |
|---|---|---|---|---|---|
| `PG-0` | Phase 0: Baseline and ADR lock | Baseline inventory and blocker scan complete | wasm CI lane active; blocker report stable; ADR baseline approved | Any retained invariant lacks owning ADR; blocker evidence non-reproducible | `RB-0A`: ADR contradiction or missing owner -> rollback to pre-ADR-lock state and re-run baseline inventory |
| `PG-1` | Phase 1: Dependency closure repair | `PG-0` accepted | wasm profile reaches crate compilation stage | wasm compile blocked by unresolved native dependency chain for 2 consecutive milestone cycles | `RB-1A`: closure regression -> revert offending dependency/profile changes to last green `PG-0/1` commit set |
| `PG-2` | Phase 2: Surface gating | `PG-1` accepted | wasm path excludes native-only surfaces cleanly | Any required browser-v1 surface removed without deferred-register entry; cfg fences permit forbidden native path in wasm profile | `RB-2A`: surface regression -> revert fence/export edits to last green `PG-1` and regenerate census |
| `PG-3` | Phase 3: Semantic seam extraction | `PG-2` accepted | backend interfaces wired; native parity preserved | Native parity regressions on retained invariants (`WVT-*`) or lock-order violations introduced by seam wiring | `RB-3A`: seam parity break -> rollback seam extraction PR batch to last green `PG-2` |
| `PG-4` | Phase 4: Browser scheduler/time alpha | `PG-3` accepted | scheduler and timer suites pass in browser harness | Deterministic profile replay mismatch on identical seed; starvation/fairness regression above agreed threshold in scheduler suites | `RB-4A`: scheduler drift -> rollback browser scheduler/time backend to last green `PG-3` traits-only state |
| `PG-5` | Phase 5: Browser I/O alpha | `PG-4` accepted | fetch/websocket cancel semantics verified | Obligation leaks, loser-drain failures, or capability-boundary violations in browser I/O suites | `RB-5A`: I/O semantic violation -> rollback adapter implementation while retaining seam interfaces |
| `PG-6` | Phase 6: Bindings and TS alpha | `PG-5` accepted | strict TS integration green | ABI break without version bump/migration note; ownership/lifecycle mismatch across JS<->WASM boundary | `RB-6A`: binding contract break -> rollback binding layer to last green ABI schema version |
| `PG-7` | Phase 7: React/Next beta | `PG-6` accepted | example apps and framework e2e suites green | Framework integration hides cancellation/ownership semantics or introduces nondeterministic failure clusters | `RB-7A`: framework semantic mismatch -> rollback framework adapters/hooks to last green TS core |
| `PG-8` | Phase 8: Replay beta | `PG-7` accepted | deterministic reproduction of real trace bug demonstrated | Replay pipeline cannot reproduce captured incidents from pinned artifact set | `RB-8A`: replay non-reproducible -> rollback trace/replay schema changes to last green `PG-7` |
| `PG-9` | Phase 9: Hardening + GA | `PG-8` accepted | GA criteria satisfied across correctness, perf/size, security, release ops | Any red gate in GA board: invariant, security, perf/size budget, or release automation | `RB-9A`: GA blocker -> rollback release candidate to last green `PG-8` and reopen blocked bead cluster |

### 19.3 Rollback execution protocol (mandatory)

1. Incident declaration:
   - issue ID `RB-*` opened with gate ID and trigger statement.
2. Freeze scope:
   - pause promotions on affected track until rollback decision lands.
3. Reproduce deterministically:
   - attach `rch exec -- cargo check --all-targets` / `rch exec -- cargo test` / relevant replay command output as artifact links.
4. Execute rollback:
   - revert only the scoped PR/bead set tied to the trigger; do not widen blast radius without a second approval.
5. Verify rollback target:
   - rerun required gate evidence and confirm return to last known-green state.
6. Resume conditions:
   - corrective bead created, owner assigned, and prevention check added to gate evidence.

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

### 22.1 Owner-assigned risk control table

| Risk ID | Risk | Trigger signal | Impact | Mitigation owner | Mitigation controls | Verification evidence | Review cadence | Escalation trigger |
|---|---|---|---|---|---|---|---|---|
| `R-01` | Dependency regression | New native dependency enters wasm profile closure checks | wasm build break, release delay | Build/Dependency owner | dependency CI gate, feature-profile closure checks, forbidden-dep policy checks | `cargo tree` diff artifact, wasm compile evidence bundle | Every PR + weekly triage | 2 consecutive red wasm lane runs |
| `R-02` | Semantic drift | Native vs browser parity mismatch on retained invariants | cancellation/quiescence correctness loss | Runtime invariants owner | `WVT-*` parity matrix, oracle suites, seam contract checks | parity report with reproducible seed/trace IDs | Every milestone gate | Any invariant gate failure (`PG-3` to `PG-9`) |
| `R-03` | Scheduler fairness/jank regression | Queue starvation or event-loop budget overruns | degraded UX, latent task completion | Browser scheduler owner | fairness budget checks, yield discipline, worker-offload policy | scheduler benchmark + determinism run artifacts | Weekly + perf gate | p95/p99 fairness budget miss in 2 runs |
| `R-04` | Binding lifecycle unsoundness | JS<->WASM ownership mismatch, leaked handles, stale refs | correctness and stability regressions | Bindings/API owner | ABI versioning policy, handle-generation checks, lifecycle conformance tests | ABI contract tests + leak/lifecycle reports | Every PR touching bindings | Any high-severity binding conformance failure |
| `R-05` | Size/perf budget creep | Bundle/runtime metrics exceed defined budgets | adoption friction, runtime sluggishness | Perf/Release owner | budget thresholds, tiered package outputs, CI regression gates | size/perf trend report with baseline deltas | Weekly + release checkpoint | 10% budget overrun without approved waiver ADR |
| `R-06` | Security/capability boundary breach | Implicit authority path or forged capability handle | misuse/exfiltration risk | Security/Capability owner | default-deny capsules, capability scope audits, fuzz/adversarial tests | security gate report + red-team scenario logs | Weekly security review | any unmitigated high-severity security finding |
| `R-07` | Replay non-determinism | Same trace seed reproduces divergent outcomes | incident forensics become untrusted | Trace/Replay owner | trace schema contract tests, replay-delta verifier, artifact immutability checks | replay reproducibility ledger (`RP-*`) | Every replay change + weekly | any non-reproducible critical incident replay |
| `R-08` | Coordination drift between beads and gates | Bead status, gate status, and evidence links diverge | blocked delivery and audit gaps | Program architecture owner | bead-thread discipline, gate board audits, ownership rebalancing | weekly audit report linking beads->gates->evidence | Weekly triage + bi-weekly milestone | orphaned high-priority bead for >1 milestone |

### 22.2 Review rhythm and governance protocol

1. Weekly risk review:
   - validate trigger signals, owner status, and mitigation progress for all `R-*`.
2. Bi-weekly milestone board:
   - map open risks to `PG-*` promotion decisions and capture waivers/blocks explicitly.
3. PR-time obligation:
   - any PR touching risky surfaces must reference affected `R-*` rows and updated evidence.
4. Escalation SLA:
   - escalation triggers must be acknowledged by the mitigation owner within one working day.

### 22.3 Risk closure criteria

1. A risk row can be marked mitigated only when:
   - trigger signal is controlled,
   - verification evidence is green for two consecutive review cycles,
   - and residual risk is documented with explicit owner acceptance.
2. No `R-*` in escalated state is allowed at `PG-9` promotion.

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
