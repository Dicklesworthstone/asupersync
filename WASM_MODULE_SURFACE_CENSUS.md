# WASM Module Surface Census

Bead: `asupersync-umelq.2.1`  
Date: `2026-02-28`  
Purpose: enumerate workspace and module surfaces for browser viability with explicit required/optional/deferred classification, dependency fan-in/fan-out signals, and OS primitive assumptions.

## 1. Method and reproducibility

Data sources:

1. `AGENTS.md`
2. `README.md`
3. Workspace manifests (`Cargo.toml` + member `Cargo.toml` files)
4. Module inventory from `src/lib.rs` and `src/**`

Commands used to reproduce this census:

```bash
rg -n '^pub mod ' src/lib.rs
rg -n '^pub use ' src/lib.rs

# Workspace member manifests
sed -n '1,220p' asupersync-macros/Cargo.toml
sed -n '1,260p' conformance/Cargo.toml
sed -n '1,220p' franken_kernel/Cargo.toml
sed -n '1,220p' franken_evidence/Cargo.toml
sed -n '1,220p' franken_decision/Cargo.toml
sed -n '1,260p' frankenlab/Cargo.toml

# Platform/OS assumption probes
rg -n '^signal-hook\\s*=|^nix\\s*=|^libc\\s*=|^socket2\\s*=|^polling\\s*=' Cargo.toml
rg -n 'tokio' src/net -g '*.rs'
```

Fan-in/fan-out notes:

1. Fan-in is approximate file-level references to `crate::<module>`.
2. Fan-out is approximate count of unique `crate::<other_module>` targets imported by module files.
3. Values are used for triage and sequencing, not as exact dependency graph truth.

## 2. Workspace crate census

| Crate | Files | LOC | Local dependency fan-in | Local dependency fan-out | Browser role |
|---|---:|---:|---|---|---|
| `asupersync` | 517 | 475394 | consumed by `frankenlab` and external users | depends on `franken-kernel`, `franken-evidence`, `franken-decision`; optional `asupersync-macros`, optional `conformance` | Core runtime product |
| `asupersync-macros` | 7 | 2671 | optional feature in `asupersync` | `syn`, `quote`, `proc-macro2` | Optional ergonomics |
| `conformance` | 21 | 11722 | optional feature in `asupersync` and used in tests | `serde`, `serde_json`, `tempfile` | Required for parity validation |
| `franken-kernel` | 1 | 1607 | used by `asupersync` and `franken-decision` | `serde` | Optional evidence substrate |
| `franken-evidence` | 3 | 2352 | used by `asupersync` and `franken-decision` | `serde`, `serde_json` | Optional evidence substrate |
| `franken-decision` | 1 | 1613 | used by `asupersync` | depends on `franken-kernel`, `franken-evidence`, `serde` | Optional policy/decision layer |
| `frankenlab` | 1 | 506 | standalone binary | depends on `asupersync` with `cli` + `test-internals` features | Tooling/dev harness, not browser runtime |

## 3. Public vs internal surface map

Public API anchors (from `src/lib.rs`):

1. Core re-exports: `Cx`, `Scope`, `Outcome`, `Budget`, `CancelKind`, `CancelReason`, `TaskId`, `RegionId`.
2. Runtime constructors: `RuntimeBuilder`, `LabConfig`, `LabRuntime`.
3. Structured protocol layers: channels, combinators, observability, trace, remote APIs.
4. Optional proc-macro exports behind `proc-macros` feature.

Internal-heavy surfaces (not suitable as browser public API as-is):

1. `runtime::reactor::*`, `runtime::io_driver`, `runtime::spawn_blocking` (native primitives and worker/thread assumptions).
2. `net::tcp`, `net::unix`, `fs::*`, `process`, `signal` (OS/socket/process coupling).
3. `server`, native listener stacks, and database wire clients for browser-inapplicable deployment shapes.

## 4. Module-by-module viability census (runtime crate)

Disposition classes:

1. `Required`: retained for browser subset (possibly with internal refactor).
2. `Adapter`: retained with browser-specific backend seam/capsule.
3. `Deferred`: out of browser v1 runtime scope.

| Module | LOC | Fan-in | Fan-out | OS primitive signal | Disposition | Browser viability notes |
|---|---:|---:|---:|---:|---|---|
| `types` | 12257 | 220 | 27 | 1 | Required | Core semantic contracts and IDs; must remain cross-platform stable. |
| `error` | 282 | 33 | 2 | 0 | Required | Shared error taxonomy; no platform gate required. |
| `cx` | 11911 | 94 | 33 | 2 | Required | Capability boundary stays; backend handles need wasm-safe adapters. |
| `cancel` | 4299 | 0 | 6 | 0 | Required | Core cancellation protocol state machine is non-negotiable. |
| `obligation` | 28260 | 16 | 89 | 0 | Required | Obligation lifecycle and leak prevention must be preserved. |
| `record` | 8077 | 58 | 34 | 1 | Required | Task/region bookkeeping; keep deterministic invariants intact. |
| `runtime` | 48864 | 60 | 223 | 18 | Adapter | Split semantic scheduler core from native reactor/thread implementation. |
| `time` | 8216 | 37 | 52 | 3 | Adapter | Requires browser time backend while preserving deterministic mode. |
| `channel` | 10112 | 20 | 59 | 3 | Required | Two-phase reserve/commit semantics required in browser subset. |
| `sync` | 11654 | 17 | 45 | 5 | Adapter | Keep cancel-aware semantics; swap internals where OS-coupled. |
| `combinator` | 17573 | 13 | 30 | 4 | Required | Keep race/join/timeout laws and loser-drain behavior. |
| `trace` | 36409 | 47 | 80 | 1 | Required | Retain deterministic trace semantics; browser sink/export adapters needed. |
| `lab` | 37796 | 32 | 186 | 3 | Required | Deterministic verification surface is required for browser parity testing. |
| `bytes` | 3096 | 34 | 28 | 0 | Required | Portable buffer layer; no major platform blockers. |
| `stream` | 7136 | 35 | 120 | 5 | Required | Stream API retained; audit internal poll/wake assumptions per backend. |
| `codec` | 1883 | 15 | 21 | 0 | Optional | Retain for browser transport paths where framing is needed. |
| `plan` | 13337 | 1 | 20 | 0 | Optional | Optimization/planning layer can ship after core parity. |
| `observability` | 11600 | 17 | 36 | 1 | Optional | Keep schema contracts; browser export pipeline can phase in. |
| `security` | 1092 | 20 | 7 | 0 | Required | Capability/auth boundaries stay explicit for browser adapters. |
| `remote` | 3785 | 10 | 6 | 0 | Optional | Browser v1 can defer distributed spawn/lease semantics. |
| `io` | 5100 | 36 | 49 | 2 | Adapter | Abstract to browser event APIs and deterministic virtual backend. |
| `net` | 26261 | 22 | 121 | 14 | Adapter | Keep browser-relevant surfaces (fetch/websocket capsules), defer native socket internals. |
| `http` | 23082 | 8 | 54 | 1 | Adapter | Client-side protocol subset possible; server/listener paths out of v1. |
| `transport` | 10846 | 10 | 47 | 2 | Adapter | Multipath/routing semantics can remain with browser-safe IO substrate. |
| `service` | 5711 | 2 | 33 | 1 | Optional | Useful for middleware shape parity; not day-1 blocker. |
| `web` | 4138 | 8 | 13 | 1 | Optional | Candidate integration layer; define strict browser boundary first. |
| `fs` | 3751 | 5 | 58 | 7 | Deferred | Native file system and uring assumptions are out of browser v1. |
| `signal` | 1864 | 3 | 24 | 2 | Deferred | Process-signal handling is non-browser. |
| `process` | 1474 | 0 | 7 | 1 | Deferred | Non-browser process control surface. |
| `database` | 6435 | 0 | 14 | 0 | Deferred | Browser direct DB clients are out of initial runtime subset. |
| `tls` | 3337 | 5 | 18 | 0 | Deferred | Browser-managed TLS; explicit TLS stack not required in wasm v1. |
| `grpc` | 6593 | 3 | 48 | 0 | Deferred | Defer until core browser transport and ABI layers stabilize. |
| `messaging` | 6232 | 1 | 16 | 1 | Deferred | External broker clients deferred after core parity. |
| `server` | 1820 | 3 | 18 | 0 | Deferred | Server hosting paths are outside browser runtime mission. |

## 5. OS primitive and policy assumptions

Observed native assumptions:

1. `runtime` is the densest native-coupled area (epoll/kqueue/io_uring/libc/nix/polling).
2. `net` and `fs` contain heavy socket/OS API coupling.
3. `signal` and `process` are directly non-browser.
4. Manifest-level native dependencies that must stay out of wasm closure: `polling`, `socket2`, `libc`, `nix`, `signal-hook`.

Tokio policy check:

1. No direct `tokio` dependency line is currently present in root `Cargo.toml`.
2. One source mention exists in `src/net/quic_native/forensic_log.rs` documentation text (`no tokio / async`), not as an active runtime dependency path.

## 6. Environment matrix for browser census

Target matrix used for viability classification:

1. Browser engines: Chromium (primary), Firefox (secondary), WebKit/Safari (secondary).
2. Bundlers: Vite, Webpack, Turbopack.
3. Framework lanes: vanilla TS, React, Next.js App Router.
4. Runtime modes: live mode and deterministic mode.

Any module marked `Required` or `Adapter` must eventually produce evidence in at least one lane for each of the four matrix axes.

## 7. Outputs for downstream beads

Unblocks expected:

1. `asupersync-umelq.2.2`: portability classification now has concrete per-module disposition data.
2. `asupersync-umelq.2.3`: invariant parity obligations can attach directly to `Required` + `Adapter` rows.
3. `asupersync-umelq.3.4`: workspace slicing can derive feature/profile boundaries from this census.
4. `asupersync-umelq.2.5`: deferred-surface register can be seeded from all `Deferred` rows above.

Recommended next artifact:

1. A machine-readable ledger (`json` or `toml`) keyed by `module -> {disposition, invariants, test_requirements}` for CI gating and drift checks.

## 8. Portability classification details (`asupersync-umelq.2.2`)

Classification rules used:

1. `Portable`: no required native OS primitive boundary for semantic correctness in browser runtime mode.
2. `Adapter-required`: semantics are retained, but implementation needs browser capability capsules or platform backend seams.
3. `Deferred`: surface is non-essential for browser v1 and/or depends on native process, socket, file, or host networking responsibilities outside browser constraints.

Portable-now module set:

1. `types`
2. `error`
3. `cancel`
4. `obligation`
5. `record`
6. `bytes`
7. `security`

Adapter-required module set:

1. `runtime`
2. `cx`
3. `time`
4. `channel`
5. `sync`
6. `combinator`
7. `trace`
8. `lab`
9. `stream`
10. `io`
11. `net`
12. `http`
13. `transport`

Deferred module set:

1. `fs`
2. `signal`
3. `process`
4. `database`
5. `tls`
6. `grpc`
7. `messaging`
8. `server`

### 8.1 Deferred-surface user impact and mitigation

| Deferred module | Why deferred | User-visible impact in browser v1 | Mitigation / future path |
|---|---|---|---|
| `fs` | depends on host file APIs and io_uring/native syscall paths | no direct file-descriptor style async fs API | route persistence through browser storage adapters (`IndexedDB`/`Cache`) in follow-up |
| `signal` | process signal model does not exist in browser sandbox | no POSIX-style signal handling hooks | represent lifecycle via browser visibility/unload events and explicit cancel tokens |
| `process` | browser has no child process model | no subprocess orchestration in browser runtime | keep subprocess features server-side; use worker-based abstractions where needed |
| `database` | current drivers target native wire/socket + blocking bridges | no embedded DB driver parity in wasm runtime | expose browser-safe data adapters and keep DB clients on server/backend tiers |
| `tls` | browser owns TLS stack under fetch/websocket APIs | no direct rustls-style tls config surface in browser runtime | rely on browser transport security; provide capability-level policy metadata only |
| `grpc` | current gRPC stack depends on transport layers not yet browser-parity-ready | no first-party browser gRPC endpoint runtime in v1 | revisit after browser transport/ABI stabilization; consider grpc-web compatibility lane |
| `messaging` | broker clients assume native sockets and host networking traits | no direct Kafka/NATS/Redis client in browser runtime | defer to backend gateways; browser interacts via fetch/websocket bridge |
| `server` | listener/accept loop model is host/server concern | no in-browser server hosting APIs | keep server runtime outside wasm browser profile |

## 9. Browser v1 "most useful subset" boundary (`asupersync-umelq.2.4`)

### 9.1 Include in v1 (high-value, invariant-safe)

1. Structured task orchestration core:
   - `types`, `error`, `cancel`, `obligation`, `record`, semantic `runtime` slice.
2. Capability-centric execution:
   - `cx`, `security`, capability wrappers needed for browser authority boundaries.
3. Deterministic correctness tooling:
   - `trace` deterministic event model, `lab` deterministic mode used in CI and replay.
4. Concurrency primitives needed by real browser apps:
   - selected `channel` and `sync` primitives with cancel-safe behavior.
5. Time and scheduling essentials:
   - browser-backed `time` and scheduler lanes with fairness and cancel-streak bounds.
6. Browser-relevant I/O adapters:
   - `io`/`net`/`http` subsets for fetch and websocket capsule flows.
7. Developer product surface:
   - stable wasm ABI + TS wrappers + React/Next integration layer for common app workflows.

### 9.2 Explicit non-goals for v1

1. Native socket/server hosting surfaces (`server`, native TCP/UNIX listener paths).
2. Native filesystem/process/signal surfaces (`fs`, `process`, `signal`).
3. Embedded database and broker client stacks (`database`, `messaging`).
4. First-party browser gRPC runtime parity in initial launch.
5. Full native parity for every optional feature flag in a single release.

### 9.3 Tradeoff rationale

1. Why this subset maximizes adoption:
   - it solves the highest-frequency frontend reliability problems (cancellation, structured ownership, deterministic replay) while avoiding low-ROI native-only scope.
2. Why this subset preserves semantics:
   - all non-negotiable invariants remain enforced in retained/adapted modules, with deferred areas clearly marked rather than silently degraded.
3. Why non-goals are explicit:
   - avoids accidental feature promises and keeps roadmap expectations auditable for users and CI gates.

### 9.4 User-facing impact statement

1. Supported v1 user jobs:
   - orchestrate async UI workflows with explicit cancel trees;
   - run deterministic replay for browser incidents;
   - integrate runtime semantics into TS, React, and Next client-side flows.
2. Deferred user jobs:
   - host servers in-browser, manage OS signals/processes, direct DB/broker wire clients from wasm runtime.
3. Migration expectation:
   - deferred jobs require backend service adapters in v1 and become candidates for phased expansion after parity gates are stable.
