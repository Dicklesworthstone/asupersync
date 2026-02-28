# WASM API Surface Census (asupersync-umelq.2.1)

Generated: `2026-02-28T05:29:45Z`  
Bead: `asupersync-umelq.2.1`  
Purpose: module-by-module API surface census for browser viability with explicit required/optional/deferred classification, dependency fan-in/fan-out, and OS-primitive assumptions.

## 1. Method and Determinism

This inventory is generated from repository state using deterministic shell queries and stable sorting:

1. Module list from `src/lib.rs` `pub mod ...` declarations.
2. Quantitative surface metrics per module:
   - file count
   - LOC
   - `pub` item count
   - OS-risk token hits (`libc`, `nix::`, `socket2`, `polling`, `signal_hook`, `std::os::`, `std::net::`, `std::process::`, `std::fs::`, `io_uring`, `epoll`, `kqueue`, `wepoll`)
3. Cross-module references from `crate::<module>` usage, collapsed to unique directed edges to compute fan-in/fan-out.
4. wasm dependency closure evidence from `cargo tree` and `cargo check` (offloaded via `rch`).

## 2. Workspace Crate Census

| Crate | Browser-v1 status | Workspace fan-out | Notes |
|---|---|---:|---|
| `asupersync` | Required | 5 | Primary runtime/library surface shipped in wasm profile. |
| `asupersync-macros` | Optional | 0 | DSL ergonomics; not required to ship runtime semantics. |
| `conformance` | Deferred (tooling) | 0 | Test-suite crate, not browser runtime payload. |
| `franken_kernel` | Optional (integration-dependent) | 0 | Types substrate; keep optional unless browser diagnostics path requires it. |
| `franken_evidence` | Optional (integration-dependent) | 0 | Evidence schema support; default browser MVP can defer. |
| `franken_decision` | Optional (integration-dependent) | 2 | Depends on `franken_evidence` + `franken_kernel`; useful for advanced policy loops. |
| `frankenlab` | Deferred (tooling) | 0 | Deterministic harness crate; not required in end-user browser package. |

## 3. Module Surface Metrics (Top-Level `src/`)

Columns:
- `os_risk_hits`: static indicator of platform-native assumptions.
- `fan_in`: number of top-level modules referencing this module.
- `fan_out`: number of top-level modules this module references.

| module | files | loc | pub_items | os_risk_hits | fan_in | fan_out |
|---|---:|---:|---:|---:|---:|---:|
| actor | 1 | 2176 | 52 | 0 | 2 | 8 |
| app | 1 | 1980 | 33 | 0 | 2 | 7 |
| audit | 2 | 636 | 15 | 8 | 0 | 0 |
| bytes | 9 | 3096 | 66 | 0 | 6 | 0 |
| cancel | 3 | 4299 | 127 | 0 | 0 | 5 |
| channel | 10 | 10082 | 234 | 15 | 11 | 8 |
| cli | 9 | 17089 | 897 | 1 | 0 | 1 |
| codec | 10 | 1883 | 83 | 0 | 3 | 5 |
| combinator | 16 | 17573 | 500 | 13 | 7 | 5 |
| config | 1 | 1438 | 68 | 2 | 7 | 3 |
| conformance | 1 | 648 | 29 | 0 | 0 | 3 |
| console | 1 | 1286 | 50 | 0 | 1 | 1 |
| cx | 7 | 11911 | 249 | 2 | 31 | 16 |
| database | 4 | 6435 | 231 | 5 | 0 | 7 |
| decoding | 1 | 1851 | 32 | 0 | 3 | 6 |
| distributed | 9 | 8490 | 255 | 0 | 0 | 9 |
| encoding | 1 | 917 | 19 | 0 | 5 | 4 |
| epoch | 1 | 2997 | 126 | 0 | 0 | 7 |
| error | 1 | 1276 | 59 | 0 | 19 | 2 |
| evidence | 1 | 1371 | 40 | 0 | 1 | 2 |
| evidence_sink | 1 | 582 | 13 | 0 | 3 | 2 |
| fs | 12 | 3751 | 127 | 136 | 0 | 3 |
| gen_server | 1 | 5509 | 72 | 0 | 2 | 11 |
| grpc | 10 | 6593 | 351 | 1 | 0 | 3 |
| http | 24 | 23082 | 689 | 5 | 1 | 16 |
| io | 15 | 5100 | 112 | 2 | 9 | 1 |
| lab | 43 | 37796 | 1574 | 12 | 11 | 16 |
| link | 1 | 1836 | 35 | 0 | 1 | 2 |
| messaging | 6 | 6232 | 269 | 2 | 0 | 8 |
| migration | 1 | 609 | 24 | 0 | 0 | 2 |
| monitor | 1 | 1382 | 30 | 0 | 5 | 2 |
| net | 42 | 26261 | 876 | 160 | 4 | 11 |
| obligation | 20 | 28260 | 824 | 0 | 6 | 8 |
| observability | 12 | 11600 | 493 | 2 | 6 | 7 |
| plan | 7 | 13337 | 392 | 0 | 0 | 8 |
| process | 1 | 1474 | 45 | 6 | 0 | 3 |
| raptorq | 13 | 19094 | 558 | 0 | 2 | 11 |
| record | 8 | 8077 | 379 | 2 | 11 | 6 |
| remote | 1 | 3785 | 193 | 0 | 4 | 6 |
| runtime | 45 | 48864 | 1092 | 416 | 19 | 15 |
| security | 6 | 1092 | 52 | 0 | 7 | 2 |
| server | 3 | 1820 | 42 | 3 | 1 | 6 |
| service | 9 | 5711 | 157 | 4 | 0 | 4 |
| session | 1 | 740 | 18 | 0 | 0 | 4 |
| signal | 6 | 1864 | 70 | 35 | 1 | 2 |
| spork | 1 | 794 | 31 | 0 | 0 | 9 |
| stream | 27 | 7136 | 111 | 7 | 5 | 4 |
| supervision | 1 | 8284 | 218 | 0 | 5 | 7 |
| sync | 11 | 11654 | 209 | 7 | 7 | 4 |
| time | 10 | 8216 | 174 | 4 | 16 | 4 |
| tls | 6 | 3337 | 140 | 2 | 2 | 5 |
| trace | 38 | 36409 | 1198 | 24 | 8 | 7 |
| tracing_compat | 1 | 401 | 21 | 0 | 15 | 0 |
| transport | 8 | 10846 | 303 | 7 | 2 | 7 |
| types | 14 | 12257 | 458 | 1 | 42 | 10 |
| util | 7 | 2771 | 120 | 0 | 29 | 1 |
| web | 8 | 4138 | 180 | 3 | 1 | 7 |

## 4. Browser-Viability Classification

### 4.1 Required in Browser-v1 Semantic Core

`bytes`, `cancel`, `channel`, `codec`, `combinator`, `config`, `cx`, `decoding`, `encoding`, `error`, `obligation`, `record`, `runtime` (semantic core with browser backend), `security`, `sync`, `time`, `trace`, `types`, `util`, `observability`

Why: these modules encode core invariants (structured ownership, cancellation protocol, obligation accounting, quiescence, determinism, explicit capabilities).

### 4.2 Adapter-Required (Retain Semantics, Replace Platform Bindings)

`io`, `net`, `http`, `tls`, `fs`, `signal`, `process`, `server`, `service`, `transport`, `stream`, `web`, `grpc`, `messaging`, `database`

Why: these contain platform/native assumptions (`epoll/kqueue/io_uring`, socket/process/fs APIs, signal handling, native TLS/db stacks) and require browser-specific adapters or capability capsules.

### 4.3 Optional/Deferred for Initial Browser Product

`actor`, `app`, `audit`, `cli`, `conformance`, `console`, `distributed`, `epoch`, `evidence`, `evidence_sink`, `gen_server`, `lab` (ship as tooling profile, not default payload), `link`, `migration`, `monitor`, `plan`, `raptorq`, `remote`, `session`, `spork`, `supervision`, `tracing_compat`

Why: useful for advanced workflows/tooling, but not required for the first browser runtime slice.

### 4.4 Invariant Parity Obligations Per Retained Surface (asupersync-umelq.2.3)

Obligation codes:

- `PO-OWN`: structured ownership retained (no orphan tasks/fibers/messages).
- `PO-CAN`: cancellation semantics retained (`request -> drain -> finalize`).
- `PO-REG`: region lifecycle parity retained (close implies quiescence).
- `PO-OBL`: obligation accounting retained (permits/acks/leases commit-or-abort).

Evidence source codes:

- `U-*`: deterministic unit assertions.
- `I-*`: integration assertions spanning modules/adapters.
- `R-*`: replay-proof artifacts/oracle parity.

| Retained surface | Parity obligations | Measurable parity assertions | Evidence sources |
|---|---|---|---|
| `types` | `PO-OWN`, `PO-CAN`, `PO-REG`, `PO-OBL` | Outcome severity lattice and cancel-kind mappings unchanged across native/wasm. | `U-TYPES-01`, `I-PARITY-01`, `R-DET-01` |
| `error` | `PO-CAN`, `PO-OBL` | Error category/recoverability mapping is profile-invariant; cancellation errors do not degrade to generic failures. | `U-ERR-01`, `I-CANCEL-ERR-01` |
| `cx` | `PO-OWN`, `PO-CAN`, `PO-REG` | Capability checks fail-closed; checkpoint behavior equivalent for matching seeds/scenarios. | `U-CX-01`, `I-CX-CAP-01`, `R-CX-01` |
| `cancel` | `PO-CAN`, `PO-REG`, `PO-OBL` | State transitions preserve phase ordering and idempotence; no skipped finalize phase. | `U-CANCEL-01`, `I-CANCEL-02`, `R-CANCEL-01` |
| `obligation` | `PO-OBL`, `PO-CAN`, `PO-REG` | No leaked obligations under timeout/user-cancel/race-lost paths. | `U-OBL-01`, `I-OBL-02`, `R-OBL-01` |
| `record` | `PO-OWN`, `PO-REG`, `PO-OBL` | Task/region/obligation record transitions remain valid and acyclic. | `U-REC-01`, `I-REC-02` |
| `runtime` (semantic core) | `PO-OWN`, `PO-CAN`, `PO-REG`, `PO-OBL` | Scheduler lane policy preserves fairness bounds and drain progress invariants under browser backend. | `U-RT-01`, `I-RT-03`, `R-RT-01` |
| `time` | `PO-CAN`, `PO-REG` | Deadline/timeout semantics preserve ordering and cancellation responsiveness in browser clock model. | `U-TIME-01`, `I-TIME-02`, `R-TIME-01` |
| `channel` | `PO-OBL`, `PO-CAN` | Reserve/commit behavior remains cancel-correct; no silent drop across wasm adapters. | `U-CHAN-01`, `I-CHAN-02`, `R-CHAN-01` |
| `combinator` | `PO-CAN`, `PO-OBL`, `PO-REG` | Race losers always drain; join/race outcome aggregation remains severity-monotone. | `U-COMB-01`, `I-COMB-02`, `R-RACE-01` |
| `sync` | `PO-CAN`, `PO-OBL` | Locks/semaphores preserve cancel-aware wake/cleanup semantics; no permit leaks. | `U-SYNC-01`, `I-SYNC-02` |
| `trace` | `PO-CAN`, `PO-REG` | Trace schema fields and deterministic ordering are replay-compatible cross-profile. | `U-TRACE-01`, `I-TRACE-02`, `R-TRACE-01` |
| `bytes` | `PO-OBL` | Buffer ownership and mutation semantics remain deterministic and leak-free. | `U-BYTES-01`, `I-CODEC-01` |
| `util` | `PO-CAN` | Deterministic RNG/time helper behavior is profile-consistent for seeded runs. | `U-UTIL-01`, `R-DET-02` |
| `security` | `PO-OWN`, `PO-OBL` | Capability/handle validation remains fail-closed in wasm boundary layers. | `U-SEC-01`, `I-SEC-02`, `R-HANDLE-01` |
| `observability` | `PO-REG`, `PO-CAN` | Diagnostic summaries retain causal attribution and do not hide cancellation lineage. | `U-OBS-01`, `I-OBS-02` |
| `encoding` | `PO-OBL` | Encode pipeline preserves deterministic symbol/output behavior under same input+seed. | `U-ENC-01`, `R-ENC-01` |
| `decoding` | `PO-OBL`, `PO-CAN` | Decode failure/repair semantics remain deterministic and replay-auditable. | `U-DEC-01`, `I-DEC-02`, `R-DEC-01` |
| `codec` | `PO-OBL`, `PO-CAN` | Framing/parse round-trips preserve boundary safety and cancel safety invariants. | `U-CODEC-01`, `I-CODEC-02` |
| `config` | `PO-OWN` | Browser profile flags cannot enable forbidden ambient/native authority implicitly. | `U-CFG-01`, `I-CFG-02` |
| `io` (adapter) | `PO-CAN`, `PO-OBL` | Browser I/O capsules map cancellation to abort semantics with obligation closure. | `U-IO-01`, `I-IO-02`, `R-IO-01` |
| `net` (adapter) | `PO-CAN`, `PO-OBL`, `PO-REG` | Network operations preserve explicit ownership and deterministic teardown sequencing. | `U-NET-01`, `I-NET-02`, `R-NET-01` |
| `http` (adapter) | `PO-CAN`, `PO-OBL` | Request/response lifecycle preserves reserve/commit semantics and cancel attribution. | `U-HTTP-01`, `I-HTTP-02`, `R-HTTP-01` |
| `tls` (adapter) | `PO-OBL`, `PO-CAN` | Handshake and close semantics map to explicit obligations with deterministic failure classes. | `U-TLS-01`, `I-TLS-02` |
| `fs` (adapter) | `PO-CAN`, `PO-OBL` | Browser storage adapter preserves explicit capability checks and close/finalize discipline. | `U-FS-01`, `I-FS-02` |
| `signal` (adapter) | `PO-REG`, `PO-CAN` | Signal-like browser events cannot bypass region ownership/cancel protocol boundaries. | `U-SIG-01`, `I-SIG-02` |
| `process` (adapter/deferred bridge) | `PO-REG`, `PO-CAN` | Unsupported process semantics fail deterministically with explicit capability errors. | `U-PROC-01`, `I-PROC-02` |
| `server` (adapter) | `PO-OWN`, `PO-CAN` | Connection/session ownership remains region-bound; close drains pending obligations. | `U-SRV-01`, `I-SRV-02` |
| `service` (adapter) | `PO-CAN`, `PO-OBL` | Middleware/service composition preserves cancellation propagation and obligation closure. | `U-SVC-01`, `I-SVC-02` |
| `transport` (adapter) | `PO-OBL`, `PO-CAN` | Routing/queue backpressure remains explicit, with no lost wake or silent drop regressions. | `U-TRN-01`, `I-TRN-02`, `R-TRN-01` |
| `stream` (adapter) | `PO-CAN`, `PO-OBL` | Stream operators preserve cancellation checkpoints and deterministic termination. | `U-STR-01`, `I-STR-02` |
| `web` (adapter) | `PO-CAN`, `PO-OWN` | Browser-facing API wrappers preserve capability boundaries and explicit lifecycle transitions. | `U-WEB-01`, `I-WEB-02` |
| `grpc` (adapter) | `PO-CAN`, `PO-OBL` | Request stream cancel/finalize semantics remain invariant under browser transport substitution. | `U-GRPC-01`, `I-GRPC-02` |
| `messaging` (adapter) | `PO-OBL`, `PO-CAN` | Messaging paths preserve ack/lease accounting and cancel-correct delivery semantics. | `U-MSG-01`, `I-MSG-02`, `R-MSG-01` |
| `database` (adapter/deferred bridge) | `PO-OBL`, `PO-CAN` | Browser profile excludes native DB drivers with deterministic unsupported-surface behavior. | `U-DB-01`, `I-DB-02` |

Gate rule for this bead:

1. Any retained surface lacking at least one `U-*` and one `I-*` evidence reference is parity-incomplete.
2. Any `PO-CAN`/`PO-REG` retained surface without replay proof (`R-*`) for high-risk paths must be explicitly documented as temporary risk debt.

## 5. OS Primitive Assumption Ledger

Observed from static token census:

1. Reactor stack is the largest native hotspot:
   - `runtime` has `416` OS-risk hits.
   - heavy `libc`, `polling`, `epoll`, `kqueue`, `io_uring` references.
2. Networking + filesystem are next:
   - `net` has `160` OS-risk hits.
   - `fs` has `136` OS-risk hits.
3. Signal/process remain native-bound:
   - `signal` has `35` OS-risk hits.
   - `process` has `6` OS-risk hits.
4. Cross-cutting native tokens in the current tree:
   - `libc`
   - `nix`
   - `polling`
   - `socket2`
   - `signal-hook`
   - reactor-specific terms (`epoll`, `kqueue`, `io_uring`)

## 6. wasm Dependency Closure Evidence

### 6.1 `cargo tree` snapshot (`wasm32-unknown-unknown`, normal deps)

Forbidden/policy-sensitive crates currently present in the resolved tree:

- `libc`
- `nix`
- `polling`
- `signal-hook` (+ `signal-hook-registry`)
- `socket2`

### 6.2 Remote wasm compile check (`rch` offloaded)

Command:

```bash
rch exec -- cargo check -p asupersync --target wasm32-unknown-unknown --no-default-features
```

Observed failure:

```text
error: The target OS is "unknown" or "none", so it's unsupported by the errno crate.
...
error: could not compile `errno` (lib) due to 1 previous error
```

Interpretation: current dependency closure still includes native-only assumptions incompatible with `wasm32-unknown-unknown`.

## 7. Deliverable Mapping to Downstream Beads

This census directly unblocks:

1. `asupersync-umelq.2.2` portability-classification elaboration (portable / adapter / deferred).
2. `asupersync-umelq.2.5` deferred-surface register with reintegration criteria.
3. `asupersync-umelq.3.4` workspace slicing + optionalization sequencing.
4. `asupersync-umelq.6.3` obligation-ledger parity for wasm permits/acks/leases.

## 8. Repro Commands

```bash
# 1) Module metrics and OS-risk hits
awk '/^pub mod [a-z_]+;/{gsub(";","",$3);print $3}' src/lib.rs

# 2) Fan-in/fan-out edges
rg -n -o 'crate::([a-z_]+)' -r '$1' src

# 3) wasm dependency tree
rch exec -- cargo tree -p asupersync --target wasm32-unknown-unknown -e normal

# 4) wasm compile viability
rch exec -- cargo check -p asupersync --target wasm32-unknown-unknown --no-default-features
```

## 9. Phase Gates, Kill Criteria, and Rollback Triggers (asupersync-umelq.1.3)

Scope: governance control surface for browser-delivery phases (`Alpha`, `Beta`, `Pilot`, `GA`) with explicit stop/rollback triggers and escalation authority.

### 9.1 Entry/Exit Gates by Phase

| Phase | Entry gates (must be true before start) | Exit gates (must be true to advance) |
|---|---|---|
| Alpha | 1) wasm feature profile compiles with documented unsupported-surface list. 2) Core invariants mapped to parity obligations (`PO-*`) and evidence IDs. 3) Deterministic trace schema contract frozen for this phase. | 1) `PO-CAN`, `PO-REG`, `PO-OBL` core checks pass for retained surfaces in deterministic harness. 2) No unresolved P0 correctness defects in retained core. 3) Replay artifacts produced for critical cancellation scenarios (`R-CANCEL-01`, `R-OBL-01`, `R-DET-01`). |
| Beta | 1) Alpha exit complete. 2) Browser adapters (`io/net/http/transport`) available behind explicit capability boundaries. 3) CI emits artifactized logs/traces for wasm lanes. | 1) Adapter parity checks pass (`U-*` + `I-*`) for all retained adapter surfaces. 2) Size/init/latency budgets are within Beta thresholds. 3) No open high-severity security findings on wasm boundary/handle validation. |
| Pilot | 1) Beta exit complete. 2) Integration paths for at least one real app stack (vanilla/React/Next) validated. 3) Rollback playbook validated in staging. | 1) Pilot cohort success metrics meet threshold for two consecutive windows. 2) Deterministic replay reproduces at least one real defect and validated fix. 3) Flake rate stays below pilot cap with no critical invariant regressions. |
| GA | 1) Pilot exit complete. 2) Operational docs + migration guides published. 3) Oncall/incident workflow includes replay + rollback procedures. | 1) GA scoreboard remains green across correctness/perf/security/adoption windows. 2) No unresolved release-blocking regressions for two release candidates. 3) Governance board signs-off with no active kill triggers. |

### 9.2 Hard Kill Criteria (Immediate Stop)

Any single condition below triggers immediate phase stop and escalation:

1. Structured-concurrency ownership break (detected orphan-task/fiber behavior in retained surfaces).
2. Cancellation protocol regression (`request -> drain -> finalize` violated or bypassed).
3. Region close quiescence regression under deterministic replay.
4. Obligation leak regression (permits/acks/leases unresolved at terminal boundaries).
5. Deterministic replay divergence for required `R-*` scenarios.
6. Security boundary break: stale/forged handle accepted or capability bypass confirmed.
7. Performance budget breach beyond hard cap for two consecutive gated runs (after noise controls).

### 9.3 Rollback Triggers and Actions

| Trigger | Severity | Mandatory action | Recovery exit condition |
|---|---|---|---|
| P0 invariant regression in retained core | Critical | Roll back to last green baseline; freeze feature merges on affected surfaces. | Reproducible fix + replay proof + regression test landed. |
| Determinism/replay instability (required `R-*`) | Critical | Roll back phase promotion; pin seed set and disable new adapter expansion. | Fingerprint parity restored across mandatory scenarios. |
| Security boundary defect at wasm API edge | Critical | Immediate release hold; revert affected boundary commits; run focused security sweep. | Security verification suite clean + independent review sign-off. |
| Sustained perf budget breach (size/init/latency) | High | Revert optimization-risk changes; enforce perf gate in blocking mode. | Two consecutive green perf gates with same corpus. |
| CI artifact integrity or provenance gap | High | Block promotion; rerun full gated pipeline with artifact contract checks enabled. | Artifact lineage complete and reproducible from pinned command set. |

### 9.4 Decision Rights and Escalation

| Decision type | Owner | Escalation path |
|---|---|---|
| Stop/continue within a phase | Phase owner | Runtime architect + reliability lead |
| Cross-phase promotion | Governance triad (runtime architect, reliability lead, security lead) | Program owner final tie-break |
| Kill-trigger override request | Governance triad unanimous vote required | No unilateral override permitted |
| Emergency rollback execution | Oncall release owner | Mandatory postmortem within next governance cycle |

Escalation SLA:

1. Critical kill trigger: triad decision within 4 hours.
2. High severity trigger: decision within 1 business day.
3. Medium governance dispute: decision within 3 business days.

### 9.5 Gate Instrumentation Requirements

Every phase-gate decision packet must include:

1. Exact command provenance (`rch exec -- ...`) for every gating run.
2. Evidence bundle pointers (logs, traces, replay manifests, CI run IDs).
3. Explicit checklist of `PO-*` obligations and pass/fail state.
4. Signed decision note with approver identities and timestamp.

## 10. Program Risk Register (asupersync-umelq.1.4)

Scoring scale:

- Likelihood: `1` (rare) to `5` (very likely)
- Impact: `1` (low) to `5` (critical)
- Priority score: `likelihood * impact`

| Risk ID | Category | Risk statement | Likelihood | Impact | Trigger signals | Mitigation strategy | Owner role | Review cadence | Closure criteria |
|---|---|---|---:|---:|---|---|---|---|---|
| `RISK-TECH-01` | Technical | Browser backend breaks structured ownership guarantees. | 3 | 5 | Orphan-task oracle failures, region-close drift, unexplained live descendants. | Block promotion on ownership regressions; enforce `PO-OWN` replay gates before merge. | Runtime backend owner | Weekly + every release candidate | 4 consecutive green ownership gate runs across required scenarios. |
| `RISK-TECH-02` | Technical | Cancellation semantics diverge (`request -> drain -> finalize` incomplete). | 3 | 5 | Cancel-phase transition mismatches, stranded cleanup tasks, replay divergence. | Maintain mandatory cancel replay pack; reject changes without `R-CANCEL-*` evidence. | Cancellation owner | Weekly + incident-triggered | No critical cancel regressions for 2 release cycles. |
| `RISK-TECH-03` | Technical | Obligation leaks in browser adapters (permits/acks/leases). | 2 | 5 | Obligation leak oracle alerts, unclosed tokens at shutdown, retry storms. | Add adapter-specific closure tests and explicit commit/abort instrumentation. | Obligation owner | Weekly | Leak rate remains zero on gated deterministic suite for 30 days. |
| `RISK-TECH-04` | Technical | Deterministic replay parity degrades across wasm/native. | 3 | 4 | Fingerprint drift for fixed seeds, flaky replay outcomes, nondeterministic traces. | Pin deterministic corpus; block promotion when fingerprint class diverges. | Determinism/replay owner | Per CI run + weekly summary | Required replay corpus matches parity thresholds for 4 consecutive weeks. |
| `RISK-PROD-01` | Product | Browser v1 scope expands beyond reliable delivery envelope. | 4 | 4 | Repeated scope additions without evidence updates, deferred list shrink pressure. | Strict phase-gate scope lock; require explicit defer/reintegrate decision logs. | Program owner | Weekly planning review | No unapproved scope additions in active milestone. |
| `RISK-PROD-02` | Product | DX complexity blocks adoption despite semantic strength. | 3 | 4 | High time-to-first-success, repeated setup failures, docs/support escalation. | Prioritize onboarding KPIs; enforce quickstart validation in CI and pilot scripts. | DX/framework owner | Bi-weekly | Median pilot setup time below target threshold for 2 cycles. |
| `RISK-SUP-01` | Supply chain | wasm dependency closure reintroduces forbidden runtime crates. | 4 | 4 | `cargo tree` detects forbidden set (`signal-hook`, `nix`, etc.) in wasm profile. | Keep dependency policy gate mandatory; attach transitive chain evidence to failures. | Dependency policy owner | Every PR touching manifests/features | No forbidden crates in required wasm profiles for 30 days. |
| `RISK-SUP-02` | Supply chain | Third-party crate update changes behavior without parity evidence. | 3 | 4 | Unexpected test/replay shifts after lockfile updates, semver surprises. | Require update ADR + before/after replay/perf artifacts for risky crate changes. | Release/reliability owner | Per dependency update | All high-risk dependency updates ship with approved evidence packet. |
| `RISK-SEC-01` | Security | wasm boundary permits stale/forged handle use. | 2 | 5 | Boundary fuzz findings, capability bypass indicators, authorization mismatch logs. | Enforce handle-generation checks, capability assertions, and fuzz regression suite. | Security owner | Weekly + security triage | Zero open critical boundary findings and green fuzz suite for 2 milestones. |
| `RISK-OPS-01` | Operational | CI artifacts are incomplete for reproducibility. | 3 | 4 | Missing trace/log manifests, broken replay pointers, unresolvable provenance. | Treat artifact contract failures as promotion blockers; maintain validation checksums. | CI/infra owner | Every gated run | 100% gated runs include valid artifact bundle + replay pointer. |
| `RISK-OPS-02` | Operational | Flake debt hides real regressions and delays release decisions. | 4 | 3 | Rising flaky-test suppression, nondeterministic failures with no triage closure. | Track flake burndown SLO; enforce closure windows and quarantine policy. | Quality owner | Twice weekly | Flake rate below target and no stale unresolved flakes >14 days. |
| `RISK-ADOPT-01` | Adoption | Pilot conversion stalls due integration friction in React/Next lanes. | 3 | 3 | Pilot drop-offs, repeated integration blockers, unresolved framework defects. | Maintain framework-specific migration playbooks and response SLAs. | Pilot success owner | Bi-weekly | Pilot conversion meets target for two consecutive review periods. |

### 10.1 Review Protocol

1. Weekly risk board: review all `priority score >= 12` risks and open trigger incidents.
2. Bi-weekly full register sweep: refresh likelihood/impact, owner status, and mitigation progress.
3. Milestone gate requirement: no unowned high-priority risk may carry into next phase.
4. Incident override: any trigger event can force immediate out-of-band review within 24 hours.

### 10.2 Risk Lifecycle States

`Open -> Mitigating -> Watch -> Closed`

State transition rules:

1. `Open -> Mitigating`: owner assigned and mitigation plan committed with dated milestones.
2. `Mitigating -> Watch`: triggers quiet for one full cadence window and mitigations verified.
3. `Watch -> Closed`: closure criteria satisfied and governance triad signs off.
4. Any new trigger reopens risk to `Open` immediately.

## 11. Success Metrics and Program Scoreboard (asupersync-umelq.1.5)

### 11.1 Scoreboard Dimensions

The scoreboard is tracked across four dimensions:

1. Correctness and invariant parity
2. Performance and size budgets
3. Developer experience (DX) onboarding quality
4. Adoption and pilot conversion outcomes

### 11.2 Metric Contract

| Metric ID | Dimension | Definition | Target / threshold | Data source | Cadence |
|---|---|---|---|---|---|
| `M-COR-01` | Correctness | Retained-surface parity pass rate = passed parity checks / total required parity checks. | `>= 99.5%` on gated runs. | CI parity suite (`U-*`, `I-*`, `R-*`) | Per gated run + weekly rollup |
| `M-COR-02` | Correctness | Critical invariant regression count (`PO-OWN`, `PO-CAN`, `PO-REG`, `PO-OBL`). | `0` per release candidate. | Oracle + replay verification logs | Per gated run |
| `M-COR-03` | Correctness | Deterministic replay equivalence rate on required seed corpus. | `100%` class-equivalent outcomes on mandatory corpus. | Replay manifests + fingerprint reports | Daily + release gates |
| `M-PERF-01` | Performance | wasm artifact size (`core-min`, `core-trace`, `full-dev`) for raw and gzip artifacts. | Hard caps from `WASM_SIZE_PERF_BUDGETS.md`: raw <= `650/900/1300 KiB`, gzip <= `220/320/480 KiB` (profile ordered as `core-min/core-trace/full-dev`). | Build artifacts + size gate reports | Per build |
| `M-PERF-02` | Performance | Runtime cold-init latency p95 on reference desktop and mobile browser matrix. | Hard caps from `WASM_SIZE_PERF_BUDGETS.md`: desktop p95 <= `60/85/130 ms`, mobile p95 <= `160/220/320 ms` (`core-min/core-trace/full-dev`). | Browser benchmark harness | Nightly + release gates |
| `M-PERF-03` | Performance | Cancellation responsiveness and steady-state memory envelope under deterministic scenario seeds. | Hard caps from `WASM_SIZE_PERF_BUDGETS.md`: cancellation p95 <= `2.5/3.5/5.0 ms`; steady heap p95 <= `24/32/48 MiB` (`core-min/core-trace/full-dev`). | Deterministic stress suite + traces | Nightly |
| `M-DX-01` | DX | Time-to-first-success for new integrator (clean environment to running sample). | At or below phase target; red if above threshold in 2 consecutive windows. | Scripted onboarding runs + pilot telemetry | Weekly |
| `M-DX-02` | DX | Documentation success rate (quickstart completion without manual intervention). | `>= 95%` completion in pilot cohort. | Pilot runbooks + support logs | Bi-weekly |
| `M-DX-03` | DX | API ergonomics friction index (blocking integration defects per 10 pilot attempts). | Downward trend, hard cap per phase. | Issue tracker + pilot incident tags | Bi-weekly |
| `M-ADOPT-01` | Adoption | Pilot conversion rate (invited teams -> successfully integrated teams). | Meets phase-specific conversion target. | Pilot program tracker | Bi-weekly |
| `M-ADOPT-02` | Adoption | Retention of active pilot integrations across two review windows. | No net-negative retention trend. | Adoption dashboard | Monthly |
| `M-ADOPT-03` | Adoption | Mean time to resolve pilot-blocking defects. | Under SLA per severity band. | Incident/defect tracker | Weekly |

### 11.3 Measurement Protocol

1. All metrics must be derived from reproducible command runs or audited system records.
2. Every metric sample must include:
   - timestamp
   - source artifact pointer
   - scenario/profile identifier
   - environment fingerprint (toolchain/profile/browser matrix)
3. Missing data is treated as failure for phase-gate decisions unless an explicit waiver is approved by governance triad.
4. Any metric schema change requires an ADR-style decision note with backward-comparison guidance.

### 11.4 Interpretation Rules

| Scoreboard status | Rule |
|---|---|
| `Green` | All critical correctness metrics (`M-COR-*`) and required phase thresholds pass. |
| `Yellow` | No critical failures, but one or more non-critical metrics out of band for a single window. |
| `Red` | Any critical correctness failure OR repeated non-critical threshold breach across two windows. |

Escalation rules:

1. `Red` on any `M-COR-*` metric immediately invokes kill criteria review (`Section 9.2`).
2. `Red` on `M-PERF-*`, `M-DX-*`, or `M-ADOPT-*` for two consecutive windows blocks phase promotion.
3. `Yellow` status can proceed only with explicit mitigation owner and dated remediation plan.

### 11.5 Scoreboard Publication Contract

1. Publish a weekly scoreboard packet containing raw metric extracts, trend deltas, and gate recommendation.
2. Attach replay pointers for any metric connected to deterministic correctness claims.
3. Keep at least the last 8 reporting windows accessible for audit and trend analysis.

### 11.6 Budget Baseline Package (asupersync-umelq.13.1)

`WASM_SIZE_PERF_BUDGETS.md` is the canonical threshold contract for `M-PERF-*`
metrics and includes:

1. profile-specific hard caps (`core-min`, `core-trace`, `full-dev`),
2. warn-to-fail escalation semantics for operational p95 metrics,
3. deterministic seed protocol and artifact schema for CI gates,
4. downstream integration points for `asupersync-umelq.13.2`,
   `asupersync-umelq.13.3`, and `asupersync-umelq.18.4`.
