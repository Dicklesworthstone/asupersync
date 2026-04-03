# Browser Quickstart and Migration Guide (WASM-15)

Contract ID: `wasm-browser-quickstart-migration-v1`  
Bead: `asupersync-umelq.16.2`  
Depends on: `asupersync-umelq.16.1`, `asupersync-umelq.2.5`

## Purpose

Provide a single onboarding and migration path for Browser Edition that is:

1. deterministic and reproducible,
2. explicit about capability and cancellation semantics,
3. aligned with deferred-surface policy decisions.

This guide is intentionally command-first so users can move from "new to Browser
Edition" to "verified onboarding evidence" without improvisation.

## Prerequisites

Required:

- Rust toolchain from `rust-toolchain.toml`
- `wasm32-unknown-unknown` target
- `rch` for offloaded cargo operations

Setup:

```bash
rustup target add wasm32-unknown-unknown
rch doctor
```

## Profile Selection

Choose exactly one Browser profile for wasm32:

| Profile | Feature set | Intended usage |
|---|---|---|
| `FP-BR-MIN` | `--no-default-features --features wasm-browser-minimal` | Contract-only or ABI boundary checks |
| `FP-BR-DEV` | `--no-default-features --features wasm-browser-dev` | Local development and diagnostics |
| `FP-BR-PROD` | `--no-default-features --features wasm-browser-prod` | Production-lean build envelope |
| `FP-BR-DET` | `--no-default-features --features wasm-browser-deterministic` | Deterministic replay-oriented validation |

Guardrails:

- On wasm32, exactly one canonical browser profile must be enabled.
- Forbidden surfaces (`cli`, `io-uring`, `tls`, `sqlite`, `postgres`, `mysql`,
  `kafka`) are compile-time rejected.

Reference: `docs/integration.md` ("wasm32 Guardrails"), `src/lib.rs` compile
error gates.

## Supported Runtime Envelope (DX Snapshot)

Use this table to decide whether Browser Edition runs directly in the current
environment or must be used through a bridge-only boundary.

| Runtime context | Direct Browser Edition runtime | Guidance |
|---|---|---|
| Browser main thread (client-hydrated app) | Supported | Use one canonical browser profile and capability-scoped APIs |
| Dedicated worker context (when required Web APIs are present) | Supported for direct Browser Edition runtime | Bootstrap through a dedicated-worker module, run profile checks, and keep deterministic evidence artifacts |
| Node.js server runtime | Bridge-only | Keep runtime execution in browser boundary; call server logic over explicit RPC/API seams |
| Next.js server components / route handlers | Bridge-only | Do not run browser runtime core in server contexts |
| Edge/serverless runtimes (non-browser Web API subsets) | Bridge-only unless explicitly validated | Treat missing APIs as unsupported-runtime diagnostics, not partial support |

Non-goals for Browser Edition v1:

- native-only surfaces (`fs`, `process`, `signal`, `server`)
- native DB clients (`sqlite`, `postgres`, `mysql`) inside browser runtime
- native transport stacks (`kafka`, native QUIC/HTTP3 lanes) in browser closure

When a runtime is outside the supported envelope, route through the bridge-only
pattern and keep capability boundaries explicit instead of adding ambient
runtime fallbacks.

## Rust-Authored Browser Consumer Snapshot

Use this table when the author is writing browser-facing code in Rust rather
than consuming the shipped JS/TS packages.

| Goal | Status today | Recommended lane |
|---|---|---|
| Verify browser-safe cfg/feature closure for the semantic core | Supported | `rch exec -- cargo check --target wasm32-unknown-unknown --no-default-features --features wasm-browser-<profile>` against `asupersync` |
| Maintain the wasm ABI/export boundary from Rust | Supported for workspace contributors; `asupersync-browser-core` is the canonical owner and `asupersync-wasm` is retained scaffold | `rch exec -- cargo check -p asupersync-browser-core --target wasm32-unknown-unknown --no-default-features --features dev`; use the `asupersync-wasm` manifest only when you need to keep the scaffold honest |
| Ship a browser app that constructs Browser Edition runtimes directly from external Rust consumer code | Preview public lane | Use `RuntimeBuilder::browser()` plus execution-ladder inspection for truthful lane negotiation and structured fail-closed diagnostics, while keeping the support claim narrower than the shipped JS/TS Browser Edition packages |

Rules for migration guidance:

- Do not describe `asupersync-browser-core` or `asupersync-wasm` as the public
  end-user Browser Edition SDK for Rust consumers. They are binding/export
  crates that feed the JS/TS packages.
- Treat `asupersync-browser-core` as the canonical shipped boundary owner and
  `asupersync-wasm` as retained non-canonical scaffold rather than two equal
  live owners.
- Do not promise broad `RuntimeBuilder` parity or stable direct `Cx`/`Scope`
  browser bootstrapping beyond the current preview dispatcher-backed
  `RuntimeBuilder::browser()` lane.
- Keep the Rust-authored browser story on the same support matrix as JS/TS:
  browser main thread and dedicated worker are the direct-runtime contexts for
  the shipped product, while service/shared workers, SAB-based parallelism, and
  native-only surfaces remain deferred or unsupported.

### Decision Guide For Rust Authors

Use this table to choose the correct lane before writing browser-facing Rust.

| Situation | Recommended lane | Why |
|---|---|---|
| You need a shipped browser SDK for application code today | Start from `@asupersync/browser`, `@asupersync/react`, or `@asupersync/next` | These are the public Browser Edition product surfaces; they own the supported runtime diagnostics and packaging story |
| You need to prove the semantic core still closes under browser cfg/profile rules | Run the canonical `rch exec -- cargo check --target wasm32-unknown-unknown --no-default-features --features wasm-browser-<profile>` commands against `asupersync` | This validates wasm-safe semantic closure without implying stable parity for the preview Rust browser builder lane |
| You maintain the wasm ABI/package boundary inside this repository | Work in `asupersync-browser-core` first; touch `asupersync-wasm` only to keep its retained non-canonical scaffold role honest | These crates are the Rust-side binding/export infrastructure for the JS/TS packages, not the end-user browser SDK |
| You need the maintained Rust-authored browser example that the tree actually proves | Use `tests/fixtures/rust-browser-consumer/` plus `scripts/validate_rust_browser_consumer.sh` | This is the truthful current Rust-authored browser workflow: an in-repo fixture with deterministic validation, not general external `RuntimeBuilder` parity |
| You need service/shared workers, cross-origin-isolated `SharedArrayBuffer` parallelism, or native-only modules | Do not start from the Rust-authored browser lane | Those surfaces are deferred, guarded optional, bridge-only, or explicit non-goals today |

### Maintained Repository Workflow For Rust-Authored Browser Consumers

The current supported Rust-authored browser workflow is the repository-maintained
fixture at `tests/fixtures/rust-browser-consumer/`. It proves that the tree can
build and run a browser-facing Rust-authored wasm package layout while keeping
the scope honest:

- it uses the existing wasm dispatcher/provider helpers rather than inventing a
  second browser startup story alongside the preview public builder
- it keeps the contract honest about the remaining blocker: `src/runtime/builder.rs`
  still assumes `std::thread`-backed worker and deadline-monitor startup, so
  this fixture does not pretend the preview public browser bootstrap API is
  already broad stable parity
- it proves lifecycle semantics plus truthful execution-ladder diagnostics
  through a real browser matrix on both browser main-thread and
  dedicated-worker entrypoints
- it does **not** widen the public contract beyond what `docs/WASM.md`,
  `tests/wasm_browser_feasibility_matrix.rs`, and
  `tests/wasm_rust_browser_example_contract.rs` already enforce

Supported and unsupported contexts for this workflow:

| Context / surface | Status for Rust-authored guidance | What to do |
|---|---|---|
| Browser main thread with `window`, `document`, and `WebAssembly` | Maintained repository workflow | Use the fixture pattern and validate it with `scripts/validate_rust_browser_consumer.sh` |
| Dedicated worker | Maintained repository workflow inside the Rust browser matrix, still not a stable Rust browser constructor | Use the same fixture workflow and read it as proof of truthful dedicated-worker diagnostics plus lifecycle behavior, not as broad external `RuntimeBuilder` parity |
| Service worker / shared worker | Deferred / not shipped | Keep them on explicit message/data boundaries until host contracts and docs are promoted together |
| Next.js server components, route handlers, edge runtimes, or plain Node.js | Bridge-only or native-only | Keep direct runtime creation in the browser/client boundary and move Rust server logic behind explicit RPC/API seams |
| `SharedArrayBuffer` worker pools / multi-threaded WASM | Guarded optional, not shipped | Do not treat SAB-based parallelism as a default migration target |
| Native-only modules (`fs`, `process`, `signal`, native DB clients, native transports) | Non-goal for browser runtime | Keep these on native/server lanes and cross the boundary with explicit bridges |

Canonical validation command:

```bash
PATH=/usr/bin:$PATH bash scripts/validate_rust_browser_consumer.sh
```

Expected evidence bundle:

- `target/e2e-results/rust_browser_consumer/<timestamp>/consumer_build.log`
- `target/e2e-results/rust_browser_consumer/<timestamp>/browser-run.json`
- `target/e2e-results/rust_browser_consumer/<timestamp>/summary.json`

The validation is only considered healthy when the browser-run report confirms:

- `scenario_id = "RUST-BROWSER-CONSUMER"`
- `support_lane = "repository_maintained_rust_browser_fixture"`
- `ready_phase = "ready"` and `disposed_phase = "disposed"`
- `completed_task_outcome = "ok"`
- `cancel_event_count = 1`
- browser capabilities show `has_window`, `has_document`, and `has_webassembly`

If you are evaluating the preview public builder directly, inspect the truthful
execution ladder before promoting it in your own crate:

```rust
let ladder = RuntimeBuilder::new().inspect_browser_execution_ladder();
let preferred = RuntimeBuilder::new()
    .inspect_browser_execution_ladder_with_preferred_lane(
        BrowserExecutionLane::DedicatedWorkerDirectRuntime,
    );
let selection = RuntimeBuilder::browser().build_selection();
```

The minimum fields to log or inspect are:

- `selected_lane`
- `host_role`
- `reason_code`
- `preferred_lane`
- `downgrade_order`
- `message`
- `guidance`

Migration rule of thumb:

- if you want a shipped product surface, use the JS/TS packages
- if you want to keep the Rust-authored lane honest inside this repository, use
  the maintained fixture and its validation script
- if you need runtime authority outside a browser main-thread page, move that
  logic to a bridge/native lane instead of stretching the Rust browser contract

## Release Channel Workflow (WASM-14 / `asupersync-umelq.15.3`)

Browser onboarding and migration should flow through the release-channel
contract before promotion beyond local/dev usage.

Canonical policy:

- `docs/wasm_release_channel_strategy.md`

Channel model:

1. `nightly` (`wasm-browser-dev`) for rapid iteration,
2. `canary` (policy label carried by the release process, typically validated
   with `wasm-browser-prod`) for pre-stable validation,
3. `stable` (policy label, not a Cargo feature) only after the
   `wasm-browser-prod` lane plus the required deterministic/minimal evidence
   lanes and release gates all pass.

Important:

- `wasm-browser-canary` and `wasm-browser-release` are **not** Cargo feature
  names in this repository.
- The canonical browser feature flags remain exactly:
  `wasm-browser-minimal`, `wasm-browser-dev`, `wasm-browser-prod`, and
  `wasm-browser-deterministic`.

Minimum gate bundle before promotion:

```bash
python3 scripts/check_wasm_optimization_policy.py \
  --policy .github/wasm_optimization_policy.json

python3 scripts/check_wasm_dependency_policy.py \
  --policy .github/wasm_dependency_policy.json

python3 scripts/check_security_release_gate.py \
  --policy .github/security_release_policy.json \
  --check-deps \
  --dep-policy .github/wasm_dependency_policy.json
```

Cargo-heavy profile checks remain `rch`-offloaded:

```bash
rch exec -- cargo check --target wasm32-unknown-unknown \
  --no-default-features --features wasm-browser-dev

rch exec -- cargo check --target wasm32-unknown-unknown \
  --no-default-features --features wasm-browser-prod
```

If any release-blocking gate fails, treat as promotion-blocking and follow the
demotion/rollback sequence in `docs/wasm_release_channel_strategy.md`.

Rust-author quick rule:

- use `wasm-browser-dev` while iterating on the repository-maintained Rust
  browser fixture or ABI crates,
- use `wasm-browser-prod` when validating the browser package boundary you
  intend to promote,
- keep `wasm-browser-deterministic` and `wasm-browser-minimal` as evidence
  lanes, not as ad hoc replacement feature names for canary/stable.

## Workspace Slicing Checkpoint (WASM-02 / `asupersync-umelq.3.4`)

Before onboarding framework adapters, verify workspace slicing closure for the
browser path.

Core slicing intent:

1. Keep semantic runtime invariants in the wasm-safe core path.
2. Keep native-only modules behind `cfg(not(target_arch = "wasm32"))`.
3. Keep optional adapters out of default browser closure unless explicitly needed.

Validation commands:

```bash
rch exec -- cargo check --target wasm32-unknown-unknown \
  --no-default-features --features wasm-browser-minimal \
  | tee artifacts/onboarding/profile-minimal-check.log

rch exec -- cargo check --target wasm32-unknown-unknown \
  --no-default-features --features wasm-browser-dev \
  | tee artifacts/onboarding/profile-dev-check.log

rch exec -- cargo check --target wasm32-unknown-unknown \
  --no-default-features --features wasm-browser-deterministic \
  | tee artifacts/onboarding/profile-deterministic-check.log
```

Expected outcomes:

- each profile compiles independently,
- no native-only module leaks into wasm32 compilation closure,
- profile guardrails reject invalid multi-profile feature combinations.

## Package Install and First-Success Paths (`asupersync-3qv04.9.1`)

Use this as the canonical package-selection and install flow for Browser
Edition. Start with the highest layer that matches your runtime boundary; only
drop down to lower-level packages when you need that surface explicitly.

Package layering:

1. `@asupersync/browser-core` (low-level ABI/types)
2. `@asupersync/browser` (recommended default app-facing browser SDK)
3. `@asupersync/react` (React client-boundary adapter over browser SDK)
4. `@asupersync/next` (Next boundary adapter over browser SDK)

Install/quickstart decision table:

| Package | Use when | Install | First-success checkpoint |
|---|---|---|---|
| `@asupersync/browser-core` | You need raw ABI handles/types or metadata-driven compatibility checks | `npm install @asupersync/browser-core` | Run `rch exec -- cargo test --test wasm_packaged_abi_compatibility_matrix -- --nocapture` |
| `@asupersync/browser` | You need direct browser runtime APIs without framework adapters (recommended starting point) | `npm install @asupersync/browser` | Run `rch exec -- cargo test --test wasm_js_exports_coverage_contract -- --nocapture` |
| `@asupersync/react` | You are running Browser Edition inside a client-rendered React tree | `npm install @asupersync/react react react-dom` | Run `python3 scripts/run_browser_onboarding_checks.py --scenario react` |
| `@asupersync/next` | You need Next-specific client/server/edge boundary guidance | `npm install @asupersync/next next react react-dom` | Run `python3 scripts/run_browser_onboarding_checks.py --scenario next` |

Selection rules:

- choose `@asupersync/browser` first unless you have an explicit low-level ABI
  need (`browser-core`) or framework boundary need (`react`/`next`)
- keep direct runtime creation in browser/client boundaries only
- treat Next server/edge paths as bridge-only lanes; do not run direct Browser
  Edition runtime APIs there
- keep package versions aligned across `browser-core`, `browser`, `react`, and
  `next`

## Quickstart Flows

Each flow has:

1. a deterministic command bundle,
2. expected verification outcomes,
3. artifact pointers for replay/debug.

Automated runner (preferred for CI/replay bundles):

```bash
python3 scripts/run_browser_onboarding_checks.py --scenario all
```

Scenario-scoped runs:

```bash
python3 scripts/run_browser_onboarding_checks.py --scenario vanilla
python3 scripts/run_browser_onboarding_checks.py --scenario react
python3 scripts/run_browser_onboarding_checks.py --scenario next
```

Canonical framework examples and deterministic replay pointers:
`docs/wasm_canonical_examples.md`.

### Flow A: Baseline Browser Smoke (Vanilla)

Goal: verify scheduler, cancellation/quiescence, and capability boundaries.

```bash
mkdir -p artifacts/onboarding

rch exec -- cargo test -p asupersync browser_ready_handoff -- --nocapture \
  | tee artifacts/onboarding/vanilla-browser-ready.log

rch exec -- cargo test --test close_quiescence_regression \
  browser_nested_cancel_cascade_reaches_quiescence -- --nocapture \
  | tee artifacts/onboarding/vanilla-quiescence.log

rch exec -- cargo test --test security_invariants browser_fetch_security -- --nocapture \
  | tee artifacts/onboarding/vanilla-security.log
```

Expected outcomes:

- browser handoff tests pass (no starvation regressions)
- nested cancel-cascade reaches quiescence
- browser fetch security policy tests pass with default-deny behavior

### Flow B: Framework Readiness Gate (React)

Goal: verify browser-capable seams and deterministic behavior before integrating
React adapters.

```bash
rch exec -- cargo test --test native_seam_parity \
  browser_clock_through_trait_starts_at_zero -- --nocapture \
  | tee artifacts/onboarding/react-clock.log

rch exec -- cargo test --test native_seam_parity \
  browser_clock_through_trait_advances_with_host_samples -- --nocapture \
  | tee artifacts/onboarding/react-clock-advance.log

rch exec -- cargo test --test obligation_wasm_parity \
  wasm_full_browser_lifecycle_simulation -- --nocapture \
  | tee artifacts/onboarding/react-obligation.log
```

Expected outcomes:

- browser clock abstraction is monotonic and deterministic
- obligation lifecycle invariants hold across browser-style lifecycle phases

### Flow C: Framework Readiness Gate (Next.js)

Goal: verify profile closure and dependency policy before wiring App Router
boundaries.

Reference template and deployment guidance:
`docs/wasm_nextjs_template_cookbook.md`.

```bash
python3 scripts/check_wasm_dependency_policy.py \
  --policy .github/wasm_dependency_policy.json \
  | tee artifacts/onboarding/next-dependency-policy.log

rch exec -- cargo check --target wasm32-unknown-unknown \
  --no-default-features --features wasm-browser-dev \
  | tee artifacts/onboarding/next-wasm-check.log

python3 scripts/check_wasm_optimization_policy.py \
  --policy .github/wasm_optimization_policy.json \
  | tee artifacts/onboarding/next-optimization-policy.log
```

Expected outcomes:

- dependency policy script exits cleanly and produces summary artifacts
- wasm profile check confirms chosen profile closure rules
- optimization policy summary is emitted for downstream CI gates

Known failure signature and remediation:

- Signature: `getrandom` compile error requiring `wasm_js` support during
  `next.wasm_profile_check`.
- Immediate action: treat this as a blocker for Next onboarding, capture
  `artifacts/onboarding/next.wasm_profile_check.log`, and route fix through the
  wasm profile/dependency closure beads before retrying this flow.

### Flow D: Maintained Rust Browser Fixture

Goal: validate the repository-maintained Rust-authored browser workflow without
claiming a general external Rust browser SDK.

Reference surfaces:

- `tests/fixtures/rust-browser-consumer/README.md`
- `tests/wasm_rust_browser_example_contract.rs`
- `scripts/validate_rust_browser_consumer.sh`

```bash
PATH=/usr/bin:$PATH bash scripts/validate_rust_browser_consumer.sh
```

Expected outcomes:

- the nested Rust crate builds through `wasm-pack` with cargo execution routed
  through `rch exec -- ...`
- the staged Vite bundle contains both JavaScript and `.wasm` assets
- the browser-run report records `scenario_id = "RUST-BROWSER-CONSUMER"`
- the support lane is `repository_maintained_rust_browser_fixture`
- the run reaches `ready` before unmount and `disposed` after unmount
- exactly one cancellation event is emitted during teardown and the completed
  task reports `ok`

Expected artifacts:

- `target/e2e-results/rust_browser_consumer/<timestamp>/consumer_build.log`
- `target/e2e-results/rust_browser_consumer/<timestamp>/browser-run.json`
- `target/e2e-results/rust_browser_consumer/<timestamp>/summary.json`

## Migration Guides

### Migration 1: `Promise.race()` to explicit loser-drain semantics

Common legacy pattern:

- `Promise.race([...])` returns winner, losers continue silently

Asupersync browser model:

- race winner returned,
- losers explicitly cancelled and drained,
- obligation closure is required before region close.

What to do:

1. model the competing operations as scoped tasks,
2. wire explicit cancellation on loser branches,
3. verify with quiescence and obligation parity tests.

Verification commands:

```bash
rch exec -- cargo test --test close_quiescence_regression browser_ -- --nocapture
rch exec -- cargo test --test obligation_wasm_parity wasm_cancel_drain_ -- --nocapture
```

### Migration 2: implicit global authority to capability-scoped authority

Common legacy pattern:

- direct `fetch`, timers, or storage calls without explicit authority envelope

Asupersync browser model:

- effects must flow through explicit capability contracts,
- default-deny policy for browser fetch authority.

What to do:

1. define explicit origin/method/credential/header constraints,
2. pass capability through call chain; avoid ambient globals,
3. add policy tests before exposing API surface.

Verification command:

```bash
rch exec -- cargo test --test security_invariants browser_fetch_security -- --nocapture
```

### Migration 3: fire-and-forget async to region-owned structured scopes

Common legacy pattern:

- detached async work that outlives UI/component lifecycle

Asupersync browser model:

- each task belongs to one region,
- region close requires quiescence,
- cancellation follows request -> drain -> finalize.

What to do:

1. move detached work into explicit scope/region ownership,
2. ensure close paths drive cancel+drain,
3. reject lifecycle completion while obligations remain unresolved.

Verification command:

```bash
rch exec -- cargo test --test close_quiescence_regression browser_ -- --nocapture
```

## Deferred Surface Register Alignment

Migration docs must not promise deferred capabilities as available. Authoritative
register: `PLAN_TO_BUILD_ASUPERSYNC_IN_WASM_FOR_USE_IN_BROWSERS.md`, Section
6.6 ("Deferred Surface Register").

Required mappings:

| DSR ID | Deferred surface | Browser guidance |
|---|---|---|
| `DSR-001` | OS network sockets and listener stack | Use browser transport envelopes (`fetch`, WebSocket, browser stream bridges) through capability wrappers |
| `DSR-002` | Reactor + io-uring paths | Use browser event-loop scheduling contract and timer adapters; do not reference native pollers |
| `DSR-003` | Native TLS stack | Use browser trust model; no native cert-store assumptions in browser guides |
| `DSR-004` | `fs`/`process`/`signal`/`server` modules | Treat as explicit non-goals for browser-v1; route to server-side companion services |
| `DSR-005` | Native DB clients (`sqlite`/`postgres`/`mysql`) | Use browser-safe RPC boundaries and keep DB access out of browser runtime core |
| `DSR-006` | Native-only transport protocols (kafka/quic-native/http3-native) | Use browser-compatible transport facade and declare protocol availability explicitly |
| `DSR-007` | Runtime-dependent observability sinks | Use browser-safe tracing/export pathways and preserve deterministic artifact contracts |

## Structured Onboarding Evidence Contract

Each onboarding run should capture:

- `scenario_id` (`vanilla-smoke`, `react-readiness`, `next-readiness`)
- command bundle used
- profile flags and target triple
- pass/fail outcome per step
- artifact paths
- remediation hint per step (`remediation_hint`)
- terminal failure excerpt (`failure_excerpt`) for failing steps

Minimum artifact set:

- `artifacts/onboarding/*.log`
- `artifacts/onboarding/*.ndjson`
- `artifacts/onboarding/*.summary.json`
- `artifacts/wasm_dependency_audit_summary.json`
- `artifacts/wasm_optimization_pipeline_summary.json`

## Troubleshooting Fast Path

Use this quick triage table before deep debugging:

| Symptom | First command | Expected artifact |
|---|---|---|
| wasm profile compile failure | `rch exec -- cargo check --target wasm32-unknown-unknown --no-default-features --features wasm-browser-dev` | `artifacts/onboarding/*-wasm-check.log` |
| profile/policy mismatch | `python3 scripts/check_wasm_dependency_policy.py --policy .github/wasm_dependency_policy.json` | `artifacts/wasm_dependency_audit_summary.json` |
| onboarding scenario drift | `python3 scripts/run_browser_onboarding_checks.py --scenario all` | `artifacts/onboarding/*.summary.json` + `*.ndjson` |
| unclear capability/authority failure | `rch exec -- cargo test --test security_invariants browser_fetch_security -- --nocapture` | `artifacts/onboarding/vanilla-security.log` |

Escalate only after capturing command output + artifact pointers. Treat missing
artifacts as a workflow failure that must be fixed before filing runtime bugs.

## CI and Drift Checks

Use this bundle for documentation drift detection:

```bash
# Core compile/lint/format gates
rch exec -- cargo check --all-targets
rch exec -- cargo clippy --all-targets -- -D warnings
rch exec -- cargo fmt --check

# Browser policy checks referenced by this guide
python3 scripts/check_wasm_dependency_policy.py --policy .github/wasm_dependency_policy.json
python3 scripts/check_wasm_optimization_policy.py --policy .github/wasm_optimization_policy.json
python3 scripts/run_browser_onboarding_checks.py --scenario all
```

Drift policy:

1. Any command change in this guide must be accompanied by updated expected
   outcomes.
2. Any profile/surface statement change must be validated against DSR mappings.
3. Any migration guidance change must keep an explicit verification command.
