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
