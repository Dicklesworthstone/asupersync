# Browser And Framework Integration

Use this reference when the target includes browser execution, React, or
Next.js. The browser lane is real, but it is not "run the entire native runtime
everywhere JavaScript exists."

## Table of Contents

- [The First Decision: Direct Runtime Or Bridge-Only?](#the-first-decision-direct-runtime-or-bridge-only)
- [Profile Selection Is Mandatory](#profile-selection-is-mandatory)
- [Vanilla Browser Pattern](#vanilla-browser-pattern)
- [React Pattern](#react-pattern)
- [Next.js Pattern](#nextjs-pattern)
- [Browser Scheduler Semantics Matter](#browser-scheduler-semantics-matter)
- [Worker Offload Is Policy-Governed](#worker-offload-is-policy-governed)
- [Unsupported Runtime Failures Are Useful](#unsupported-runtime-failures-are-useful)
- [Evidence Contract For Browser Adoption](#evidence-contract-for-browser-adoption)
- [Browser Troubleshooting Ladder](#browser-troubleshooting-ladder)
- [High-Value Adoption Advice](#high-value-adoption-advice)
- [Anti-Patterns](#anti-patterns)
- [Read Next](#read-next)

## The First Decision: Direct Runtime Or Bridge-Only?

| Environment | Direct Browser Edition Runtime | Guidance |
|------------|-------------------------------|----------|
| browser main thread | yes (GA for JS/TS consumers) | canonical direct-runtime lane |
| dedicated Web Worker | yes (GA for JS/TS consumers) | direct-runtime supported; fetch routes through `WorkerGlobalScope.fetch()` |
| service worker | no — broker/coordinator-only, direct runtime fail-closed | bounded broker registration / durable handoff only (`detectBrowserServiceWorkerBrokerSupport()`, `BrowserServiceWorkerBrokerStore`) |
| shared worker | no — broker/coordinator-only, direct runtime fail-closed | bounded coordinator attach / version handshake / truthful fallback only (`detectBrowserSharedWorkerCoordinatorSupport()`, `createBrowserSharedWorkerCoordinatorSelection()`) |
| Node.js server runtime | no | bridge-only |
| Next.js server components / route handlers | no | bridge-only (`supportClass: "bridge_only"` in Next diagnostics) |
| edge/serverless runtimes with partial Web APIs | assume no unless explicitly validated | unsupported-runtime is the default posture |
| external Rust consumer (`wasm32`) | preview public lane only | `RuntimeBuilder::browser()` — dispatcher-backed, fail-closed; inspect with `RuntimeBuilder::new().inspect_browser_execution_ladder()` or consume a browser builder with `BrowserRuntimeBuilder::inspect_execution_ladder()` |

Do not blur these boundaries.

If the environment is not a supported direct-runtime lane, keep runtime
execution in a browser boundary and communicate over explicit RPC/API seams.

Package surfaces (workspace version 0.4.9; not yet published to npm — use
workspace-local references): `@asupersync/browser-core` (ABI/wasm),
`@asupersync/browser` (SDK), `@asupersync/react`, `@asupersync/next`.

## Profile Selection Is Mandatory

Choose exactly one wasm browser profile:

- `wasm-browser-minimal`
- `wasm-browser-dev`
- `wasm-browser-prod`
- `wasm-browser-deterministic`

Rules:

- exactly one canonical profile on wasm32
- native-only features are compile-time rejected
- browser onboarding should validate profile closure before framework work

Use profile intent correctly:

- `minimal` for contract/ABI checks (smallest artifact)
- `dev` for local development and diagnostics (browser I/O)
- `prod` for production-lean envelope (browser I/O)
- `deterministic` for replay-oriented validation (deterministic mode + browser trace)

## Vanilla Browser Pattern

Good direct-runtime posture:

- initialize in a real browser entrypoint
- keep capability boundaries explicit
- verify quiescence, cancellation, and security policy early

What to validate first:

- browser-ready handoff
- nested cancel cascade reaches quiescence
- browser fetch security/default-deny policy

Do not start with framework glue before the vanilla browser lane is green.

Browser-native application-boundary helpers (`MessageChannel` / `MessagePort`
/ `BroadcastChannel`, WHATWG `ReadableStream` / `WritableStream` byte
wrappers) are capability-gated: construction requires explicit
`BrowserNativeMessagingCapability` / `BrowserNativeStreamCapability`
authority and denies `capability_not_granted` / `degraded_mode_denied`. They
are guarded same-browser wrappers, not asupersync channels or raw transports.

## React Pattern

The repo's React guidance is more specific than "use an effect."

Canonical patterns:

- task groups with explicit cancellation UX
- bounded retry after transient failure
- bulkhead isolation between independent work groups
- tracing-hook transitions with deterministic scenario ids

Practical rules:

- component lifecycle should map cleanly onto scope ownership
- user cancel actions should drive explicit cancellation, not silent abandonment
- retries should stay bounded and observable
- sibling feature areas that can overload independently should use bulkhead
  thinking rather than one shared failure domain

React anti-patterns:

- detached async work that outlives component lifecycle
- retries with no total budget
- effect cleanup that does not actually drain outstanding work
- unstructured logs that cannot be replay-correlated

## Next.js Pattern

The important mental model is phase-based (`NextBootstrapPhase` in
`@asupersync/next`):

- `server_rendered -> hydrating -> hydrated -> runtime_ready`
  (with `runtime_failed` as the explicit failure terminal)

Use that model explicitly.

Rules:

- runtime init belongs in client-hydrated code, not server or edge phases
- hard navigation and cache revalidation should be treated as explicit runtime
  scope invalidations
- re-init should be deterministic and logged as such
- App Router boundaries are real lifecycle boundaries, not incidental framework
  details

Good posture:

- keep browser runtime creation in client components or browser-only modules
- treat `server_rendered`/`client_ssr` runtime init failures as misuse, not a
  flaky environment problem
- make rebootstrap on navigation or invalidation explicit

## Browser Scheduler Semantics Matter

The browser adapter is not allowed to throw away the native scheduler model.

Important semantics from the repo docs:

- lane order still matters: cancel > timed > ready
- cancel fairness must remain bounded
- scheduler pump must be non-reentrant
- wake dedup must survive host-turn boundaries
- `yield_now()` must cooperate without monopolizing the same turn
- deterministic metadata should exist for parity and replay

Practical implication for downstream code:

- do not build UI/runtime glue that assumes unlimited same-turn microtask churn
- do not inline-poll on timer callbacks or wake callbacks
- treat main-thread starvation as a semantic bug, not just a UX bug

## Worker Offload Is Policy-Governed

Dedicated workers are a supported direct-runtime lane; service and shared
workers are broker/coordinator-only (direct runtime fail-closed). If browser
runtime work moves into Web Workers, treat it as a policy boundary:

- ownership remains attached to the originating region/task
- cancellation must cross the worker boundary explicitly
- replay metadata must follow the job
- offload should not be used to hide scheduler bugs or unbounded main-thread
  work
- do not try to smuggle a direct runtime into service/shared workers; use the
  bounded broker/coordinator APIs and their maintained fixtures
  (`scripts/validate_service_worker_broker_consumer.sh`,
  `scripts/validate_shared_worker_consumer.sh`)

## Unsupported Runtime Failures Are Useful

The browser stack deliberately throws unsupported-runtime diagnostics for bad
contexts. Treat them as guidance, not noise.

Representative codes from the repo docs:

- `ASUPERSYNC_BROWSER_UNSUPPORTED_RUNTIME`
- `ASUPERSYNC_REACT_UNSUPPORTED_RUNTIME`
- `ASUPERSYNC_NEXT_UNSUPPORTED_RUNTIME`
- `ASUPERSYNC_BROWSER_NATIVE_MESSAGING_UNSUPPORTED` / `_OPERATION_FAILED`
- `ASUPERSYNC_BROWSER_NATIVE_STREAM_UNSUPPORTED` / `_OPERATION_FAILED`

Typical causes:

- attempted init in Node or SSR
- missing browser DOM/WebAssembly/fetch/runtime prerequisites
- direct runtime usage in server or edge paths
- direct runtime attempted in service/shared workers
  (`service_worker_direct_runtime_not_shipped` /
  `shared_worker_direct_runtime_not_shipped` — broker/coordinator-only)
- browser-native helper construction without the required capability grant
  (`capability_not_granted`, `degraded_mode_denied`)

Correct response:

- move runtime creation into a supported client/browser boundary
- keep server/edge paths on bridge-only adapters

## Evidence Contract For Browser Adoption

Browser work should produce artifacts, not just console impressions.

Capture:

- scenario id
- profile flags
- command bundle used
- pass/fail per step
- artifact paths
- failure excerpts and remediation hints

This matters because the browser lane has explicit policy, closure, redaction,
and replay contracts. The checked support-class rows live in
`artifacts/browser_edition_readiness_matrix_v1.json`; the scoped JS/TS GA
signoff is `artifacts/browser_ga_final_signoff_v1.json`.

## Browser Troubleshooting Ladder

1. verify onboarding scenario bundle
2. verify dependency/profile policy
3. verify log-quality and redaction contracts
4. run targeted lifecycle/security/parity tests
5. escalate only with artifacts in hand

Treat missing artifacts as workflow failure.

## High-Value Adoption Advice

- start with the vanilla/browser core lane before React or Next
- validate profile closure before fighting framework behavior
- keep runtime state in client-controlled lifecycle boundaries
- make cache invalidation and hard navigation explicit rebootstrap events
- use deterministic scenario ids and structured logs from the beginning

## Anti-Patterns

- trying to run Browser Edition directly in Node, SSR, edge, or
  service/shared workers by default
- mixing multiple canonical browser profiles in one wasm build
- treating the preview Rust `RuntimeBuilder::browser()` lane as stable parity
  with the shipped JS/TS packages
- assuming browser support means native DB/TLS/process/fs/server surfaces exist
- hiding lifecycle bugs behind retries or generic "hydration issue" language
- treating unsupported-runtime diagnostics as optional warnings

## Read Next

- `BROWSER-WASM.md`
- `TESTING-FORENSICS.md`
- `OBSERVABILITY-FORENSICS.md`
- `TROUBLESHOOTING.md`
