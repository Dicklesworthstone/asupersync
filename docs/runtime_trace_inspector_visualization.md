# Runtime Trace Inspector Visualization

<!-- RUNTIME-TRACE-INSPECTOR:SOURCE -->

`artifacts/runtime_trace_inspector_visualization_v1.json` is the checked source
of truth for `asupersync-idea-wizard-fifth-wave-3gaiun.9`.

This packet defines the first deterministic visualization contract for runtime
trace and task-inspector data. It is intentionally scoped to schema, redaction,
static HTML renderer anchors, and fail-closed proof interpretation. It does not
claim a production dashboard or debug-server route.

<!-- RUNTIME-TRACE-INSPECTOR:SCHEMA -->

## Input Schema

The visualization input schema is
`asupersync.runtime-trace-inspector-input.v1`. It joins five existing or planned
runtime surfaces:

| input | primary source | visualization use |
|---|---|---|
| `trace-events` | `src/trace/event.rs` | timeline and flamechart rows |
| `task-console-wire-snapshot` | `src/observability/task_inspector.rs` | task table and region ownership |
| `cancellation-propagation` | `src/observability/cancellation_visualizer.rs` | cancellation tree and propagation rows |
| `scheduler-lane-snapshot` | `src/runtime/scheduler/three_lane.rs` | lane strip and pressure context |
| `evidence-links` | crashpacks plus proof manifest/status artifacts | evidence panel and stale-proof warnings |

Timeline rows are ordered by logical time, event sequence, then stable node id.
Wall-clock fields are advisory and cannot reorder the visual timeline.

<!-- RUNTIME-TRACE-INSPECTOR:RENDERER -->

## Static Renderer Contract

The first renderer surface is
`runtime-trace-inspector-static-html-contract`. It is a deterministic static HTML
contract, not a production dashboard. The checked DOM anchors are:

| DOM id | role |
|---|---|
| `trace-timeline` | trace/flamechart event timeline |
| `region-tree` | region ownership and parentage |
| `task-state-table` | task phase, poll budget, wake, waiter state |
| `obligation-holdings` | held obligation chips and ownership |
| `cancel-propagation` | cancel root, propagation steps, anomaly links |
| `scheduler-lanes` | scheduler lane pressure context |
| `evidence-links` | proof/crashpack links and freshness state |
| `redaction-status` | redaction policy result |
| `no-claim-boundaries` | scope limits for the report |

Golden DOM checks verify stable anchors and classes. Screenshot checks are
deferred until a browser route or packaged static viewer exists.

<!-- RUNTIME-TRACE-INSPECTOR:REDACTION -->

## Redaction

The redaction profile is `runtime-trace-inspector-redaction-v1`. It preserves
structural identifiers such as task, region, obligation, timer, logical-time,
and finite enum discriminant fields. It forbids raw panic text, cancel reason
free text, worker labels, down reason errors, message bodies, chaos detail
payloads, absolute paths, secrets, tokens, credentials, and API keys.

Inputs that require redaction but do not carry a completed redaction pass render
only a blocked redaction panel. They cannot render as partial success.

<!-- RUNTIME-TRACE-INSPECTOR:VALIDATION -->

## Validation

Use the focused remote-only contract lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_runtime_trace_inspector_visualization" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test runtime_trace_inspector_visualization_contract --no-default-features -- --nocapture
```

Local Cargo fallback is not evidence for this contract.

<!-- RUNTIME-TRACE-INSPECTOR:NO-CLAIMS -->

## No-Claim Boundaries

This contract does not implement a production debug-server route, provide
browser screenshot coverage, prove runtime correctness, prove trace correctness,
prove scheduler correctness, prove cancellation correctness, prove performance
improvement, prove broad workspace health, prove release readiness, prove live
RCH fleet availability, or authorize local Cargo fallback.
