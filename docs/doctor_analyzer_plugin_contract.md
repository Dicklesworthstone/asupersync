# doctor Analyzer Plugin API + Schema Versioning Contract

## Scope

`asupersync` exposes a deterministic analyzer plugin API for diagnostics packs so
new analyzers can be added without destabilizing output schemas or execution
order.

Canonical implementation:

- `src/observability/analyzer_plugin.rs`

Contract id:

- `doctor-analyzer-plugin-v1`

## Goals

1. Extension points for third-party analyzers.
2. Deterministic plugin ordering and result aggregation.
3. Explicit capability boundaries (no ambient authority).
4. Schema negotiation and compatibility fallback with provenance.
5. Failure isolation so one plugin cannot block the entire pack.

## Core API Surface

- `AnalyzerPlugin` trait:
  - `descriptor() -> AnalyzerPluginDescriptor`
  - `analyze(request, negotiated_input_schema) -> Result<AnalyzerOutput, AnalyzerPluginRunError>`
- `AnalyzerPluginRegistry`:
  - deterministic registration validation
  - deterministic pack execution (`run_pack`)
- `AnalyzerRequest`:
  - host schema version
  - capability grants
  - run/correlation provenance

## Determinism Rules

1. Plugin execution order is lexical by `plugin_id`.
2. Requested plugin lists are sorted + deduplicated before execution.
3. Findings are normalized and aggregated in stable lexical order:
   - primary key: `plugin_id`
   - secondary key: `finding_id`
4. Lifecycle events are emitted in deterministic phase order.

## Capability Boundary Rules

Capabilities are explicit and grant-based:

- `WorkspaceRead`
- `EvidenceRead`
- `TraceRead`
- `StructuredEventEmit`

If a plugin requests a capability not present in `AnalyzerRequest.granted_capabilities`,
execution is skipped with `SkippedMissingCapabilities` and a lifecycle event is emitted.

## Schema Negotiation Rules

Input schema type:

- `AnalyzerSchemaVersion { major, minor }`

Decision matrix:

1. **Exact**: host schema is directly supported.
2. **BackwardCompatibleFallback**: same major, fallback to highest supported minor `<= host`.
3. **IncompatibleMajor**: plugin does not support host major.
4. **HostMinorTooOld**: host major matches but host minor is lower than plugin minimum.

Only `Exact` and `BackwardCompatibleFallback` permit execution.

## Isolation + Error Semantics

Execution is isolated per plugin:

- typed plugin errors -> `Failed`
- panic -> `Panicked` (caught and isolated)
- contract mismatch (for example output schema mismatch) -> `ContractViolation` lifecycle event + failed record

Pack execution continues regardless of individual plugin failure.

## Structured Lifecycle Logging

Every run emits `PluginLifecycleEvent` entries with:

- `plugin_id`
- `phase` (`Registered`, `Negotiated`, `Started`, `Completed`, `Skipped`, `Failed`, `Panicked`, `ContractViolation`)
- optional schema decision
- `run_id`
- `correlation_id`
- deterministic message

This provides replay-friendly provenance for registration, negotiation, failures,
and fallback behavior.

## Compatibility + Deprecation Policy

Policy for `doctor-analyzer-plugin-v1`:

1. Additive fields and additive enum variants are allowed in minor upgrades.
2. Removing or redefining semantics of existing fields requires a major version bump.
3. Plugin descriptors must keep `plugin_id` stable across compatible revisions.
4. Hosts may support multiple major lines concurrently, but every run must record
   the selected schema decision in lifecycle events.
5. Migration guidance must be documented before introducing a new major contract id.

## Validation Coverage

Contract tests in `src/observability/analyzer_plugin.rs` cover:

1. registration and duplicate-id rejection
2. schema negotiation exact/fallback/incompatible cases
3. deterministic ordering + aggregation behavior
4. error/panic isolation
5. missing capability and incompatible-schema skip behavior
