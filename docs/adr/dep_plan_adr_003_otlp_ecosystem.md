# DEP-ADR-003: Preserve OTLP metrics, traces, and logs plus external SDK/provider/collector interoperability

- Status: accepted
- Date: 2026-07-24
- Owner: SapphireHill
- Program: `asupersync-ir2uf0` (dependency sovereignty)
- Bead: `asupersync-dep-p3-api-adrs-h3jspm.3`
- Capability: `CAP-OTLP-ECOSYSTEM`
- Decision: `ADDITIVE_COEXISTENCE` / `KEEP_UNTIL_PARITY` / `KEEP_INCUMBENT`
- Machine row: `artifacts/dependency_api_adr_registry_v1.json`
- Supersedes: `COMPREHENSIVE_DEPENDENCY_REPLACEMENT_PLAN.md` §7 item 3.3 and the
  Appendix B `metrics` row

## Context

The dependency-sovereignty program asked whether asupersync can drop the
`opentelemetry` and `opentelemetry_sdk` crates from the `metrics` feature. The
Rev-3 plan framed this as a binary: remove external OpenTelemetry `Meter`/SDK
interoperability, or abandon the replacement. The Rev-4/Rev-5 no-loss gate
rejects both branches, so this ADR has to describe a third outcome.

Reading the live source rather than the prior inventory changes the picture
substantially, and the change is what drives the decision.

**Telemetry today is two tiers, and they are not redundant — they cover
different signals.**

Tier 1 is the owned surface. `observability::otlp_trace_exporter` is ungated:
its span types, bounded queue, head-based sampling, and brownout policy are
available at default features with no OpenTelemetry dependency at all. Inside
the `metrics`-gated `observability::otel` module, `OtlpHttpExporter` implements
OTLP over HTTP with `application/x-protobuf` bodies, RFC-compliant retry with
`Retry-After` handling, deterministic (replayable) jitter, gzip compression
behind the `compression` feature, bearer/API-key/custom auth headers, and
fail-closed TLS inherited from the crate's own HTTP/1.1 client.

Tier 2 is the ecosystem bridge. All three `OtelMetrics` constructors take an
`opentelemetry::metrics::Meter` supplied by the embedder, and the re-exported
`SpanStorage` type materializes spans through an embedder-supplied
`opentelemetry::trace::BoxedTracer`.

**The critical finding: only the logs signal has a complete owned production
path to the wire.** `LogsSnapshot::to_otlp_protobuf` and its internal
`otlp_logs_proto` prost message set are ungated inside the `metrics`-gated
module, so under `--features metrics` logs encode and send in production today.
The equivalent request builders for metrics and traces live in
`observability::otel::otlp_request_builder`, which is gated:

```rust
#[cfg(all(
    any(test, feature = "fuzz"),
    feature = "metrics",
    feature = "tracing-integration"
))]
pub mod otlp_request_builder { /* ... */ }
```

They are unreachable in any production build. They are gated that way for a
good reason: they depend on `opentelemetry-proto`, whose `gen-tonic-messages`
feature pulls `tonic` and therefore `tokio`, which the `metrics` production
graph must never contain.

The consequence is decisive. For the metrics and traces signals, the external
SDK bridge is not one integration option among several — **it is the only
production export path that exists.** Removing the ecosystem crates would not
trim an optional adapter; it would leave asupersync with no way to export
metrics or traces at all, while also deleting `OtelMetrics::new`, the sole
integration point for downstream code that already owns a `MeterProvider`.

## Decision

Asupersync **MUST** keep both telemetry tiers. `opentelemetry` and
`opentelemetry_sdk` remain production dependencies of the `metrics` feature
under disposition `KEEP_UNTIL_PARITY` and cutover state `KEEP_INCUMBENT`.

Specifically:

1. The crate **MUST** preserve all three OTLP signals as they exist today:
   owned wire export for logs, ecosystem-mediated export for metrics and
   traces, and the ungated in-process trace pipeline.
2. The crate **MUST** preserve `OtelMetrics::new`,
   `OtelMetrics::new_with_resource_detection`, and
   `OtelMetrics::new_with_config`, each accepting a caller-supplied `Meter`
   from any `MeterProvider` implementation.
3. The owned trace surface **MUST** stay reachable at default features. It
   **MUST NOT** be moved behind the `metrics` feature.
4. `observability::otel` **MUST** stay behind the `metrics` feature, and
   `opentelemetry-proto` **MUST** stay behind `fuzz`. The two tokio proof lanes
   `metrics-production-tokio-tree` and `fuzz-tokio-quarantine-tree` remain the
   binding checks.
5. The exporter configuration surface — endpoint used verbatim, per-attempt
   timeout, bounded retry, gzip default OFF, auth headers, fail-closed TLS,
   resource and scope attributes, cardinality bounds, privacy redaction,
   sampling, and bounded load shedding — **MUST** be preserved with its current
   defaults. Changing a default silently is an interop regression.
6. Redaction **MAY** widen; it **MUST NOT** narrow. Auth headers **MUST** be
   treated as secret material.
7. New owned surfaces **MAY** be added alongside the existing ones. The owned
   tier **MAY** be documented as the preferred path for logs. Neither
   permission weakens the bridge.
8. A dependency exit **MUST NOT** be attempted until an owned, tokio-free
   production wire encoder exists for metrics and traces *and* an owned adapter
   accepts the same downstream provider handles with proven behavioral parity.
   Until both hold, the answer is KEEP.

## Allowed tradeoffs

- Downstream consumers must pin a compatible `opentelemetry` major version
  themselves, because the coupling is by function signature and the crate
  deliberately publishes no `pub use opentelemetry` re-export.
- Metrics and traces export cadence stays the embedder's responsibility; there
  is no periodic reader inside asupersync.
- Cumulative temporality remains the only supported mode.
- Documentation may steer new users toward the owned logs path first.

## Forbidden compromises

- Deleting the ecosystem bridge, in whole or in part.
- Dropping any of the three signals.
- Moving the owned trace surface behind a feature gate.
- Letting `opentelemetry-proto`, `tonic`, or `tokio` into the `metrics`
  production graph in order to promote the test/fuzz request builders.
- Narrowing redaction, weakening the fail-closed TLS posture, silently changing
  the compression default, or beginning to rewrite caller-supplied endpoints.
- Counting the quarantined audit files (see OTLP-GAP-06) as evidence.

## Known gaps

These are recorded so they cannot silently widen. None is an authorized loss;
each names an owning bead and may only ever improve.

| ID | Gap | Owner |
|---|---|---|
| OTLP-GAP-01 | No owned production wire encoder for metrics or traces; the builders are test/fuzz-gated behind the tokio-carrying proto crate. | `asupersync-5z2scg.2` |
| OTLP-GAP-02 | The synchronous exporter-trait methods on the HTTP exporters return an error directing callers to the async path, because the real send needs an explicit `&Cx`. | `asupersync-5z2scg.2` |
| OTLP-GAP-03 | `OtelMetrics::new_with_resource_detection` builds the resource attribute set and then discards it. | `asupersync-5z2scg.2` |
| OTLP-GAP-04 | Only `OTEL_RESOURCE_ATTRIBUTES` is honored; the `OTEL_EXPORTER_OTLP_*` family is unsupported, as is scheduled collection. | `asupersync-5z2scg.2` |
| OTLP-GAP-05 | The owned log body encoder supports only the string variant of the OTLP `AnyValue` union. | `asupersync-5z2scg.2` |
| OTLP-GAP-06 | Roughly 39 OTLP audit test files under `src/observability/` are tracked but not declared in `mod.rs`, so they never compile. The quarantine is deliberate and documented in `artifacts/otlp_audit_cluster_inventory_v1.json`. | `asupersync-lf1a77` |
| OTLP-GAP-07 | Tail-based sampling is explicitly unsupported via a pinned support-class contract. Recorded so the explicit declaration is not mistaken for an accidental omission. | `asupersync-5z2scg.2` |

## Invariant impact checklist

- [x] No accepted public API is removed or narrowed.
- [x] No Cargo feature is removed; four are frozen verbatim against the manifest.
- [x] No OTLP signal is dropped.
- [x] Third-party ecosystem integration is preserved.
- [x] The no-Tokio guarantee for the default and `metrics` production graphs is unchanged.
- [x] The fuzz-only tokio quarantine edge stays scoped and documented.
- [x] Fail-closed TLS, redaction coverage, and secret handling are unchanged.
- [x] `Cx`-owned exporter work, bounded flush, and bounded shutdown are unchanged.
- [x] No compatibility shim or deprecated alias is introduced.
- [x] No root export changes, so `artifacts/api_surface_map_v1.json` is untouched.

## Evidence

Evidence state is `BASELINE_PLANNED`: the corpus is specified, not executed.

- Baseline: `asupersync-5z2scg.2.1`
- Unit: `asupersync-5z2scg.2.3`
- No-mock E2E: `asupersync-5z2scg.2.9`
- Scenario IDs: `otlp_metrics`, `otlp_traces`, `otlp_logs`,
  `otlp_external_sdk_adapter`, `otlp_failure_matrix`
- Suite command:
  `scripts/run_all_e2e.sh --suite dependency-sovereignty --scenario otlp_multisignal`

Required classes span unit happy/boundary/malformed/error paths;
cancellation, race, shutdown, leak, and quiescence states for every exporter
including the bounded Drop-path flush; property and fuzz coverage of the wire
format; a differential comparison of the owned logs encoder against the
reference proto encoding; a sparse-feature build matrix over default, `metrics`,
`metrics`+`tracing-integration`, and `metrics`+`compression`; downstream
consumers driving both `OtelMetrics::new` and the long-path
`observability::otel::PrivacyConfig`; a live collector accepting logs on the
owned path and metrics/traces through a reference SDK, with partial-success,
throttle, auth-failure, and TLS-failure rows; and both tokio proof lanes green.

## Rollback

Any downstream build break, collector interop failure, lost signal, silently
changed default, new tokio normal-edge in the `metrics` graph, or narrowed
redaction triggers a revert to the frozen surface. Because the decision is
coexistence, rollback reverts an additive change rather than resurrecting a
deleted capability. Re-run the focused contract, the `CAP-OTLP-ECOSYSTEM`
scenario IDs, and both tokio proof lanes before declaring rollback complete.

## Focused contract

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_dependency_api_adr_registry" cargo test -p asupersync --test dependency_api_adr_registry_contract -- --nocapture
```

## No-claim boundary

This ADR is a frozen decision and public-surface inventory only. It does not
prove that the planned evidence has run, that the owned logs encoder is
byte-compatible with any reference implementation, that a live collector accepts
asupersync output, that metrics, traces, or logs parity has been measured, that
performance is unchanged, that the workspace is healthy, or that any dependency
may be removed. Agreement on the metrics signal alone, or on generated-message
shapes alone, does not prove traces, logs, provider ecosystem, lifecycle, or
real collector parity.
