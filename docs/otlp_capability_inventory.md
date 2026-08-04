# OTLP capability inventory

<!-- BEGIN OTLP CAPABILITY INVENTORY -->

This is the operator-readable view of
`artifacts/otlp_capability_inventory_v1.json`, owned by
`asupersync-5z2scg.2.1` for `CAP-OTLP-ECOSYSTEM`. The machine artifact is
authoritative for exact symbols, hashes, commands, evidence states, child
routing, and counts.

The governing decision is `DEP-ADR-003`: `ADDITIVE_COEXISTENCE`,
`KEEP_UNTIL_PARITY`, and `KEEP_INCUMBENT`. The owned telemetry tier and the
OpenTelemetry ecosystem bridge cover different signals, so both remain. This
inventory authorizes no dependency exit.

## Frozen signal map

| Signal or integration | Current production state | Gate | Production route | Child |
| --- | --- | --- | --- | --- |
| Logs | `SHIPPED_OWNED` | `metrics` | `LogsSnapshot::to_otlp_protobuf` to `OtlpLogsHttpExporter::export_async` to owned OTLP/HTTP | A5 |
| Metrics | `SHIPPED_VIA_DEPENDENCY` | `metrics` | `OtelMetrics` records into a caller-supplied `Meter`; the embedder SDK collects and exports | A3 |
| Traces | `SHIPPED_OWNED_INPROCESS` | default | owned bounded in-process exporter; collector-bound spans use an embedder `BoxedTracer` | A4 |
| External provider bridge | `SHIPPED_VIA_DEPENDENCY` | `metrics` | all three `OtelMetrics` constructors accept a caller-supplied `Meter` | A11 |

The asymmetry is intentional and binding. Logs have an owned production wire
encoder. Metrics and traces do not: their owned request builders remain
test/fuzz-gated because the generated reference messages carry the quarantined
Tokio dependency chain. The default-feature trace pipeline must remain
reachable even when `metrics` is disabled.

## Supported feature profiles

| Profile | Features | Evidence | Frozen boundary |
| --- | --- | --- | --- |
| `OTLP-PROFILE-DEFAULT` | default | executed | dependency-free metrics registry, owned in-process traces, W3C propagation |
| `OTLP-PROFILE-METRICS` | `metrics` | executed | external Meter bridge, owned logs wire, HTTP transport, privacy/cardinality |
| `OTLP-PROFILE-METRICS-TRACING` | `metrics,tracing-integration` | planned | real span semantics; production request builders remain gated |
| `OTLP-PROFILE-METRICS-COMPRESSION` | `metrics,compression` | planned | gzip is available but stays off by default |
| `OTLP-PROFILE-FUZZ` | `fuzz` | blocked graph probe | generated reference messages; explicitly outside the production no-Tokio guarantee |

There are zero `UNKNOWN` profile, capability, journey, version, gap, or
baseline rows. A row is explicitly executed, source-baselined, partial,
planned, blocked, or unsupported.

## Public API freeze

The accepted ADR surface has six exact groups and 72 symbols. The inventory
also code-reads the top-level public declarations in the five in-scope modules:

| Module | Top-level public items |
| --- | ---: |
| `src/observability/metrics.rs` | 11 |
| `src/observability/otel.rs` | 40 |
| `src/observability/otlp_trace_exporter.rs` | 16 |
| `src/observability/otel_structured_concurrency.rs` | 8 |
| `src/observability/w3c_trace_context.rs` | 13 |
| Total | 88 |

The second count includes public module names, constants, aliases, traits, and
free functions as well as types. It closes long-path gaps that a root re-export
list alone would miss. The focused contract compares both lists to live source
and compares the 72-symbol authority subset to `DEP-ADR-003`.

## Frozen wire and configuration semantics

The owned route is OTLP over HTTP using protobuf and
`application/x-protobuf`. The caller supplies the complete signal URL; the
exporter must not append `/v1/logs`, `/v1/metrics`, or `/v1/traces`. The schema
URL is `https://opentelemetry.io/schemas/1.37.0`, the default scope is
`asupersync.observability.otel`, temporality is cumulative, and retry jitter is
deterministic.

The following contracts are assigned and may not silently change:

| Contract | Frozen behavior | Child |
| --- | --- | --- |
| Endpoint | caller-supplied signal URL used verbatim | A2 |
| Timeout | 10 seconds per attempt; bounded, non-retryable expiry | A2 |
| Retry | 3 retries; 100ms initial; 30s cap; deterministic exponential backoff; `Retry-After` wins | A7 |
| Compression | gzip off by default; missing feature is a hard error | A2 |
| Auth | bearer, API-key, and custom headers; all secret | A2 |
| TLS | fail closed; no protocol downgrade or silent root fallback | A2 |
| Resource | defaults, then `OTEL_RESOURCE_ATTRIBUTES`, then programmatic values | A8 |
| Scope/schema | pinned defaults, overridable per snapshot | A8 |
| Cardinality | bounded names and labels with Drop/Aggregate/Warn plus counts | A8 |
| Privacy | drop lists, glob allowlist, custom regex, built-in PII detection; widen only | A8 |
| Log limits | 128 attributes and 4096 value bytes with counted drops | A5 |
| Sampling | deterministic metric and head-based trace decisions | A4 |
| Load shedding | bounded queues; metrics drop newest, traces drop oldest, brownout explicit | A7 |

HTTP status handling is also frozen: 2xx succeeds; 408, 429, and 502–504 are
retryable; 405 and other terminal 4xx/5xx drop; 415 permits one uncompressed
retry.

## Child ownership

Every epic child owns an explicit row:

| Child | Owned capability slice | Evidence state |
| --- | --- | --- |
| A1 | inventory, profiles, API, versions, journeys, routing | executed |
| A2 | endpoint, TLS, auth, timeout, compression, Cx ownership | source-baselined |
| A3 | metrics, Meter bridge, temporality, aggregation, limits | executed |
| A4 | traces, lineage, sampling, brownout, limits | executed |
| A5 | logs/events, severity, body, context, attributes | source-baselined |
| A6 | owned protobuf request/response and transport | blocked gap |
| A7 | batching, retry, backpressure, cancellation, shutdown | partial |
| A8 | resources, scopes, schema, cardinality, redaction | partial |
| A9 | real collectors, reference SDK, failures, fuzz, logs | blocked inert fixture |
| A10 | aggregate graph/performance/rollback/cutover | planned |
| A11 | external provider adapter and downstream journeys | partial |

A10 must consume all eleven rows. Any planned, partial, blocked, regressed, or
missing row forces `KEEP`.

## Named reference versions

The compiled baseline pins:

- `opentelemetry` 0.32.0;
- `opentelemetry_sdk` 0.32.1;
- `opentelemetry-proto` 0.32.0, quarantined to fuzz/test evidence;
- `prost` 0.14.4.

The Prometheus example documents `opentelemetry-prometheus` 0.17 but does not
compile that crate. A11 owns replacing that documentation-only claim with a
real downstream consumer.

Two real collector compatibility targets are named:

- OpenTelemetry Collector 0.88.0;
- OpenTelemetry Collector 0.90.0.

Both version strings currently occur only in inert audit fixtures. Their state
is `BLOCKED_INERT_FIXTURE`: neither collector was launched, contacted, or
accepted as evidence. A9 owns activation and no-mock execution.

## User journeys

Six journeys are frozen:

1. Owned logs encode and export over explicit-Cx OTLP/HTTP.
2. Default-feature owned traces retain bounded sampling and brownout.
3. An external provider supplies a `Meter` to `OtelMetrics`, with the
   long-path `PrivacyConfig` surface preserved.
4. An embedder SDK owns collection for the Prometheus/local metrics example.
5. Collector failures preserve partial-success, throttle, auth, TLS, media
   type, and terminal-response distinctions.
6. Cancellation, flush, drain, and shutdown are bounded and ultimately prove
   no task, obligation, batch, retry-loop, or region-quiescence leaks.

The third, fourth, and sixth journeys have partial evidence. The first is
source-baselined. The fifth is blocked on inert fixtures. Those distinctions
are part of the contract.

## Executed baselines

All executed commands used RCH with remote-required, clean `HEAD`, no overlay,
`CARGO_INCREMENTAL=0`, `CARGO_PROFILE_TEST_DEBUG=0`, and
`RUSTFLAGS='-D warnings -C debuginfo=0'`.

| Baseline | Result |
| --- | --- |
| `OTLP-BASELINE-METRICS` | 33 passed, 0 failed |
| `OTLP-BASELINE-TRACE` | 9 passed, 0 failed; 2,048 exported + 30,720 dropped = 32,768 submitted spans |
| `OTLP-BASELINE-DOWNSTREAM` | 8 passed, 0 failed; doc tests green |
| `OTLP-BASELINE-PROMETHEUS-EXAMPLE` | example compiled with `metrics` |

The exact replay commands and source revision are in the machine artifact.

The three required `cargo tree` proof attempts did not execute. Installed RCH
classified `cargo tree` as a non-compilation command and remote-required mode
refused local fallback with `[RCH-E301]`. Therefore
`OTLP-GRAPH-DEFAULT`, `OTLP-GRAPH-METRICS`, and `OTLP-GRAPH-FUZZ` are
`BLOCKED_RCH_POLICY`, not passes. Expected outcomes remain:

- default: no normal-edge Tokio path;
- `metrics`: no normal-edge Tokio path;
- `fuzz`: the documented `opentelemetry-proto` to `tonic`/`tonic-prost` to
  Tokio quarantine path.

The real multi-signal command remains planned:

```bash
scripts/run_all_e2e.sh --suite dependency-sovereignty --scenario otlp_multisignal
```

## Known gaps

| Gap | Frozen interpretation | Routed child |
| --- | --- | --- |
| `OTLP-GAP-01` | no owned production metrics/traces encoder | A6 |
| `OTLP-GAP-02` | sync HTTP exporter trait methods cannot perform explicit-Cx sends | A7 |
| `OTLP-GAP-03` | resource-detection constructor discards built attributes | A8 |
| `OTLP-GAP-04` | no `OTEL_EXPORTER_OTLP_*` or scheduled collection | A2 |
| `OTLP-GAP-05` | owned log body supports string `AnyValue` only | A5 |
| `OTLP-GAP-06` | quarantined OTLP audit files cannot count as evidence | A9 |
| `OTLP-GAP-07` | tail-based sampling is explicitly unsupported | A4 |

## Validation

Run the focused structural, source-pin, authority-join, and negative-fixture
contract:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay --overlay-path artifacts/otlp_capability_inventory_v1.json --overlay-path docs/otlp_capability_inventory.md --overlay-path tests/otlp_capability_inventory_contract.rs -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_otlp_capability_inventory" cargo test -p asupersync --test otlp_capability_inventory_contract -- --nocapture
```

## No-claim boundary

This packet proves inventory completeness, 14 exact source pins, explicit
ownership, explicit evidence state, and zero unknown rows. It does not prove
live collector interoperability, owned metrics/traces wire parity, all-signal
lifecycle correctness, performance, broad workspace health, release readiness,
or permission to remove any dependency, feature, signal, API, security
default, redaction rule, or user journey.

<!-- END OTLP CAPABILITY INVENTORY -->
