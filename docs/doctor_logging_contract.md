# doctor Structured Logging Contract

## Scope

`asupersync doctor logging-contract` emits the baseline structured logging contract
for `doctor_asupersync` core flows.

This contract defines:

- the required event envelope for deterministic diagnostics
- required correlation primitives and formatting rules
- allowed outcome classes and event taxonomy
- per-flow required/optional fields for execution, replay, remediation, and integration
- compatibility/versioning policy for downstream consumers

## Command

```bash
asupersync doctor logging-contract
```

## Contract Version

- `contract_version`: `doctor-logging-v1`
- Additive field extensions are allowed inside `v1`.
- Semantic changes to required fields, formatting rules, or outcome semantics require a version bump.

## Tail-Latency Taxonomy Companion Contract

AA-01.1 adds a code-backed companion contract on the runtime observability
surface in `src/observability/diagnostics.rs`:

- `contract_version`: `runtime-tail-latency-taxonomy-v1`
- canonical equation:
  `tail_latency_ns = queueing_ns + service_ns + io_or_network_ns + retries_ns + synchronization_ns + allocator_or_cache_ns + unknown_ns`
- direct-duration fields use `ns`
- always-on proxy fields stay under the `tail.*` namespace
- `tail.unknown.unmeasured_ns` is mandatory whenever attribution is incomplete

This contract standardizes both direct-duration buckets and the compact
always-on proxy vocabulary that runtime/test emitters can produce before
full replay/forensics enrichment is available. Any producer that cannot yet be
isolated must remain visible in the explicit unknown bucket instead of
silently disappearing.

Current producer anchors:

| Term | Unit | Current anchors |
|------|------|-----------------|
| `queueing` | `count` proxy + `ns` direct duration | `src/obligation/lyapunov.rs::StateSnapshot.ready_queue_depth`; `src/obligation/lyapunov.rs::StateSnapshot.draining_regions`; `src/combinator/bulkhead.rs::BulkheadMetrics::queue_depth`; `src/sync/pool.rs::PoolStats::waiters` |
| `service` | `count`/quota proxies + `ns` direct duration | `src/runtime/state.rs::TaskSnapshot::poll_count`; `src/observability/resource_accounting.rs::ResourceAccountingSnapshot::poll_quota_consumed`; `src/observability/resource_accounting.rs::ResourceAccountingSnapshot::cost_quota_consumed` |
| `io_or_network` | `count` proxy + `ns` direct duration | `src/runtime/io_driver.rs::IoStats::events_received`; `src/runtime/io_driver.rs::IoStats::polls`; `src/runtime/io_driver.rs::IoStats::wakers_dispatched` |
| `retries` | `ns` direct duration + count proxy | `src/combinator/retry.rs::RetryState::total_delay`; `src/combinator/rate_limit.rs::RateLimitMetrics::total_wait_time`; `src/combinator/circuit_breaker.rs::CircuitBreakerMetrics::total_rejected` |
| `synchronization` | `ns` direct duration + count proxy | `src/sync/contended_mutex.rs::LockMetricsSnapshot::wait_ns`; `src/sync/contended_mutex.rs::LockMetricsSnapshot::hold_ns`; `src/sync/pool.rs::PoolStats::total_wait_time`; `src/observability/resource_accounting.rs::ResourceAccountingSnapshot::obligations_pending` |
| `allocator_or_cache` | `count`/bytes proxies + `ns` direct duration | `src/runtime/region_heap.rs::HeapStats::live`; `src/runtime/region_heap.rs::HeapStats::bytes_live`; `src/observability/resource_accounting.rs::ResourceAccountingSnapshot::heap_bytes_peak` |
| `unknown` | `ns` | contract-level residual in `src/observability/diagnostics.rs::tail_latency_taxonomy_contract` via `tail.unknown.unmeasured_ns` |

Validation expectations:

1. `required_log_fields` stay unique and under the `tail.*` namespace.
2. `terms` stay in canonical equation order and preserve the `unknown` bucket.
3. Every non-unknown term defines at least one concrete producer signal.
4. Every signal points at an existing producer file in the repository.
5. Unknown contribution stays explicit instead of collapsing to zero-by-omission.

## Output Schema

```json
{
  "contract_version": "doctor-logging-v1",
  "envelope_required_fields": [
    {
      "key": "string",
      "field_type": "string|enum",
      "format_rule": "string",
      "description": "string"
    }
  ],
  "correlation_primitives": [
    {
      "key": "run_id|scenario_id|trace_id|command_provenance|outcome_class",
      "format_rule": "string",
      "purpose": "string"
    }
  ],
  "outcome_classes": ["cancelled", "failed", "success"],
  "core_flows": [
    {
      "flow_id": "execution|replay|remediation|integration",
      "description": "string",
      "required_fields": ["string"],
      "optional_fields": ["string"],
      "event_kinds": ["string"]
    }
  ],
  "event_taxonomy": ["string"],
  "compatibility": {
    "minimum_reader_version": "doctor-logging-v1",
    "supported_reader_versions": ["doctor-logging-v1"],
    "migration_guidance": [
      {
        "from_version": "doctor-logging-v0",
        "to_version": "doctor-logging-v1",
        "breaking": false,
        "required_actions": ["string"]
      }
    ]
  }
}
```

## Required Envelope Fields

`doctor-logging-v1` requires these fields on every event:

1. `artifact_pointer`
2. `command_provenance`
3. `flow_id`
4. `outcome_class`
5. `run_id`
6. `scenario_id`
7. `trace_id`

## Correlation Primitive Formatting Rules

1. `run_id`: `run-[a-z0-9._:/-]+`
2. `scenario_id`: `[a-z0-9._:/-]+`
3. `trace_id`: `trace-[a-z0-9._:/-]+`
4. `command_provenance`: single-line shell command
5. `outcome_class`: `cancelled|failed|success`

## E2E Redaction + Log-Quality Gate Contract

The E2E orchestrator (`scripts/run_all_e2e.sh`) is part of the logging contract
enforcement surface for CI and release gating.

Required policy invariants:

1. `ARTIFACT_REDACTION_MODE` must be one of `metadata_only|none|strict`.
2. In CI, `ARTIFACT_REDACTION_MODE=none` is forbidden (fail closed).
3. `ARTIFACT_RETENTION_DAYS_LOCAL` and `ARTIFACT_RETENTION_DAYS_CI` must be numeric and strictly greater than `0`.
4. `LOG_QUALITY_MIN_SCORE` must be numeric and constrained to `0..100`.
5. Per-suite manifest entries must include:
   - `log_quality_score`
   - `log_quality_threshold`
   - `log_quality_gate_ok`
   - `summary_schema_reason`
6. Lifecycle artifacts must include `redaction_mode` so downstream policy
   auditors can verify redaction posture without replaying the suite.

Extension policy:

- Redaction/quality gate fields may be extended additively in `doctor-logging-v1`.
- Removing or renaming any required redaction/quality field requires a contract
  version bump and migration guidance update.

## Core Flow Coverage

`core_flows` include deterministic requirements for:

- `execution` (build/test/lint gate events)
- `replay` (deterministic replay verification events)
- `remediation` (guided fix + verification events)
- `integration` (adapter and cross-system boundary events)

Each flow must:

1. define lexically sorted, unique `required_fields`
2. define lexically sorted, unique `optional_fields`
3. define lexically sorted, unique `event_kinds`
4. require all correlation primitives
5. keep `event_kinds` as a subset of global `event_taxonomy`

## Determinism + Validation Expectations

`validate_structured_logging_contract` enforces schema and ordering invariants.

`emit_structured_log_event` enforces:

- required field presence
- non-empty required values
- formatting rules for correlation primitives
- flow/event taxonomy compatibility

`run_structured_logging_smoke` and
`validate_structured_logging_event_stream` provide deterministic smoke coverage
across all four core flows and enforce lexical stream ordering by:

- `flow_id`
- `event_kind`
- `trace_id`

## Consumer Guidance

1. Fail closed on unknown `contract_version`.
2. Validate event envelopes before rendering/export.
3. Preserve `command_provenance` and `artifact_pointer` for replay and audit.
4. Treat unknown flow IDs/event kinds as schema violations, not soft warnings.
5. Require explicit migration handling whenever `contract_version` changes.
