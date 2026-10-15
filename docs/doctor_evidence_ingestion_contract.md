# doctor Evidence Ingestion Contract

## Scope

`doctor_asupersync` ingestion accepts a versioned `DoctorEvidenceBundle` and
normalizes runtime and operator artifacts into deterministic `EvidenceRecord`
entries with explicit provenance. This contract covers:

- the versioned bundle boundary and fail-closed metadata validation
- accepted artifact kinds (`trace`, `structured_log`, `ubs_findings`,
  `benchmark`, `runtime_inspector`, `proof_status`, `proof_lane_manifest`,
  `rch_receipt`, `browser_package_readiness`, `cargo_feature_graph`,
  `tracker_context`, `redacted_log`)
- deterministic normalization and deduplication behavior
- rejection semantics for malformed/unsupported artifacts
- redaction failure semantics for log-like or receipt-like artifacts
- no-claim boundaries carried by every accepted source adapter
- structured ingestion events for debugging and replay

## Schema Version

- bundle `schema_version`: `doctor-evidence-v1`
- report `schema_version`: `doctor-evidence-v1`
- Compatibility policy: additive fields are allowed within `v1`; semantic changes
  to required fields or normalization rules require a version bump.

## Ingestion Input

Evidence ingestion accepts a versioned `DoctorEvidenceBundle`:

```json
{
  "schema_version": "doctor-evidence-v1",
  "bundle_id": "string",
  "run_id": "string",
  "source_profile": "string",
  "generated_by": "string",
  "artifacts": [
    {
      "artifact_id": "string",
      "artifact_type": "trace|structured_log|ubs_findings|benchmark|runtime_inspector|proof_status|proof_lane_manifest|rch_receipt|browser_package_readiness|cargo_feature_graph|tracker_context|redacted_log",
      "source_path": "string",
      "replay_pointer": "string",
      "content": "string"
    }
  ]
}
```

Required bundle fields:

1. `schema_version`
2. `bundle_id`
3. `run_id`
4. `source_profile`
5. `generated_by`
6. `artifacts`

The bundle schema version must be `doctor-evidence-v1`; `bundle_id`, `run_id`,
`source_profile`, and `generated_by` must be non-empty; and `artifacts` must
contain at least one entry. Invalid bundles fail closed through
`ingest_doctor_evidence_bundle` as a deterministic one-row rejection report with
no normalized records. Artifact-level malformation is report-local: malformed
artifacts are emitted in `rejected` while the bundle can still ingest.

Each artifact is represented as:

```json
{
  "artifact_id": "string",
  "artifact_type": "trace|structured_log|ubs_findings|benchmark|runtime_inspector|proof_status|proof_lane_manifest|rch_receipt|browser_package_readiness|cargo_feature_graph|tracker_context|redacted_log",
  "source_path": "string",
  "replay_pointer": "string",
  "content": "string"
}
```

Required fields:

1. `artifact_id`
2. `artifact_type`
3. `source_path`
4. `replay_pointer`
5. `content`

Missing required metadata causes rejection with reason
`artifact missing required metadata fields`.

## Normalized Output

The ingestion report is:

```json
{
  "schema_version": "doctor-evidence-v1",
  "run_id": "string",
  "records": [
    {
      "evidence_id": "string",
      "artifact_id": "string",
      "artifact_type": "string",
      "source_path": "string",
      "correlation_id": "string",
      "scenario_id": "string",
      "seed": "string",
      "outcome_class": "success|cancelled|failed",
      "summary": "string",
      "replay_pointer": "string",
      "provenance": {
        "normalization_rule": "string",
        "source_digest": "string",
        "source_kind": "string",
        "adapter_version": "doctor-evidence-adapter-v1",
        "no_claim_boundary": "does_not_prove:string",
        "redaction_policy": "string"
      }
    }
  ],
  "rejected": [
    {
      "artifact_id": "string",
      "artifact_type": "string",
      "source_path": "string",
      "replay_pointer": "string",
      "reason": "string"
    }
  ],
  "events": [
    {
      "stage": "string",
      "level": "info|warn",
      "message": "string",
      "elapsed_ms": 0,
      "artifact_id": "string|null",
      "replay_pointer": "string|null"
    }
  ]
}
```

Required `EvidenceRecord` fields:

1. `evidence_id`
2. `artifact_id`
3. `artifact_type`
4. `source_path`
5. `correlation_id`
6. `scenario_id`
7. `seed`
8. `outcome_class`
9. `summary`
10. `replay_pointer`
11. `provenance.normalization_rule`
12. `provenance.source_digest`
13. `provenance.source_kind`
14. `provenance.adapter_version`
15. `provenance.no_claim_boundary`
16. `provenance.redaction_policy`

## Determinism Rules

1. Artifacts are processed in lexical order by `(artifact_id, artifact_type, source_path)`.
2. Normalized records are emitted in lexical order by `evidence_id`.
3. Rejected artifacts are emitted in lexical order by `(artifact_id, artifact_type, reason)`.
4. Event `elapsed_ms` is synthetic and monotonic (deterministic stage tick), not wall clock.
5. Duplicate normalized records are dropped by canonical key and logged via `dedupe_record` event.

## Normalization Rules by Artifact Type

- `trace`: parse JSON object, map `trace_id`/`correlation_id`, `scenario_id`, `seed`, `outcome_class`, and `summary/message`.
- `structured_log`: parse JSON object, map `correlation_id`, `scenario_id`, `seed`, `outcome_class`, and `summary/message`.
- `ubs_findings`: each non-empty line becomes one failed evidence record.
- `benchmark`: each `key=value` line becomes one success evidence record.
- `runtime_inspector`: parse JSON object as a runtime-inspector snapshot.
- `proof_status`: parse JSON object as a proof-status snapshot row.
- `proof_lane_manifest`: parse JSON object as proof-lane manifest metadata.
- `rch_receipt`: parse JSON object as a terminal or blocker RCH receipt.
- `browser_package_readiness`: parse JSON object as browser/package readiness evidence.
- `cargo_feature_graph`: each non-empty line becomes one success evidence record.
- `tracker_context`: parse JSON object as tracker/bead context.
- `redacted_log`: parse JSON object after redaction checks pass.

Malformed JSON, invalid benchmark line format, empty findings, and unsupported
artifact type are rejected with explicit reasons.

## Source Adapter Provenance

Every accepted source type has a deterministic adapter row with:

1. `source_kind`: canonical source family for downstream analyzers.
2. `adapter_version`: currently `doctor-evidence-adapter-v1`.
3. `normalization_rule`: stable rule identifier for replay/debugging.
4. `no_claim_boundary`: a `does_not_prove:*` statement naming what the record
   does not prove by itself.
5. `redaction_policy`: stable policy identifier for the adapter.

Examples:

- `rch_receipt` uses `source_kind = "rch_receipt"` and does not prove source
  code correctness.
- `proof_status` uses `source_kind = "proof_status_snapshot"` and does not prove
  that the proof command executed at ingestion time.
- `cargo_feature_graph` uses line-snippet normalization and does not prove build
  success.

## Redaction Rules

Ingestion fails closed when content contains common unredacted secret markers,
including private-key headers, bearer-token headers, `AWS_SECRET_ACCESS_KEY`, or
the test sentinel `UNREDACTED_SECRET`. A `redacted_log` artifact that mentions a
token/password/secret without also carrying a redaction marker is also rejected.
Rejected artifacts retain artifact id, source path, replay pointer, and reason.

## Structured Event Taxonomy

- `ingest_start`
- `parse_artifact`
- `normalize_record`
- `dedupe_record`
- `reject_artifact`
- `ingest_complete`

Events are part of the compatibility surface for downstream diagnostics and
must remain stable within `doctor-evidence-v1`.

## Downstream Consumer Assumptions

1. Consumers must fail closed on unknown bundle or report `schema_version`.
2. Consumers can trust `replay_pointer` to provide deterministic repro context.
3. Consumers can rely on `outcome_class` normalization to one of:
   - `success`
   - `cancelled`
   - `failed`
4. Consumers should retain `provenance.source_digest` for audit and dedupe tracing.
5. Consumers should treat unknown artifact types as expected rejection paths,
   not runtime panics.
6. Consumers must carry forward `no_claim_boundary` and must not promote a
   source record into a stronger proof claim without a later proof lane.
