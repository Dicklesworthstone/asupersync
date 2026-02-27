# doctor Evidence Ingestion Contract

## Scope

`doctor_asupersync` ingestion normalizes runtime artifacts into deterministic
`EvidenceRecord` entries with explicit provenance. This contract covers:

- accepted artifact kinds (`trace`, `structured_log`, `ubs_findings`, `benchmark`)
- deterministic normalization and deduplication behavior
- rejection semantics for malformed/unsupported artifacts
- structured ingestion events for debugging and replay

## Schema Version

- `schema_version`: `doctor-evidence-v1`
- Compatibility policy: additive fields are allowed within `v1`; semantic changes
  to required fields or normalization rules require a version bump.

## Ingestion Input

Each artifact is represented as:

```json
{
  "artifact_id": "string",
  "artifact_type": "trace|structured_log|ubs_findings|benchmark",
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
        "source_digest": "string"
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

Malformed JSON, invalid benchmark line format, empty findings, and unsupported
artifact type are rejected with explicit reasons.

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

1. Consumers must fail closed on unknown `schema_version`.
2. Consumers can trust `replay_pointer` to provide deterministic repro context.
3. Consumers can rely on `outcome_class` normalization to one of:
   - `success`
   - `cancelled`
   - `failed`
4. Consumers should retain `provenance.source_digest` for audit and dedupe tracing.
5. Consumers should treat unknown artifact types as expected rejection paths,
   not runtime panics.
