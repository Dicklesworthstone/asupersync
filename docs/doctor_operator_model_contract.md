# doctor Operator Model Contract

## Scope

`asupersync doctor operator-model` emits the canonical operator personas, missions,
and deterministic decision-loop model for `doctor_asupersync` track 1.

This contract defines:

- stable persona identifiers and mission statements
- deterministic decision-loop definitions used by UI and orchestration layers
- global evidence requirements attached to every decision path
- validation invariants for schema consumers

## Command

```bash
asupersync doctor operator-model
```

## Output Schema

The command emits an `OperatorModelContract`.

```json
{
  "contract_version": "doctor-operator-model-v1",
  "personas": [
    {
      "id": "string",
      "label": "string",
      "mission": "string",
      "primary_views": ["string"],
      "default_decision_loop": "string"
    }
  ],
  "decision_loops": [
    {
      "id": "string",
      "title": "string",
      "steps": [
        {
          "id": "string",
          "action": "string",
          "required_evidence": ["string"]
        }
      ]
    }
  ],
  "global_evidence_requirements": ["string"]
}
```

## Contract Invariants

1. `contract_version` is non-empty and versioned.
2. `personas`, `decision_loops`, and `global_evidence_requirements` are non-empty.
3. Persona IDs are unique.
4. Decision-loop IDs are unique.
5. Step IDs are unique within each loop.
6. Every persona references an existing `default_decision_loop`.
7. `global_evidence_requirements` is lexically sorted and duplicate-free.
8. Empty evidence keys are rejected.

## Canonical Personas (v1)

- `conformance_engineer`: drives deterministic reproduction and correctness closure.
- `release_guardian`: enforces release gates and signoff/hold decisions.
- `runtime_operator`: contains live incidents while preserving replayable evidence.

## Canonical Decision Loops (v1)

- `triage_investigate_remediate`
- `release_gate_verification`
- `incident_containment`

## Determinism Guarantees

1. Persona ordering is lexical by `id`.
2. Decision-loop ordering is lexical by `id`.
3. Step ordering is stable and explicit in contract source.
4. Global evidence requirements are lexically sorted.
5. Repeated invocations on unchanged code emit byte-stable JSON ordering.

## Compatibility Notes

- New fields must be additive and backward-compatible.
- Existing field names are stable for downstream track consumers.
- New personas/loops may be appended, but existing IDs must not be renamed.
- Breaking semantic changes require a new `contract_version`.
