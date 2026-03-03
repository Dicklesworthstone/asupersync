# doctor Remediation Recipe DSL Contract

## Scope

`asupersync doctor remediation-contract` emits the machine-readable remediation DSL contract for `doctor_asupersync` Track 4 workflows.

This contract defines:

- deterministic recipe schema for fix intents, preconditions, rollback plans, and confidence inputs
- confidence scoring model (weighted inputs in basis points)
- risk band policy for `apply` vs. `review` decisioning
- compatibility/versioning guidance for future DSL evolution
- deterministic fixture bundle for parser/validator/scorer regression testing

## Command

```bash
asupersync doctor remediation-contract
```

## Contract Version

- `contract_version`: `doctor-remediation-recipe-v1`
- Depends on logging contract: `doctor-logging-v1`
- Backward-compatible additive fields are allowed within `v1`
- Any semantic changes to required fields, scoring math, or risk-band semantics require a version bump

## Output Schema

```json
{
  "contract": {
    "contract_version": "doctor-remediation-recipe-v1",
    "logging_contract_version": "doctor-logging-v1",
    "required_recipe_fields": [
      "confidence_inputs",
      "finding_id",
      "fix_intent",
      "preconditions",
      "recipe_id",
      "rollback"
    ],
    "required_precondition_fields": [
      "evidence_ref",
      "expected_value",
      "key",
      "predicate",
      "required"
    ],
    "required_rollback_fields": [
      "rollback_command",
      "strategy",
      "timeout_secs",
      "verify_command"
    ],
    "required_confidence_input_fields": [
      "evidence_ref",
      "key",
      "rationale",
      "score"
    ],
    "allowed_fix_intents": ["..."],
    "allowed_precondition_predicates": ["contains", "eq", "exists", "gte", "lte"],
    "allowed_rollback_strategies": ["..."],
    "confidence_weights": [
      {"key": "analyzer_confidence", "weight_bps": 3200, "rationale": "..."}
    ],
    "risk_bands": [
      {
        "band_id": "critical_risk",
        "min_score_inclusive": 0,
        "max_score_inclusive": 39,
        "requires_human_approval": true,
        "allow_auto_apply": false
      }
    ],
    "compatibility": {
      "minimum_reader_version": "doctor-remediation-recipe-v1",
      "supported_reader_versions": ["doctor-remediation-recipe-v1"],
      "migration_guidance": [{"from_version": "doctor-remediation-recipe-v0", "to_version": "doctor-remediation-recipe-v1", "breaking": false, "required_actions": ["..."]}]
    }
  },
  "fixtures": [
    {
      "fixture_id": "fixture-guarded-auto-apply",
      "description": "...",
      "recipe": {"recipe_id": "recipe-*", "finding_id": "...", "fix_intent": "...", "preconditions": ["..."], "rollback": {"...": "..."}, "confidence_inputs": ["..."]},
      "expected_confidence_score": 80,
      "expected_risk_band": "guarded_auto_apply",
      "expected_decision": "apply"
    }
  ]
}
```

## Determinism and Validation Rules

`validate_remediation_recipe_contract` enforces:

1. lexical ordering + uniqueness of deterministic string arrays
2. required recipe fields are present
3. confidence weights are non-zero and sum to exactly `10_000` bps
4. risk bands are contiguous and gap-free over `0..=100`
5. compatibility metadata is complete and migration actions are deterministic

`validate_remediation_recipe` enforces:

1. `recipe_id` must be a `recipe-*` slug
2. `fix_intent`, predicates, and rollback strategy must be in contract allowlists
3. preconditions and confidence inputs must be lexically ordered and unique by key
4. rollback commands must be single-line command strings with non-zero timeout
5. confidence inputs must provide required evidence references and per-input rationale

`parse_remediation_recipe` fails closed on invalid JSON or schema violations.

## Confidence Scoring Model

`compute_remediation_confidence_score` computes:

```text
score = floor(sum(input_score * weight_bps) / 10_000)
```

Where:

- each `input_score` is in `0..=100`
- `weight_bps` values come from the contract
- contributions are emitted as deterministic trace strings

Risk band selection is policy-driven by score interval. Output includes:

- `confidence_score`
- `risk_band`
- `requires_human_approval`
- `allow_auto_apply`
- `weighted_contributions`

## Structured Logging Expectations

`run_remediation_recipe_smoke` emits deterministic remediation-flow events via `doctor-logging-v1`:

- `remediation_apply`
- `remediation_verify`
- `verification_summary`

Events include rule-evaluation context, confidence contributions, and rejection or override rationale fields when applicable, with stable `run_id`/`scenario_id`/`trace_id` correlation.

## Guided Preview/Apply Pipeline

Track 4 guided remediation uses a staged preview -> apply -> verify flow:

1. `build_guided_remediation_patch_plan` generates a deterministic patch plan with:
   - explicit diff preview (`---/+++` hunk headers + intent line)
   - impacted invariants list
   - staged approval checkpoints before mutation
   - rollback-point metadata and rollback instructions
   - operator guidance for accept/reject/recovery decisions
2. `run_guided_remediation_session` executes one deterministic session:
   - preview phase logs decision checkpoint and patch metadata without mutation
   - apply phase enforces checkpoint approval guardrails before mutation
   - verify phase records trust delta + unresolved risk flags
   - summary phase records recovery instructions for partial/failing applies
3. `run_guided_remediation_session_smoke` runs deterministic success/failure sessions and validates replay-ready event streams.

### Staged Approval Checkpoints

The canonical checkpoint sequence is:

- `checkpoint_diff_review`
- `checkpoint_risk_ack`
- `checkpoint_rollback_ready`
- `checkpoint_apply_authorization`

Mutation is blocked until all checkpoints are approved.

### Idempotency and Rollback Semantics

- Re-applying the same `idempotency_key` yields `idempotent_noop` (no mutation).
- Apply failures are classified deterministically (`blocked_pending_approval`, `partial_apply_failed`, etc.).
- Every apply attempt includes rollback instructions and rollback-point artifact pointers in structured logs.

### Operator Guidance

Guidance text is embedded in patch plans and summary events:

- when to accept an apply request
- when to reject and escalate for human approval
- how to recover from partial application states (rollback + verify + rerun preview)

## Post-Remediation Verification Loop and Trust Scorecard

After preview/apply sessions complete, Track 4 verification uses:

- `compute_remediation_verification_scorecard`
- `run_remediation_verification_loop_smoke`

The loop recomputes diagnostics from verify-stage evidence and emits per-scenario
scorecard entries with:

- `trust_score_before`
- `trust_score_after`
- `trust_delta`
- `unresolved_findings`
- `confidence_shift` (`improved|stable|degraded`)
- `recommendation` (`accept|monitor|escalate|rollback`)

Scorecard recommendation policy is threshold-driven:

- accept when trust score and trust delta clear configured acceptance thresholds and no unresolved findings remain
- escalate when score drops below escalation threshold or unresolved findings persist without positive movement
- rollback when verification status explicitly requests rollback or trust delta crosses rollback threshold
- monitor otherwise

Structured logs for scorecards use `doctor-logging-v1` remediation
`verification_summary` events and include before/after metrics, unresolved findings,
confidence shifts, recommendation rationale, and replay pointers.

## Safe Extension Strategy

1. Additive only within `doctor-remediation-recipe-v1`:
   - new optional recipe metadata fields
   - new fixture entries
   - additional fix intents/predicates/rollback strategies (must stay lexical and validated)
2. Version bump required for:
   - required field changes
   - confidence weight semantics or score formula changes
   - risk-band decision policy changes
3. Consumers should:
   - fail closed on unknown contract versions
   - validate contract + recipe payloads before execution
   - persist emitted confidence traces and decision rationale for replay/audit
