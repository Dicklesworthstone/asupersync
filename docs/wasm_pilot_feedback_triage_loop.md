# Browser Pilot Feedback Triage and Roadmap Assimilation Loop (WASM-16)

Contract ID: `wasm-pilot-feedback-triage-loop-v1`  
Bead: `asupersync-umelq.17.3`  
Depends on: `asupersync-umelq.17.1`, `asupersync-umelq.16.5`

## Goal

Define a deterministic loop that turns pilot feedback into prioritized,
traceable roadmap actions without weakening runtime invariants.

This loop must always answer:

1. what user impact was reported,
2. why a given signal was prioritized or deferred,
3. which bead/owner was assigned,
4. how to replay supporting evidence.

## Canonical Inputs and Outputs

Inputs:

- `artifacts/pilot/pilot_cohort_eval.json` (cohort eligibility context)
- `artifacts/pilot/pilot_observability_summary.json` (SLO/parity context)
- `artifacts/pilot/pilot_feedback_events.json` (user and operator feedback payloads)

Outputs:

- `artifacts/pilot/pilot_feedback_triage_report.json`
- `artifacts/pilot/pilot_feedback_triage_decisions.ndjson`
- optional Beads issue ids for newly created follow-up work

## Triage Taxonomy

Each feedback item is classified into exactly one primary class:

| Class ID | Meaning | Severity Weight | Examples |
|---|---|---:|---|
| `runtime_correctness` | Invariant or semantic correctness concern | 50 | cancellation/drain leak, quiescence violation |
| `determinism_replay` | Replay mismatch, missing trace evidence, nondeterministic behavior | 40 | flaky reproduction, missing replay command |
| `security_policy` | Redaction/auth/provenance/guardrail policy failure | 45 | unredacted artifact, capability boundary breach |
| `performance_budget` | Regression beyond declared budget/SLO envelope | 30 | startup or throughput drift outside policy |
| `dx_adoption` | Documentation/API ergonomics causing migration friction | 20 | unclear migration step, missing adapter guidance |

Secondary tags (multi-value) may include:
`framework`, `profile`, `feature_family`, `affected_artifact`, `owner_route`.

## Deterministic Prioritization Formula

For each feedback item:

```text
priority_score =
  severity_weight
  + user_impact_weight
  + reproducibility_weight
  + recency_weight
  - workaround_weight
```

Normalized component rules:

- `severity_weight`: from taxonomy table (`20` to `50`)
- `user_impact_weight`: `0|10|20` (single user / pilot cohort / cross-cohort)
- `reproducibility_weight`: `20` when deterministic repro exists, else `0`
- `recency_weight`: `0|5|10` from event age bucket
- `workaround_weight`: `0|5|15` from validated mitigation availability

Tie-breaker order (strict):

1. higher `priority_score`
2. higher `severity_weight`
3. lexicographically smaller `feedback_id`

## Roadmap Assimilation Rules

| Score Band | Action | SLA | Expected Owner |
|---|---|---|---|
| `>= 85` | Create/assign P0 follow-up bead immediately | same day | track owner + oncall |
| `65-84` | Create/assign P1/P2 bead in next planning cycle | <= 3 days | area maintainer |
| `45-64` | Queue with explicit rationale and monitor trigger | weekly review | roadmap triage owner |
| `< 45` | Archive with rationale and re-open criteria | monthly review | docs/support owner |

All non-created items must still emit a rationale record with clear reopen
conditions.

## Decision Log Schema (Required)

Every triage decision row must include:

- `ts`
- `feedback_id`
- `class_id`
- `priority_score`
- `severity_weight`
- `user_impact_weight`
- `reproducibility_weight`
- `workaround_weight`
- `decision` (`create_bead` | `queue` | `defer` | `close`)
- `rationale`
- `owner_route`
- `linked_bead_id` (nullable)
- `evidence_artifacts`
- `replay_command`
- `trace_pointer`

This schema is mandatory for later GA readiness and postmortem audits.

## End-to-End Loop (Deterministic Command Bundle)

```bash
python3 scripts/evaluate_wasm_pilot_cohort.py --self-test

python3 scripts/evaluate_wasm_pilot_cohort.py \
  --telemetry-input artifacts/pilot/pilot_observability_events.json \
  --telemetry-output artifacts/pilot/pilot_observability_summary.json \
  --telemetry-log-output artifacts/pilot/pilot_observability_alerts.ndjson

bash scripts/test_wasm_pilot_observability_e2e.sh

bash ./scripts/run_all_e2e.sh --verify-matrix

rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_wasm_pilot_feedback_docs cargo test --test wasm_pilot_feedback_triage_loop -- --nocapture
```

Optional reproducibility fingerprint:

```bash
sha256sum artifacts/pilot/pilot_observability_summary.json \
  artifacts/pilot/pilot_observability_alerts.ndjson
```

## Escalation Policy

Escalate immediately when either condition holds:

1. `runtime_correctness` or `security_policy` item has no deterministic repro.
2. identical feedback class appears in 2+ pilot cohorts inside 7 days.

Escalation payload must include:

- feedback ids and class ids,
- computed scores and tie-break decisions,
- command output and artifact pointers,
- recommended bead owner + thread id.

## Cross-References

- `docs/wasm_pilot_cohort_rubric.md`
- `docs/wasm_pilot_observability_contract.md`
- `docs/wasm_rationale_index.md`
- `docs/wasm_troubleshooting_compendium.md`
- `docs/integration.md`
