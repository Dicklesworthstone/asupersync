# Browser Pilot Cohort Rubric and Success Criteria (WASM-16)

Contract ID: `wasm-pilot-cohort-rubric-v1`  
Bead: `asupersync-umelq.17.1`  
Depends on: `asupersync-umelq.16.2`, `asupersync-umelq.18.1`

## Goal

Define who qualifies for Browser Edition pilot intake, what they are allowed to
exercise, and how success is measured without drifting beyond current runtime
guarantees.

This rubric is strict by design: pilot quality is more important than pilot
volume.

## Selection Rubric

Each candidate is scored deterministically (`0-100`) and assigned a risk tier.

| Dimension | Points | Rule |
|---|---:|---|
| Browser profile fit | 30 | `FP-BR-DET` or `FP-BR-DEV` gets max points |
| Framework readiness | 30 | `vanilla`, `react`, `next` each contributes points |
| Replay/CI readiness | 25 | replay pipeline + CI present |
| Security ownership | 10 | named security owner present |
| Pilot support ownership | 5 | named support contact present |

Eligibility baseline:

1. Candidate uses an allowed profile (`FP-BR-MIN`, `FP-BR-DEV`, `FP-BR-PROD`, `FP-BR-DET`).
2. Candidate requests no deferred surfaces from DSR (`PLAN_TO_BUILD_ASUPERSYNC_IN_WASM_FOR_USE_IN_BROWSERS.md`, Section 6.6).
3. Candidate selects at least one supported framework lane (`vanilla`, `react`, `next`).

Risk tier policy:

- `low`: eligible candidate with score `>= 70` and replay pipeline available
- `medium`: eligible but replay or profile posture needs tighter controls
- `high`: any candidate requesting deferred surfaces or violating baseline constraints

## Exclusions and Non-Goals

Immediate exclusion conditions:

- requests any deferred-surface capability (`DSR-001` .. `DSR-007`)
- unknown/unsupported browser profile
- no declared framework integration target

Pilot scope exclusions:

- native socket/listener assumptions
- native DB client expectations (`sqlite`, `postgres`, `mysql`)
- OS process/filesystem/signal flows
- native transport assumptions (`kafka`, `quic_native`, `http3_native`)

## Deterministic Cohort Evaluation Automation

Evaluator script:

- `scripts/evaluate_wasm_pilot_cohort.py`

Unit checks:

```bash
python3 scripts/evaluate_wasm_pilot_cohort.py --self-test
```

Evaluation run:

```bash
python3 scripts/evaluate_wasm_pilot_cohort.py \
  --input artifacts/pilot/candidates.json \
  --output artifacts/pilot/pilot_cohort_eval.json \
  --log-output artifacts/pilot/pilot_intake.ndjson
```

Output contract:

- `artifacts/pilot/pilot_cohort_eval.json` (`asupersync-pilot-cohort-eval-v1`)
- `artifacts/pilot/pilot_intake.ndjson` (`pilot_intake_evaluation` events)

## Intake Log Schema (Required Fields)

Every intake event must include:

- `ts`
- `event` (`pilot_intake_evaluation`)
- `candidate_id`
- `profile`
- `frameworks`
- `eligible`
- `score`
- `risk_tier`
- `warning_flags`
- `exclusion_reasons`
- `source_file`

These fields are mandatory for support handoff and reproducible triage.

## Pilot Dry-Run Matrix (E2E Onboarding)

Before admitting a cohort batch, run onboarding dry-runs:

```bash
# Scenario-level onboarding checks (uses rch for heavy cargo commands)
python3 scripts/run_browser_onboarding_checks.py --scenario vanilla
python3 scripts/run_browser_onboarding_checks.py --scenario react
python3 scripts/run_browser_onboarding_checks.py --scenario next
```

Required artifacts for each scenario:

- `artifacts/onboarding/<scenario>.ndjson`
- `artifacts/onboarding/<scenario>.summary.json`
- step-level logs referenced by each NDJSON row

Admission rule:

- `vanilla` and `react` must pass for pilot acceptance.
- `next` failures must be explicitly triaged with blocker routing and repro
  command references before onboarding Next-focused cohorts.

## Success Criteria

Pilot cohort success is measured on three axes:

1. Reliability:
   - no unresolved obligation leak incidents in pilot traces
   - region-close quiescence invariants hold in replayed failures
2. Performance:
   - no budget regressions relative to `WASM_SIZE_PERF_BUDGETS.md`
   - cold-start and steady-state checks remain within selected profile thresholds
3. Integration friction:
   - onboarding failures are reproducible from artifacts
   - remediation guidance resolves issues without ad-hoc undocumented steps

## Escalation and Support Expectations

Escalate to track owners immediately when:

- candidate requires deferred surfaces as hard requirement
- profile closure check fails with dependency/provenance blockers
- onboarding failure has no deterministic repro artifact

Escalation payload must include:

- candidate id + selected profile
- failing command
- artifact paths (`ndjson`, summary, step log)
- mapped owning bead/thread id for remediation
