# WASM TypeScript Type-Model Contract

Contract ID: `wasm-typescript-type-model-v1`  
Bead: `asupersync-umelq.9.2`

## Purpose

Define a deterministic TypeScript semantic model for Browser Edition that
faithfully preserves runtime invariants for:

1. four-valued `Outcome`
2. explicit `Budget`
3. cancellation phase transitions
4. region/task ownership handles

## Canonical Inputs

- Policy: `.github/wasm_typescript_type_model_policy.json`
- Gate script: `scripts/check_wasm_typescript_type_model_policy.py`
- Onboarding runner: `scripts/run_browser_onboarding_checks.py`

## Outcome Contract

`Outcome` must retain the four runtime variants:

1. `ok`
2. `err`
3. `cancelled`
4. `panicked`

Variant removal or renaming fails policy.

## Cancellation Contract

Cancellation phase ordering is normative:

1. `requested`
2. `cancelling`
3. `finalizing`
4. `completed`

Any order drift fails policy.

## Budget Contract

Required `Budget` fields:

1. `pollQuota`
2. `deadlineMs`
3. `priority`
4. `cleanupQuota`

Each field has explicit numeric bounds in policy for deterministic validation.

## Ownership Contract

Required handle kinds:

1. `runtime`
2. `scope`
3. `task`
4. `channel`
5. `obligation`

Required invariants:

1. `single_region_owner`
2. `no_orphan_tasks`
3. `region_close_implies_quiescence`
4. `no_obligation_leaks`

## Framework Scenario Contract

Policy includes deterministic scenario rows for:

1. `TS-TYPE-VANILLA`
2. `TS-TYPE-REACT`
3. `TS-TYPE-NEXT`

Each scenario includes:

1. `package_entrypoint`
2. `adapter_path`
3. `runtime_profile`
4. `repro_command`
5. `diagnostic_category`

## Structured Logging Contract

Onboarding/type-model diagnostics require:

1. `scenario_id`
2. `step_id`
3. `package_entrypoint`
4. `adapter_path`
5. `runtime_profile`
6. `diagnostic_category`
7. `repro_command`
8. `outcome`

## Outputs

- Summary JSON: `artifacts/wasm_typescript_type_model_summary.json`
- NDJSON log: `artifacts/wasm_typescript_type_model_log.ndjson`

## Repro Commands

Self-test:

```bash
python3 scripts/check_wasm_typescript_type_model_policy.py --self-test
```

Full policy gate:

```bash
python3 scripts/check_wasm_typescript_type_model_policy.py \
  --policy .github/wasm_typescript_type_model_policy.json
```

Framework-scoped checks:

```bash
python3 scripts/check_wasm_typescript_type_model_policy.py \
  --policy .github/wasm_typescript_type_model_policy.json \
  --only-scenario TS-TYPE-VANILLA

python3 scripts/check_wasm_typescript_type_model_policy.py \
  --policy .github/wasm_typescript_type_model_policy.json \
  --only-scenario TS-TYPE-REACT

python3 scripts/check_wasm_typescript_type_model_policy.py \
  --policy .github/wasm_typescript_type_model_policy.json \
  --only-scenario TS-TYPE-NEXT
```
