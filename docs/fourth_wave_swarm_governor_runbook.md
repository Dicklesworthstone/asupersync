# Fourth-Wave Swarm Governor Runbook

This runbook is the operator entrypoint for `asupersync-86fe9v.5` fourth-wave governor signoff. It ties together the schema, pure policy engine, deterministic replay corpus, explicit runtime bridge, benchmark contract, proof manifest, and proof-status rows without converting any of those contracts into a fresh performance claim.

Document path: `docs/fourth_wave_swarm_governor_runbook.md`.

Canonical surfaces:

- `artifacts/fourth_wave_swarm_governor_contract_v1.json`
- `artifacts/swarm_workload_scenario_corpus_v1.json`
- `artifacts/slo_policy_bundle_contract_v1.json`
- `artifacts/fourth_wave_swarm_governor_benchmark_contract_v1.json`
- `artifacts/proof_lane_manifest_v1.json`
- `artifacts/proof_status_snapshot_v1.json`
- `tests/fourth_wave_swarm_governor_runbook_contract.rs`

## Single Proof Command

Run the runbook verifier with remote-required RCH and an isolated target dir:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_fourth_wave_governor_runbook CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test fourth_wave_swarm_governor_runbook_contract -- --nocapture
```

This is the `fourth-wave-governor-signoff-runbook` manifest lane. It proves only that the operator text, manifest rows, proof-status rows, README/AGENTS markers, no-local-fallback language, decision taxonomy, rollback guidance, and no-claim boundaries stay aligned.

## Clean Tree And Coordination

Before running or citing any fourth-wave lane:

1. Check the shared tree with `git status --short --branch`.
2. Confirm work is on `main`; do not create branches, worktrees, or scratch clones.
3. Reserve touched files with `file_reservation_paths`, renew long leases with `renew_file_reservations`, and release them with `release_file_reservations`.
4. Check Agent Mail, acknowledge messages that require it, and send an Agent Mail closeout with exact proof commands and outcomes.
5. Leave peer dirt unstaged. If unrelated peer changes block a broad lane, cite the blocker and run only a narrower supplemental proof for your touched files.
6. Push with `git push origin main` and mirror legacy URLs with `git push origin main:master` only after the commit is ready.

## Fourth-Wave Proof Map

The fourth-wave governor proof map is intentionally split:

| Proof slice | Manifest lane | Claim boundary |
|-------------|---------------|----------------|
| Schema and decision receipt | `fourth-wave-governor-schema-contract` | Schema fields, fail-closed evidence rows, redaction, stable ordering, and non-claims only |
| Pure policy engine | `fourth-wave-governor-policy-engine` | Deterministic receipt selection for malformed, missing, local fallback, stale, advisory-only, no-worker, brownout, and admit cases |
| Replay corpus | `fourth-wave-swarm-replay-corpus` | Deterministic large-host workload dimensions and stable scenario fixtures |
| Runtime bridge | `fourth-wave-runtime-bridge-contract` | Explicit opt-in `Cx` bridge behavior, base SLO preservation, cancellation precedence, brownout, no-worker defer, fail-closed receipts, and redaction |
| Benchmark contract | `fourth-wave-benchmark-contract` | Scenario catalog, compare modes, metric fields, log fields, RCH refresh commands, flamegraph targets, and no-claim report |
| Aggregate signoff | `fourth-wave-governor-signoff-runbook` | Operator checklist alignment only |

The fourth-wave final aggregated signoff is yellow-scoped until every child lane has fresh remote proof and any benchmark refresh artifacts are committed and classified.

## Child Lane Commands

Run child lanes through RCH. No local fallback is permitted for these Cargo proof lanes.

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_fourth_wave_governor_schema_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test fourth_wave_swarm_governor_contract -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_fourth_wave_policy_engine CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --lib fourth_wave_governor --features test-internals -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_fourth_wave_swarm_replay_corpus CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test swarm_workload_scenario_corpus_contract -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_fourth_wave_runtime_bridge CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test slo_policy_bundle_contract runtime_slo_policy_bridge_fourth_wave --features test-internals -- --nocapture
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_fourth_wave_benchmark_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test fourth_wave_swarm_governor_benchmark_contract -- --nocapture
```

Do not cite a zero-test exact filter as green proof. If a filtered command reports zero tests, fix the manifest lane before closing the bead.

## Decision Receipt Taxonomy

Read `selected_action`, `rule_id`, `fail_closed`, `non_action_reason`, `rejected_rows`, and `non_claims` before summarizing a receipt.

| Receipt action | Operator meaning | Closeout rule |
|----------------|------------------|---------------|
| `admit_required_work` | Required work may continue under the base SLO decision | Cite the decision id and covered work class only |
| `brownout_optional_work` | Optional work is browned out before start | Cite brownout reason and drained/denied optional work evidence |
| `defer_no_remote_worker` | Remote-required lane has no admissible worker | Treat as no-win delay, not a local fallback |
| `fail_closed_malformed_input` | Input shape is invalid | Block the lane and fix schema or collector output |
| `fail_closed_missing_evidence` | Required evidence class is absent | Block the lane until the missing evidence is collected |
| `fail_closed_local_rch_fallback` | A local Cargo fallback marker was detected | Reject the proof and rerun through RCH |
| `fail_closed_stale_evidence` | Evidence is older than the freshness policy | Refresh the evidence before citation |
| `fail_closed_advisory_only` | Evidence lacks replay-backed or remote-backed authority | Keep the result advisory and do not take runtime action |

Brownout, no-win, and blocked outcomes are valid receipts, not degraded passes.

## No Local Fallback

Every Cargo proof command in this runbook must start with `RCH_REQUIRE_REMOTE=1 rch exec -- env` and include `CARGO_TARGET_DIR=`. Treat these transcript markers as failures:

- `[RCH] local`
- `Executing command locally`
- `local fallback accepted`
- `falling back to local execution`

A remote-required proof can be green only when the transcript shows remote execution and exits 0 with nonzero test evidence. RCH refusal, worker timeout, active project exclusion, SSH timeout, and local fallback are fail-closed operator outcomes.

## Bridge Rollback

The runtime bridge is explicit opt-in through `SloRuntimePolicyBridge::evaluate_fourth_wave`. If child evidence is stale, advisory-only, local-fallback-tainted, or contradicted by benchmark refresh results:

1. Stop calling the fourth-wave bridge from the opt-in workload path.
2. Keep the base SLO policy path in place.
3. Preserve the failed receipt and non-claim text in Agent Mail and the bead closeout.
4. do not delete or remove artifacts or files without explicit written permission.
5. Re-run the focused bridge lane after reverting the opt-in call path.

This rollback does not delete the schema, policy engine, corpus, runbook, or benchmark contract. It only removes runtime use of the opt-in control bridge until evidence is strong enough.

## Non-Claims

The fourth-wave benchmark no-claim contract is not a fresh benchmark result. The current proof map makes no claim that:

- fourth-wave control improves p95 latency
- fourth-wave control improves throughput
- fourth-wave control has no regression
- fourth-wave control closes scheduler performance regressions
- fourth-wave control is production-on-by-default
- RCH fleet availability is proven
- broad workspace health is proven

Only committed fresh benchmark artifacts, remote-required transcripts, and reviewed flamegraph attribution can support a later performance claim.
