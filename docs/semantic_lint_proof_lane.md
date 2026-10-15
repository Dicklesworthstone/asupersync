# Semantic Lint Proof Lane

Status: Active
Bead: `asupersync-idea-wizard-fifth-wave-3gaiun.3.4`
Contract: `artifacts/semantic_lint_proof_lane_contract_v1.json`
Verifier: `tests/semantic_lint_proof_lane_contract.rs`

<!-- SEMANTIC-LINT-L4-PROOF-LANE -->

The aggregate semantic-lint proof lane is `semantic-lint-proof-lane-contract` in
`artifacts/proof_lane_manifest_v1.json`. Its canonical command is:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_semantic_lint_proof_lane CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -j 1 -p asupersync --test semantic_lint_proof_lane_contract --test semantic_lint_rule_inventory_contract --test semantic_lint_diagnostic_codes_contract --test error_code_registry_contract --test semantic_lint_ambient_contract --test semantic_lint_cleanup_budget_contract --test semantic_lint_core_tokio_contract --test semantic_lint_loop_checkpoint_contract --test semantic_lint_ignored_outcome_contract --test semantic_lint_await_holding_contract --test semantic_lint_drop_race_loser_contract -- --nocapture
```

The command is remote-required, pins `CARGO_TARGET_DIR`, and runs the aggregate
contract, rule inventory, ASUP diagnostic code checks, error-code registry
contract, and every semantic-lint per-rule fixture contract.

<!-- SEMANTIC-LINT-L4-SUMMARY-EVENTS -->

The checked summary artifact is
`artifacts/semantic_lint_proof_lane_summary_v1.json`. The checked event stream is
`artifacts/semantic_lint_proof_lane_events_v1.ndjson` with schema
`semantic-lint-proof-lane-event-v1`.

Both artifacts intentionally carry `proof_evidence_status = rerun-required`.
They are contract metadata, not fresh RCH evidence. Fresh evidence requires
rerunning the exact manifest command through RCH.

<!-- SEMANTIC-LINT-L4-FAILURE-REHEARSAL -->

The aggregate lane rehearses semantic-lint failure behavior through existing
per-rule contracts:

1. Positive fixtures must fail with findings.
2. Invalid allow-marker fixtures must fail and must not suppress findings.
3. Unsupported engines must fail closed with deterministic diagnostics.
4. The core-Tokio default-leak fixture must report `ASUP-E908`.

The intended false-positive control surface is the negative-fixture and
valid-allow fixture coverage declared in each per-rule contract.

<!-- SEMANTIC-LINT-L4-NO-CLAIMS -->

A green semantic-lint proof lane reduces known lint-rule drift but is not a formal proof of cancel-correctness. It does not certify broad workspace health, release readiness, performance, live RCH fleet availability, or complete absence of semantic issues outside the declared rule contract surfaces.
