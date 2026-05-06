# Authority Flow Audit Contract

Bead: `asupersync-1508v.7.6`

## Purpose

This contract defines the adversarial validation corpus for authority flow: abuse scenarios covering confused-deputy, stale-token, over-delegation, replay, revocation races, depth bypass, sandbox escape, and ambient authority. Revocation drills verify fail-closed behavior. Audit evidence requirements ensure incident traceability.

## Contract Artifacts

1. Canonical artifact: `artifacts/authority_flow_audit_v1.json`
2. Smoke runner: `scripts/run_authority_flow_audit_smoke.sh`
3. Invariant suite: `tests/authority_flow_audit_contract.rs`

## Abuse Scenarios

| Scenario | Attack | Expected |
|----------|--------|----------|
| AFA-CONFUSED-DEPUTY | Token scoped to wrong seam | deny |
| AFA-STALE-TOKEN | Expired token used | deny |
| AFA-OVER-DELEGATION | Child grants more than parent | deny |
| AFA-REPLAY-ATTACK | Single-use token replayed | deny |
| AFA-REVOCATION-RACE | Use during revocation window | deny |
| AFA-DEPTH-BYPASS | Exceed max delegation depth | deny |
| AFA-SANDBOX-ESCAPE | Bypass membrane for direct mutation | deny |
| AFA-AMBIENT-AUTHORITY | Operate without presenting token | deny |

## Revocation Drills

| Drill | Description |
|-------|-------------|
| RD-SINGLE-REVOKE | Revoke one token, verify immediate denial |
| RD-CASCADE-REVOKE | Revoke parent, verify descendants denied |
| RD-EXPIRY-AUTO | Advance past expiry, verify denial |
| RD-REVOKE-DURING-RECOVERY | Revoke during recovery, verify persistence |

## Audit Evidence

| Evidence | Required Log Fields |
|----------|-------------------|
| AE-TOKEN-PROVENANCE | token_id, issuer_id, capabilities, caveats, action_id |
| AE-DENIAL-REASON | denial_reason, expected_capability, caveat_violation |
| AE-REVOCATION-TRAIL | revoked_token_id, cascade_count, revocation_reason |
| AE-RECOVERY-AUTHORITY | domain_id, old_capabilities, new_capabilities, recovery_phase |

## Validation

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_authority_flow_audit cargo test -p asupersync --test authority_flow_audit_contract --features test-internals -- --nocapture
```

## Cross-References

- `artifacts/authority_flow_audit_v1.json`
- `artifacts/capability_token_model_v1.json` -- Token structure and attenuation
- `artifacts/controller_sandbox_membrane_v1.json` -- Sandbox membrane
- `artifacts/failure_domain_compiler_v1.json` -- Recovery authority rules
- `src/runtime/kernel.rs` -- ControllerRegistry
