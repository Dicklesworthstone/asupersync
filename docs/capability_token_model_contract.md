# Capability Token Model Contract

Bead: `asupersync-1508v.7.4`

## Purpose

This contract defines the distributed capability token model for Asupersync: attenuated delegation, expiry, caveats, revocation, auditability, and interop with the existing local capability boundary. Local-only operation remains the default baseline.

## Contract Artifacts

1. Canonical artifact: `artifacts/capability_token_model_v1.json`
2. Smoke runner: `scripts/run_capability_token_model_smoke.sh`
3. Invariant suite: `tests/capability_token_model_contract.rs`

## Token Structure

Tokens carry explicit authority grants:

| Field | Description |
|-------|-------------|
| token_id | Unique identifier |
| issuer_id | Who issued this token |
| subject_id | Who this token authorizes |
| capabilities | Set of CAP-* grants |
| caveats | Restrictions (seam, time, rate, single-use) |
| expiry_epoch | When the token expires |
| attenuation_depth | How many delegations deep |
| parent_token_id | Parent token (null for root) |

## Capability Hierarchy

```
CAP-ADMIN
  -> CAP-PROMOTE, CAP-ROLLBACK, CAP-DECIDE, CAP-OBSERVE
CAP-PROMOTE
  -> CAP-DECIDE, CAP-OBSERVE
CAP-DECIDE
  -> CAP-OBSERVE
CAP-ROLLBACK
  -> CAP-OBSERVE
CAP-OBSERVE
  -> (leaf)
```

## Attenuation Rules

1. **ATT-MONOTONIC**: Child capabilities subset of parent
2. **ATT-EXPIRY**: Child expiry <= parent expiry
3. **ATT-DEPTH**: Depth strictly increasing, max 5
4. **ATT-CAVEAT-UNION**: Child inherits all parent caveats
5. **ATT-NO-AMPLIFICATION**: No operation produces excess authority

## Revocation

- **REV-EXPLICIT**: Issuer revokes by token ID
- **REV-CASCADE**: Parent revocation cascades to descendants
- **REV-EXPIRY**: Automatic on epoch boundary
- Zero grace period; revocation is synchronous

## Threat Model

| Scenario | Mitigation |
|----------|-----------|
| TM-AMPLIFICATION | Monotonic attenuation enforced at mint |
| TM-REPLAY | Nonce and single-use caveat |
| TM-STALE-REVOCATION | Synchronous revocation, zero grace |
| TM-DEPTH-ESCAPE | Depth check at mint time |

## Validation

```bash
rch exec -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-C debuginfo=0' CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_capability_token_model cargo test -p asupersync --test capability_token_model_contract --features test-internals -- --nocapture
```

## Cross-References

- `artifacts/capability_token_model_v1.json`
- `src/runtime/kernel.rs` -- ControllerRegistry, controller registration
- `artifacts/runtime_kernel_snapshot_contract_v1.json` -- Snapshot schema
