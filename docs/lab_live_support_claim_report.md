# Lab-Live Support Claim Report

`artifacts/lab_live_support_claim_report_v1.json` is the V4 aggregation gate
for `asupersync-idea-wizard-fifth-wave-3gaiun.5.4`. It maps lab/live
differential evidence into documentation and proof-status claims without
promoting unsupported or stale evidence.

The report consumes the existing lab-live scenario contract, the V2 captured
filesystem runner, and the V3 timing/platform policy. It is deliberately scoped:
it can allow a captured-filesystem documentation claim when fresh evidence is
present, but it cannot promote raw host filesystem parity, process support,
signal support, reactor support, or broad workspace health.

## Claim Rules

- Fresh passing evidence can allow a scoped claim only for the exact surface and
  adapter family named by the report row.
- A skipped platform capability is never pass evidence.
- Stale evidence cannot strengthen README or support-matrix claims.
- A failing live comparison must demote, block, or leave the claim unchanged
  until a fresh passing lane exists.
- Every report row must carry no-claim boundaries and a proof-status mapping.

## Demotion Policy

When a previously scoped row receives fresh drift evidence, the support claim is
not kept green. The report must either demote the claim to a blocked or
unsupported state, or refuse the documentation update until the drift is fixed
and the exact manifest lane is rerun through remote-required RCH.

## Proof Lane

The focused verifier is:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_lab_live_support_claim_report" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test lab_live_support_claim_report_contract -- --nocapture
```

This verifier checks the support-claim report artifact, stale-evidence refusal,
drift demotion, README markers, proof-lane manifest mapping, proof-status
snapshot mapping, and no-claim boundaries. It does not execute every child
lab/live lane and does not prove broad workspace health.

## Adding The Next Adapter Family

1. Add or update the adapter-family runner artifact and fixtures.
2. Add a support-claim report row that names the exact claim scope, fixture,
   docs row, proof-status row, and no-claim boundaries.
3. Add at least one stale or failed evidence rehearsal for that family.
4. Add or update README/docs only for the scoped claim proven by fresh evidence.
5. Rerun the focused support-claim report verifier through remote-required RCH.
