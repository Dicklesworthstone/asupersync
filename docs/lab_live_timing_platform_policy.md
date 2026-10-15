# Lab-Live Timing, Platform Skip, and Failure-Bundle Policy

**Bead**: `asupersync-idea-wizard-fifth-wave-3gaiun.5.3`
**Contract artifact**: `artifacts/lab_live_timing_platform_policy_v1.json`
**Contract test**: `tests/lab_live_timing_platform_policy_contract.rs`

This contract is the fifth-wave V3 policy layer for lab/live differential
reports. It builds on the V1 scenario map and on the older lab-live contracts:

- `docs/lab_live_time_normalization_policy.md`
- `docs/lab_live_virtualized_surface_matrix.md`
- `docs/lab_live_divergence_taxonomy.md`
- `docs/lab_live_verification_taxonomy.md`
- `artifacts/lab_live_differential_scenario_contract_v1.json`

The goal is to make timing normalization, platform capability absence, stale
evidence, failure bundles, and redaction mandatory before a later runner can
claim a lab/live result.

## Verdict Classes

`pass` means the surface is admitted, the platform prerequisites are met, the
failure-bundle fields are present, redaction checks pass, and normalized
semantic fields match.

`fail` means an admitted surface emitted complete evidence and then violated a
semantic field such as region quiescence, obligation balance, loser drain, or a
promoted time outcome.

`skip` means the platform or surface is not admitted. A skip is not pass. A
skipped raw-socket, browser-host, or real-network capability cannot strengthen a
README or support-matrix claim.

`stale` means the claim may be meaningful, but the retained evidence is too old
or missing. Stale is not pass, and it cannot promote support class until a fresh
fixture is run.

## Timing Policy

Every fixture names one of the existing time classes:

- `semantic_time`
- `qualified_time`
- `provenance_only_time`
- `scheduler_noise_signal`
- `unsupported_time_surface`

The rules come from `docs/lab_live_time_normalization_policy.md`. Wall-clock
fields remain provenance unless a scenario declares a clock, deadline, and
normalization window. Scheduler noise can explain a report, but it cannot erase
a hard semantic mismatch.

## Platform Report

Every valid fixture must carry a `platform_report` with:

- `surface_family`
- `host_role`
- `capability_status`
- `eligibility_verdict`
- `observability_status`
- `platform_prerequisites`

This aligns with `docs/lab_live_virtualized_surface_matrix.md`. Capability
absence is classified separately from implementation failure. Missing
virtualization, unsupported host role, or incomplete observability is a skip or
blocked evidence state, not a weak pass.

## Failure Bundle

Every fixture must include a failure bundle with:

- `seed`
- `repro_command`
- `platform`
- `adapter`
- `logs`
- `replay_pointers`
- `redaction`

The `repro_command` must use `rch exec --` for Cargo work. Bundles without seed
lineage, platform identity, adapter identity, structured logs, or replay
pointers are invalid.

## Redaction

The redaction section freezes the minimum privacy contract for retained logs and
operator reports. Fixtures include raw input samples, redacted samples, and
forbidden substrings. The contract test rejects any redacted output that still
contains a forbidden token.

## Fixture Set

The checked fixture set covers:

- `pass_timer_deadline.json`: admitted timer deadline semantics with
  `semantic_time`.
- `fail_region_close.json`: admitted region close semantic failure.
- `skip_raw_socket.json`: unsupported raw socket surface; skip is not pass.
- `stale_browser_evidence.json`: browser support evidence too old to promote.
- `malformed_missing_platform_report.json`: negative fixture rejected for
  missing `platform_report`.

## No-Claim Boundary

Green tests for this contract prove only that the policy artifact, docs, and
fixtures enforce pass/fail/skip/stale classification, redaction, platform
reporting, and failure-bundle shape. They do not run live adapter scenarios,
prove broad workspace health, certify raw OS/browser/network parity, or replace
the V2 adapter-family runner.

## Validation

Use the focused RCH lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_lab_live_timing_platform_policy" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS="-D warnings -C debuginfo=0" cargo test -p asupersync --test lab_live_timing_platform_policy_contract -- --nocapture
```
