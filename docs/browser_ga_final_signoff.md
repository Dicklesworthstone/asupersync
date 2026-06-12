# Browser GA Final Signoff

Contract ID: `browser-ga-final-signoff-v1`
Bead: `asupersync-idea-wizard-fifth-wave-3gaiun.4.4`

Canonical machine artifact:
`artifacts/browser_ga_final_signoff_v1.json`.

## Scope

This B4 packet is the scoped Browser Edition GA signoff for the JS/TS package
line:

- `@asupersync/browser-core`
- `@asupersync/browser`
- `@asupersync/react`
- `@asupersync/next`

The packet decision is `pass_scoped_js_ts_ga` for the `stable` release channel
when B1 readiness, B2 package integrity, B3 consumer compatibility, and this
B4 signoff lane pass in the same candidate window.

Rust browser API remains preview-only. Service-worker and shared-worker direct
runtime remain unsupported; those rows are broker/coordinator-only. This B4
packet does not execute npm publish, does not prove broad workspace health, and
does not promote native-only browser capability parity.

## Source Evidence

| Evidence | Artifact | Contract | Boundary |
|---|---|---|---|
| B1 readiness | `artifacts/browser_edition_readiness_matrix_v1.json` | `tests/browser_edition_readiness_matrix_contract.rs` | Support classes, rollback status, row freshness, and no-claims. |
| B2 package integrity | `artifacts/browser_package_integrity_gate_v1.json` | `tests/browser_package_integrity_gate_contract.rs` | Package metadata, ABI, integrity, SBOM/provenance, bundle budget, rollback, and readiness aggregation. |
| B3 consumer compatibility | `artifacts/browser_consumer_compatibility_matrix_v1.json` | `tests/browser_consumer_compatibility_matrix_contract.rs` | Consumer fixture compatibility and fail-closed unsupported rows. |
| B4 final signoff | `artifacts/browser_ga_final_signoff_v1.json` | `tests/browser_ga_final_signoff_contract.rs` | Aggregated JS/TS package GA signoff and rollback drill. |

## Package Versions

All Browser Edition JS/TS packages in this packet are version `0.3.4`. The
machine artifact records the package manifest hash and every committed package
artifact hash used by the signoff. A changed hash without a matching refreshed
B2/B4 packet is a release-blocking mismatch.

## Rollback Drill

Rollback rehearsal fixture:
`tests/fixtures/browser_ga_final_signoff/rollback_drill.json`.

The fixture must fail closed for:

- `bad_browser_core_wasm_digest`
- `abi_metadata_mismatch`
- `consumer_compatibility_regression`
- `rust_preview_stable_overclaim`

Bad package digest and ABI metadata mismatch block package GA. Consumer
regression demotes the candidate to canary. A Rust preview stable overclaim is
rejected and keeps `RuntimeBuilder::browser()` preview-only.

## Focused Proof

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_browser_ga_final_signoff CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test browser_ga_final_signoff_contract -- --nocapture
```

This command verifies the signoff artifact, rollback drill, package hashes,
support-class boundaries, docs freshness markers, proof-lane manifest row, and
proof-status row.
