# Rust Crate Release Provenance Final Signoff

Primary bead: `asupersync-release-provenance-core-crates-jpts8n.5`

This is the scoped R5 operator packet for the Rust crates.io release provenance
lane. It ties together the R1 policy, R2 artifact schema, R3 publish workflow
gate, and R4 contract verifier. It does not perform a live crates.io publish.

## Artifact Set

| Artifact | Role |
|---|---|
| `artifacts/rust_crate_release_provenance_final_signoff_v1.json` | Machine-readable R5 final signoff packet. |
| `artifacts/rust_crate_release_provenance_dry_run_e2e_v1.log` | Deterministic dry-run e2e fixture log. |
| `docs/rust_crate_release_provenance_final_signoff.md` | Human operator packet. |
| `artifacts/rust_crate_release_provenance_contract_v1.json` | R2 schema and crate surface contract. |
| `.github/workflows/publish.yml` | R3 publish workflow provenance gate. |

## Deterministic Dry-Run E2E

The R5 e2e is a deterministic fixture run of the Rust provenance path. It
models package record creation, package hash capture, integrity/report output,
and final signoff aggregation without `cargo publish` or network-dependent
`cargo publish --dry-run` execution. The publish workflow remains responsible
for real GitHub-hosted package dry-runs and live publication when credentials
are present.

| Order | Package | Status | Record |
|---:|---|---|---|
| 1 | `franken-kernel` | `packaged` | `fixture-e2e-franken-kernel-0.3.4` |
| 2 | `franken-evidence` | `packaged` | `fixture-e2e-franken-evidence-0.3.4` |
| 3 | `franken-decision` | `packaged` | `fixture-e2e-franken-decision-0.3.4` |
| 4 | `asupersync-macros` | `packaged` | `fixture-e2e-asupersync-macros-0.3.4` |
| 5 | `asupersync` | `packaged` | `fixture-e2e-asupersync-0.3.4` |
| 6 | `asupersync-conformance` | `packaged` | `fixture-e2e-asupersync-conformance-0.3.4` |
| 7 | `frankenlab` | `packaged` | `fixture-e2e-frankenlab-0.3.4` |
| 8 | `asupersync-browser-core` | `packaged` | `fixture-e2e-asupersync-browser-core-0.3.4` |
| 9 | `asupersync-tokio-compat` | `packaged` | `fixture-e2e-asupersync-tokio-compat-0.3.4` |

The status vocabulary for this packet is `packaged`, `skipped`,
`already_published`, and `blocked`. All current fixture rows are `packaged`
because the deterministic e2e exercises every crate surface. These rows are not
real `.crate` tarball evidence.

## RCH Proof Commands

Focused manifest lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_rust_crate_release_provenance_contract CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test rust_crate_release_provenance_contract -- --nocapture
```

Closeout verifier used for the R3/R5 packet:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_rust_crate_release_provenance_contract" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo test -p asupersync --test rust_crate_release_provenance_contract --test proof_lane_manifest_contract --test proof_status_snapshot_contract -- --nocapture
```

Local direct-main Cargo proof claims for this lane require RCH and no local
fallback. GitHub-hosted publish execution is runner-specific and may use local
runner Cargo with isolated `CARGO_TARGET_DIR`; credentials are never routed
through RCH.

## Child Evidence

| Bead | Status | Evidence |
|---|---|---|
| `asupersync-release-provenance-core-crates-jpts8n.1` | `closed` | `docs/rust_crate_release_provenance_policy.md` |
| `asupersync-release-provenance-core-crates-jpts8n.2` | `closed` | `artifacts/rust_crate_release_provenance_contract_v1.json` |
| `asupersync-release-provenance-core-crates-jpts8n.3` | `closed` | `.github/workflows/publish.yml` |
| `asupersync-release-provenance-core-crates-jpts8n.4` | `closed` | `tests/rust_crate_release_provenance_contract.rs` |

## Closeout Boundary

This R5 packet is `yellow_scoped_signoff_complete`: it closes the Rust crate
release-provenance evidence lane once the tracker comment, Agent Mail handoff,
and focused RCH verifier are recorded. It does not prove release readiness,
runtime correctness, broad workspace health, security audit completion, live
crates.io publication, or real package tarball integrity.
