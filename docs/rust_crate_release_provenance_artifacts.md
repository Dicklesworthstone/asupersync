# Rust Crate Release Provenance Artifacts

Primary bead: `asupersync-release-provenance-core-crates-jpts8n.2`

This page explains the artifact contract in
[`artifacts/rust_crate_release_provenance_contract_v1.json`](../artifacts/rust_crate_release_provenance_contract_v1.json).
It is the R2 machine-readable layer for Rust crates.io provenance. It does not
publish crates, build packages, or replace the existing browser/WASM provenance
bundle.

The companion integrity manifest is
[`artifacts/rust_crate_release_provenance_integrity_manifest_v1.json`](../artifacts/rust_crate_release_provenance_integrity_manifest_v1.json).
It indexes the R2 contract, this operator page, and the R1 policy baseline. The
manifest intentionally excludes a self-hash to avoid a circular digest.

## Artifact Classes

| Class | Meaning | Citeable for | Not citeable for |
|---|---|---|---|
| `contract_fixture` | Checked shape and fixture examples for the Rust crate provenance schema. | Required fields, package surface inventory, fixture status semantics. | Release readiness, real publish outcome, real tarball integrity. |
| `dry_run_only` | A package dry run produced package/integrity evidence but no live publish is claimed. | Dry-run command and artifact existence. | crates.io visibility or live publication. |
| `already_published_noop` | The workflow found the package version already visible and skipped publish idempotently. | Idempotent no-op semantics and expected visibility check. | A fresh publish event. |
| `published` | A future live publish record with a successful visibility check. | Live publish outcome for that package only. | Runtime correctness or broad workspace health. |
| `superseded` | A retained historical record that points at a successor. | Audit history. | Current evidence unless the successor is cited. |

## Fixture Scope

The R2 contract includes three fixture records:

| Fixture | Package role | Status modeled |
|---|---|---|
| `fixture-asupersync-0.3.4-dry-run` | runtime core | `dry_run_only` |
| `fixture-franken-kernel-0.3.4-already-published` | support crate | `already_published_noop` |
| `fixture-asupersync-tokio-compat-0.3.4-dry-run` | satellite crate | `dry_run_only` |

The tarball hashes in these fixtures are deterministic hashes of explicit
fixture strings. They are not hashes of real `.crate` files. Future workflow
integration must replace fixture hashes with hashes of the package bytes created
by the publish or dry-run path.

## Required Record Fields

Every real Rust crate release provenance record must include:

- package name, version, manifest path, role, and publish order,
- release tag and exact git commit,
- SHA-256 digests for `Cargo.lock`, root `Cargo.toml`, and package
  `Cargo.toml`,
- `cargo metadata --no-deps --format-version 1` package snapshot,
- dependency/license/SBOM rows used for release review,
- dry-run command and outcome,
- package tarball SHA-256,
- publish command with credentials redacted,
- publish outcome and crates.io visibility check,
- integrity manifest path and digest,
- no-claim boundaries.

## Non-Destructive Supersession

Release provenance artifacts are append-and-supersede. Do not delete older
records during cleanup. If a record is replaced, set status to `superseded`,
retain the old record, and point `successor_record_id` at the replacement.

Ephemeral package outputs belong under an isolated target or temporary release
directory until promoted. Committed fixtures and contracts belong under
`artifacts/`, `docs/`, `tests/`, or an established release-artifact location.

## Validation Boundary

The direct-main Cargo proof policy from
[`docs/rust_crate_release_provenance_policy.md`](rust_crate_release_provenance_policy.md)
still applies: Cargo build, test, package, or dry-run proof commands must use
`RCH_REQUIRE_REMOTE=1 rch exec --` with an isolated `CARGO_TARGET_DIR`.

This R2 artifact contract does not prove:

- release readiness,
- actual crates.io publication,
- runtime correctness,
- broad workspace health,
- security audit completion,
- real package tarball integrity.
