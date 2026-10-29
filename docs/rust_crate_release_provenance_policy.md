# Rust Crate Release Provenance Policy

Primary bead: `asupersync-release-provenance-core-crates-jpts8n.1`
Status: inventory and policy baseline

## Goal

Define the Rust crates.io release surface before adding provenance artifact
generation, publish gates, or final signoff packets. This policy covers Rust
crate packages published by `.github/workflows/publish.yml`; it is separate
from the existing WASM/browser SBOM, browser package, and npm provenance lane.

## Current Publish Surface

The retained `.github/workflows/publish.yml` publishes crates in the order
below when explicitly enabled, the release tag is not a prerelease, and
`CARGO_REGISTRY_TOKEN` is configured. GitHub Actions remains disabled under
the owner decision in `AGENTS.md`; the established RCH/DSR release route is
unchanged. This table describes the current 0.6.0 candidate, not a delivered
release.

The workflow uses `cargo metadata --no-deps --format-version 1` to read
versions and dependencies from the workspace. Before any package or publish,
`scripts/ci/release_source.py --check-publish-order <metadata.json>` compares
the workflow order and `published_crate_surface` against that graph. Every
publishable workspace member must appear exactly once, with normal and build
dependencies before their consumers. Optional, renamed and target-specific
dependencies are included. Development dependency cycles do not constrain
publication order.

| Order | Package | Manifest | Candidate version | Role |
|---:|---|---|---|---|
| 1 | `franken-kernel` | `franken_kernel/Cargo.toml` | `0.6.0` | FrankenSuite support |
| 2 | `franken-evidence` | `franken_evidence/Cargo.toml` | `0.6.0` | FrankenSuite support |
| 3 | `franken-decision` | `franken_decision/Cargo.toml` | `0.6.0` | FrankenSuite support |
| 4 | `asupersync-macros` | `asupersync-macros/Cargo.toml` | `0.6.0` | proc macro |
| 5 | `asupersync-zstd` | `asupersync-zstd/Cargo.toml` | `0.6.0` | compression codec |
| 6 | `asupersync` | `Cargo.toml` | `0.6.0` | runtime core |
| 7 | `asupersync-conformance` | `conformance/Cargo.toml` | `0.6.0` | conformance |
| 8 | `frankenlab` | `frankenlab/Cargo.toml` | `0.6.0` | deterministic testing harness |
| 9 | `asupersync-browser-core` | `asupersync-browser-core/Cargo.toml` | `0.6.0` | browser boundary |
| 10 | `asupersync-tokio-compat` | `asupersync-tokio-compat/Cargo.toml` | `0.6.0` | compat satellite |

Each package retains its own `cargo package` and `cargo publish --dry-run`
checks before publication. `asupersync-zstd` must be available before the
runtime is packaged even when its optional feature is not selected.
`drop_unwrap_finder` declares `publish = false` and remains excluded.

The contract's `fixture_crate_surface` preserves the nine-package snapshot
for the June 13, 2026 synthetic 0.3.4 records and final-signoff packet.
Those historical rows, hashes and receipts remain unchanged; they do not
cover the added codec or establish readiness of the current candidate.
The current inventory and graph checks are independent of that snapshot.

## Version Policy

The release workflow currently validates the tag against the root `Cargo.toml`
version before publishing. The provenance gate should record the effective
package version for every published manifest and fail closed if a published
package version differs from the planned release version without an explicit
operator override artifact.

Required version evidence per package:

- release tag and normalized release version from the `plan` job,
- `package.name` and `package.version` from `cargo metadata --no-deps`,
- manifest path and SHA-256 digest of the package `Cargo.toml`,
- root `Cargo.toml` digest and `Cargo.lock` digest,
- publish order index and dependency ordering rationale.

## Required Rust Crate Provenance Fields

Every Rust crate provenance record must contain:

| Field | Requirement |
|---|---|
| `git_head` | Exact commit SHA used for the release checkout. |
| `tag` | Release tag that triggered or parameterized the workflow. |
| `cargo_lock_sha256` | SHA-256 digest of `Cargo.lock` from the checkout. |
| `cargo_toml_sha256` | SHA-256 digest of the package manifest. |
| `root_cargo_toml_sha256` | SHA-256 digest of the root workspace manifest. |
| `package` | Package name, manifest path, version, role, and publish order. |
| `cargo_metadata_snapshot` | Deterministic metadata snapshot sufficient to reconstruct the package/version mapping. |
| `dependency_snapshot` | Dependency and license/SBOM snapshot used for release review. |
| `dry_run_command` | Exact `cargo publish -p <package> --dry-run --locked` command and executor metadata. |
| `dry_run_outcome` | Exit status, timestamp, and artifact/log pointer for the dry run. |
| `package_tarball_sha256` | SHA-256 digest of the `.crate` tarball produced for or by the publish path. |
| `publish_command` | Exact publish command, with credentials redacted. |
| `publish_outcome` | Published, skipped because already published, or skipped because token was absent. |
| `crates_io_visibility_check` | Whether crates.io returned the expected package version after publish. |
| `integrity_manifest` | Path and digest for the release artifact integrity manifest that indexes all per-package records. |

Credentials must never be copied into provenance artifacts. A record may state
that `CARGO_REGISTRY_TOKEN` was present or absent, but must not expose the token
value, derived headers, or command environments containing the secret.

## Relationship to Browser and npm Provenance

The browser lane already owns:

- `docs/wasm_browser_sbom_v1.json`,
- `docs/wasm_browser_provenance_attestation_v1.json`,
- `docs/wasm_browser_artifact_integrity_manifest_v1.json`,
- `packages/browser-core/package.json`,
- `packages/browser-core/asupersync_bg.wasm`,
- `packages/browser/package.json`,
- `packages/react/package.json`,
- `packages/next/package.json`.

Those artifacts prove browser/WASM package integrity and npm release inputs.
They do not prove crates.io package tarball integrity, Rust package publish
order, all Rust package manifest digests, dependency/license snapshots for
crates.io packages, or crates.io visibility checks.

The Rust crate provenance gate must consume browser artifacts only as optional
cross-lane references for `asupersync-browser-core`. It must not treat a passing
browser SBOM or npm package integrity check as proof that the Rust crate publish
surface is reproducible or complete.

## Direct-Main Validation Policy

Direct-main Cargo proof claims for this release lane must run through RCH with
an isolated `CARGO_TARGET_DIR` and no local fallback. A valid proof command has
this shape:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_release_provenance_<lane>" CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 RUSTFLAGS='-D warnings -C debuginfo=0' cargo <check-or-test-command>
```

Local `cargo` commands may be used only for non-proof metadata discovery when
they do not build or test the workspace, such as `cargo metadata --no-deps`.
They cannot be cited as release validation evidence.

## No-Claim Boundaries

This R1 policy does not:

- change release credentials,
- perform a live crates.io publish,
- generate the Rust crate SBOM or package tarball artifacts,
- update the publish workflow to enforce the provenance gate,
- prove release readiness,
- prove broad workspace health,
- replace the existing WASM/browser SBOM and npm provenance lane.
