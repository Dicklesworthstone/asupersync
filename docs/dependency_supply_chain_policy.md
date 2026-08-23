# Dependency supply-chain policy

The canonical dependency gate is `scripts/ci/audit_dependencies.sh`. It applies
the checked `deny.toml` and `.cargo/audit.toml` policies to both the root
workspace and the separately locked, workspace-excluded `fuzz/` graph without
updating either lockfile or build tree. Its machine-readable policy is
`artifacts/dependency_supply_chain_policy_v1.json`.

## Tool and database admission

Only the Cargo installation path is admitted:

```bash
scripts/ci/audit_dependencies.sh install-tools
```

The policy pins `cargo-deny` 0.19.4 and `cargo-audit` 0.22.2. `run` compares
both exact `--version` outputs before scanning. A missing or mismatched tool
emits `summary.json` with `BLOCKED_EXTERNAL` and exits 75; it never silently
skips a scanner.

Both scanners consume the same RustSec advisory database checkout. The runner
records its origin URL, Git revision, commit timestamp, observed age, maximum
age, fetch status, and freshness in `advisory-database-receipt.json`. The
maximum admitted age is seven days. A missing, ambiguous, or older checkout is
blocked evidence, not a green audit. CI fetches on every run; an operator using
an offline checkout must still satisfy the revision and freshness receipt.

## Policy coverage

The root `Cargo.toml` virtual workspace is evaluated with its locked graph,
all workspace members and features, normal/build/dev/proc-macro edges, and the
Apple, Linux, Windows, and wasm target filters in `deny.toml`.

The separately tracked `fuzz/Cargo.lock` is evaluated through
`fuzz/Cargo.toml` with the same advisory, license, source, and duplicate-version
policy. Workspace exclusion is an execution boundary, not a safety exemption.

- Advisories and yanked crates are denied. Informational unmaintained and
  unsound findings are policy failures unless an explicit exception records
  package, reason, owner, and expiry.
- License evaluation includes dev dependencies, uses a 0.93 confidence
  threshold, and admits only the SPDX expressions listed in `deny.toml`.
- Unknown registries and Git sources are denied. The crates.io index is the
  only admitted registry, and any future Git source must be revision-pinned
  and explicitly reviewed.
- Wildcard registry dependencies are denied. Existing duplicate families are
  a ratchet: versions may disappear, but no family or version may expand
  beyond the checked baseline.

The sole current root advisory exception is `RUSTSEC-2025-0134` for
`rustls-pemfile` 2.2.0. It is owned by `asupersync-mnotoo.4.3`, expires on
2026-09-01, and has no automatic renewal. The planned remediation is migration
to `rustls-pki-types::pem::PemObject`.

The 2026-08-23 live refresh also advanced `h2` from 0.4.15 to 0.4.18 for
`RUSTSEC-2026-0258` and `event-listener` from 5.4.1 to 5.4.2 for
`RUSTSEC-2026-0221`; neither advisory is ignored.

## Downstream bounds, lockfiles, and vendoring

The repository's `Cargo.lock` records the graph used by Asupersync's own
workspace gates. It does not constrain the versions selected when another
package depends on Asupersync. A downstream application should commit and
enforce its own lockfile; a downstream library should review the graph resolved
by its own integration and release fixtures. Neither consumer inherits a green
advisory, license, source, or duplicate-version result from this repository.

The current lower-bound contract is deliberately narrow:

| Consumer profile | Declared bound | Current evidence state |
| --- | --- | --- |
| Default features | `nightly-2026-07-05` from `rust-toolchain.toml`; default features include `nightly-outcome-try` | Pinned contributor/release snapshot, not a numeric stable MSRV or lower-bound proof |
| Stable subset | A toolchain supporting Edition 2024, with default features disabled and `proc-macros` enabled | Audited stable profile, but no numeric minimum is declared because `[package].rust-version` is absent |
| Dependency versions | The semver requirements in the consumer's resolved Asupersync manifest | Current-version coverage only; the workspace lock is not a verified minimum-version set |

`nightly-2026-07-05` is a point-in-time toolchain pin, not an MSRV-style
range. A change to `[toolchain].channel` must update this row and the README
guidance in the same review. Until a focused drift contract enforces that
relationship, synchronized review remains an operator obligation.

The synthesized fixture at
`tests/fixtures/downstream-consumer-proof/Cargo.toml` exercises selected public
API and feature profiles through a path dependency. Its proof-status row is
`rerun-required`, and even a fresh pass would establish compatibility with the
current manifest resolution only. It has no committed independent lockfile and
does not exercise Cargo's direct-minimal or transitive-minimal resolution.
Therefore this project does **not** currently claim a numeric stable MSRV or a
verified minimum dependency set.

Establishing either claim requires a separate, synthesized consumer with an
independent lockfile, an explicitly pinned toolchain, exact feature and target
profiles, and a minimum-version resolution receipt. Any lower bound that fails
that lane must be raised in the manifest before the bound is published. The
existing [dependency budget contract](./dependency_budget_contract.md) and
[feature/platform/consumer matrix](./dependency_feature_platform_consumer_matrix.md)
define current graph ceilings and profile coverage; they are not downstream
resolution guarantees.

`cargo vendor` is an optional consumer control, not a universal reproducibility
or trust guarantee. A consumer that vendors should first resolve and commit its
own lockfile, commit the generated source configuration and vendor tree, and
review changes to all three together. Vendoring copies the selected sources; it
does not by itself freeze resolution, authenticate publishers, find advisories,
approve licenses, validate build scripts, or cover unreviewed `[patch]` and
source-replacement configuration. Consumers remain responsible for running
their own advisory, license, source, and target/profile checks against the graph
they actually ship.

## Direct-main and CI runs

Run the live gate from the repository root:

```bash
DEPENDENCY_AUDIT_OUTPUT_DIR="${TMPDIR:-/tmp}/asupersync-dependency-audit" \
  scripts/ci/audit_dependencies.sh run
```

The output directory contains `summary.json`, `events.ndjson`, the database
receipt, raw JSON scanner output, the observed duplicate inventory, and any
ratchet expansions for both graphs. The result exits nonzero for an advisory,
license, source, or duplicate-ratchet violation in either graph. `PASS` means
both locked dependency-policy surfaces passed; there is no root-only green
fallback for a non-green excluded fuzz graph.

The CI job uses a repository artifact output directory, runs the same pinned
tool installation and gate, and uploads the complete receipt directory even
on failure. Scanner commands run directly because RCH deliberately rejects
non-compilation Cargo plugins; the Rust policy contract is the separate
remote-required lane:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- \
  env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_dependency_supply_chain_policy" \
      CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
      RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -p asupersync \
    --test dependency_supply_chain_policy_contract -- --nocapture
```

## Negative fixtures

The self-test creates a fresh temporary directory outside the repository and
does not alter or delete production manifests:

```bash
DEPENDENCY_AUDIT_OUTPUT_DIR="${TMPDIR:-/tmp}/asupersync-dependency-self-test" \
  scripts/ci/audit_dependencies.sh self-test
```

It proves five fail-closed paths: removing the `RUSTSEC-2025-0134` exception,
removing the required root ISC license allowance, removing the fuzz-only NCSA
allowance required by `libfuzzer-sys`, adding an unreviewed duplicate version,
and replacing one metadata source with an unapproved revision-pinned Git URL.
Each fixture must produce the expected named rejection.

## Excluded fuzz workspace

`fuzz/Cargo.toml` is outside the root virtual workspace, so the runner reports
it separately and requires its own tracked `fuzz/Cargo.lock`. The lock inherits
the repository's `nightly-2026-07-05` rustup override from
`rust-toolchain.toml`. Its direct `libfuzzer-sys 0.4.13` edge depends on
`cc 1.4.4`; building a fuzz target therefore requires the pinned nightly plus
a working C/C++ compiler, linker, and archiver. `cc` also records
`find-msvc-tools`, `jobserver`, `libc`, and `shlex` as build-support edges.

The 2026-08-23 refresh removed `crossbeam-epoch 0.9.18`
(`RUSTSEC-2026-0204`) from the graph and updated `anyhow 1.0.102`
(`RUSTSEC-2026-0190`) to 1.0.104. The checked scan reports zero advisories.
`libfuzzer-sys` declares `(MIT OR Apache-2.0) AND NCSA`; NCSA is deliberately
allowed and its removal is covered by the fuzz-specific negative fixture.

Tokio remains quarantined to non-production edges. The excluded fuzz graph has
a direct Tokio edge in `fuzz/conformance/` for vendor-comparison scaffolding,
and `opentelemetry-proto`'s `gen-tonic-messages` feature carries generated
tonic/Tokio wire helpers. Those expected paths do not weaken the separate
default and metrics production proofs, both of which must still report no Tokio
path.

### Updating the excluded fuzz graph

Review `fuzz/Cargo.toml`, `fuzz/conformance/Cargo.toml`, and upstream release
and security notes before changing resolution. Preview and then perform the
Cargo-only lock update:

```bash
cargo update --manifest-path fuzz/Cargo.toml --dry-run
cargo update --manifest-path fuzz/Cargo.toml
```

Review the full lock diff, especially native/build-script edges, source URLs,
license expressions, Tokio/tonic paths, and removals or additions to duplicate
families. Then update the checked fingerprints and downward-only duplicate
ratchet in `artifacts/dependency_supply_chain_policy_v1.json`. Do not approve
an expansion merely because Cargo selected it. Run the direct scanners and
safe fixtures, followed by the focused remote Rust contract and the canonical
locked fuzz-manifest compile:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR="${TMPDIR:-/tmp}/rch_target_fuzz_manifest_smoke" CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 RUSTFLAGS='-C debuginfo=0' cargo check -j 2 --locked --manifest-path fuzz/Cargo.toml
```

The compile must use RCH and the tracked lock; scanner success is not a
substitute for that execution.

## No-claim boundaries

A policy `PASS` covers the checked root and excluded-fuzz dependency graphs at
the recorded manifest, lock, tool, and RustSec revisions. It does not prove
that any fuzz target compiles, runs, or finds all defects. Scanner freshness
does not prove that no undisclosed vulnerability exists. License
metadata evaluation is not legal advice. The duplicate ratchet prevents
expansion but does not endorse retained duplication. Source allowlisting does
not authenticate publishers or prove crate correctness. This lane does not
prove release readiness, broad workspace health, runtime correctness,
performance, or live RCH fleet availability.
