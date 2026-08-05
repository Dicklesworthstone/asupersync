# Dependency supply-chain policy

The canonical dependency gate is `scripts/ci/audit_dependencies.sh`. It applies
the checked `deny.toml` and `.cargo/audit.toml` policies to the root workspace
without updating a lockfile or build tree. Its machine-readable policy is
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
ratchet expansions. The root result exits nonzero for an advisory, license,
source, or duplicate-ratchet violation. A passing root scan with a non-green
excluded fuzz graph is reported as `PASS_ROOT_FUZZ_NON_GREEN`, not `PASS`.

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

It proves four fail-closed paths: removing the `RUSTSEC-2025-0134` exception,
removing the required ISC license allowance, adding an unreviewed duplicate
version, and replacing one metadata source with an unapproved revision-pinned
Git URL. Each fixture must produce the expected named rejection.

## Excluded fuzz workspace

`fuzz/Cargo.toml` is outside the root virtual workspace, so the runner reports
it separately. At the 2026-07-25 baseline, `cargo-deny --locked` is blocked
because `fuzz/Cargo.lock` requires regeneration, and `cargo-audit` reports
`RUSTSEC-2026-0204` (`crossbeam-epoch` 0.9.18) plus `RUSTSEC-2026-0190`
(`anyhow` 1.0.102). This policy-only gate does not rewrite that lockfile.
`asupersync-mnotoo.3.4` owns the excluded-fuzz graph follow-up.

## No-claim boundaries

A root pass does not prove the excluded fuzz workspace is green. Scanner
freshness does not prove that no undisclosed vulnerability exists. License
metadata evaluation is not legal advice. The duplicate ratchet prevents
expansion but does not endorse retained duplication. Source allowlisting does
not authenticate publishers or prove crate correctness. This lane does not
prove release readiness, broad workspace health, runtime correctness,
performance, or live RCH fleet availability.
