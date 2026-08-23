# Dependency CI/provenance final signoff

`artifacts/dependency_ci_provenance_final_signoff_v1.json` is the terminal
machine packet for `asupersync-mnotoo.3.7`. Its verdict is
`PASS_SCOPED_KEEP_DEFER`: every P1-P5 child reached its own accepted terminal
state, but those states intentionally do not all mean the same thing. The
focused proof lane is `dependency-ci-provenance-final-signoff`.

## Joined child outcomes

| Child | Accepted outcome | What remains outside the outcome |
| --- | --- | --- |
| P1 `asupersync-mnotoo.3.1` | 12 workflow files and 182 external `uses:` references are pinned to reviewed lowercase full SHAs, with 13 repositories and zero exceptions | Action trust, least privilege, workflow execution, runner isolation, and artifact integrity |
| Owner decision/P2 `asupersync-mnotoo.3.2-.3` | Owner-selected `STATIC_ONLY_EXECUTABLE_AUDIT_DEFERRED` receipt for 15 tracked package manifests and no tracked JS lock | Executable package-tree resolution, advisories, integrity, lifecycle/native-binary safety, duplicates, and reproducibility |
| P3 `asupersync-mnotoo.3.4` | Root and separately tracked excluded-fuzz Cargo policies pass with pinned scanners, tracked locks, native-edge inventory, and Tokio quarantine | Fuzz-target behavior, undisclosed vulnerabilities, legal conclusions, and publisher identity |
| P4 `asupersync-mnotoo.3.5` | Pinned-nightly direct-minimal consumer lane passes | Full transitive-minimal remains blocked at `curve25519-dalek 4.0.0`; no numeric stable MSRV or universal vendor guarantee |
| P5 `asupersync-mnotoo.3.6` | Cargo-built 14-row / 15-dependency AGENTS projection and read-only drift check pass | The table is not the complete 106-edge allowset and has no automatic local rewrite path |

The aggregate never promotes a child beyond its own evidence. In particular,
the explicit owner decision is resolved by preserving the static path, not by
quietly invoking pnpm or relabeling an absent lockfile as an executable pass.

## Fresh scanner receipt

The aggregate run on 2026-08-23 executed the pinned Cargo scanner entrypoint:

```bash
scripts/ci/audit_dependencies.sh run
```

It returned `PASS` for both the root and excluded-fuzz workspaces with
`cargo-deny 0.19.4`, `cargo-audit 0.22.2`, and RustSec revision
`bf5c0d245a92671908518d7e765914d437954ed6`. The database age was 194825
seconds against a 604800-second maximum; both scans exited zero and reported no
duplicate expansion. This is a receipt at the recorded time. A future operator
must rerun the command before claiming current scanner health.

The excluded-fuzz scope retains the expected `libfuzzer-sys 0.4.13` and
`cc 1.4.4` native build edges and the `expected_excluded_fuzz_only` Tokio
quarantine. That does not turn the static scanner receipt into fuzz execution.

## Package-manager boundary

The owner-selected JavaScript decision remains `STATIC_ONLY`. The signoff does
not run npm, pnpm, yarn, Corepack, Bun, Deno, install, audit, build, test,
publish, a lifecycle hook, or registry resolution. It records the checked
topology facts only:

- `packageManager` is `pnpm@10.34.3`; Node is `>=18.12.0`; pnpm is
  `>=10.34.3`;
- `pnpm-workspace.yaml` admits `packages/*`;
- `.npmrc` enables pre/post scripts and disables strict peer-dependency
  enforcement;
- `sharp` is the only allowed built dependency, so sharp/libvips and Next SWC
  remain named native/prebuilt risks;
- the executable owner is the Browser Edition package and release process.

An ignored local lock is not project evidence and must not be hashed, copied,
or interpreted by this gate. Adding package-manager authority requires a new
explicit owner decision; this signoff cannot grant it.

## Graph, consumer, and generated-document interpretation

The checked Cargo graph projection covers 12 synthesized-consumer feature
profiles, four targets, the `x86_64-unknown-linux-gnu` host, and normal plus
target-normal consumer edges. Root and excluded-fuzz manifest/lock hashes are
joined from the child policy artifacts.

The downstream lane uses `nightly-2026-07-05` and
`-Z direct-minimal-versions`. Remote job `29988810699833377` passed. The
separate full-transitive probe, job `29988810699833376`, remains non-green at
`asupersync -> nkeys 0.4.5 -> ed25519-dalek 2.0.0 -> curve25519-dalek 4.0.0`
with `E0635 unknown feature stdsimd`. The aggregate must preserve both outcomes.

The generated-document child joins 14 displayed rows and 15 dependency names
to the complete 106-edge budget. Its check mode is read-only. Any missing,
extra, stale, duplicate, reordered, unknown-field, marker, or CLI drift remains
owned by the child contract and fails the aggregate through the pinned source
hash and joined counts.

## Fail-closed mutations

The focused contract plants and rejects these aggregate overclaims:

1. a child no longer closed;
2. JavaScript package-manager execution authorized;
3. a stale RustSec database;
4. removed excluded-fuzz Tokio quarantine;
5. an erased full-transitive-minimal blocker;
6. generated-document row drift;
7. dependency-exit authority; and
8. source-contract hash drift.

These are safe in-memory mutations. They do not rewrite workflows, manifests,
locks, AGENTS, tracker history, or scanner configuration.

## Canonical replay

First refresh the only live external receipt:

```bash
scripts/ci/audit_dependencies.sh run
```

Then run the Cargo-built aggregate contract through remote-required RCH:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env \
  CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_dependency_ci_provenance_final_signoff \
  CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  cargo test -j 2 -p asupersync \
    --test dependency_ci_provenance_final_signoff_contract -- --nocapture
```

The `-j 2` bound is part of the canonical command because current workers have
two or three slots; an unbounded Cargo test was previously refused before
execution as a ten-slot request. `RCH_REQUIRE_REMOTE=1` is fail-closed and there
is no local Cargo fallback.

## Operator closeout

Before closing or citing the packet:

1. confirm P1-P5 child statuses and scoped close reasons in Beads;
2. rerun the pinned scanners and record database revision/freshness plus both
   root and excluded-fuzz exits;
3. confirm no JavaScript package manager was invoked;
4. preserve direct-minimal pass versus transitive-minimal blocker;
5. run the exact focused RCH contract and retain its terminal job receipt;
6. inspect the final artifact, proof manifest/status row, README/AGENTS markers,
   no-claim list, and tracker transition.

## No-claim boundaries

This packet does not prove release readiness, broad workspace health, runtime
correctness, performance, no regression, action trustworthiness, least
privilege, workflow execution, package-tree security, undisclosed-vulnerability
absence, legal compliance, publisher identity, fuzz-target behavior, full
transitive-minimal support, a numeric stable MSRV, universal vendoring
reproducibility, or live RCH fleet availability.

It does not authorize dependency removal, dependency or feature cutover,
package-manager execution, automatic AGENTS rewriting, file deletion, local
Cargo fallback, or closure of the parent epic by inference.
