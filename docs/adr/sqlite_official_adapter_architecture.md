# SQLite official adapter architecture: keep pending current graph and owner contract

- Status: provisional architecture; implementation blocked
- Bead: `asupersync-ym2wtv.3.1`
- Capabilities: `CAP-SQLITE`, `CAP-DOWNSTREAM-CONSUMERS`
- Governing decision: `DEP-ADR-010`
- Machine packet: [`artifacts/sqlite_official_adapter_architecture_v1.json`](../../artifacts/sqlite_official_adapter_architecture_v1.json)
- Focused contract: [`tests/sqlite_official_adapter_architecture_contract.rs`](../../tests/sqlite_official_adapter_architecture_contract.rs)
- Decision state: `KEEP_PENDING_CURRENT_GRAPH_AND_OWNER_CONTRACT`

## Outcome first

The supported path remains `asupersync[sqlite]` with `rusqlite` and
`sqlparser`. The preferred provisional official-adapter placement is the existing
`fsqlite` package in the FrankenSQLite repository, under
`fsqlite::async_api` with the existing `fsqlite::AsyncConnection` re-export.
A companion package remains a permitted alternative pending owner and graph
comparison.

This is a provisional package and ownership proposal, not implementation
approval. Current
evidence does not yet establish the all-profile graph, native/io-uring feature
separation, a supported cross-project version interval, named owner acceptance,
or an accepted pinned-nightly versus stable-source policy. Those missing facts fail
closed: the incumbent remains supported, the bead remains open, and no source
or dependency change is authorized.

## Why the existing `fsqlite` package

The integration surface already exists in the public façade:

- package: `fsqlite` `0.1.19`;
- repository: `https://github.com/Dicklesworthstone/frankensqlite`;
- feature: `async-api`;
- namespace: `fsqlite::async_api`;
- root re-export: `fsqlite::AsyncConnection`;
- Asupersync dependency observed in the workspace: `^0.3.10` with default
  features disabled.

A new `fsqlite-asupersync` crate would point in the same acyclic direction and
appears to duplicate the API entry point, documentation, release train, and
support surface. That comparison has not been measured or owner-accepted, so the
companion alternative is deferred rather than rejected. The existing façade is
the preferred candidate for the next graph comparison.

The current feature forwarding is not the accepted final contract. It forwards
`dep:asupersync`, `dep:futures-lite`, and `fsqlite-types/native`. Making the
adapter self-contained by forwarding `native` currently pulls
`fsqlite-vfs/native`, which recursively enables `linux-asupersync-uring`; the
`io-uring` dependency is also unconditional for Linux in the observed VFS
manifest. The preferred feature contract therefore remains blocked until owners
either accept that Linux edge explicitly or split the base native feature from
the optional io-uring feature. The machine state is
`BLOCKED_BY_CURRENT_NATIVE_URING_COUPLING`.

## Proposed dependency direction

```text
supported user
  +--> asupersync 0.3.10 (one source, one package ID)
  +--> fsqlite 0.1.19 [async-api]
          +--> asupersync ^0.3.10 (direct optional edge from async-api)
          +--> fsqlite-core 0.1.19 (unconditional facade edge)
                  +--> asupersync ^0.3.10 (structural target-cfg edge)

asupersync 0.3.10 [sqlite]           # incumbent remains supported
  +--> rusqlite 0.40
  +--> sqlparser 0.62
```

Every arrow between repositories points from FrankenSQLite toward Asupersync.
An Asupersync normal, dev, or build edge to any FrankenSQLite package remains
forbidden because it would close the reverse Cargo cycle. A supported combined
consumer must resolve exactly one Asupersync package ID from one source.
Disabling `async-api` is not a cycle escape: the unconditional façade-to-core
edge and core's Asupersync target dependencies remain.

The neutral parity consumer is evidence infrastructure, not a production
adapter. It may depend on both engines from its standalone workspace and use a
patch to unify the Asupersync source while unreleased revisions are compared.
An unpublished patch can never define the supported installation path.

## Public API boundary

The required candidate surface takes `&asupersync::Cx` as the first non-receiver
argument of every async operation. The current implementation instead exposes
`fsqlite_types::cx::Cx` and discovers the native context through
`NativeCx::current` or `Runtime::current_handle`. That dual-context and ambient
lookup design is a downstream implementation gap owned by the I2 API work; it
is not grandfathered by this architecture packet and is not an I1 closure
dependency.

The current adapter also owns a dedicated OS thread per connection and states
that an admitted command continues when the caller abandons its response.
Thread stack allocation, command admission, interrupt, masked drain, response
abandonment, worker join, and shutdown must be explicit profile and lifecycle
contracts. I2.4 owns the behavioral proof after I1 selects the architecture.
I1 records the requirement, does not wait on its blocked dependent, and makes no
cancellation-correctness claim.

## Ownership and release contract

The responsibility split is concrete even though named people have not yet
accepted it:

| Owner | Responsibility |
|---|---|
| FrankenSQLite maintainers | `fsqlite::async_api`, feature forwarding, adapter API, package release, migration notes, examples, first-line support |
| Asupersync maintainers | `Cx` and runtime contracts, the incumbent `sqlite` feature, stable-subset declaration, runtime API change notices |
| Joint release gate | compatibility matrix, one-package-ID proof, cross-repository CI, rollback rehearsal, published support interval |

Release order starts by freezing immutable packaged candidates and the proposed
support interval, then validating every supported pair and graph coordinate
before either publication. Only then may Asupersync publish. A clean crates.io
resolution without a patch follows, then the matching `fsqlite` release, then
public adapter documentation after both published packages resolve cleanly. The
current observed pair is Asupersync `0.3.10` and `fsqlite` `0.1.19`; the manifest
interval is `^0.3.10`, but no supported semantic interval is proved or published
yet.

Each supported `fsqlite` release must publish its Asupersync interval, minimum
Rust version, target set, deprecation window, and rollback version. The current
and immediately previous compatible pair must remain in CI for at least one
`fsqlite` minor-release interval. Until a named owner accepts this lifecycle,
the state remains `MISSING_NAMED_OWNER_APPROVAL`.

## Toolchain contract

Asupersync `0.3.10` pins `nightly-2026-07-05`. FrankenSQLite declares Rust
`1.85` while its repository toolchain is floating `nightly`. Stable support is
not merely unproved: the observed x86_64 graph unconditionally reaches
`feature(core_intrinsics)` in `fsqlite-btree` and `fsqlite-pager`, and Windows
reaches `feature(windows_by_handle)` in the VFS. FrankenSQLite's README also
requires nightly.

The current stable disposition is therefore
`KNOWN_UNSUPPORTED_AT_CURRENT_REVISION_ON_X86_64_AND_WINDOWS`. Before I1 closes,
owners must either accept and date-pin a shared nightly or require a stable-source
refactor. In either case the adapter dependency keeps Asupersync default features
disabled and must not enable `nightly-outcome-try`. A floating nightly and the
bare Rust `1.85` declaration are not an accepted support contract.

## Required graph matrix

The matrix below is a minimum proposed matrix, not a complete accepted allowset.
Target and version allowsets still need owner acceptance. Every supported row
requires immutable revisions, manifest and lockfile hashes, the exact command,
host and target triples, toolchain, features, package IDs by dependency kind,
metadata-derived build-script and proc-macro sets, Tokio/native classification,
exit status, and terminal timestamp.

Dependency kinds are only `normal`, `dev`, and `build`. `proc-macro` is a Cargo
target classification derived from `cargo metadata`, not an edge kind. Every row
also classifies build scripts, proc macros, native code, and Tokio.

| Coordinate | Root/profile | Host -> target | Dependency kinds | Current state |
|---|---|---|---|---|
| `ASUP-DEFAULT-LINUX` | Asupersync default production | Linux -> Linux | normal, build | missing current receipt |
| `ASUP-SQLITE-LINUX` | Asupersync incumbent sqlite | Linux -> Linux | normal, build | missing current receipt |
| `ASUP-SQLITE-DEV-LINUX` | Asupersync sqlite package tests | Linux -> Linux | normal, dev, build | missing current receipt |
| `FSQLITE-DEFAULT-LINUX` | public façade baseline | Linux -> Linux | normal, build | missing current receipt |
| `FSQLITE-WORKSPACE-DEV-LINUX` | workspace dev baseline | Linux -> Linux | normal, dev, build | missing current receipt |
| `FSQLITE-ASYNC-LINUX` | preferred adapter production | Linux -> Linux | normal, build | blocked by native/io-uring coupling |
| `FSQLITE-ASYNC-DEV-LINUX` | preferred adapter tests | Linux -> Linux | normal, dev, build | blocked by native/io-uring coupling |
| `FSQLITE-ASYNC-STABLE-X86_64` | stable/MSRV negative coordinate | Linux -> Linux | normal, build | known unsupported by current intrinsics |
| `USER-COEXIST-LINUX` | incumbent + preferred adapter | Linux -> Linux | normal, dev, build | blocked by native/io-uring coupling |
| `USER-LOWEST-SUPPORTED-LINUX` | lowest support-bound pair | Linux -> Linux | normal, dev, build | blocked by unpublished interval |
| `USER-HIGHEST-SUPPORTED-LINUX` | highest support-bound pair | Linux -> Linux | normal, dev, build | blocked by unpublished interval |
| `USER-ADAPTER-MACOS` | native-host preferred adapter | macOS ARM64 -> macOS ARM64 | normal, build | missing current receipt |
| `USER-ADAPTER-WINDOWS` | native-host preferred adapter | Windows x64 -> Windows x64 | normal, build | missing current receipt |
| `USER-ADAPTER-WASM` | unsupported-target disposition | Linux -> wasm32 | normal, build | unsupported by the dedicated-thread adapter |

Production invariants are fail-closed:

1. Every Asupersync row contains zero `fsqlite` or FrankenSQLite package IDs.
2. Every supported combined-user row contains exactly one Asupersync package
   ID.
3. The candidate production normal graph contains zero Tokio package IDs.
4. Native-code packages and dedicated worker-thread behavior are declared by
   profile.
5. Dev-only or workspace-wide Tokio packages are not misreported as production
   adapter edges.

## Why prior graph evidence is insufficient

The combined-budget packet remains useful historical evidence: it found a
33-crate increase, a duplicated Asupersync runtime in the naive consumer, and a
single runtime after applying a patch. It covered one dirty Linux release
coordinate, excluded dev edges, and predates the current `0.3.10` / `0.1.19`
pair. It is not current I1 acceptance evidence.

The parity harness proves that one standalone evidence-only consumer can unify
the Asupersync package and execute one retained vector. It does not prove a
published adapter, complete graph matrix, support contract, or lifecycle.

## I1 blockers, downstream gates, and terminal rule

I1 remains open on four architecture-owned gaps:

- current immutable dependency graphs and metadata classifications for an
  owner-accepted target/version allowset;
- named release and support owner acceptance;
- explicit acceptance or separation of the native/io-uring edge;
- a pinned-nightly or stable-source toolchain disposition.

The native `&asupersync::Cx` API, cancellation lifecycle, and exercised packaged
release remain mandatory downstream gates owned by I2, I2.4, and I4. They are
not I1 closure blockers because those beads are blocked by I1.

If any required graph has a reverse cycle, two Asupersync package IDs, an
undeclared Tokio/native edge, or materially worse supported-user cost that the
owners do not accept, the terminal I1 result is `KEEP` before implementation.
Closing I1 otherwise requires owner acceptance of the package/feature direction,
current terminal evidence for the accepted graph rows, explicit target and
version bounds, named architecture owners, pre-publication ordering, and a
defined toolchain policy. Publication and operational release proof remain I4.

## No-claim boundary

This source-free packet selects a provisional package placement and records
fail-closed requirements. It does not prove any current FrankenSQLite graph,
compile, runtime, cancellation, portability, parity, performance, publication,
owner acceptance, support interval, or release readiness. It authorizes no
source implementation, dependency change, feature deprecation, cutover, or bead
closure.
