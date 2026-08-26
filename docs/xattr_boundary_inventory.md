# XATTR boundary inventory and terminal gate

<!-- BEGIN XATTR BOUNDARY INVENTORY -->

This is the operator-readable companion to
`artifacts/xattr_boundary_inventory_v1.json`. It freezes the claim-time
`CAP-XATTR` baseline for `asupersync-3u3tej.3.1` at revision
`e958dadee7b692faaf51bee42352d4bc6e7738ef`.

The gate outcome is terminal `DEFER`. The `xattr` crate remains in place,
`implementation_children_authorized` is false, and no source, manifest,
lockfile, registry, or dependency change is approved by this inventory. The
thirteen observed gaps are routed to incumbent integration, evidence, or
documentation owners.

## Why the gate is DEFER

The canonical marginal ledger contains 26 active `xattr` cells: thirteen
feature profiles on Linux and the same thirteen on macOS, all measured from
the Linux ledger host. Every baseline-minus-counterfactual package set is
exactly `xattr@1.6.1`. Each cell therefore removes one package version, no
build script, no proc macro, and no marginal native package.

Most importantly, `rustix@1.1.4` is present in all 26 active baselines but is
absent from every marginal set. It remains after the `xattr` edge is removed
in every measured profile/target/host cell. The lockfile also shows
independent `rustix` parents including `polling@3.11.0` and
`tempfile@3.27.0`. `xattr` is not the last `rustix` parent.

Windows and wasm each have thirteen target-filtered cells in which the
`cfg(unix)` edge is absent. Those are graph observations, not runtime proof.
The ledger retains `root_native_status: unknown`; its
`marginal_native_status: none` result must not be expanded into a whole-graph
native-code claim.

A first-party replacement would still have to own Linux-like calls, macOS
position/options signatures, FreeBSD and NetBSD namespace APIs, unsupported
Unix behavior, allocation races, path/fd conversion, buffer initialization,
and partial-application semantics. That is a high unsafe and maintenance
delta for removal of one safe wrapper package while `rustix` remains. The
stated parent-removal trigger is not met.

## Exact call inventory

There are five direct production calls, all in
`src/net/atp/transport_common/metadata.rs`:

| Call | Operation | Link behavior | Current reachability |
| --- | --- | --- | --- |
| `xattr::list_deref` | list | follows target | unreachable today |
| `xattr::list` | list | operates on the link itself | regular files/directories |
| `xattr::get_deref` | get | follows target | unreachable today |
| `xattr::get` | get | operates on the link itself | regular files/directories |
| `xattr::set` | set | operates on the link itself | destination files/directories |

The helper accepts a dereference flag, but the production caller passes
`false`. Symlink metadata returns before extended-attribute capture, so the
two dereference branches are currently unreachable and neither link nor
target xattrs are preserved for symlink entries.

The TCP metadata fixture contains the only two direct test calls: a plain
`set` helper and a plain `get` assertion on a regular file. The fixture
returns successfully when the setup `set` fails. It therefore proves exact
value bytes only when setup succeeds; it does not retain a typed unsupported
receipt.

No production or test call removes an attribute, and no production call uses
the incumbent's fd extension trait.

## ATP data and policy contract

`MetadataPolicy::preserve_extended_attributes` is public. It is false for
`Default` and `portable()`, and true for `full_preservation()`. The ordinary
CLI journey remains default-off. QUIC `send`, `recv`, and `serve` expose an
explicit `--preserve-xattrs` opt-in; direct peers must opt in independently,
while SSH bootstrap forwards the sender's option to the receiver. TCP, RQ,
and auto transport selection reject the option rather than silently dropping
the requested fidelity. The opt-in does not add a namespace allowlist,
aggregate-size budget, or transactional rollback.

Successful capture stores attributes in `EntryMetadata::xattrs`, a
`BTreeMap<String, Vec<u8>>`. The map provides canonical UTF-8 name ordering
for serialization, hashing, and application. Values remain arbitrary bytes;
the existing fixture includes a NUL and newline. Names do not remain
arbitrary bytes: the incumbent yields `OsString`, but ATP calls `to_str()` and
silently drops every non-UTF8 name.

Capture is best effort:

- any list error becomes an empty map;
- a missing value, per-name permission/I/O failure, or concurrent removal is
  omitted;
- non-UTF8 names are omitted;
- no capture report distinguishes absence, unsupported filesystem,
  permission denial, partial capture, or failure.

Application is also best effort. Plain `xattr::set` is called once per
canonical map entry. A failure records the attribute name plus display text
in `MetadataApplyReport` and later entries continue. Earlier successful writes
are not rolled back. Special-file entries skip xattr application.

The async entry points delegate their synchronous cores to blocking tasks.
The synchronous list/get/set calls have no cancellation token, and applying
multiple attributes is not transactional. Cancellation therefore does not
promise syscall interruption or rollback of already-applied entries.

## Incumbent error and resource behavior

Pinned `xattr@1.6.1` maps the platform's missing-attribute code to
`Ok(None)`: `ENODATA` on Linux-like targets and `ENOATTR` on macOS and BSD.
Missing paths, permission failures, unsupported filesystems, invalid names,
and other I/O failures remain `io::Error` at the crate boundary. On an
unsupported native target, the default `unsupported` feature supplies stubs
that return `io::ErrorKind::Unsupported`.

ATP does not preserve those distinctions during capture. At apply time it
retains only a display string in the skipped-field report. There is no typed
CAP-XATTR error taxonomy today.

The incumbent's allocation helper first tries a 4096-byte buffer. On
`ERANGE`, it queries the required size, reserves that capacity, and retries.
If the list or value grows concurrently, it retries again. Neither the crate
integration nor ATP declares an attempt ceiling, maximum name size, maximum
value size, maximum list size, attribute-count ceiling, or aggregate metadata
budget. Platform and filesystem limits are not an ATP resource contract.

## Platform matrix

### Linux, Android, and Hurd

The incumbent uses `rustix::fs`. Dereference operations use `getxattr`,
`listxattr`, `setxattr`, and `removexattr`; no-follow operations use the `l*`
forms. Set carries platform flags, currently empty. Linux reports a missing
attribute with `ENODATA`.

The one direct runtime fixture is compatible with a Linux xattr-capable
filesystem and covers one regular file over TCP. It does not establish the
full Linux matrix, Android behavior, or Hurd behavior.

### macOS

`rustix` adapts the macOS ABI rather than calling Linux-shaped `l*` symbols.
Get and set carry both position and options; list and remove carry options.
The follow path uses position `0` and options `0`. The no-follow path uses
position `0` where applicable and adds `XATTR_NOFOLLOW`. A missing attribute
is `ENOATTR`.

This is pinned-source evidence only. No retained macOS ATP runtime receipt was
found.

### FreeBSD and NetBSD

The incumbent uses libc `extattr_*_file`, `extattr_*_link`, and
`extattr_*_fd` calls. Attribute names are split into `user.` and `system.`
namespaces, then re-prefixed for the public iterator. Listing a protected
system namespace suppresses `EPERM` for that namespace while other failures
remain errors. File calls follow links and link calls do not.

This is pinned-source evidence only. No retained FreeBSD or NetBSD ATP runtime
receipt was found.

### Other Unix, Windows, and wasm

Asupersync declares `xattr` under `cfg(unix)`, so other Unix targets receive
the crate even where it only supplies explicit unsupported stubs. Windows and
wasm do not receive the direct edge. Windows uses its separate metadata model;
Unix xattrs are reported unsupported rather than emulated with Windows file
attributes.

## Evidence baseline

The current capability baseline is `BLOCKED_PLATFORM`. It points all positive,
empty/boundary, malformed/error, resource, cancellation, and recovery classes
at `tests/atp_tcp_metadata_fidelity.rs`, although the direct xattr test covers
only one successful regular-file value and can return when setup is
unsupported.

The registry names three canonical scenarios:

- `xattr_follow_nofollow`
- `xattr_atp_transfer`
- `xattr_permission_size_race`

None is implemented by `scripts/run_dependency_sovereignty_e2e.sh`. The API
surface map also contains no `CAP-XATTR` row, and the capability registry's
source-owner list omits policy, CLI, test, and runner consumers. Missing
evidence remains a blocker, never parity.

## Routed gaps

| Gap | Finding | Route |
| --- | --- | --- |
| `XATTR-A1-GAP-01` | dereference branches are unreachable and symlink xattrs are omitted | metadata policy |
| `XATTR-A1-GAP-02` | list failures collapse distinct states into an empty map | capture report |
| `XATTR-A1-GAP-03` | read failures and non-UTF8 names are silently omitted | schema/capture |
| `XATTR-A1-GAP-04` | allocation, retry, count, and aggregate limits are absent | resource policy |
| `XATTR-A1-GAP-05` | apply is partial, stringly typed, and has no rollback | apply contract |
| `XATTR-A1-GAP-06` | setup failure returns a successful test result | CAP-XATTR tests |
| `XATTR-A1-GAP-07` | retained runtime evidence covers one regular-file TCP journey; the QUIC source fixture lacks a terminal runtime receipt | CAP-XATTR E2E |
| `XATTR-A1-GAP-08` | all three canonical scenarios are absent from the runner | suite owner |
| `XATTR-A1-GAP-09` | one fixture is assigned evidence classes it does not cover | baseline owner |
| `XATTR-A1-GAP-10` | registry source owners omit real consumers | registry owner |
| `XATTR-A1-GAP-11` | API surface map has no capability mapping | surface-map owner |
| `XATTR-A1-GAP-12` | non-Linux runtime receipts are absent | platform proof |
| `XATTR-A1-GAP-13` | QUIC CLI opt-in lacks retained transfer parity, namespace/size limits, and rollback evidence | CLI evidence/security |

Every gap is incumbent hardening, evidence, or documentation work. None is a
finding that replacement is required.

## Reconsideration gate

`DEFER` may change only through a new owner-reviewed gate with one of these
evidence-backed triggers:

1. a supported-platform production defect is attributable to `xattr` and
   cannot be fixed upstream or while retaining it;
2. an applicable advisory or maintenance-abandonment record materially
   changes incumbent risk;
3. a fresh canonical ledger records a graph/native-code budget violation or
   `xattr` becomes the actual last `rustix` parent;
4. Linux, macOS, FreeBSD, NetBSD, and explicit-unsupported baselines cover
   every call, error, limit, race, lifecycle, and ATP journey, and an owner
   accepts that exact replacement contract;
5. an independent unsafe review proves a narrower design whose ABI and
   maintenance burden is no greater than the incumbent boundary.

Until then, no A2-or-later replacement child is applicable. Closing those
children under this terminal gate records that implementation is not
authorized; it does not claim their implementation or their acceptance
criteria.

## Validation and no-claim boundary

Run the focused contract through remote compilation:

```bash
RCH_REQUIRE_REMOTE=1 rch exec --base HEAD --clean-overlay \
  --overlay-path artifacts/xattr_boundary_inventory_v1.json \
  --overlay-path docs/xattr_boundary_inventory.md \
  --overlay-path tests/xattr_boundary_inventory_contract.rs \
  -- env CARGO_INCREMENTAL=0 CARGO_PROFILE_TEST_DEBUG=0 \
  RUSTFLAGS='-D warnings -C debuginfo=0' \
  CARGO_TARGET_DIR="${RCH_TARGET_BASE:-${TMPDIR:-/tmp}}/rch_target_xattr_boundary_inventory" \
  cargo test -p asupersync \
  --test xattr_boundary_inventory_contract -- --nocapture
```

No local Cargo fallback is approved. This inventory does not prove broad
workspace health, release readiness, performance, complete metadata parity,
transactional apply, or non-Linux runtime behavior. It does not authorize
deletion, dependency removal, replacement implementation, or cutover.

<!-- END XATTR BOUNDARY INVENTORY -->
