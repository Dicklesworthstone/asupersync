# io_uring Bounded Operation Probes Proof Note

Bead: `asupersync-sched-hot-path-perf-bt4y5f.7.2`

Source basis: committed `HEAD` `ec94712c62d084d9da7c76c2b014b3ec44bae1d5`
plus the reserved `src/runtime/reactor/io_uring.rs` and
`src/runtime/reactor/mod.rs` clean overlay.

## Claim

This note now covers the complete six-operation source set, including the
current bounded `MappedBufferRing` probe and the preceding requested
`MultishotAccept` and dependency-gated `MultishotRecv` probes. The mapped-ring
probe owns one page-aligned shared entry, completes one selected-buffer receive,
returns that lease, unregisters the group, and unmaps through RAII. The accept
probe binds a loopback listener,
owns two distinct accepted descriptors, requires `MORE` on both completions,
then explicitly cancels and drains the terminal completion. The receive probe
adds a dependency-gated startup probe for the requested
`ProvidedGroups` plus `MultishotRecv` capability pair. The probe establishes
that one multishot receive request can select two distinct provided buffers,
retain the kernel `MORE` indication on both data completions, terminate after
explicit cancellation, and return all selected buffers before removing the
group. The result is cached and reported through the existing capability
policy. It is not used by the reactor data plane.

## Safety Argument

The mapped-ring backing buffer and mapping owner are declared before their
temporary ring. The mapping is page aligned, contains exactly one initialized
entry, and remains live until unregister succeeds or ring teardown releases
the registration. Each entry is fully written before a release-ordered tail
update publishes it to the kernel. The selected buffer is verified, returned,
and unregistered after terminal receive completion; uncertain paths drop the
ring before the mapping owner unmaps once.

The accept listener is declared before its temporary ring. Every nonnegative
accept completion is immediately converted into one `OwnedFd`, including any
unexpected positive completion, so every early return closes it exactly once.
The two accepted descriptors remain owned and distinct until after explicit
cancellation and terminal drain.

The receive-buffer backing array and descriptor table are declared before the
temporary ring, so the ring and its pending requests are dropped before their
borrowed storage on every return path. Buffer identifiers are range-checked
before indexing, each selected identifier must be distinct, and the completion
length must fit the fixed eight-byte buffer. The two payloads are sent and
consumed sequentially to make each completion observable independently.

After the second data completion, the probe submits an explicit cancellation
request and requires both its successful completion and the terminal receive
completion with `-ECANCELED` and no `MORE` flag. It then re-provides the two
selected buffers and requires removal of the exact three-buffer group. Any
unsupported opcode, unexpected completion, failed cancellation, invalid buffer
identifier, missing terminal event, or cleanup mismatch fails closed to an
inactive capability decision.

The mapped probe adds five narrow operations for mmap/munmap ownership, shared
entry publication, and registration. The accept probe adds one narrow
ownership-transfer operation in `own_accepted_fd`; its safe precheck rejects
negative completion results before `OwnedFd::from_raw_fd`. The receive probe
reuses the existing narrowly scoped SQE push operation. The unsafe-boundary
ledger accounts for all 26 exact reactor source operations.

## Evidence

- The current RCH clean-overlay
  `cargo check -p asupersync --lib --features io-uring` passed on worker `hz2`;
  project hash `d0377bbff7e312d6`, base
  `ec94712c62d084d9da7c76c2b014b3ec44bae1d5`, overlay fingerprint
  `ed1aec7338e99b01215d55267a9bc064fa34e29d740f1677a971d665a7df91d1`.
- The focused mapped-ring test command exited 124 at its explicit 300-second
  bound while compiling the project test target, before running a test. Project
  hash `d6a8da596deb1574`; no executable or live-host outcome is claimed.
- The required all-target/all-feature `--keep-going` attempt reached its
  600-second bound with exit 124 after exposing unrelated blockers in the
  futures-lite inventory contract, time/UTC inventory contract, and SQLite test
  code. Project hash `f13c6b102aaa0987`; no completed target-matrix outcome is
  claimed.
- The current RCH clean-overlay feature-library Clippy passed on worker
  `vmi1152480` with all warnings denied
  except the known current-main `clippy::redundant_pub_crate` family in
  `future.rs`; project hash `208cb44c15c4165d`, overlay fingerprint
  `ed1aec7338e99b01215d55267a9bc064fa34e29d740f1677a971d665a7df91d1`.
- The final RCH clean-overlay `io_uring_capability_inventory_contract` passed
  6/6 on worker `ovh-a`; project hash `6a9e598aba55f2e0`, overlay
  fingerprint
  `7e6ea4ba225ef51dd85deb936c3832f0b4c191311e4c4641699dcfa94bfd9975`.

## No-Claim Boundary

These receipts do not prove focused executable success, live-kernel support on
a named production target, reactor data-plane integration, sustained operation,
throughput, latency, memory improvement, broad lib-test health, or completion
of URING-2. A focused executable receipt and the target evidence matrix remain
open on the bead.
