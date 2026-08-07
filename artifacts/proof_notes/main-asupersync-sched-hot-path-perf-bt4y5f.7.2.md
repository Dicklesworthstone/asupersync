# io_uring Multishot Operation Probes Proof Note

Bead: `asupersync-sched-hot-path-perf-bt4y5f.7.2`

Source basis: committed `HEAD` `9a3d6b9c5ed4d3005eb7935a241e07a0224d941e`
plus the reserved `src/runtime/reactor/io_uring.rs` and
`src/runtime/reactor/mod.rs` clean overlay.

## Claim

This note covers bounded startup probes for requested `MultishotAccept` and
dependency-gated `MultishotRecv`. The accept probe binds a loopback listener,
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

The accept probe adds one narrow unsafe ownership-transfer operation in
`own_accepted_fd`. Its safe precheck rejects negative completion results before
`OwnedFd::from_raw_fd`; a successful accept CQE is the kernel's transfer of a
new descriptor to the caller. The receive probe reuses the existing narrowly
scoped SQE push operation. The unsafe-boundary ledger accounts for 21 exact
reactor source operations.

## Evidence

- RCH clean-overlay `cargo check -p asupersync --lib --features io-uring`
  passed on worker `hz2`; project hash `30d538e3f406ef90`, overlay fingerprint
  `26f22fd6237fd2fa0194f974ff7c15123a3eba4715c5bef2b5b845323c217361`.
- RCH clean-overlay feature-library Clippy passed with all warnings denied
  except the known current-main `clippy::redundant_pub_crate` family in
  `future.rs`; project hash `b7d4130dc08a2763`, overlay fingerprint
  `26f22fd6237fd2fa0194f974ff7c15123a3eba4715c5bef2b5b845323c217361`.
- The final RCH clean-overlay `io_uring_capability_inventory_contract` passed
  6/6 on worker `vmi1149989`; project hash `58da686f54026de2`, overlay
  fingerprint
  `85b42affc3df7f3deb7113b88cc2747e176024c822e71d98a7516b1ef5b97164`.
- The focused lib-test lane did not execute the selected test. Its remote build
  was cancelled after RCH reported stale progress with a fresh heartbeat, and
  its terminal output exposed pre-existing `non_snake_case` errors in
  `src/observability/otlp_proto.rs`, outside this bead's reserved paths.

## No-Claim Boundary

These receipts do not prove live-kernel support on a named production target,
reactor data-plane integration, sustained operation, throughput, latency,
memory improvement, broad lib-test health, or completion of URING-2. Mapped
buffer-ring probing, a focused executable receipt, and the target evidence
matrix remain open on the bead.
