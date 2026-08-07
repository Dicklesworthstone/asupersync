# io_uring Multishot Receive Probe Proof Note

Bead: `asupersync-sched-hot-path-perf-bt4y5f.7.2`

Source basis: committed `HEAD` `6211ab5cc22ef68dbe3c4c4da1bb17160240e982`
plus the reserved `src/runtime/reactor/io_uring.rs` and
`src/runtime/reactor/mod.rs` clean overlay.

## Claim

This slice adds a dependency-gated startup probe for the requested
`ProvidedGroups` plus `MultishotRecv` capability pair. The probe establishes
that one multishot receive request can select two distinct provided buffers,
retain the kernel `MORE` indication on both data completions, terminate after
explicit cancellation, and return all selected buffers before removing the
group. The result is cached and reported through the existing capability
policy. It is not used by the reactor data plane.

## Safety Argument

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

The slice adds no unsafe block. It reuses the existing narrowly scoped SQE push
operation through `push_probe_entry`; the unsafe-boundary ledger still accounts
for the same 20 source operations, with line anchors refreshed after the helper
extraction.

## Evidence

- RCH clean-overlay `cargo check -p asupersync --lib --features io-uring`
  passed on worker `hz2`; project hash `abd5f27f7d240023`, overlay fingerprint
  `37504271985ea1cad0aa420a4f8ef20a2d13274f24ad6ab57da383e0cfb70a82`.
- RCH clean-overlay feature-library Clippy passed with all warnings denied
  except the known current-main `clippy::redundant_pub_crate` family in
  `future.rs`; project hash `228dd566d1dbd7ec`, overlay fingerprint
  `5c85d017b3b90b0205adad314af72f968f7a46fa69a5339c2e6a2ebe833101a5`.
- The final RCH clean-overlay `io_uring_capability_inventory_contract` passed
  6/6 on worker `ovh-a`; project hash `b943f557085dc7ed`, overlay fingerprint
  `002357c0a3fd049f92b53490ad5f7d54aafd71bdafc26a2161f1b7288b48c126`.
- The focused lib-test lane did not execute the selected test. Its remote build
  was cancelled after RCH reported stale progress with a fresh heartbeat, and
  its terminal output exposed pre-existing `non_snake_case` errors in
  `src/observability/otlp_proto.rs`, outside this bead's reserved paths.

## No-Claim Boundary

These receipts do not prove live-kernel support on a named production target,
reactor data-plane integration, sustained operation, throughput, latency,
memory improvement, broad lib-test health, or completion of URING-2. Mapped
buffer-ring probing, multishot accept probing, and the target evidence matrix
remain open on the bead.
