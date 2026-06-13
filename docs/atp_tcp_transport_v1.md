# ATP-over-TCP Transport v1

Status: **active build** (br-asupersync-qk02uw,
asupersync-atp-transport-dos-hardening-abmj9q). This is the first *real* ATP
transport — it moves actual file bytes between two machines, verified, over
`asupersync::net::TcpStream` / `TcpListener`. It replaces the CLI/daemon facade
documented in `asupersync-qk02uw` (fake sleep-loop progress, no sockets).

## Why TCP first (not native QUIC)

The native QUIC stack under `src/net/atp/quic*` is largely real but depends on a
working I/O reactor; the default runtime currently has none wired by default
(`asupersync-1ajbtl`), so a UDP/QUIC path would run on the slow fallback-poll
regime and is the hardest transport to get correct. `TcpStream`/`TcpListener`
are real and have a shipped loopback lifecycle proof, and TCP already provides
reliable, ordered, flow-controlled byte delivery — exactly what a file transfer
needs. QUIC becomes an opt-in transport once the reactor lands. v1 reuses the
**real** ATP building blocks: the `AtpFrameCodec` wire format, the
`ObjectGraph`/`MerkleRoot` integrity model, and SHA-256 content hashing.

## Wire protocol (v1)

All control frames carry JSON payloads; bulk data frames use a compact binary
header. Frames are the canonical `AtpFrameCodec` frames (varint header + payload).

```
sender                                   receiver
  | --- Handshake(Hello) ----------------> |
  | <-- HandshakeAck(HelloAck) ----------- |   (accepted? protocol ok?)
  | --- ObjectManifest(TransferManifest) -> |   (entries, sizes, sha256, merkle root)
  | --- ObjectData[index,offset]+bytes ---> |   (256 KiB chunks, sequential per entry)
  | --- ObjectData ... -------------------> |
  | --- ObjectComplete -------------------> |   (all entries streamed)
  | <-- Proof(ReceiveReceipt) ------------- |   (sha_ok && merkle_ok => committed)
  | --- Close ----------------------------> |
```

### Frames
- `Handshake` (0x0001): `Hello { protocol, role, peer_id }`
- `HandshakeAck` (0x0002): `HelloAck { accepted, peer_id, reason? }`
- `ObjectManifest` (0x0100): `TransferManifest { transfer_id, root_name, is_directory, total_bytes, merkle_root_hex, entries[] }` where each `entry = { index, rel_path, size, sha256_hex }`
- `ObjectData` (0x0102): payload = `index:u32 BE` ++ `offset:u64 BE` ++ chunk bytes
- `ObjectComplete` (0x0103): empty (end of stream marker)
- `Proof` (0x0402): `ReceiveReceipt { committed, bytes_received, files, sha_ok, merkle_ok, reason?, committed_paths[] }`
- `Close` (0x0302) / `Error` (0x0301): orderly / error teardown

## Integrity (fail-closed)

The receiver buffers each declared entry in memory, validates the completed
transfer, and only then writes verified bytes to the destination with
`crate::fs::write_atomic`. Before allocating buffers it rejects manifests whose
declared total, per-entry sum, entry count, entry ordering, relative paths, or
single-file/directory shape are invalid.

After the byte stream completes it:
1. finalizes each entry's SHA-256 and compares to the manifest (`sha_ok`);
2. computes the same flat Merkle root from borrowed receive buffers, without
   cloning each buffer into an owned `ObjectGraph`, and compares it to
   `manifest.merkle_root_hex` (`merkle_ok`);
3. only if both hold, atomically writes each destination path and reports
   `committed = true`.

Any mismatch, short read, oversize entry, unreachable peer, rejected handshake,
invalid manifest, or protocol timeout is a hard error — the CLI exits non-zero
and the destination is untouched. There is no success path that moves zero bytes.

## Bounds and timeouts

v1 is deliberately bounded while it remains a memory-buffered TCP transport:

- Bulk `ObjectData` chunks default to 256 KiB so each data frame stays below the
  canonical `MAX_FRAME_SIZE`.
- JSON control frames, including `ObjectManifest`, are preflighted against
  `MAX_FRAME_SIZE`. Oversized manifests fail before send with an error that tells
  callers to split or chunk the manifest/control payload.
- A transfer defaults to a 4 GiB total-byte ceiling and 4 MiB initial receive
  reservation per entry. Buffers grow only from real received bytes.
- One-shot `receive_once` applies an accept timeout. Connected peers must make
  progress within the idle timeout for handshake, manifest, data, proof, and
  close operations.
- Persistent `serve` accepts concurrently up to the configured active-connection
  limit, aborts and drains children on cancellation, and does not let one idle
  peer monopolize the listener.

These bounds are operational guardrails, not throughput claims. Large directory
transfers that exceed one JSON manifest frame need manifest chunking or a higher
level split before they can be sent through v1.

## Determinism

The filesystem→graph builder walks entries in sorted `rel_path` order, maps each
file to `Object::file(bytes)` and directories to `Object::directory(edges)` with
`ObjectEdge::new(child_id, name)`, so the merkle root is identical on both sides
for identical content + layout. This is the integrity anchor.

## Module map
- `src/net/atp/transport_tcp/mod.rs` — wire types, `FrameTransport`, `send_path`,
  `receive_once`, `serve` accept loop, graph builder, verification, atomic writes,
  timeout handling, and manifest bounds.
- Consumed by: `atp send` / `atp get` (CLI), `atpd start` (daemon listener), and
  the standalone `atp` binary.
- Gated by: `tests/atp_tcp_loopback_e2e.rs` (two in-process endpoints transfer a
  real file + directory on 127.0.0.1 and assert byte-identical receipt + SHA +
  merkle match + fail-closed on a corrupted stream).
