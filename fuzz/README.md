# Fuzzing Infrastructure for asupersync

This directory contains fuzz targets for testing protocol parsers and runtime
invariants using cargo-fuzz (libFuzzer backend).

## Prerequisites

```bash
# Install cargo-fuzz (requires nightly Rust)
rustup install nightly
cargo +nightly install cargo-fuzz
```

## Available Targets

| Target | Description | Priority |
|--------|-------------|----------|
| `fuzz_http1_request` | HTTP/1.1 request parser | High |
| `fuzz_http1_response` | HTTP/1.1 response parser | High |
| `dns_resolver_name_compression` | Real resolver RFC 1035 compression and RDATA name parsing | High |
| `h1_parsed_url` | HTTP/1 client URL parser | High |
| `length_delimited_encode_width` | Length-delimited encode width and round-trip invariants | High |
| `length_delimited_decoder_state` | Length-delimited decoder chunking and invalid-header invariants | High |
| `fuzz_lines_codec` | Newline-delimited frame parsing, mixed delimiters, UTF-8 rejection, and max-line enforcement | High |
| `bytes_slice_split_to` | Immutable Bytes slicing, split_to, and partition invariants | High |
| `bytes_cursor_reader` | BytesCursor and reader() position, chunk, and copy invariants | High |
| `gf256_simd_edge_cases` | GF(256) SIMD/scalar parity, fast-path, alignment, and threshold-boundary invariants | High |
| `grpc_prost_codec_decode` | Direct ProstCodec decode limits, malformed-wire, and unknown-field invariants | High |
| `grpc_gzip_message_decode` | Gzip-compressed gRPC frame decode, malformed-gzip rejection, bomb guards, and max-message enforcement | High |
| `grpc_length_prefixed` | gRPC frame roundtrip, partial-body accumulation, invalid-flag rejection, and max-size enforcement invariants | High |
| `grpc_streaming` | Bidirectional gRPC stream interleaving, half-close/cancel propagation, deadline, and backpressure invariants | High |
| `fuzz_distributed_snapshot_merge` | CRDT snapshot merge convergence under delta reordering, malformed-wire rejection, and region-mismatch handling | High |
| `h3_native_frames` | HTTP/3 frame-header varint bounds, malformed-frame rejection, unknown-frame preservation, and GREASE tolerance | High |
| `qpack_field_section` | QPACK encoded field section parsing for static-indexed fields, static-name literals, dynamic-reference rejection, and prefixed-integer overflow | High |
| `kafka_protocol` | Kafka request-header ApiKey/ApiVersion, correlation echo, tagged-field varint, and size-bound invariants | High |
| `key_derivation_context` | AuthKey seed/raw/RNG derivation, chained purpose isolation, and mutated-tag/symbol verification invariants | High |
| `region_heap_allocator` | RegionHeap mixed-size/high-alignment allocation, stale-handle reuse, and reclaim-all invariants | High |
| `otel_span_attributes` | OpenTelemetry span attribute/event limit, overwrite, truncation, and mixed value-shape encoding invariants | High |
| `quic_stream_flow` | QUIC stream flow-control window updates, RESET_STREAM/STOP_SENDING, and credit-accounting invariants | High |
| `symbol_auth` | AuthenticatedSymbol MAC verification, forged-tag rejection, replay-window, and field-tampering invariants | High |
| `symbol_cancel_broadcast` | Symbol cancel fanout, duplicate suppression, max-hop termination, and late-subscriber cancellation invariants | High |
| `postgres_scram` | PostgreSQL SCRAM-SHA-256 server-first/server-final parsing, iteration-bound enforcement, and malformed-signature rejection | High |
| `raptorq_decoder_gauss_matrix` | RaptorQ decoder Gaussian-elimination rank-deficient, malformed-equation, and corrupt-RHS invariants | High |
| `source_payload_hash_verification` | DecodeProof replay verification for divergent recovered-source payloads with identical symbol structure and deterministic source-payload-hash mismatch detection | High |
| `fuzz_raptorq_rfc6330` | RFC 6330 OTI transfer-length, sub-block partitioning, duplicate-ESI tolerance, and checksum-mismatch invariants | High |
| `tls_stream_record_framing` | TlsStream handshake/read/write behavior under fragmented and malformed TLS records | High |
| `transport_router` | RoutingTable add/remove/lookup, TTL pruning, fallback routing, and dispatcher strategy invariants | High |
| `fuzz_websocket_frame_parsing` | RFC 6455 frame parser invariants for control, continuation, masking, RSV bits, and extended lengths | High |
| `fuzz_hpack_decode` | HPACK header compression decoder | Critical |
| `hpack_indexed` | HPACK indexed-header static/dynamic table lookup invariants | High |
| `fuzz_http2_frame` | HTTP/2 frame parser | Critical |
| `fuzz_interest_flags` | Reactor Interest bitflags | Low |

## Running Fuzz Targets

```bash
# Change to fuzz directory
cd fuzz

# Run a specific target
cargo +nightly fuzz run fuzz_http2_frame

# Run with timeout (e.g., 60 seconds)
cargo +nightly fuzz run fuzz_http2_frame -- -max_total_time=60

# Run with specific number of jobs (parallel)
cargo +nightly fuzz run fuzz_http2_frame -- -jobs=4 -workers=4
```

## Corpus Management

Corpora are stored in `corpus/<target_name>/`. To merge and minimize:

```bash
# Merge new findings into corpus
cargo +nightly fuzz cmin fuzz_http2_frame

# Minimize a specific crash
cargo +nightly fuzz tmin fuzz_http2_frame <crash_file>
```

## Seed Files

Initial seed files are in `seeds/`. These provide starting points for fuzzing:

- `seeds/http1/` - Valid HTTP/1.1 messages
- `seeds/http2/` - Valid HTTP/2 frames
- `seeds/hpack/` - Valid HPACK-encoded headers
- `corpus/dns_resolver_name_compression/` - Resolver name-compression and rdlen-bound scenarios
- `corpus/h1_parsed_url/` - Valid and invalid HTTP/1 client URLs
- `corpus/length_delimited_encode_width/` - Width-sensitive length-delimited encode scenarios
- `corpus/length_delimited_decoder_state/` - Decoder chunking and invalid-header scenarios
- `corpus/fuzz_lines_codec/` - Newline-delimited frame seeds covering empty lines, trailing EOF without newline, and oversized-line recovery
- `corpus/bytes_slice_split_to/` - Immutable Bytes slicing and split partition scenarios
- `corpus/bytes_cursor_reader/` - BytesCursor reader and cursor-position scenarios
  including empty views, clone-heavy cursor churn, and position-reset cases
- `corpus/gf256_simd_edge_cases/` - GF(256) fast-path, threshold-boundary, unaligned, and dual-slice parity scenarios
- `corpus/grpc_prost_codec_decode/` - Direct ProstCodec decode boundary and malformed-wire scenarios
- `corpus/grpc_gzip_message_decode/` - Gzip-compressed gRPC frame decode, malformed-gzip rejection, and bomb-guard scenarios
- `corpus/grpc_length_prefixed/` - gRPC frame seeds covering roundtrip framing, partial-body completion, invalid compression flags, and oversize-length rejection
- `corpus/grpc_streaming/` - Bidirectional stream seeds covering interleaving, half-close/cancel, and deadline/backpressure scenarios
- `corpus/h2_connection_window_update/` - HTTP/2 connection-state WINDOW_UPDATE seeds covering zero-increment rejection, idle-stream protocol errors, queued frame ordering, and window-overflow guards
- `corpus/fuzz_distributed_snapshot_merge/` - CRDT merge seeds covering reordering convergence, malformed delta bytes, and region mismatch handling
- `corpus/h3_native_frames/` - HTTP/3 DATA/HEADERS header varint, GREASE unknown-frame, reserved-type, and truncated-payload scenarios
- `corpus/qpack_field_section/` - QPACK field section seeds covering static indexed fields, static-name literals, dynamic references without table state, and prefixed-integer overflow
- `corpus/kafka_protocol/` - Kafka request-header scenarios covering ApiKey/version mismatches, tagged-field varints, correlation echo, and oversized frames
- `corpus/key_derivation_context/` - AuthKey seed/raw/RNG derivation, chained purpose isolation, and mutated-tag/symbol scenarios
- `corpus/region_heap_allocator/` - RegionHeap allocation, stale-handle, reclaim-all, and high-alignment slot-reuse scenarios
- `corpus/otel_span_attributes/` - Span attribute overwrite, mixed value-shape, event truncation, and max-event cap scenarios
- `corpus/quic_stream_flow/` - QUIC flow-control, reset, stop-sending, window-regression, and credit-exhaustion scenarios
- `corpus/symbol_auth/` - AuthenticatedSymbol forged-tag, wrong-key, replay-window, and payload/context-tampering scenarios
- `corpus/symbol_cancel_broadcast/` - Symbol cancel fanout scenarios covering duplicate delivery, max-hop exhaustion, and late-child/late-listener observation
- `corpus/postgres_bind_execute_sync/` - Extended-query Bind/Execute/Sync seeds covering binary/text parameters, embedded-NUL portal names, injected bind errors, and excessive parameter-count rejection
- `corpus/postgres_scram/` - SCRAM server-first/server-final seeds covering valid nonces, low-iteration rejects, and malformed signatures
- `corpus/raptorq_decoder_gauss_matrix/` - Rank-deficient duplicate-source/repair systems plus malformed-equation and corrupt-RHS decoder scenarios
- `corpus/source_payload_hash_verification/` - DecodeProof replay seeds covering matching replay, regenerated divergent payloads, and single-byte source mutation with recomputed repairs
- `corpus/fuzz_raptorq_rfc6330/` - RFC 6330 OTI seeds covering aligned transfer lengths, invalid sub-block divisibility, duplicate ESIs, and checksum mismatch cases
- `corpus/tls_stream_record_framing/` - TlsStream record fragmentation, truncation, and close-notify scenarios
- `corpus/transport_router/` - RoutingTable insert/remove/reinsert, lookup-miss fallback, TTL expiry, and dispatch-strategy scenarios
- `corpus/fuzz_websocket_frame_parsing/` - RFC 6455 control, continuation, mask-role, RSV-bit, and extended-length frame scenarios
- `corpus/hpack_indexed/` - HPACK indexed-header valid static indices and invalid dynamic lookups

To run with seeds:

```bash
cargo +nightly fuzz run fuzz_http2_frame seeds/http2/
```

## Coverage

Generate coverage report:

```bash
# Build with coverage instrumentation
cargo +nightly fuzz coverage fuzz_http2_frame

# View coverage report
# (Output in fuzz/coverage/fuzz_http2_frame/)
```

## CI Integration

Fuzzing runs in CI using:

```yaml
# Example GitHub Actions snippet
- name: Run fuzz tests
  run: |
    cargo +nightly fuzz run fuzz_http2_frame -- -max_total_time=300
```

## Security Notes

- Crashes are saved in `artifacts/<target_name>/`
- Review all crashes for security implications before disclosure
- HPACK decoder is critical - vulnerable to HPACK bomb attacks
- HTTP/2 frame parser is critical - vulnerable to resource exhaustion

## Adding New Targets

1. Create `fuzz_targets/<name>.rs` with the fuzz harness
2. Add `[[bin]]` entry in `Cargo.toml`
3. Create initial seeds in `seeds/<category>/`
4. Update this README

## References

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [RFC 7540 - HTTP/2](https://tools.ietf.org/html/rfc7540)
- [RFC 7541 - HPACK](https://tools.ietf.org/html/rfc7541)
