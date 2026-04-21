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
| `bytes_slice_split_to` | Immutable Bytes slicing, split_to, and partition invariants | High |
| `bytes_cursor_reader` | BytesCursor and reader() position, chunk, and copy invariants | High |
| `grpc_prost_codec_decode` | Direct ProstCodec decode limits, malformed-wire, and unknown-field invariants | High |
| `tls_stream_record_framing` | TlsStream handshake/read/write behavior under fragmented and malformed TLS records | High |
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
- `corpus/bytes_slice_split_to/` - Immutable Bytes slicing and split partition scenarios
- `corpus/bytes_cursor_reader/` - BytesCursor reader and cursor-position scenarios
  including empty views, clone-heavy cursor churn, and position-reset cases
- `corpus/grpc_prost_codec_decode/` - Direct ProstCodec decode boundary and malformed-wire scenarios
- `corpus/tls_stream_record_framing/` - TlsStream record fragmentation, truncation, and close-notify scenarios
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
