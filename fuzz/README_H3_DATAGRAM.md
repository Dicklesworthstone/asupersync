# HTTP/3 DATAGRAM Frame Fuzz Target

## Overview

The `h3_datagram_frame` fuzz target provides comprehensive testing for HTTP/3 DATAGRAM frame implementation per RFC 9297. It focuses specifically on the encode/decode logic for DATAGRAM frames with quarter_stream_id and payload components.

## Scope

This fuzz target covers:

- **Crash detection**: Raw bytes → DATAGRAM frame parsing without panics
- **Round-trip testing**: Encode → decode consistency for various scenarios  
- **Edge cases**: Empty payloads, large quarter_stream_id values, boundary conditions
- **Malformed input handling**: Invalid varint encoding, oversized lengths, truncated frames
- **Metamorphic properties**: Concatenation preservation, encoding order invariance

## Key Features

### Frame Operations
- Parse DATAGRAM frames from raw bytes
- Parse structured DATAGRAM frames with specific quarter_stream_id and payload
- Parse multiple consecutive frames
- Parse truncated frames (graceful error handling)

### Edge Cases
- Empty payload with various quarter_stream_id values
- Maximum quarter_stream_id values (up to 2^62 - 1)
- Large payloads up to 16KB
- Invalid varint encodings for quarter_stream_id
- Single byte inputs and malformed frame headers
- Length mismatches and oversized frame declarations

### Round-Trip Testing
- Standard encode → decode → verify scenarios
- Boundary value testing (powers of 2, varint boundaries)
- Payload pattern preservation (zeros, ones, alternating, sequential, UTF-8)

### Metamorphic Properties
- Empty payload invariance testing
- Concatenation preservation across multiple frames
- Encoding order invariance for identical frames
- Payload byte order sensitivity verification

## Usage

### Basic Fuzzing

```bash
# Run the DATAGRAM frame fuzz target
cd fuzz/
cargo +nightly fuzz run h3_datagram_frame

# Run for specific duration
cargo +nightly fuzz run h3_datagram_frame -- -max_total_time=60

# Run with specific corpus
cargo +nightly fuzz run h3_datagram_frame corpus/h3_datagram_frame/
```

### Advanced Options

```bash
# Run with AddressSanitizer (default for fuzzing)
RUSTFLAGS="-Zsanitizer=address" cargo +nightly fuzz run h3_datagram_frame

# Run with MemorySanitizer (for unsafe code)
RUSTFLAGS="-Zsanitizer=memory" cargo +nightly fuzz run h3_datagram_frame

# Minimize crash inputs
cargo +nightly fuzz tmin h3_datagram_frame artifacts/h3_datagram_frame/crash-<hash>

# Coverage information
cargo +nightly fuzz coverage h3_datagram_frame
```

## Implementation Details

### Constants
- `MAX_PAYLOAD_SIZE`: 16KB (prevents memory exhaustion)
- `MAX_QUARTER_STREAM_ID`: 2^62 - 1 (maximum valid QUIC stream ID)
- `MAX_OPERATIONS`: 50 (prevents timeout in complex scenarios)
- `MAX_FRAMES`: 10 (limits concatenation testing)

### Frame Structure (RFC 9297)
```
DATAGRAM Frame {
  Type (varint): 0x30
  Length (varint): Variable
  Quarter Stream ID (varint): Variable  
  Payload (bytes): Variable (0 to MAX_PAYLOAD_SIZE)
}
```

### Error Handling
The fuzz target verifies proper error handling for:
- `H3NativeError::UnexpectedEof` for truncated frames
- `H3NativeError::InvalidFrame` for malformed frame structure
- Graceful handling of invalid varint encodings
- Size limit enforcement

## Relationship to Existing Tests

This fuzz target complements:
- `h3_native_protocol.rs`: General HTTP/3 protocol fuzzing (covers broader H3 surface)
- Unit tests in `src/http/h3_native.rs`: Specific DATAGRAM frame logic
- Integration tests: End-to-end HTTP/3 DATAGRAM functionality

## RFC 9297 Compliance

The fuzz target validates compliance with HTTP/3 DATAGRAM specification:
- Frame type 0x30 (H3_FRAME_DATAGRAM)
- Varint quarter_stream_id encoding
- Arbitrary payload length (within implementation limits)
- Proper error handling for malformed inputs
- Setting 0x33 (H3_SETTING_H3_DATAGRAM) capability negotiation (tested separately)

## Expected Findings

Common issues this fuzz target may discover:
- Integer overflow in quarter_stream_id handling
- Buffer overruns in payload processing
- Incorrect varint decoding edge cases
- Memory leaks in error paths
- Panic conditions on malformed input
- Inconsistent round-trip encoding/decoding

## Performance Characteristics

Target performance metrics:
- **Execution rate**: >1000 exec/s for parser fuzzing
- **Coverage**: Focus on DATAGRAM-specific code paths in h3_native.rs
- **Memory usage**: Bounded by MAX_PAYLOAD_SIZE limits
- **Corpus growth**: Expect plateau after covering varint boundaries and payload patterns

## Corpus Management

Recommended corpus seed files:
- Empty payload DATAGRAM frame
- Small quarter_stream_id with typical payload
- Maximum quarter_stream_id with empty payload
- Varint boundary values (63, 16383, 1073741823)
- Various payload sizes and patterns