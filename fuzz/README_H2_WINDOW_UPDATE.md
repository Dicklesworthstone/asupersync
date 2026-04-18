# HTTP/2 WINDOW_UPDATE Frame Fuzz Target

## Overview

The `h2_window_update_frame` fuzz target provides comprehensive testing for HTTP/2 WINDOW_UPDATE frame implementation per RFC 7540 §6.9. It focuses specifically on the flow control aspects, boundary conditions, and error handling that are critical for HTTP/2 compliance.

## Scope

This fuzz target covers the specific requirements from task asupersync-ronzpw:

- **Increment 0 reject**: Zero window size increment validation (RFC 7540 §6.9.1)
- **Max 2^31-1 boundary**: Maximum window increment boundary testing 
- **Connection-level vs stream-level**: Different error handling for stream ID 0 vs non-zero
- **Flow-control overflow**: Window size overflow detection scenarios
- **Reserved bit handling**: Reserved bit validation and clearing

## Key Features

### Frame Operations
- Parse WINDOW_UPDATE frames from raw bytes
- Parse structured WINDOW_UPDATE frames with specific stream_id and increment
- Parse multiple consecutive frames
- Parse truncated frames (graceful error handling)

### Edge Cases & Boundary Conditions
- **Zero Increment Validation**: RFC 7540 §6.9.1 compliance
  - Connection-level (stream ID 0): Protocol error
  - Stream-level (stream ID > 0): Stream error with correct error code
- **Maximum Increment Testing**: 2^31-1 (0x7FFFFFFF) boundary validation
- **Stream ID Boundaries**: Connection-level vs stream-level behavior differences
- **Invalid Payload Length**: Non-4-byte payload rejection
- **Reserved Bit Handling**: Proper reserved bit clearing and validation

### Round-Trip Testing
- Standard encode → decode → verify scenarios
- Boundary increment values (min=1, max=2^31-1, powers of 2)
- Stream ID pattern testing (sequential, alternating, random)

### Flow Control Testing
- Window overflow detection (current + increment > 2^31-1)
- Cumulative increment overflow scenarios
- Large increment boundary testing

### Reserved Bit Testing
- Reserved bit set in increment field (should be cleared)
- Multiple reserved bits pattern testing
- Encoding reserved bit clearing verification

## Implementation Details

### Constants (RFC 7540)
- `MAX_INCREMENT`: 0x7FFFFFFF (2^31-1) - Maximum valid window increment
- `MAX_WINDOW_SIZE`: 0x7FFFFFFF - Maximum flow control window size  
- `WINDOW_UPDATE_PAYLOAD_SIZE`: 4 bytes - Fixed payload size requirement
- `MAX_OPERATIONS`: 50 (prevents timeout in complex scenarios)

### Frame Structure (RFC 7540 §6.9)
```
WINDOW_UPDATE Frame {
  Type (8-bit): 0x8
  Flags (8-bit): 0 (no flags defined)
  Stream ID (31-bit): 0 for connection, >0 for stream
  Window Size Increment (31-bit): 1-2^31-1
}
```

### Error Handling (RFC 7540 §6.9.1)
- **Zero increment on stream**: Stream error (PROTOCOL_ERROR)
- **Zero increment on connection**: Connection error (PROTOCOL_ERROR)
- **Invalid payload length**: Frame size error
- **Reserved bit validation**: Automatic clearing during parsing

## Usage

### Basic Fuzzing

```bash
# Run the WINDOW_UPDATE frame fuzz target
cd fuzz/
cargo +nightly fuzz run h2_window_update_frame

# Run for specific duration
cargo +nightly fuzz run h2_window_update_frame -- -max_total_time=60

# Run with specific corpus
cargo +nightly fuzz run h2_window_update_frame corpus/h2_window_update_frame/
```

### Advanced Options

```bash
# Run with AddressSanitizer (default for fuzzing)
RUSTFLAGS="-Zsanitizer=address" cargo +nightly fuzz run h2_window_update_frame

# Run with MemorySanitizer (for unsafe code)
RUSTFLAGS="-Zsanitizer=memory" cargo +nightly fuzz run h2_window_update_frame

# Minimize crash inputs
cargo +nightly fuzz tmin h2_window_update_frame artifacts/h2_window_update_frame/crash-<hash>

# Coverage information
cargo +nightly fuzz coverage h2_window_update_frame
```

## Test Categories

### 1. Zero Increment Rejection (RFC 7540 §6.9.1)
Tests proper rejection of zero window size increments:
- Connection-level (stream ID 0) → Protocol error
- Stream-level (stream ID > 0) → Stream error with PROTOCOL_ERROR code
- Error message validation (should mention "zero increment")

### 2. Boundary Value Testing
- Minimum valid increment: 1
- Maximum valid increment: 2^31-1 (0x7FFFFFFF)
- Powers of 2: 1, 2, 4, 8, ..., 2^30
- Near-boundary values: MAX-1, MAX+1 (should overflow)

### 3. Stream ID Validation
- Connection-level: stream ID 0
- Stream-level: stream IDs 1, 3, 5, ... (odd numbers for client-initiated)
- Maximum stream ID: 2^31-1
- Reserved bit handling: stream IDs with bit 31 set

### 4. Flow Control Overflow
- Current window + increment > 2^31-1
- Cumulative increments leading to overflow
- Large increments near maximum values

### 5. Reserved Bit Handling
- Increment with reserved bit set (bit 31)
- Multiple reserved bits in various patterns
- Verification that encoding clears reserved bits

## Expected Findings

Common issues this fuzz target may discover:
- Incorrect zero increment error classification (connection vs stream)
- Integer overflow in window size calculations
- Reserved bit handling inconsistencies
- Frame length validation bypass
- Memory leaks in error handling paths
- Incorrect error code assignment

## RFC 7540 Compliance

The fuzz target validates compliance with HTTP/2 specification:
- **§6.9**: WINDOW_UPDATE frame format and semantics
- **§6.9.1**: Zero increment error handling requirements
- **§4.1**: Frame header format (9-byte header + 4-byte payload)
- **§6.9.1**: Connection vs stream error classification

## Performance Characteristics

Target performance metrics:
- **Execution rate**: >1000 exec/s for frame parsing
- **Coverage**: Focus on WINDOW_UPDATE-specific code paths in h2/frame.rs
- **Memory usage**: Bounded by frame size limits
- **Corpus growth**: Expect plateau after covering boundary values and error conditions

## Relationship to Existing Tests

This fuzz target complements:
- `http2_frame.rs`: General HTTP/2 frame fuzzing (covers all 10 frame types)
- `h2_settings_frame.rs`: HTTP/2 SETTINGS frame specific testing
- Unit tests in `src/http/h2/frame.rs`: Basic WINDOW_UPDATE roundtrip testing
- Integration tests: End-to-end HTTP/2 flow control scenarios

## Corpus Management

Recommended corpus seed files:
- Minimum increment WINDOW_UPDATE frame (increment=1)
- Maximum increment WINDOW_UPDATE frame (increment=2^31-1) 
- Connection-level WINDOW_UPDATE (stream ID=0)
- Stream-level WINDOW_UPDATE (stream ID=1)
- Zero increment frames (should trigger errors)
- Reserved bit test cases
- Invalid payload length frames