# WebSocket Handshake Parser Fuzzing

This document describes the WebSocket handshake parser fuzzing implementation for bead asupersync-qs3664.

## Overview

The WebSocket handshake parser fuzzer (`fuzz/fuzz_targets/websocket_handshake_parser.rs`) targets RFC 6455 protocol negotiation vulnerabilities in the WebSocket handshake implementation at `src/net/websocket/handshake.rs`.

## Test Coverage

The fuzzer comprehensively tests the following attack vectors:

### 1. Sec-WebSocket-Key Validation (RFC 6455 §4.1)
- **Target**: 16-byte base64 key validation
- **Vectors**: Invalid base64 characters, wrong padding, incorrect lengths, oversized keys
- **Critical Property**: Must accept only valid 16-byte base64-encoded keys

### 2. Connection/Upgrade Header Injection (RFC 6455 §4.2.1)  
- **Target**: HTTP header parsing and validation
- **Vectors**: CRLF injection attempts, malformed token lists, case variations
- **Critical Property**: Must prevent HTTP header injection attacks

### 3. Protocol/Extension Negotiation (RFC 6455 §4.2.2)
- **Target**: Subprotocol and extension selection logic
- **Vectors**: Oversized protocol lists, embedded control chars, duplicate protocols
- **Critical Property**: Must fail gracefully on malicious negotiation attempts

### 4. HTTP Request/Response Boundary Parsing
- **Target**: HTTP message parsing boundaries 
- **Vectors**: Missing terminators, malformed headers, oversized header counts
- **Critical Property**: Must handle boundary conditions without panics or infinite loops

### 5. URL Parsing Edge Cases
- **Target**: WebSocket URL parsing (ws:// and wss://)
- **Vectors**: IPv6 brackets, malformed components, extremely long URLs
- **Critical Property**: Must validate URLs according to WebSocket URL scheme

### 6. Complete Handshake Flow Testing
- **Target**: End-to-end client/server handshake integration
- **Vectors**: Accept key mutations, extra headers, protocol mismatches
- **Critical Property**: Must maintain security invariants throughout handshake

## Test Operations

The fuzzer implements seven distinct operation types, each targeting specific vulnerability classes:

1. **WebSocketKeyTest**: Sec-WebSocket-Key validation edge cases
2. **ConnectionUpgradeTest**: Header injection vulnerability testing  
3. **ProtocolNegotiationTest**: Protocol/extension negotiation attacks
4. **HttpRequestBoundaryTest**: HTTP request parsing boundaries
5. **HttpResponseBoundaryTest**: HTTP response parsing validation
6. **FullHandshakeFlowTest**: Complete handshake sequence testing
7. **UrlParsingTest**: WebSocket URL parsing edge cases

## Running the Fuzzer

```bash
# From the fuzz directory
cargo fuzz run websocket_handshake_parser

# With time limit
cargo fuzz run websocket_handshake_parser -- -max_total_time=300

# With specific number of runs
cargo fuzz run websocket_handshake_parser -- -runs=10000
```

## Security Properties Verified

The fuzzer asserts the following security invariants:

- **No panics**: All parsing functions must handle malformed input gracefully
- **No infinite loops**: Parsing must terminate on all inputs within reasonable time
- **No memory exhaustion**: Oversized inputs must be rejected without OOM
- **Injection resistance**: CRLF injection attempts must be sanitized
- **Protocol compliance**: Only RFC 6455-compliant handshakes should succeed

## Implementation Notes

- Uses `DetEntropy` for deterministic key generation in testing scenarios
- Implements structure-aware input generation for realistic attack vectors
- Covers both client-side and server-side handshake validation paths
- Tests integration between handshake parsing and higher-level protocol logic

## Integration with Existing Test Suite

This fuzzer complements the existing WebSocket frame fuzzing targets:
- `websocket_frame.rs` - Frame-level protocol testing
- `websocket_fragmentation_*.rs` - Message fragmentation testing  
- `websocket_deflate.rs` - Extension-specific testing

The handshake fuzzer specifically targets the security-critical negotiation phase that occurs before frame-level communication begins.