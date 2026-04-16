# gRPC Connect Conformance Test Suite

This directory contains a comprehensive conformance test suite for gRPC with Connect protocol compatibility. It implements Pattern 6 (Process-Based Conformance) to verify that our gRPC implementation conforms to the gRPC specification and is compatible with Connect clients.

## Architecture

```text
┌─────────────────────┐    ┌─────────────────────┐
│ Connect Client      │    │ gRPC Client         │
│ (Reference)         │    │ (Our Implementation)│
└──────────┬──────────┘    └──────────┬──────────┘
           │                          │
           ▼                          ▼
┌─────────────────────────────────────────────────┐
│          Our gRPC Server                        │
│  (Target Implementation Under Test)             │
└─────────────────────────────────────────────────┘
```

## Test Categories

- **Unary RPC**: Single request → single response
- **Server Streaming**: Single request → multiple responses  
- **Client Streaming**: Multiple requests → single response
- **Bidirectional Streaming**: Multiple requests ↔ multiple responses
- **Error Handling**: Status codes, metadata, cancellation
- **Protocol Compliance**: HTTP/2 framing, compression, timeouts

## Running Tests

### Standalone Server

Start the test server:

```bash
cargo run --bin connect-server -- --port 8080 --enable-compression --connect-protocol
```

### Conformance Runner

Run the complete test suite:

```bash
cargo run --bin conformance-runner -- --server http://127.0.0.1:8080 --connect-protocol --enable-compression
```

### Custom Configuration

```bash
# Test against external server
cargo run --bin conformance-runner -- --server https://api.example.com --enable-tls

# Run specific test categories
cargo run --bin conformance-runner -- --filter "unary"

# Parallel execution
cargo run --bin conformance-runner -- --parallel
```

## Test Results

The conformance runner generates detailed reports:

- **Console Output**: Real-time test progress and summary
- **JSON Report**: `grpc_conformance_report.json` with detailed results
- **Exit Codes**:
  - `0`: ≥95% conformance (PASS)
  - `1`: 80-95% conformance (PARTIAL)
  - `2`: <80% conformance (FAIL)
  - `3`: Test suite execution error

## Connect Protocol Support

The test suite includes Connect protocol specific validation:

- Request/response header validation
- Error format compliance
- Streaming protocol specifics
- Compression negotiation
- Timeout handling

## Integration with External Tools

This conformance suite is designed to integrate with:

- Connect conformance runners
- gRPC ecosystem test suites
- CI/CD pipelines
- External gRPC implementations

## Development

### Adding New Test Cases

1. Add test case definitions to `src/test_cases.rs`
2. Implement test logic in appropriate category methods
3. Update service implementation in `src/service.rs` if needed
4. Verify Connect protocol compliance

### Debugging Test Failures

Enable verbose logging:

```bash
RUST_LOG=grpc_conformance_suite=debug,asupersync=debug cargo run --bin conformance-runner
```

View detailed error information in the generated JSON report.

## Status

- ✅ Basic unary RPC conformance
- ✅ Error handling and status codes  
- ✅ Metadata and headers
- 🚧 Server streaming (placeholder)
- 🚧 Client streaming (placeholder)
- 🚧 Bidirectional streaming (placeholder)
- 🚧 Connect protocol specifics
- 🚧 Compression testing
- 🚧 TLS/SSL testing

## Future Enhancements

- Complete streaming method implementations
- Full Connect protocol validation
- Performance benchmarking
- Interoperability with other gRPC implementations
- Advanced timeout and cancellation scenarios