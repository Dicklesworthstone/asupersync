# ATP Native QUIC Protocol Conformance

This directory contains conformance test specifications and reference data for ATP's native QUIC protocol implementation.

## Structure

- `frame_specs/` - QUIC frame specification tests
- `packet_specs/` - QUIC packet format tests  
- `reference_vectors/` - Test vectors for protocol validation
- `interop_tests/` - Interoperability test cases

## Usage

The conformance tests in `tests/atp/quic/conformance.rs` reference the specifications and test vectors in this directory to validate protocol correctness.

## Test Coverage

- Frame encoding/decoding round-trip tests
- Packet number space handling
- Transport parameters negotiation
- Version negotiation
- ACK range processing
- Flow control boundaries
- Connection close/drain behavior

## Status

Placeholder implementation - will be populated when ATP-N2 dependencies are complete.