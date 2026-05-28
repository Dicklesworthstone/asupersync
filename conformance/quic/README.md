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

ATP native QUIC conformance material is specification scaffolding until the
ATP-N2 dependency chain lands. Current production claims come from the
root-level ATP/native-QUIC test lanes; this directory is reference material and
must not be counted as live pass evidence until a later ATP-N2 proof promotes
specific vectors.
