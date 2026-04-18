# QUIC-TLS State Machine Fuzzer

## Overview

The `fuzz_quic_tls_state_machine.rs` fuzzer targets the QUIC-TLS state machine in `src/net/quic_native/tls.rs`. This is a specialized fuzzer for QUIC's key management and handshake confirmation logic, which is distinct from general TLS parsing or handshake sequence fuzzing.

## Target Coverage

### Core State Machine Components
- **CryptoLevel progression**: Initial → Handshake → OneRtt (monotonic transitions)
- **Key phase updates**: Local/remote key rotation for QUIC key updates  
- **Handshake confirmation**: Transition from 0-RTT to 1-RTT capability
- **Session resumption**: 0-RTT enablement/disablement logic
- **Generation tracking**: Key phase generation overflow/underflow scenarios

### Attack Surfaces Tested
1. **Invalid state transitions** - Backwards progression, skipped levels
2. **Key update race conditions** - Request/commit ordering, pending state management
3. **Phase bit manipulation** - Boolean phase flips, generation counters
4. **Capability calculations** - 0-RTT/1-RTT authorization logic bugs
5. **Invariant violations** - Simultaneous capabilities, invalid combinations

## Fuzzing Strategy

### Operation Sequence Testing
The fuzzer generates random sequences of state machine operations:
- `OnHandshakeKeysAvailable` / `On1RttKeysAvailable` (level progression)
- `OnHandshakeConfirmed` (confirmation logic)  
- `RequestLocalKeyUpdate` / `CommitLocalKeyUpdate` (key rotation)
- `OnPeerKeyPhase` (remote key phase processing)
- `EnableResumption` / `DisableResumption` (0-RTT control)

### Invariant Checking
After each operation, the fuzzer validates:
- Level progression is monotonic
- 1-RTT requires OneRtt level AND handshake confirmation
- 0-RTT and 1-RTT are mutually exclusive
- 0-RTT requires resumption enabled + >= Handshake level
- Key phase bits are well-defined booleans

### Error Testing
The fuzzer tests error conditions:
- `HandshakeNotConfirmed` errors for key operations before confirmation
- `InvalidTransition` errors for backwards level progression
- Proper error messages and display formatting

## Implementation Details

### Arbitrary Wrapper
Since `CryptoLevel` doesn't implement `Arbitrary`, we use `ArbitraryCryptoLevel` wrapper:
```rust
#[derive(Arbitrary, Debug, Clone, Copy)]
enum ArbitraryCryptoLevel {
    Initial, Handshake, OneRtt,
}
```

### Differential Testing
The fuzzer tracks expected state alongside actual state to catch divergences:
- Expected crypto level progression
- Clone consistency verification
- State machine determinism checks

### Safety Limits
- Maximum 1000 operations per run (prevents timeouts)
- Maximum 100 key phase values (bounded input)
- Invariant checking after every operation

## Usage

### Basic Fuzzing
```bash
cargo fuzz run fuzz_quic_tls_state_machine
```

### Corpus Management  
```bash
# Minimize corpus (recommended weekly)
cargo fuzz cmin fuzz_quic_tls_state_machine

# Minimize crash inputs for debugging
cargo fuzz tmin fuzz_quic_tls_state_machine artifacts/fuzz_quic_tls_state_machine/crash-...
```

### CI Integration
```bash
# Short fuzzing run for CI
cargo fuzz run fuzz_quic_tls_state_machine -- -max_total_time=60 -runs=1000
```

## Expected Findings

### Bug Classes Likely to be Found
1. **State transition bugs** - Invalid level progression logic
2. **Race conditions** - Key update request/commit ordering issues  
3. **Capability calculation bugs** - Incorrect 0-RTT/1-RTT authorization
4. **Generation overflow** - Key phase counter wraparound issues
5. **Invariant violations** - Simultaneous contradictory states

### Performance Characteristics
- **Target speed**: >1000 exec/s (state machine operations are fast)
- **Coverage plateau**: Expected within 10-30 minutes for this state machine
- **Memory usage**: Low (simple in-memory state, no I/O)

## Related Fuzzers

- `fuzz_tls_handshake_sequence.rs` - Tests general TLS connector handshake flow
- `fuzz_tls_message_parsing.rs` - Tests TLS wire format parsing
- `fuzz_quic_core_protocol.rs` - Tests QUIC packet/frame processing
- `fuzz_quic_frame_parsing.rs` - Tests QUIC frame format parsing

This fuzzer specifically targets the **state machine logic** rather than wire format parsing or I/O operations, providing coverage for a critical security boundary in QUIC key management.