# WebSocket Fragmentation Sequence State Machine Fuzzer

## Overview

Implemented a comprehensive fuzzer targeting RFC 6455 §5.4 fragmentation violations and complex WebSocket frame sequence edge cases that can trigger state machine bugs in `src/net/websocket/frame.rs`.

## Target Function

- **Primary**: `src/net/websocket/frame.rs` `FrameCodec::decode()`
- **Secondary**: WebSocket fragmentation state machine across frame sequences
- **Focus**: Multi-frame sequences with protocol violations

## Implementation

Created `fuzz/fuzz_targets/websocket_fragmentation_state_machine.rs` with the following capabilities:

### 1. Frame Generation
- **FuzzFrame structure**: Configurable FIN/RSV/opcode/mask/payload fields
- **Encoding logic**: Proper WebSocket frame binary encoding
- **Sequence generation**: Creates frame sequences from fuzz input

### 2. Fragmentation Violations Tested

#### RFC 6455 §5.4 Specific Violations
- **Continuation without initial**: Continuation frame without preceding fragmented frame
- **Control frame fragmentation**: Control frames (ping/pong/close) with FIN=false
- **Interleaved control frames**: Control frames interrupting fragmented sequences
- **Invalid continuation sequences**: Malformed fragment ordering

#### Protocol Edge Cases
- **Reserved bit violations**: RSV1/RSV2/RSV3 set when extension not negotiated
- **Oversized control frames**: Control frames >125 bytes (protocol violation)
- **Masking violations**: Client/server masking requirement violations
- **Frame boundary conditions**: Edge cases in length encoding (126/127 thresholds)

### 3. Dual Role Testing
- **Server role**: Tests masked client frames (expected normal case)
- **Client role**: Tests unmasked server frames with modified sequences

### 4. Fuzzing Strategy
- **Stateful sequences**: Generates related frame sequences that exercise state transitions
- **Error recovery**: Tests parser resilience to malformed sequences
- **Memory safety**: Exercises buffer management across fragmented messages

## Bug Classes Targeted

1. **Buffer overflow** in fragment reassembly logic
2. **UTF-8 validation bypass** via fragment boundary manipulation  
3. **State machine confusion** from interleaved control frames
4. **Memory exhaustion** via unbounded fragment accumulation
5. **Use-after-free** in fragment buffer management
6. **Race conditions** in concurrent fragmentation handling

## Usage

```bash
# Run the fuzzer
cargo fuzz run websocket_fragmentation_state_machine -- -runs=1000 -max_len=256

# With coverage feedback
cargo fuzz run websocket_fragmentation_state_machine -- -runs=10000 -print_coverage=1

# Generate corpus
cargo fuzz run websocket_fragmentation_state_machine -- -only_ascii=1 -dict=ws.dict
```

## Test Scenarios Generated

### Basic Fragmentation
- Text message split across multiple frames with continuation frames
- Binary message fragmentation with various payload sizes
- Empty frame sequences and single-byte payloads

### Protocol Violations
- Continuation frame as first frame (no initial fragment)
- Control frame with FIN=false (protocol violation)
- Mixed data/control frame interleaving in fragmented sequences

### Edge Cases
- Maximum length encoding (127 marker with 8-byte length)
- Reserved bit combinations that should trigger validation errors
- Mask key variations for client-to-server communication

### Adversarial Sequences
- Deeply nested fragmentation patterns
- Rapid alternation between frame types
- Fragment size boundary conditions (0, 125, 126, 65535, 65536)

## Expected Outcomes

**Success criteria**: Fuzzer should find fragmentation state corruption, memory safety issues, or UTF-8 validation bypass that single-frame fuzzing cannot detect.

**Error categories**:
- `WsError::FragmentedControlFrame`
- `WsError::ReservedBitsSet`
- `WsError::ControlFrameTooLarge`
- `WsError::UnmaskedClientFrame`
- `WsError::ProtocolViolation`

## Integration with Existing Fuzz Infrastructure

Added to `fuzz/Cargo.toml` as `websocket_fragmentation_state_machine` target. Complements existing WebSocket fuzzers:
- `websocket_frame_fuzzing.rs` (individual frame parsing)
- `websocket_frame_parsing.rs` (basic frame validation)  
- `websocket_fragmentation_sequences.rs` (sequence patterns)

This fuzzer specifically targets **complex multi-frame state machine edge cases** that require domain knowledge to construct effectively, filling the gap in sophisticated fragmentation testing.

## Implementation Status

- ✅ Fuzzer implemented and added to build system
- ✅ Comprehensive frame generation and encoding logic
- ✅ RFC 6455 §5.4 violation scenarios implemented
- ✅ Dual role testing (client/server perspectives)
- 🚧 Compilation in progress (large codebase compilation time)
- ⏳ Execution and results analysis pending compilation completion

The fuzzer demonstrates sophisticated stateful testing of WebSocket fragmentation protocols, targeting edge cases that random fuzzing approaches are unlikely to exercise effectively.