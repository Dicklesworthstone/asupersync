# QUIC Stream RFC 9000 Coverage Matrix

## Tested Requirements

| RFC Section | Requirement | Level | Test Case | Status |
|-------------|-------------|-------|-----------|--------|
| 3.2.1 | Client bidirectional stream IDs end in 0x00 | MUST | RFC9000-3.2.1 | ✅ PASS |
| 3.2.2 | Client unidirectional streams only client sends | MUST | RFC9000-3.2.2 | ❌ XFAIL |
| 3.2.3 | Server unidirectional streams only server sends | MUST | RFC9000-3.2.3 | ❌ XFAIL |
| 3.4.1 | Send stream starts in Ready state | MUST | RFC9000-3.4.1 | ❌ XFAIL |
| 3.4.2 | Ready → Send on app finish | MUST | RFC9000-3.4.2 | ❌ XFAIL |
| 3.4.3 | Send → DataSent when data transmitted | MUST | RFC9000-3.4.3 | ❌ XFAIL |
| 3.4.4 | DataSent → DataRecvd on peer ack | MUST | RFC9000-3.4.4 | ❌ XFAIL |
| 3.4.5 | Ready → ResetSent on app reset | MUST | RFC9000-3.4.5 | ❌ XFAIL |
| 3.4.6 | ResetSent → ResetRecvd on ack | MUST | RFC9000-3.4.6 | ❌ XFAIL |
| 3.4.7 | Recv stream starts in Recv state | MUST | RFC9000-3.4.7 | ❌ XFAIL |
| 3.4.8 | Recv → SizeKnown on peer FIN | MUST | RFC9000-3.4.8 | ❌ XFAIL |
| 3.4.9 | SizeKnown → DataRecvd when complete | MUST | RFC9000-3.4.9 | ❌ XFAIL |
| 3.4.10 | DataRecvd → DataRead on app read | MUST | RFC9000-3.4.10 | ❌ XFAIL |
| 3.4.11 | Recv → ResetRecvd on peer reset | MUST | RFC9000-3.4.11 | ❌ XFAIL |
| 3.4.12 | ResetRecvd → ResetRead on app ack | MUST | RFC9000-3.4.12 | ❌ XFAIL |
| 3.4.13 | Cannot send after reset | MUST | RFC9000-3.4.13 | ❌ XFAIL |
| 3.4.14 | Cannot read after stop | MUST | RFC9000-3.4.14 | ❌ XFAIL |
| 3.4.15 | STOP_SENDING triggers reset | SHOULD | RFC9000-3.4.15 | ❌ XFAIL |

## Coverage Statistics

- **Total Requirements:** 16
- **MUST Requirements:** 15  
- **SHOULD Requirements:** 1
- **MAY Requirements:** 0
- **Tested:** 16 (100%)
- **Currently Passing:** 1 (6.25%)
- **Expected Failures:** 15 (93.75%)

## Untested Areas

The following RFC 9000 areas are **NOT** covered by this conformance suite:

### Stream Flow Control (§4.1)
- MAX_STREAM_DATA frame handling
- STREAM_DATA_BLOCKED frame generation  
- Flow control credit tracking
- **Reason:** Handled internally by quinn, not exposed at our API level

### Stream Limits (§4.6)
- MAX_STREAMS frame handling
- STREAMS_BLOCKED frame generation
- Stream ID space exhaustion
- **Reason:** Connection-level concern, outside stream wrapper scope

### Connection Migration Impact (§9)
- Stream state preservation across path changes
- **Reason:** Connection-level feature, streams are path-agnostic

### Error Code Semantics (§20)
- Specific stream error code meanings
- Error code propagation rules
- **Reason:** Limited error granularity in current wrapper

## Implementation Gaps

### HIGH PRIORITY
1. **Explicit State Tracking** - Current wrapper doesn't model RFC state machine
2. **State Transition Hooks** - No validation of legal state changes
3. **Error Code Mapping** - Generic errors instead of RFC-specific codes

### MEDIUM PRIORITY  
1. **STOP_SENDING Handling** - Manual application response required
2. **Flow Control Exposure** - Applications can't inspect credit state
3. **Stream Metadata** - Limited access to stream properties

### LOW PRIORITY
1. **Debugging Hooks** - State inspection for troubleshooting
2. **Metrics Collection** - Stream lifecycle statistics
3. **Performance Counters** - State transition timing

## Testing Strategy

### Current Approach
- **Pattern 4:** Spec-derived test matrix with simulated state machine
- **Advantage:** Comprehensive RFC coverage without quinn dependencies
- **Limitation:** Tests theoretical compliance, not actual implementation

### Recommended Enhancement
- **Pattern 1:** Differential testing against quinn's internal state
- **Advantage:** Tests actual implementation behavior
- **Implementation:** Add state introspection hooks to wrapper

## Maintenance Plan

1. **Quarterly Review** - Check for RFC 9000 updates and errata
2. **Implementation Sync** - Update tests when wrapper changes
3. **Coverage Expansion** - Add integration tests for untested areas
4. **Performance Baseline** - Add timing constraints to state transitions

---

**Last Updated:** 2026-04-23  
**Next Review:** 2026-07-23  
**Maintainer:** asupersync-conformance team