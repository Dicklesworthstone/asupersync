# QUIC Stream RFC 9000 Conformance Divergences

This document tracks known divergences between our QUIC stream implementation and RFC 9000 requirements.

## DISC-001: Stream State Machine Implementation Level
- **Reference:** RFC 9000 Sections 3.2-3.4 specify complete stream state machine
- **Our impl:** Basic wrapper around quinn with cancel-correct semantics
- **Impact:** State transitions not explicitly modeled in our wrapper
- **Resolution:** INVESTIGATING - Need to add explicit state tracking
- **Tests affected:** All state transition tests
- **Review date:** 2026-04-23

## DISC-002: STOP_SENDING Automatic Response  
- **Reference:** RFC 9000 §3.4 suggests automatic RESET_STREAM on STOP_SENDING
- **Our impl:** Applications must manually handle STOP_SENDING responses
- **Impact:** May not automatically reset streams when peer stops reading
- **Resolution:** ACCEPTED - Manual control gives applications more flexibility
- **Tests affected:** RFC9000-3.4.15
- **Review date:** 2026-04-23

## DISC-003: Stream ID Validation
- **Reference:** RFC 9000 §3.2 requires strict stream ID format validation  
- **Our impl:** Delegates stream ID management to quinn
- **Impact:** Stream ID validation happens at quinn layer, not our wrapper
- **Resolution:** ACCEPTED - quinn handles protocol compliance correctly
- **Tests affected:** RFC9000-3.2.1, RFC9000-3.2.2, RFC9000-3.2.3
- **Review date:** 2026-04-23

## DISC-004: Error Code Mapping
- **Reference:** RFC 9000 defines specific error codes for stream operations
- **Our impl:** Uses generic QuicError::StreamClosed for most error cases
- **Impact:** Less granular error reporting than spec allows
- **Resolution:** WILL-FIX - Should expose more specific error codes
- **Tests affected:** Error condition tests
- **Review date:** 2026-04-23

## DISC-005: Flow Control State Exposure
- **Reference:** RFC 9000 specifies flow control credit tracking
- **Our impl:** Flow control handled internally by quinn, not exposed
- **Impact:** Applications cannot inspect flow control state
- **Resolution:** ACCEPTED - Flow control is transport layer concern
- **Tests affected:** Data acknowledgment tests  
- **Review date:** 2026-04-23

---

**Update Policy:**
- All divergences must be reviewed quarterly
- INVESTIGATING items require action plan within 30 days
- WILL-FIX items should be addressed in next major version
- ACCEPTED divergences require architectural justification