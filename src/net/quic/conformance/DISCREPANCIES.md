# Known RFC 9000 Conformance Discrepancies

This document tracks intentional deviations from RFC 9000 QUIC specification in our endpoint implementation.

## DISC-001: Quinn Library Dependency
- **RFC Section:** All sections
- **Our implementation:** Wraps quinn library for QUIC protocol implementation
- **RFC requirement:** Direct implementation of QUIC protocol
- **Impact:** Cannot directly test low-level QUIC protocol behavior (packet format, connection state machine, etc.)
- **Resolution:** ACCEPTED — quinn is a mature, RFC-compliant QUIC implementation
- **Tests affected:** RFC9000-4.1, RFC9000-6.1, RFC9000-17.1, RFC9000-18.2
- **Review date:** 2026-04-23

## DISC-002: Certificate Infrastructure Requirements
- **RFC Section:** 7.2-7.4 (TLS handshake and authentication)
- **Our implementation:** Unit tests skip certificate-based authentication tests
- **RFC requirement:** Support for certificate-based client/server authentication
- **Impact:** Cannot verify certificate validation behavior in unit test environment
- **Resolution:** INVESTIGATING — Need integration test environment with certificate infrastructure
- **Tests affected:** RFC9000-7.4 (client certificate support)
- **Review date:** 2026-04-23

## DISC-003: Live Connection Testing Limitations
- **RFC Section:** 4.1, 4.2 (Connection establishment and handshake ordering)
- **Our implementation:** Unit tests cannot create actual QUIC connections
- **RFC requirement:** Test actual connection establishment and handshake completion
- **Impact:** Cannot verify connection ID uniqueness or handshake ordering in unit tests
- **Resolution:** WILL-FIX — Need dedicated integration test suite for live connection testing
- **Tests affected:** RFC9000-4.1, RFC9000-4.2
- **Review date:** 2026-04-23

## DISC-004: Transport Parameter Validation
- **RFC Section:** 18.1, 18.2 (Transport parameter exchange and validation)
- **Our implementation:** Relies on quinn for transport parameter validation
- **RFC requirement:** Validate transport parameters and fail handshake on invalid values
- **Impact:** Cannot directly test transport parameter validation logic
- **Resolution:** ACCEPTED — quinn handles transport parameter validation according to RFC 9000
- **Tests affected:** RFC9000-18.2
- **Review date:** 2026-04-23

## DISC-005: Version Negotiation Testing
- **RFC Section:** 6.1 (Version negotiation)
- **Our implementation:** Version negotiation handled entirely by quinn
- **RFC requirement:** Test version negotiation protocol compliance
- **Impact:** Cannot verify version negotiation behavior at wrapper level
- **Resolution:** ACCEPTED — quinn implements RFC-compliant version negotiation
- **Tests affected:** RFC9000-6.1
- **Review date:** 2026-04-23

## DISC-006: Error Signaling Detail
- **RFC Section:** 12.1 (Error handling during handshake)
- **Our implementation:** Tests basic error scenarios but not detailed error codes
- **RFC requirement:** Signal specific connection errors during handshake
- **Impact:** Limited verification of error code accuracy and propagation
- **Resolution:** INVESTIGATING — Need more comprehensive error scenario testing
- **Tests affected:** RFC9000-12.1
- **Review date:** 2026-04-23

---

## Summary of Test Coverage

| Requirement Level | Total | Fully Tested | Partially Tested | Skipped | Coverage |
|-------------------|-------|--------------|------------------|---------|----------|
| MUST              | 8     | 3            | 1                | 4       | 50%      |
| SHOULD            | 1     | 0            | 0                | 1       | 0%       |
| MAY               | 0     | 0            | 0                | 0       | N/A      |

**Overall MUST Compliance:** 50% (4/8 MUST requirements fully tested)  
**Conformance Status:** NON-COMPLIANT (< 95% MUST coverage)

## Recommended Actions

1. **PRIORITY 1:** Establish integration test environment for live connection testing
2. **PRIORITY 2:** Add certificate infrastructure to test environment
3. **PRIORITY 3:** Expand error scenario testing with quinn integration
4. **PRIORITY 4:** Document quinn's compliance claims and rely on transitive conformance

## Notes

- This wrapper focuses on providing a cancel-correct, structured concurrency interface
- Core QUIC protocol compliance is delegated to the quinn library
- Future versions should include integration tests for complete RFC 9000 compliance verification
- Consider contributing upstream to quinn for any missing RFC compliance features

Last updated: 2026-04-23