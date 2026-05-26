# Known ATP Security Conformance Discrepancies

This document tracks intentional divergences from ATP security specifications in conformance testing.

## DISC-ATPSEC-001: Real ATP Type Integration
- **Reference:** Full ATP types from src/net/atp/ now integrated
- **Our impl:** Uses real FlowControlWindow, StreamState, StreamError, AtpStream, Cx, PacketAssembler types
- **Impact:** Tests now validate actual ATP security enforcement, not just harness patterns
- **Resolution:** RESOLVED - real ATP types integrated in asupersync-ppn7rq
- **Tests affected:** All ATP security conformance tests now use real implementation
- **Review date:** 2026-06-15
- **Tracking bead:** asupersync-ppn7rq (closed)

## DISC-ATPSEC-002: Timing Measurement Precision
- **Reference:** Precise timing side-channel detection requires hardware counters
- **Our impl:** Uses basic Duration measurements for demonstration
- **Impact:** May miss subtle timing side-channels in actual implementation
- **Resolution:** INVESTIGATING - evaluate hardware performance counter integration
- **Tests affected:** ATP-XCUT-002 (side-channel timing)
- **Review date:** 2026-06-15
- **Tracking bead:** asupersync-atpsec-002

## DISC-ATPSEC-003: Capability Context Integration
- **Reference:** Full capability security model not yet implemented
- **Our impl:** Simplified capability context for pattern demonstration
- **Impact:** Tests basic capability flow, not comprehensive security enforcement
- **Resolution:** PENDING - integrate with actual asupersync capability system
- **Tests affected:** ATP-CAPABILITY-* tests
- **Review date:** 2026-06-15
- **Tracking bead:** asupersync-atpsec-003

## DISC-ATPSEC-004: Error Information Leakage Detection
- **Reference:** Comprehensive state leakage analysis requires static analysis
- **Our impl:** Basic pattern matching for sensitive information
- **Impact:** May miss complex information disclosure paths
- **Resolution:** INVESTIGATING - evaluate integration with static analysis tools
- **Tests affected:** ATP-ERROR-001 (information disclosure)
- **Review date:** 2026-06-15
- **Tracking bead:** asupersync-atpsec-004

## Review Process

All discrepancies should be reviewed quarterly. When discrepancies are resolved:
1. Update the Resolution field to RESOLVED
2. Document the actual implementation in the tests
3. Update the Review date
4. Close the associated tracking bead

## Coverage Matrix

| Contract Section | Stub Coverage | Real Implementation | Score |
|------------------|:-------------:|:------------------:|-------|
| Integrity        | 4/4           | 0/4                | 0%    |
| Capability       | 4/4           | 0/4                | 0%    |
| Error Semantics  | 4/4           | 0/4                | 0%    |
| Cross-cutting    | 2/2           | 0/2                | 0%    |

**Target:** 100% real implementation coverage by Phase 2 completion.