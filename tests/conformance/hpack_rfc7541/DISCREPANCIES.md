# HPACK RFC 7541 Conformance Discrepancies

This document tracks all known and intentional divergences between our HPACK
implementation and RFC 7541 requirements or reference implementations.

## DISC-001: Dynamic Table Size Update Validation
- **Reference:** RFC 7541 Section 4.2 requires size updates ≤ SETTINGS_HEADER_TABLE_SIZE
- **Our impl:** Current implementation doesn't fully validate against SETTINGS limit
- **Impact:** May accept oversized table updates that should be rejected
- **Resolution:** INVESTIGATING — needs SETTINGS integration from HTTP/2 layer
- **Tests affected:** ERR-SIZE-1
- **Review date:** 2026-04-16

## DISC-002: Context State Inspection
- **Reference:** Test vectors assume access to internal encoder/decoder state
- **Our impl:** Dynamic table state not exposed for external inspection
- **Impact:** Some conformance tests marked as EXPECTED_FAILURE
- **Resolution:** ACCEPTED — internal state encapsulation is intentional design choice
- **Tests affected:** RFC7541-4.2-1, ERR-CONTEXT-1
- **Review date:** 2026-04-16

## DISC-003: Huffman Padding Validation Strictness
- **Reference:** RFC 7541 Appendix B requires specific padding validation
- **Our impl:** May be more lenient with Huffman padding validation
- **Impact:** Some malformed Huffman strings might be accepted
- **Resolution:** INVESTIGATING — need to verify padding validation strictness
- **Tests affected:** ERR-HUF-1, ERR-PAD-1
- **Review date:** 2026-04-16

## DISC-004: Cross-Implementation Testing
- **Reference:** Differential testing against Go net/http2, nghttp2
- **Our impl:** External reference implementation harnesses not yet implemented
- **Impact:** Limited interoperability validation
- **Resolution:** WILL-FIX — plan to add external reference implementation testing
- **Tests affected:** INTEROP-GO-1, INTEROP-NGHTTP2-1
- **Review date:** 2026-04-16

## DISC-005: Large Header List Limits
- **Reference:** RFC 7541 recommends header list size limits
- **Our impl:** Current limits may differ from reference implementations
- **Impact:** Behavior with very large header lists may vary
- **Resolution:** ACCEPTED — implementation-specific limits are allowed
- **Tests affected:** ERR-LIMIT-1
- **Review date:** 2026-04-16

## Known Conformance Status

### MUST Clause Coverage
- **Static Table (Appendix A):** CONFORMANT ✅
- **Indexed Header Fields (6.1):** CONFORMANT ✅
- **Literal Header Fields (6.2):** CONFORMANT ✅
- **Dynamic Table Management (4.1-4.3):** MOSTLY CONFORMANT ⚠️ (DISC-001, DISC-002)
- **Huffman Encoding (Appendix B):** MOSTLY CONFORMANT ⚠️ (DISC-003)

### SHOULD Clause Coverage
- **Header List Size Limits:** PARTIALLY CONFORMANT ⚠️ (DISC-005)
- **Compression Efficiency:** CONFORMANT ✅
- **Error Handling:** MOSTLY CONFORMANT ⚠️ (Various error edge cases)

### Conformance Summary
- **Total tests:** 20+ (RFC vectors + systematic + error cases)
- **MUST clause coverage:** ~90% (target: ≥95%)
- **Expected failures:** 6 tests (documented above)
- **Last updated:** 2026-04-16

## Test Maintenance Notes

1. **Fixture Updates:** RFC 7541 test vectors are stable (normative)
2. **Error Test Expansion:** Add more malformed input edge cases as needed
3. **Interop Testing:** Priority for Phase 2 implementation
4. **SETTINGS Integration:** Required for complete dynamic table size validation

## Review Schedule
- **Next review:** 2026-07-16 (quarterly)
- **Trigger for review:** Any HPACK-related bug reports or spec updates
- **Reviewer:** HTTP/2 implementation team