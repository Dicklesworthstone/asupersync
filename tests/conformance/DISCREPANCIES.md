# RFC 6330 RaptorQ Conformance Divergences

## DISC-001: GF(256) inverse operation for zero element
- **Reference:** RFC 6330 Section 5.3.3.4 - Field operations in GF(256)
- **Our impl:** Returns None for GF256(0).inverse() (undefined behavior)
- **Impact:** Zero element correctly has no multiplicative inverse
- **Resolution:** ACCEPTED — mathematically correct (0 has no inverse in any field)
- **Tests affected:** gf256_field_axioms/zero-no-inverse
- **Review date:** 2026-05-23

## DISC-002: Simplified repair symbol generation
- **Reference:** RFC 6330 Algorithm A for repair symbol generation
- **Our impl:** Uses simplified deterministic generation for testing
- **Impact:** Test vectors may not match reference implementation
- **Resolution:** INVESTIGATING — full Algorithm A implementation pending
- **Tests affected:** repair symbol generation tests
- **Review date:** 2026-05-23

## DISC-003: K' calculation simplification
- **Reference:** RFC 6330 Section 5.3.3.1 and Table 2 for K' values
- **Our impl:** Uses simplified K' calculation for testing
- **Impact:** May not use optimal K' values for all input sizes
- **Resolution:** WILL-FIX — implement full Table 2 lookup
- **Tests affected:** encoding parameter validation
- **Review date:** 2026-05-23

---

**Review Guidelines:**
- All ACCEPTED divergences are intentional and documented
- INVESTIGATING items are under analysis 
- WILL-FIX items are planned for future implementation
- Tests use XFAIL for ACCEPTED divergences, not SKIP