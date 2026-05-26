# ATP Protocol and RaptorQ Conformance Divergences

## ATP Protocol Conformance Divergences

### DISC-ATP-001: Data integrity verification pending
- **Reference:** ATP Protocol Section 6.1 - Data integrity verification requirements
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Cannot verify cryptographic integrity of transfers
- **Resolution:** WILL-FIX — implement full integrity verification system
- **Tests affected:** ATP-INTEGRITY-001
- **Review date:** 2026-05-26

### DISC-ATP-002: Corruption detection not implemented
- **Reference:** ATP Protocol Section 6.2 - Corruption detection and rejection
- **Our impl:** Placeholder test with XFAIL status  
- **Impact:** Cannot detect or reject corrupted data during transfers
- **Resolution:** WILL-FIX — implement corruption detection mechanisms
- **Tests affected:** ATP-INTEGRITY-002
- **Review date:** 2026-05-26

### DISC-ATP-003: Capability requirement enforcement pending
- **Reference:** ATP Protocol Section 7.1 - Explicit capability requirements
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Cannot enforce capability boundaries for operations
- **Resolution:** WILL-FIX — implement capability scoping system
- **Tests affected:** ATP-SECURITY-001
- **Review date:** 2026-05-26

### DISC-ATP-004: Authorization boundary enforcement pending
- **Reference:** ATP Protocol Section 7.2 - Authorization boundary enforcement
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Cannot enforce authorization boundaries across trust domains
- **Resolution:** WILL-FIX — implement authorization enforcement system
- **Tests affected:** ATP-SECURITY-002
- **Review date:** 2026-05-26

## RaptorQ RFC 6330 Conformance Divergences

### DISC-001: GF(256) inverse operation for zero element
- **Reference:** RFC 6330 Section 5.3.3.4 - Field operations in GF(256)
- **Our impl:** Returns None for GF256(0).inverse() (undefined behavior)
- **Impact:** Zero element correctly has no multiplicative inverse
- **Resolution:** ACCEPTED — mathematically correct (0 has no inverse in any field)
- **Tests affected:** gf256_field_axioms/zero-no-inverse
- **Review date:** 2026-05-23

### DISC-002: Simplified repair symbol generation
- **Reference:** RFC 6330 Algorithm A for repair symbol generation
- **Our impl:** Uses simplified deterministic generation for testing
- **Impact:** Test vectors may not match reference implementation
- **Resolution:** INVESTIGATING — full Algorithm A implementation pending
- **Tests affected:** repair symbol generation tests
- **Review date:** 2026-05-23

### DISC-003: K' calculation simplification
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