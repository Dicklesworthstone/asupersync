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

## ATP Capability Security Model Conformance Divergences

### DISC-CAP-001: Global state access prevention pending
- **Reference:** ATP Capability Model Section 7.1.2 - No ambient authority requirements
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Operations may access global state without capability validation
- **Resolution:** WILL-FIX — implement global state access prevention mechanisms
- **Tests affected:** ATP-CAP-002
- **Review date:** 2026-05-26

### DISC-CAP-002: Capability validation not implemented
- **Reference:** ATP Capability Model Section 7.1.3 - Cx capability validation
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Missing runtime validation of Cx capabilities before operations
- **Resolution:** WILL-FIX — implement Cx capability validation system
- **Tests affected:** ATP-CAP-003
- **Review date:** 2026-05-26

### DISC-CAP-003: Cache operation scoping missing
- **Reference:** ATP Capability Model Section 7.2.1 - Cache authorization scoping
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Cache operations not scoped to authorized regions - privilege escalation risk
- **Resolution:** WILL-FIX — implement cache operation authorization scoping
- **Tests affected:** ATP-CAP-004
- **Review date:** 2026-05-26

### DISC-CAP-004: Seeding operation scoping missing
- **Reference:** ATP Capability Model Section 7.2.2 - Seeding capability scoping
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Unauthorized seeding operations possible without capability validation
- **Resolution:** WILL-FIX — implement seeding operation capability scoping
- **Tests affected:** ATP-CAP-005
- **Review date:** 2026-05-26

### DISC-CAP-005: Relay operation scoping missing  
- **Reference:** ATP Capability Model Section 7.2.3 - Relay trust boundary scoping
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Relay operations not scoped to trust boundaries - trust domain violations
- **Resolution:** WILL-FIX — implement relay operation trust boundary enforcement
- **Tests affected:** ATP-CAP-006
- **Review date:** 2026-05-26

### DISC-CAP-006: Trust chain validation missing
- **Reference:** ATP Capability Model Section 7.3.2 - Cross-boundary trust chain validation
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Cross-boundary operations bypass trust chain validation
- **Resolution:** WILL-FIX — implement trust chain validation for cross-boundary operations
- **Tests affected:** ATP-CAP-008
- **Review date:** 2026-05-26

### DISC-CAP-007: Transfer capability validation missing
- **Reference:** ATP Capability Model Section 7.4.1 - Transfer capability requirements
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Transfer operations proceed without required capability validation
- **Resolution:** WILL-FIX — implement transfer capability validation
- **Tests affected:** ATP-CAP-009
- **Review date:** 2026-05-26

### DISC-CAP-008: Session capability validation missing
- **Reference:** ATP Capability Model Section 7.4.2 - Session authentication capabilities
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Sessions created without authentication capability validation
- **Resolution:** WILL-FIX — implement session capability validation
- **Tests affected:** ATP-CAP-010
- **Review date:** 2026-05-26

### DISC-CAP-009: Authorization denial mechanisms missing
- **Reference:** ATP Capability Model Section 7.5.1 - Authorization denial enforcement
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Operations not denied when lacking proper authorization
- **Resolution:** WILL-FIX — implement authorization denial mechanisms
- **Tests affected:** ATP-CAP-011
- **Review date:** 2026-05-26

### DISC-CAP-010: Authorization audit missing
- **Reference:** ATP Capability Model Section 7.5.2 - Authorization failure auditing
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Authorization failures not audited - security visibility gap
- **Resolution:** WILL-FIX — implement authorization audit logging
- **Tests affected:** ATP-CAP-012
- **Review date:** 2026-05-26

### DISC-CAP-011: Resource isolation missing
- **Reference:** ATP Capability Model Section 7.6.1 - Capability-based resource isolation
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Resource access not isolated by capability scope
- **Resolution:** WILL-FIX — implement capability-based resource isolation
- **Tests affected:** ATP-CAP-013
- **Review date:** 2026-05-26

## ATP Object Graph Transfer Conformance Divergences

### DISC-OBJ-001: Transfer atomicity not implemented
- **Reference:** ATP Object Graph Transfer Section 4.1 - Atomic transfer operations
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Object graph transfers may leave system in inconsistent state on failure
- **Resolution:** WILL-FIX — implement atomic transfer operation mechanism
- **Tests affected:** OBJ-ATOMIC-001
- **Review date:** 2026-05-26

### DISC-OBJ-002: Partial transfer rollback missing
- **Reference:** ATP Object Graph Transfer Section 4.2 - Rollback safety for partial transfers
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Partial transfers cannot be safely rolled back on errors
- **Resolution:** WILL-FIX — implement partial transfer rollback mechanism
- **Tests affected:** OBJ-ATOMIC-002
- **Review date:** 2026-05-26

### DISC-OBJ-003: Incremental transfer progress missing
- **Reference:** ATP Object Graph Transfer Section 4.3 - Incremental progress support
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Large transfers have no progress tracking or resumption capability
- **Resolution:** WILL-FIX — implement incremental transfer progress tracking
- **Tests affected:** OBJ-ATOMIC-003
- **Review date:** 2026-05-26

### DISC-OBJ-004: Transfer-time corruption detection missing
- **Reference:** ATP Object Graph Transfer Section 5.1 - Runtime corruption detection
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Corrupted objects not detected during transfer - security risk
- **Resolution:** WILL-FIX — implement runtime content verification during transfers
- **Tests affected:** OBJ-CORRUPT-001
- **Review date:** 2026-05-26

### DISC-OBJ-005: Manifest corruption detection missing
- **Reference:** ATP Object Graph Transfer Section 5.2 - Manifest verification
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Manifest tampering may go undetected - integrity risk
- **Resolution:** WILL-FIX — implement manifest corruption detection
- **Tests affected:** OBJ-CORRUPT-002
- **Review date:** 2026-05-26

### DISC-OBJ-006: Detailed corruption error reporting missing
- **Reference:** ATP Object Graph Transfer Section 5.3 - Corruption error details
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Poor debugging experience for corruption issues
- **Resolution:** WILL-FIX — implement detailed corruption error reporting
- **Tests affected:** OBJ-CORRUPT-003
- **Review date:** 2026-05-26

### DISC-OBJ-007: Duplicate child name validation missing
- **Reference:** ATP Object Graph Transfer Section 7.2 - Graph structure validation
- **Our impl:** Placeholder test with XFAIL status
- **Impact:** Invalid object graphs with duplicate child names may be accepted
- **Resolution:** WILL-FIX — implement duplicate child name validation
- **Tests affected:** OBJ-VALID-002
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