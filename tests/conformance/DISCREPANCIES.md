# ATP Protocol and RaptorQ Conformance Divergences

## ATP Protocol Conformance Divergences

### DISC-ATP-001: Data integrity verification covered
- **Reference:** ATP Protocol Section 6.1 - Data integrity verification requirements
- **Our impl:** `ATP-INTEGRITY-001` opens an in-process ATP session, writes a deterministic payload, computes `ObjectHash::from_data`, and requires `AtpSession::verify_object(..., expected_hash)` to return `verified=true`, `integrity_check_passed=true`, and matching hash bytes.
- **Impact:** Covered by live SDK object-verification evidence; a regression now fails production conformance evidence instead of being documented as a known gap.
- **Resolution:** RESOLVED - executable conformance in `tests/conformance/atp_protocol_conformance.rs`; structured output is emitted with artifact path `artifacts/conformance/atp_protocol_conformance.ndjson`.
- **Tests affected:** ATP-INTEGRITY-001
- **Review date:** 2026-05-27

### DISC-ATP-002: Corruption detection covered
- **Reference:** ATP Protocol Section 6.2 - Corruption detection and rejection
- **Our impl:** `ATP-INTEGRITY-002` writes an original payload, records its expected object hash, mutates bytes on disk, and requires `verify_object(..., expected_hash)` to reject the tampered payload with `verified=false` and `integrity_check_passed=false`.
- **Impact:** Covered by executable corruption evidence; tampered object data can no longer be counted as passing conformance.
- **Resolution:** RESOLVED - executable conformance in `tests/conformance/atp_protocol_conformance.rs`; structured output is emitted with artifact path `artifacts/conformance/atp_protocol_conformance.ndjson`.
- **Tests affected:** ATP-INTEGRITY-002
- **Review date:** 2026-05-27

### DISC-ATP-003: Capability requirement enforcement covered
- **Reference:** ATP Protocol Section 7.1 - Explicit capability requirements
- **Our impl:** `ATP-SECURITY-001` drives `SessionNegotiator::accept_client_hello` with requested read/write actions and no matching grant, then requires the negotiation path to reject with `missing_grant_action`.
- **Impact:** Covered by executable session-negotiation evidence for direct ATP sessions; broader ATP-N capability surfaces remain tracked separately.
- **Resolution:** RESOLVED - direct-session capability requirement coverage lives in `tests/conformance/atp_protocol_conformance.rs`; broader coverage gates remain owned by `asupersync-vk4kcf`.
- **Tests affected:** ATP-SECURITY-001
- **Review date:** 2026-05-27

### DISC-ATP-004: Authorization boundary enforcement covered
- **Reference:** ATP Protocol Section 7.2 - Authorization boundary enforcement
- **Our impl:** `ATP-SECURITY-002` opens a direct SDK session with a grant issued by an untrusted peer and requires high-level session negotiation to reject the authorization boundary violation.
- **Impact:** Covered by executable direct-session authorization evidence; broader trust-chain and cross-boundary cases remain tracked under ATP-N.
- **Resolution:** RESOLVED - direct-session authorization coverage lives in `tests/conformance/atp_protocol_conformance.rs`; broader coverage gates remain owned by `asupersync-vk4kcf`.
- **Tests affected:** ATP-SECURITY-002
- **Review date:** 2026-05-27

## ATP Capability Security Model Conformance Divergences

### DISC-CAP-001: Global state access prevention tracked
- **Reference:** ATP Capability Model Section 7.1.2 - No ambient authority requirements
- **Our impl:** ATP-NR linked coverage gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Operations may access global state without capability validation
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N capability gates; add executable no-ambient-authority tests before counting as production conformance evidence.
- **Tests affected:** ATP-CAP-002
- **Review date:** 2026-05-26

### DISC-CAP-002: Capability validation tracked
- **Reference:** ATP Capability Model Section 7.1.3 - Cx capability validation
- **Our impl:** ATP-NR linked coverage gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Missing runtime validation of Cx capabilities before operations
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N capability gates; add executable Cx-capability validation tests before counting as production conformance evidence.
- **Tests affected:** ATP-CAP-003
- **Review date:** 2026-05-26

### DISC-CAP-003: Cache operation scoping missing
- **Reference:** ATP Capability Model Section 7.2.1 - Cache authorization scoping
- **Our impl:** ATP-NR linked coverage gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Cache operations not scoped to authorized regions - privilege escalation risk
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N capability gates; add executable cache-scope authorization tests before counting as production conformance evidence.
- **Tests affected:** ATP-CAP-004
- **Review date:** 2026-05-26

### DISC-CAP-004: Seeding operation scoping missing
- **Reference:** ATP Capability Model Section 7.2.2 - Seeding capability scoping
- **Our impl:** ATP-NR linked coverage gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Unauthorized seeding operations possible without capability validation
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N capability gates; add executable seeding-scope tests before counting as production conformance evidence.
- **Tests affected:** ATP-CAP-005
- **Review date:** 2026-05-26

### DISC-CAP-005: Relay operation scoping missing  
- **Reference:** ATP Capability Model Section 7.2.3 - Relay trust boundary scoping
- **Our impl:** ATP-NR linked coverage gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Relay operations not scoped to trust boundaries - trust domain violations
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N capability gates; add executable relay-boundary tests before counting as production conformance evidence.
- **Tests affected:** ATP-CAP-006
- **Review date:** 2026-05-26

### DISC-CAP-006: Trust chain validation missing
- **Reference:** ATP Capability Model Section 7.3.2 - Cross-boundary trust chain validation
- **Our impl:** ATP-NR linked coverage gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Cross-boundary operations bypass trust chain validation
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N capability gates; add executable trust-chain validation tests before counting as production conformance evidence.
- **Tests affected:** ATP-CAP-008
- **Review date:** 2026-05-26

### DISC-CAP-007: Transfer capability validation missing
- **Reference:** ATP Capability Model Section 7.4.1 - Transfer capability requirements
- **Our impl:** ATP-NR linked coverage gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Transfer operations proceed without required capability validation
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N capability gates; add executable transfer-capability tests before counting as production conformance evidence.
- **Tests affected:** ATP-CAP-009
- **Review date:** 2026-05-26

### DISC-CAP-008: Session capability validation missing
- **Reference:** ATP Capability Model Section 7.4.2 - Session authentication capabilities
- **Our impl:** ATP-NR linked coverage gap; `ATP-SECURITY-001` covers missing grants for direct session negotiation, but broader authentication-capability validation is not complete.
- **Impact:** Sessions created without authentication capability validation
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N capability gates; add executable authentication-capability tests before counting the broader surface as production conformance evidence.
- **Tests affected:** ATP-CAP-010
- **Review date:** 2026-05-27

### DISC-CAP-009: Authorization denial mechanisms missing
- **Reference:** ATP Capability Model Section 7.5.1 - Authorization denial enforcement
- **Our impl:** ATP-NR linked coverage gap; `ATP-SECURITY-002` covers untrusted direct-session grant issuers, but broader denial surfaces are not complete.
- **Impact:** Operations not denied when lacking proper authorization
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N capability gates; add executable denial tests for each ATP operation class before counting the broader surface as production conformance evidence.
- **Tests affected:** ATP-CAP-011
- **Review date:** 2026-05-27

### DISC-CAP-010: Authorization audit missing
- **Reference:** ATP Capability Model Section 7.5.2 - Authorization failure auditing
- **Our impl:** ATP-NR linked coverage gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Authorization failures not audited - security visibility gap
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N observability/capability gates; add executable audit-emission tests before counting as production conformance evidence.
- **Tests affected:** ATP-CAP-012
- **Review date:** 2026-05-26

### DISC-CAP-011: Resource isolation missing
- **Reference:** ATP Capability Model Section 7.6.1 - Capability-based resource isolation
- **Our impl:** ATP-NR linked coverage gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Resource access not isolated by capability scope
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N capability gates; add executable resource-isolation tests before counting as production conformance evidence.
- **Tests affected:** ATP-CAP-013
- **Review date:** 2026-05-26

## ATP Object Graph Transfer Conformance Divergences

### DISC-OBJ-001: Transfer atomicity tracked
- **Reference:** ATP Object Graph Transfer Section 4.1 - Atomic transfer operations
- **Our impl:** ATP-NR linked object-transfer gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Object graph transfers may leave system in inconsistent state on failure
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N object-transfer gates; add executable atomicity tests before counting as production conformance evidence.
- **Tests affected:** OBJ-ATOMIC-001
- **Review date:** 2026-05-26

### DISC-OBJ-002: Partial transfer rollback missing
- **Reference:** ATP Object Graph Transfer Section 4.2 - Rollback safety for partial transfers
- **Our impl:** ATP-NR linked object-transfer gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Partial transfers cannot be safely rolled back on errors
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N object-transfer gates; add executable rollback tests before counting as production conformance evidence.
- **Tests affected:** OBJ-ATOMIC-002
- **Review date:** 2026-05-26

### DISC-OBJ-003: Incremental transfer progress missing
- **Reference:** ATP Object Graph Transfer Section 4.3 - Incremental progress support
- **Our impl:** ATP-NR linked object-transfer gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Large transfers have no progress tracking or resumption capability
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N object-transfer gates; add executable progress/resumption tests before counting as production conformance evidence.
- **Tests affected:** OBJ-ATOMIC-003
- **Review date:** 2026-05-26

### DISC-OBJ-004: Transfer-time corruption detection missing
- **Reference:** ATP Object Graph Transfer Section 5.1 - Runtime corruption detection
- **Our impl:** ATP-NR linked object-transfer gap; `ATP-INTEGRITY-002` covers object-file verification after tampering, but transfer-time corruption detection remains separate.
- **Impact:** Corrupted objects not detected during transfer - security risk
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N object-transfer gates; add executable transfer-time corruption tests before counting as production conformance evidence.
- **Tests affected:** OBJ-CORRUPT-001
- **Review date:** 2026-05-27

### DISC-OBJ-005: Manifest corruption detection missing
- **Reference:** ATP Object Graph Transfer Section 5.2 - Manifest verification
- **Our impl:** ATP-NR linked object-transfer gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Manifest tampering may go undetected - integrity risk
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N object-transfer gates; add executable manifest-corruption tests before counting as production conformance evidence.
- **Tests affected:** OBJ-CORRUPT-002
- **Review date:** 2026-05-26

### DISC-OBJ-006: Detailed corruption error reporting missing
- **Reference:** ATP Object Graph Transfer Section 5.3 - Corruption error details
- **Our impl:** ATP-NR linked object-transfer gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Poor debugging experience for corruption issues
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N object-transfer gates; add executable detailed-error tests before counting as production conformance evidence.
- **Tests affected:** OBJ-CORRUPT-003
- **Review date:** 2026-05-26

### DISC-OBJ-007: Duplicate child name validation missing
- **Reference:** ATP Object Graph Transfer Section 7.2 - Graph structure validation
- **Our impl:** ATP-NR linked object-transfer gap; no test-double or configuration-only assertion may count as pass evidence.
- **Impact:** Invalid object graphs with duplicate child names may be accepted
- **Resolution:** TRACKED - owned by `asupersync-vk4kcf` ATP-N object-transfer gates; add executable graph-structure validation tests before counting as production conformance evidence.
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
- TRACKED items must name their owning bead and must not count as pass evidence
- Known-gap tests must emit case id, requirement level, category, observed behavior, status, owner bead, and artifact path
