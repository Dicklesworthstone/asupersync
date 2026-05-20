# ATP Definition of Done Checklist

This checklist must be completed before closing any ATP implementation bead. Each implementation bead either provides its own focused evidence or explicitly links to ATP-N proof workstream coverage.

## Implementation Bead Information
- **Bead ID**: `_______`  
- **Title**: `_______`
- **ATP Surface Area**: `_______` (native_quic | atp_protocol | object_graph | disk_journal | scheduler | raptorq_repair | path_graph | atpd | cli_sdk | mailbox_swarm | adapters | lab_bench | release_governance)
- **Agent**: `_______`
- **Completion Date**: `_______`

## Evidence Requirements

### Unit Test Evidence *(Required for all implementation beads)*
- [ ] **Unit tests implemented** 
  - Command: `_______` 
  - Path: `_______`
  - Coverage: `_____%` (minimum 85% for new code)
- [ ] **Property/metamorphic tests** *(for codecs/manifests/chunking/schedulers/repair/path choice)*
  - Command: `_______`
  - Properties tested: `_______`
- [ ] **Alternative justification** *(design-only/non-code beads)*
  - Exemption reason: `_______`
  - Reviewer approval: `_______`

### Integration Test Evidence *(Required for user-visible or cross-process beads)*
- [ ] **Integration tests implemented**
  - Command: `_______`
  - Scenarios covered: `_______`
- [ ] **E2E scripts implemented**
  - Script path: `_______` 
  - User workflows tested: `_______`
- [ ] **Lab tests implemented** *(for cancellation/concurrency/faults)*
  - Command: `_______`
  - Fault scenarios: `_______`
- [ ] **Staged-lane exemption** *(if applicable)*
  - Exemption reason: `_______`
  - Future lane reference: `_______`

### Observability Evidence *(Required for user-visible or cross-process beads)*
- [ ] **Structured logging implemented**
  - Log statements added: `_______` locations
  - Trace context preserved: Yes/No
  - Key events logged: `_______`
- [ ] **Failure bundle support**
  - Replay artifacts generated: Yes/No
  - Evidence collection: `_______`
- [ ] **No-log exemption** *(if applicable)*
  - Exemption reason: `_______`
  - Alternative observability: `_______`

### Dependency Compliance *(Required for ATP core modules)*
- [ ] **No external QUIC dependencies**
  - Verification command: `./scripts/dependency_audit.sh`
  - Result: PASS/FAIL
- [ ] **No external runtime dependencies** *(ATP native core)*
  - Tokio runtime usage: None/Justified
  - Alternative async approach: `_______`
- [ ] **Approved dependencies only**
  - New dependencies: `_______`
  - Security review: Yes/No/N/A

### Platform Coverage *(Required for platform-sensitive behavior)*
- [ ] **Cross-platform testing**
  - Platforms tested: Linux/macOS/Windows/WASM
  - Platform-specific code: None/Documented
  - Capability verification: `./scripts/cross_platform_test.sh`
- [ ] **Platform exemption** *(if applicable)*
  - Platform limitations: `_______`
  - Documentation: `_______`

## Proof Command Verification

### Local Evidence
- [ ] **Unit test command verified**
  - Command: `_______`
  - Result: PASS
  - Execution time: `_____ seconds`
- [ ] **Integration test command verified**  
  - Command: `_______`
  - Result: PASS
  - Execution time: `_____ minutes`

### RCH-Backed Evidence *(if applicable)*
- [ ] **RCH verification completed**
  - Command: `rch '____'`
  - Result: PASS
  - Artifact path: `_______`

### Deterministic Lab Evidence *(for complex scenarios)*
- [ ] **Lab scenario executed**
  - Scenario: `_______`
  - Deterministic: Yes/No
  - Oracle validation: PASS/FAIL
  - Evidence ledger: `_______`

### Manual/Platform-Specific Evidence *(if required)*
- [ ] **Manual verification completed**
  - Procedure: `_______`
  - Reviewer: `_______`
  - Documentation: `_______`

## Anti-Pattern Verification

**DoD explicitly rejects the following evidence patterns:**

- [ ] **Not compile-only**: Implementation includes runtime behavior verification
- [ ] **Not happy-path-only**: Error conditions and edge cases tested  
- [ ] **Not no-log**: Appropriate logging/observability implemented
- [ ] **Not no-replay**: Failure scenarios can be reproduced
- [ ] **Not external-QUIC/Tokio-smuggled**: Dependencies comply with ATP core principles

## Proof Lane Integration

- [ ] **Existing proof lane updated** *(if applicable)*
  - Proof lane: `_______`
  - Command updated: Yes/No
  - Guarantee extended: `_______`
- [ ] **New proof lane required** *(if applicable)*
  - New proof lane: `_______`
  - Guarantee: `_______`
  - Integration with `ATP_PROOF_LANE_MANIFEST.md`: Yes
- [ ] **No proof impact**
  - Justification: `_______`

## Artifact Verification

- [ ] **Test artifacts preserved**
  - Path: `artifacts/test_results/_______`
  - Machine-readable: Yes/No
- [ ] **Evidence artifacts generated**
  - Coverage report: `_______`
  - Log samples: `_______`
  - Replay bundles: `_______`
- [ ] **Documentation updated**
  - API docs: Yes/No/N/A
  - Integration guide: Yes/No/N/A
  - Troubleshooting: Yes/No/N/A

## Automated Validation

- [ ] **DoD validation executed**
  - Command: `./scripts/validate_dod.sh`
  - Result: COMPLIANT/NON_COMPLIANT
  - Violations: `_____ violations, _____ warnings`
- [ ] **All violations addressed**
  - Resolution summary: `_______`

## Skip Reasons and Blockers

### Known Blockers *(document any blockers preventing evidence completion)*
- `_______`
- `_______`

### Skip Reasons *(provide justification for any skipped requirements)*
- Unit tests skipped: `_______`
- Integration tests skipped: `_______`  
- Platform coverage skipped: `_______`
- Logging skipped: `_______`

### Future Work References *(link to beads that will provide missing evidence)*
- Missing unit tests: Bead `_______`
- Missing integration tests: Bead `_______`
- Missing proof lane: Bead `_______`

## Reviewer Sign-off

- [ ] **Technical review completed**
  - Reviewer: `_______`
  - Review date: `_______`
  - Approval: Yes/No
- [ ] **DoD compliance verified**
  - Compliance officer: `_______`
  - Verification date: `_______`
  - Status: COMPLIANT/EXEMPT/DEFERRED

## Release Lane Mapping

- [ ] **Release proof lane identified**
  - Relevant proof lanes: `_______`
  - Command integration: Yes/No
  - Release gate impact: None/Minor/Major

---

**Implementation Agent Declaration:**

I hereby declare that this ATP implementation bead meets the Definition of Done requirements as documented above, with any exemptions properly justified and approved.

Agent: `_______`  
Date: `_______`  
Signature: `_______`

---

**DoD Compliance Officer Review:**

This bead closure meets ATP Definition of Done requirements and may proceed.

Officer: `_______`  
Date: `_______`  
Status: APPROVED/APPROVED_WITH_CONDITIONS/REJECTED

Conditions (if any): `_______`

---

*This checklist is enforced by `./scripts/validate_dod.sh` and integrated into ATP release gates.*