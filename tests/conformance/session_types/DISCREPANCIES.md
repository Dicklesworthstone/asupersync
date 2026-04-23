# Session Types Duality Conformance Discrepancies

This document tracks all known deviations from perfect theoretical duality in the session types implementation.

## DISC-001: Limited Dual Type Construction
- **Theory**: Perfect duality requires `Dual<Send<T, S>> = Recv<T, Dual<S>>`
- **Implementation**: No explicit `Dual` trait or type-level duality operator
- **Impact**: Duality must be verified manually rather than mechanically
- **Resolution**: ACCEPTED - Type-level duality would require complex type machinery
- **Tests affected**: DL-1.1, DL-1.2
- **Justification**: Rust's type system limitations make automatic dual construction impractical
- **Review date**: 2026-04-23

## DISC-002: Runtime vs Compile-time Duality Checking
- **Theory**: Duality violations should be compile-time errors
- **Implementation**: Some duality properties only verified at runtime or through tests
- **Impact**: Invalid dual protocol composition might compile but fail at runtime
- **Resolution**: INVESTIGATING - Consider additional type-level constraints
- **Tests affected**: DL-3.1, DL-3.2, DL-3.3
- **Justification**: Full compile-time verification would require dependent types
- **Review date**: 2026-04-23

## DISC-003: Transport Backing vs Pure Typestate Asymmetry
- **Theory**: Transport-backed and pure channels should be perfectly equivalent
- **Implementation**: Different construction patterns and async capabilities
- **Impact**: Cannot freely substitute transport-backed for pure typestate channels
- **Resolution**: ACCEPTED - Design trade-off for practical async integration
- **Tests affected**: DL-5.1
- **Justification**: Async operations require `&Cx` parameter which pure types cannot provide
- **Review date**: 2026-04-23

## DISC-004: Channel ID Accessibility
- **Theory**: Dual endpoints should expose their shared identity for verification
- **Implementation**: channel_id is private, only accessible through SessionProof after close()
- **Impact**: Cannot directly verify endpoint pairing during protocol execution
- **Resolution**: ACCEPTED - Encapsulation prevents invalid channel manipulation
- **Tests affected**: DL-3.1, DL-3.2, DL-3.3
- **Justification**: Exposing channel_id would break encapsulation invariants
- **Review date**: 2026-04-23

## DISC-005: Error Handling Duality
- **Theory**: Error conditions should preserve duality (both endpoints aware of failures)
- **Implementation**: SessionError propagation not explicitly tested for dual consistency
- **Resolution**: WILL-FIX - Add error handling duality tests in future iteration
- **Tests affected**: None (gap in current test suite)
- **Target**: Add DL-6 series tests for error case duality
- **Review date**: 2026-04-23

## DISC-006: Recursive Type Duality
- **Theory**: Recursive session types should preserve duality through unfolding
- **Implementation**: Rec<F> and Var markers exist but duality not explicitly verified
- **Impact**: Recursive protocols might not maintain dual correspondence
- **Resolution**: INVESTIGATING - Requires deep analysis of lease protocol recursion
- **Tests affected**: None (not covered in current suite)
- **Target**: Add DL-7 series tests for recursive duality
- **Review date**: 2026-04-23