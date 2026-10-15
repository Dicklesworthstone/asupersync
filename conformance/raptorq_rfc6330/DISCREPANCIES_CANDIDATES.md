# RFC 6330 Potential Conformance Discrepancies

**Generated:** 2026-04-16  
**Purpose:** Identify potential intentional divergences from RFC 6330 for documentation in DISCREPANCIES.md  
**Status:** Candidates for investigation during conformance testing

## Overview

This document catalogs potential areas where the asupersync RaptorQ implementation may intentionally diverge from RFC 6330 due to performance, security, or implementation constraints. Each candidate will be validated during conformance testing and documented appropriately.

## Candidate Categories

### Implementation Optimizations
Areas where performance optimizations may create intentional divergences from RFC behavior while preserving correctness.

### Security Considerations  
Areas where security requirements may necessitate divergence from RFC specification.

### Platform Constraints
Areas where Rust language features or target platform limitations may require RFC adaptations.

### Operational Requirements
Areas where asupersync's operational model may require RFC modifications.

---

## DISC-CANDIDATE-001: GF(256) Arithmetic Implementation

### RFC Requirement
RFC 6330 Section 5.3.3.2 specifies exact algorithms for GF(256) operations but allows implementation flexibility for the arithmetic itself.

### Potential Divergence
- **Our implementation**: May use optimized SIMD or lookup table approaches for GF(256) multiply/add
- **RFC specification**: Provides reference algorithms but allows equivalent implementations
- **Impact**: Performance difference, but mathematically equivalent results

### Investigation Plan
```rust
#[test]
fn gf256_arithmetic_equivalence() {
    // Test that our optimized GF(256) operations produce
    // results equivalent to RFC reference implementation
    for a in 0..=255u8 {
        for b in 0..=255u8 {
            assert_eq!(our_gf256_mul(a, b), reference_gf256_mul(a, b));
            assert_eq!(our_gf256_add(a, b), reference_gf256_add(a, b));
        }
    }
}
```

### Resolution Strategy
- **If equivalent**: Document as ACCEPTED optimization in DISCREPANCIES.md
- **If divergent**: Investigate whether mathematical equivalence is maintained

---

## DISC-CANDIDATE-002: Maximum Object Size Constraints

### RFC Requirement  
RFC 6330 specifies maximum source block sizes and symbol counts but doesn't mandate specific object size limits.

### Potential Divergence
- **Our implementation**: May impose stricter limits than RFC for memory safety
- **RFC specification**: Allows implementations to set practical limits
- **Impact**: May reject some valid RFC inputs due to resource constraints

### Investigation Plan
```rust
#[test]
fn maximum_object_size_validation() {
    // Test behavior at RFC-specified maximum limits
    let max_k = 8192;
    let max_symbol_size = /* investigate current limit */;
    let max_object_size = max_k * max_symbol_size;
    
    // Should our implementation handle RFC maximum sizes?
    let result = encode_object(&vec![0; max_object_size], max_symbol_size);
    // Document if we reject due to implementation limits
}
```

### Resolution Strategy
- **If accepted**: Document object size limits in DISCREPANCIES.md  
- **If problematic**: Consider increasing limits or streaming approaches

---

## DISC-CANDIDATE-003: Error Handling and Recovery Behavior

### RFC Requirement
RFC 6330 specifies encoding/decoding algorithms but doesn't mandate specific error handling behavior for malformed inputs.

### Potential Divergence
- **Our implementation**: May fail fast with specific error types for invalid inputs
- **RFC specification**: Doesn't specify error handling behavior for implementation errors
- **Impact**: Different error reporting than other RFC 6330 implementations

### Investigation Plan
```rust
#[test]
fn error_handling_conformance() {
    // Test error conditions: invalid K, malformed symbols, etc.
    // Compare error behavior with reference implementation
    
    let invalid_cases = [
        (0, "K=0 should be rejected"),
        (8193, "K>8192 should be rejected"),  
        // ... other invalid parameter cases
    ];
    
    for (invalid_k, description) in invalid_cases {
        let result = create_encoder_with_k(invalid_k);
        // Document error handling behavior differences
    }
}
```

### Resolution Strategy
- **If different**: Document error handling policy in DISCREPANCIES.md
- **If critical**: Consider aligning error behavior for interoperability

---

## DISC-CANDIDATE-004: Cancellation and Async Behavior

### RFC Requirement
RFC 6330 specifies synchronous encoding/decoding algorithms.

### Potential Divergence  
- **Our implementation**: Implements async interfaces with cancellation support
- **RFC specification**: Only defines synchronous behavior
- **Impact**: Additional async semantics beyond RFC scope

### Investigation Plan
```rust
#[test]
fn cancellation_behavior_validation() {
    // Ensure cancellation doesn't corrupt encoder/decoder state
    // Verify cancelled operations don't affect subsequent operations
    
    // This divergence is likely ACCEPTABLE since it adds functionality
    // without changing RFC algorithm behavior
}
```

### Resolution Strategy
- **Expected result**: Document as ACCEPTED enhancement in DISCREPANCIES.md
- **Cancellation should not affect RFC algorithm conformance**

---

## DISC-CANDIDATE-005: Memory Layout and Symbol Representation

### RFC Requirement
RFC 6330 defines symbols as sequences of T bytes but doesn't mandate specific memory layout.

### Potential Divergence
- **Our implementation**: May use specific memory alignment or layout for performance
- **RFC specification**: Only defines logical symbol structure
- **Impact**: Memory representation differences that don't affect algorithm behavior

### Investigation Plan
```rust
#[test]  
fn symbol_layout_compatibility() {
    // Ensure our symbol representation produces RFC-compliant outputs
    // Test interoperability with reference implementation symbol formats
    
    let source_data = generate_test_data(1024);
    let our_symbols = encode_to_symbols(&source_data);
    let reconstructed = decode_from_symbols(&our_symbols);
    
    assert_eq!(source_data, reconstructed);
    
    // Test compatibility with external symbol formats if possible
}
```

### Resolution Strategy
- **If compatible**: Document layout choices as implementation detail
- **If incompatible**: Investigate standardization requirements

---

## DISC-CANDIDATE-006: Numerical Precision and Rounding

### RFC Requirement
RFC 6330 algorithms involve integer arithmetic and should be exact.

### Potential Divergence
- **Our implementation**: All operations should be exact integer arithmetic
- **RFC specification**: Specifies exact integer results
- **Impact**: Should be no divergence, but worth validating

### Investigation Plan
```rust
#[test]
fn numerical_precision_validation() {
    // Validate that all RFC calculations produce exact integer results
    // No floating point operations should be involved
    
    // This is a validation test rather than expected divergence
    // All RFC 6330 operations are integer-based
}
```

### Resolution Strategy
- **Expected result**: No divergence - confirm exact integer arithmetic throughout

---

## DISC-CANDIDATE-007: Systematic Index Table Implementation

### RFC Requirement
RFC 6330 Table 2 provides systematic index values for K.

### Potential Divergence
- **Our implementation**: May use calculated systematic index vs lookup table
- **RFC specification**: Provides table but allows equivalent calculation methods
- **Impact**: Same results through different methods

### Investigation Plan
```rust
#[test]
fn systematic_index_method_validation() {
    // Compare our systematic index calculation with RFC Table 2
    let rfc_table = load_rfc_table_2();
    
    for k in 1..=8192 {
        let our_index = calculate_systematic_index(k);
        let table_index = rfc_table.lookup(k);
        
        assert_eq!(our_index, table_index, 
                  "Systematic index mismatch for K={k}");
    }
}
```

### Resolution Strategy
- **If equivalent**: Document calculation method as ACCEPTED alternative  
- **If divergent**: Investigate and fix calculation algorithm

---

## DISC-CANDIDATE-008: Performance vs. Accuracy Trade-offs

### RFC Requirement
RFC 6330 prioritizes correctness over performance considerations.

### Potential Divergence
- **Our implementation**: May include performance optimizations with accuracy implications
- **RFC specification**: Focuses on algorithmic correctness
- **Impact**: Need to ensure optimizations don't compromise RFC compliance

### Investigation Plan
```rust
#[test]
fn performance_optimization_conformance() {
    // Validate that performance optimizations maintain RFC accuracy
    
    // Test optimized code paths against reference implementation
    let test_cases = generate_comprehensive_test_cases();
    
    for case in test_cases {
        let optimized_result = our_optimized_implementation(&case);
        let reference_result = reference_implementation(&case);
        
        assert_eq!(optimized_result, reference_result);
    }
}
```

### Resolution Strategy
- **If equivalent**: Document optimizations as ACCEPTED enhancements
- **If divergent**: Remove optimizations or document accuracy trade-offs

---

## Investigation Workflow

### Phase 1: Candidate Validation
For each candidate, implement targeted conformance tests to determine:
1. **Is there actually a divergence?**
2. **Is the divergence intentional or accidental?**  
3. **Does the divergence affect interoperability?**
4. **Is the divergence acceptable for our use case?**

### Phase 2: Documentation Decision
Based on investigation results:
- **No divergence**: Remove from candidate list
- **Acceptable divergence**: Document in DISCREPANCIES.md as ACCEPTED
- **Problematic divergence**: Document as INVESTIGATING or WILL-FIX
- **Critical divergence**: Fix implementation to match RFC

### Phase 3: DISCREPANCIES.md Population
Convert validated divergences to formal DISCREPANCIES.md entries:

```markdown
## DISC-001: GF(256) SIMD Optimization
- **Reference:** RFC 6330 Section 5.3.3.2 reference algorithms
- **Our impl:** SIMD-optimized GF(256) arithmetic with lookup tables  
- **Impact:** 10x performance improvement, mathematically equivalent results
- **Resolution:** ACCEPTED — optimization maintains RFC correctness
- **Tests affected:** All GF(256) arithmetic tests (marked XPASS for perf)
- **Review date:** 2026-04-16
```

## Documentation Standards

### Required Information for Each Discrepancy
1. **Sequential ID**: DISC-NNN
2. **Resolution status**: ACCEPTED, INVESTIGATING, WILL-FIX
3. **Reference behavior**: What RFC 6330 specifies
4. **Our behavior**: What asupersync actually does  
5. **Impact assessment**: Effects on interoperability/correctness
6. **Test implications**: Which tests need XFAIL/XPASS marking
7. **Review date**: When divergence was last evaluated

### Maintenance Requirements
- **Quarterly review**: Reassess all INVESTIGATING divergences  
- **Version tracking**: Update when RFC or implementation changes
- **Test alignment**: Ensure tests reflect documented divergences

---

**Status**: Candidate list established. Each candidate requires investigation during conformance testing phase. Most candidates are expected to be either non-divergent or acceptable optimizations, but systematic validation is required for defensible conformance claims.