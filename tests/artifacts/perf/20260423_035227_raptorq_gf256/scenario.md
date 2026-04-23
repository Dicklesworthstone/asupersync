# RaptorQ Decoder GF256 Inner Loops - Profiling Scenario

## Scenario Definition

**Target**: `src/raptorq/decoder.rs` GF256 finite field operations  
**Focus**: Inner loops in Gaussian elimination and symbol processing  
**Date**: 2026-04-23  
**Run ID**: 20260423_035227_raptorq_gf256  

## Problem Statement

RaptorQ decoding involves intensive GF(256) finite field arithmetic in:
1. **Gaussian elimination**: `gf256_addmul_slice` operations during pivot elimination
2. **Symbol reconstruction**: Linear combinations of intermediate symbols
3. **Matrix operations**: Dense core factorization and sparse updates

## Success Metrics

- **Latency**: p95 decode time for medium complexity matrices (K=1024, overhead=10%)
- **Throughput**: Symbols decoded per second
- **Memory**: Peak RSS during decode
- **Variance**: <10% p95 drift across runs

## Workload Scenarios

### 1. **Small Matrix** (baseline)
- K = 64 source symbols  
- 10% overhead (71 total symbols)
- Symbol size: 1KB
- Expected: Fast peeling, minimal Gaussian elimination

### 2. **Medium Matrix** (primary target) 
- K = 1024 source symbols
- 10% overhead (1127 total symbols) 
- Symbol size: 1KB
- Expected: Mixed peeling + dense elimination

### 3. **Large Matrix** (stress test)
- K = 4096 source symbols
- 20% overhead (4915 total symbols)
- Symbol size: 1KB  
- Expected: Heavy Gaussian elimination, cache pressure

## Expected Hotspots (Hypothesis)

1. **`gf256_addmul_slice`** - Bulk finite field multiply-accumulate
2. **`select_pivot_row`** - Pivot selection with Markowitz counting
3. **Dense matrix rebuilds** - Matrix reconstruction during hard regime
4. **Symbol reconstruction** - Final linear combination step

## Golden Outputs

Each scenario produces intermediate symbols that are validated against:
- Systematic property: first K symbols == source symbols
- Equation satisfaction: All input equations verify against decoded symbols
- Deterministic: Same input order produces identical results

## Budget Targets

Based on existing benchmarks:
- **Hard budget**: p95 < 100ms for medium matrix
- **Operational budget**: p95 < 50ms for medium matrix  
- **Regression threshold**: 15% performance degradation
- **Throughput target**: >10K symbols/sec