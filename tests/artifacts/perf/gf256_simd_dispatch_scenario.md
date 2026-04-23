# GF256 SIMD Dispatch Cost Profiling Scenario

## Scenario Definition
**Name**: GF256 SIMD Dispatch Overhead Analysis  
**Target**: `src/raptorq/gf256.rs` runtime kernel selection mechanism  
**Hypothesis**: SIMD dispatch adds measurable overhead via:
1. First-time feature detection cost (cold dispatch)
2. Function pointer dereference cost (warm dispatch)  
3. Dispatch decision logic overhead vs. direct calls

## Success Metrics
- **Primary**: Dispatch overhead in nanoseconds per operation call
- **Secondary**: Throughput impact (MB/s) across operation sizes 
- **Validation**: Cold vs warm dispatch cost breakdown

## Test Matrix
| Size (bytes) | Operation | Dispatch Type | Expected Impact |
|--------------|-----------|---------------|-----------------|
| 16          | addmul    | warm          | High (small work) |
| 64          | addmul    | warm          | Medium |  
| 1024        | addmul    | warm          | Low (amortized) |
| 4096        | addmul    | warm          | Minimal |
| 64          | addmul    | cold          | High (first call) |

## Environment Requirements
- `simd-intrinsics` feature enabled
- AVX2 or NEON capable CPU
- Release-perf build profile with debug symbols
- Isolated CPU cores (no SMT interference)

## Baseline Target
- p50 dispatch overhead < 10ns for warm calls
- p99 dispatch overhead < 100ns for warm calls  
- Cold dispatch cost < 10μs (first-time feature detection)
- Throughput degradation < 5% vs theoretical direct SIMD

## Golden Output
Working GF256 operations with identical results regardless of dispatch path.

## Artifacts
- `dispatch_cold_baseline.json` - First-time dispatch cost
- `dispatch_warm_baseline.json` - Steady-state dispatch cost  
- `throughput_comparison.json` - Dispatch vs direct SIMD throughput
- `hotspot_table.md` - Ranked dispatch cost breakdown
- `hypothesis_ledger.md` - Tested optimization hypotheses