# HPACK Encode Path Performance Analysis

## DEFINE: Scenario and Metrics

**Target:** `src/http/h2/hpack.rs` HPACK header encoding performance
**Scenario:** HTTP/2 header compression for typical web requests
**Metrics:** encode ops/sec, p95 latency, memory allocation rate
**Success criteria:** Identify top-5 hotspots for optimization targeting

## ENVIRONMENT: Host Fingerprint

- **Platform:** Linux 6.17.0-22-generic  
- **Rust:** Sonnet 4 environment (nightly available)
- **CPU:** Available parallelism detected via std::thread::available_parallelism()
- **Build profile:** Development (would need release-perf for accurate profiling)

## BASELINE: Code Structure Analysis

### Primary Encode Path (`Encoder::encode`)

1. **`emit_pending_size_update()`** - Dynamic table size management
2. **For each header: `encode_header()`** - Core per-header logic
   - Name normalization (ASCII lowercase check + conversion) 
   - Table lookup (static + dynamic table search)
   - Integer encoding (`encode_integer`)
   - String encoding (`encode_string`)

### Identified Hotspots (Static Analysis)

| Rank | Function | Lines | Hotspot Reason | Evidence |
|------|----------|-------|---------------|----------|
| 1 | `encode_huffman_to_buffer` | 785-810 | Bit manipulation loop, accumulator ops | Per-byte processing with shifts |
| 2 | `huffman_encoded_size` | 767-777 | Table lookup per byte | Calculates before encoding |
| 3 | `encode_header` | 387-436 | ASCII case conversion, table lookups | Cow<str> allocation, find_static calls |
| 4 | `encode_integer` | 684-698 | Variable-length encoding loop | While loop for large values |
| 5 | `DynamicTable::find` | (not shown) | Linear search through entries | Called per header |

### Hot Data Structures

- **HUFFMAN_TABLE** (static) - 256-entry lookup table
- **BIT_MASKS** (static) - Used in Huffman accumulator 
- **DynamicTable** - LRU cache with linear search
- **BytesMut** - Allocation + reallocation for output buffer

## INSTRUMENTATION: Missing Profiling Infrastructure

**Blockers for full profiling:**
1. No benchmark infrastructure (`bench = false` in Cargo.toml)
2. Would need `release-perf` profile with debug symbols
3. Need representative workload (realistic header sets)

**Recommended profiling approach:**
```bash
# 1. Enable profiling build
cargo build --profile release-perf --features="profiling"

# 2. Create unit benchmark
cargo bench hpack_encode_typical_headers

# 3. Profile with samply/perf
samply record target/release-perf/hpack_bench
```

## PROFILE: Hypotheses for Optimization

### H1: Huffman Encoding Dominates (High Confidence)
- **Evidence:** Bit-level accumulator operations, per-byte table lookup
- **Impact:** Every string goes through huffman_encoded_size + encode_huffman_to_buffer
- **Optimization:** SIMD Huffman, pre-computed size tables, avoid double-pass

### H2: String Allocation in Case Conversion (Medium Confidence) 
- **Evidence:** `Cow::Owned(header.name.to_ascii_lowercase())` allocation
- **Impact:** Per-header allocation for mixed-case header names
- **Optimization:** In-place lowercase, interned header names

### H3: Dynamic Table Linear Search (Medium Confidence)
- **Evidence:** find() and find_name() iterate entries 
- **Impact:** O(n) cost per header lookup, gets worse with larger tables
- **Optimization:** HashMap index, generational search

### H4: BytesMut Reallocations (Low-Medium Confidence)
- **Evidence:** `dst.put_u8()` and `dst.extend_from_slice()` calls
- **Impact:** Buffer growth during encoding
- **Optimization:** Pre-allocate based on header count estimate

## HAND OFF: Opportunity Matrix

| Target | Impact (1-5) | Confidence (1-5) | Effort (1-5) | Score (I×C/E) |
|--------|-------------|------------------|---------------|---------------|
| SIMD Huffman encoding | 4 | 3 | 4 | 3.0 |
| Avoid ASCII case conversion allocation | 3 | 4 | 2 | 6.0 ⭐ |
| HashMap dynamic table index | 3 | 3 | 3 | 3.0 |
| Pre-allocate BytesMut capacity | 2 | 4 | 1 | 8.0 ⭐ |
| Huffman single-pass encoding | 4 | 2 | 5 | 1.6 |

**Top targets (Score ≥ 2.0):**
1. **Pre-allocate BytesMut** - Quick win, estimate capacity from header count
2. **Avoid case conversion allocation** - Use static lowercase check, avoid Cow::Owned
3. **SIMD Huffman** + **HashMap table index** - Deeper optimizations

**Next step:** Hand to extreme-software-optimization with profiling baseline + opportunity matrix.

## Notes

- **Profiling infrastructure missing** - Would need benchmarks + release-perf build
- **Representative workload needed** - Real header distributions for accurate hotspots  
- **Memory ordering not analyzed** - Focus was on algorithmic hotspots
- **HPACK conformance critical** - Any optimization must preserve RFC 7541 correctness