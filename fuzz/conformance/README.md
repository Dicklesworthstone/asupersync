# HTTP Conformance Test Harnesses

This crate provides conformance testing against reference implementations to ensure protocol compliance and behavioral consistency for asupersync HTTP implementations.

## Test Harnesses

### HTTP/2 CONTINUATION Frame Ordering (`h2_continuation_ordering_conformance`)

**Purpose:** Tests HEADERS + CONTINUATION frame sequence handling through the asupersync parser and fails closed until an independent live h2/HPACK reference seam is wired.

**Key Features:**
- Explicit `xfail-no-live-h2-hpack-reference` status instead of mocked h2 differential success
- Comprehensive test cases covering RFC 9113 Section 6.10 requirements
- Frame size boundary testing (small frames forcing multiple CONTINUATION frames)
- Header block reconstruction and HPACK decoding sanity coverage for the asupersync path
- Support for various output formats (JSON, Markdown, Summary)

**Test Scenarios:**
1. **Simple Continuation** - Basic HEADERS + single CONTINUATION frame
2. **Multiple Continuations** - HEADERS + multiple CONTINUATION frames  
3. **Exact Frame Boundary** - Header blocks that exactly fill frame boundaries
4. **Large Header Values** - Very large headers requiring frame fragmentation
5. **Many Small Headers** - Numerous small headers causing frame splits
6. **Minimum Frame Size** - Testing with smallest allowed frame sizes
7. **Single Byte Continuation** - Edge case with minimal continuation frames
8. **Empty Continuation** - Zero-length continuation edge cases
9. **Huffman Encoding Split** - HPACK Huffman encoding across frame boundaries
10. **Duplicate Header Names** - Multiple headers with same name (Set-Cookie pattern)
11. **Max Stream ID** - Testing with maximum valid stream ID (0x7FFFFFFF)

**Usage:**

```bash
# Run all tests with summary output
cargo run --bin h2_continuation_ordering_conformance

# Run specific test case
cargo run --bin h2_continuation_ordering_conformance --test-case simple_continuation

# Generate detailed markdown report
cargo run --bin h2_continuation_ordering_conformance --format markdown > report.md

# Generate JSON output for CI
cargo run --bin h2_continuation_ordering_conformance --format json > results.json

# Verbose output with detailed header comparisons
cargo run --bin h2_continuation_ordering_conformance --verbose
```

**RFC Compliance Tested:**
- RFC 9113 Section 6.10: CONTINUATION frames MUST follow HEADERS without END_HEADERS
- CONTINUATION frames MUST have same stream ID as preceding HEADERS
- Only final frame in sequence may have END_HEADERS flag set
- Header block reconstruction from fragmented frames
- HPACK decoding consistency across frame boundaries

## Implementation Details

### Frame Sequence Creation
The test harness creates realistic HEADERS + CONTINUATION sequences by:
1. Encoding test headers with HPACK
2. Splitting the header block based on configurable `max_frame_size`
3. Creating HEADERS frame (first chunk, END_HEADERS=false if more frames follow)
4. Creating CONTINUATION frame(s) for remaining chunks
5. Setting END_HEADERS=true only on final frame

### Conformance Validation
For each test case:
1. **asupersync path:** Process frame sequence through asupersync's HTTP/2 implementation
2. **h2 reference path:** Report the missing live h2/HPACK seam as unsupported
3. **Comparison:** Refuse a conformance pass while the reference path is unsupported
4. **Error handling:** Preserve the malformed-input oracle intent without fabricating vendor parity

### Output Formats

**Summary Format:**
```
HTTP/2 CONTINUATION Frame Ordering Conformance Test Results
===========================================================

Total tests:  11
Passed:       0 (0.0%)
Failed:       11 (100.0%)

FAIL-CLOSED - no conformance pass is claimed without a live h2/HPACK reference
```

**JSON Format:** Structured results suitable for CI/CD integration and automated analysis.

**Markdown Format:** Detailed report with test descriptions, results, and recommendations.

## Error Conditions Tested

- Malformed frame sequences (CONTINUATION without preceding HEADERS)
- Stream ID mismatches between HEADERS and CONTINUATION frames
- Missing END_HEADERS flag on final frame
- Intervening frames between HEADERS and CONTINUATION sequence
- Frame size violations and boundary conditions

## Future Enhancements

1. **Real h2 Integration:** Wire an actual h2/HPACK observation seam for reference behavior
2. **Property-Based Testing:** Generate randomized header sets and frame boundaries
3. **Performance Benchmarking:** Compare processing speed between implementations
4. **Extended Test Coverage:** Add more edge cases and protocol violations
5. **Stream Interleaving:** Test CONTINUATION sequences across multiple concurrent streams

## Contributing

When adding new test cases:
1. Add test scenario to `generate_test_cases()` function
2. Ensure test covers specific RFC requirement or edge case
3. Include descriptive name and detailed description
4. Add corresponding unit tests in the `tests` module
5. Update this README with new test case documentation

## Dependencies

- `asupersync`: Target implementation under test
- `h2`: Future reference implementation seam for live differential testing
- `bytes`: Byte buffer manipulation
- `serde/serde_json`: JSON output format support
- `tokio`: Async runtime for HTTP/2 operations
