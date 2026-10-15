# Web Multipart ↔ Codec Length-Delimited ↔ RaptorQ E2E Integration

This document describes the comprehensive e2e test implementation for web/multipart ↔ codec/length_delimited ↔ raptorq integration, focusing on file upload pipeline chunk boundary preservation and error correction.

## Module Integration

Located in: `src/real_web_multipart_codec_raptorq_e2e_tests.rs`

### Core Subsystems

1. **`web::multipart`** - HTTP multipart form-data parsing
   - RFC 7578 compliant multipart parsing
   - File upload field extraction with metadata
   - Configurable size and part limits
   - Content type detection and validation

2. **`codec::length_delimited`** - Frame-based encoding with length prefixes
   - Variable-length frame encoding/decoding
   - 32-bit big-endian length prefixes
   - Frame boundary preservation
   - Overflow protection and error handling

3. **`raptorq::systematic`** - Systematic encoding for error correction
   - RFC 6330 compliant systematic RaptorQ
   - Source symbol pass-through (systematic property)
   - Repair symbol generation for loss recovery
   - Configurable symbol sizes and redundancy levels

## Key Integration Features

### File Upload Pipeline

Tests complete file upload processing chain:
1. **Multipart Parsing** → Extract file data and metadata from HTTP uploads
2. **Chunk Segmentation** → Split large files into manageable chunks
3. **Frame Encoding** → Wrap chunks with length-delimited framing
4. **RaptorQ Encoding** → Apply systematic error correction encoding
5. **Transmission Simulation** → Simulate network transmission with symbol loss
6. **RaptorQ Decoding** → Recover data using source and repair symbols
7. **Frame Decoding** → Extract chunks from length-delimited frames
8. **File Reconstruction** → Reassemble original file from chunks

### Chunk Boundary Preservation

**Processing Flow:** `Upload → Chunks → Frames → Symbols → Recovery → Verification`

**Boundary Preservation Patterns:**
- **Chunk-Frame Alignment**: Chunks map cleanly to frame boundaries
- **Frame-Symbol Alignment**: Frames preserve symbol boundary integrity  
- **Symbol Recovery**: Lost symbols can be reconstructed without affecting boundaries
- **End-to-End Integrity**: Original chunk structure preserved through full pipeline

### Error Correction Integration

Verifies that RaptorQ systematic encoding provides robust error correction:
- **Symbol Loss Tolerance**: Pipeline survives configurable symbol loss rates
- **Repair Symbol Efficiency**: Minimal overhead for specified protection level
- **Boundary Preservation**: Error correction doesn't corrupt frame boundaries
- **Graceful Degradation**: Performance degrades gracefully with increasing loss

## Test Scenarios

### `test_single_chunk_upload_pipeline()`
**Small File Complete Pipeline**

Tests single-chunk files through complete processing:
1. Create 4KB test file with deterministic pattern
2. Process through multipart → framing → RaptorQ encoding
3. Decode back through RaptorQ → framing → reconstruction
4. Verify byte-for-byte identical recovery

**Verification Points:**
- Metadata preservation (filename, content type, field name)
- Single chunk handling efficiency
- Frame boundary correctness
- Symbol generation and recovery
- End-to-end data integrity

### `test_multi_chunk_upload_pipeline()`
**Large File Chunk Boundary Preservation**

Tests chunk boundary preservation with large files:
1. Create 32KB file split into 4 × 8KB chunks
2. Process each chunk through framing pipeline
3. Verify chunk boundaries preserved in frames
4. Reconstruct and verify chunk-by-chunk integrity

**Chunk Properties:**
- Exact chunk size preservation
- No cross-chunk data bleeding
- Proper chunk ordering maintenance
- Frame-to-chunk mapping accuracy

### `test_symbol_loss_recovery()`
**Error Correction Under Symbol Loss**

Tests RaptorQ error correction with simulated losses:
1. Process file through complete pipeline
2. Simulate 20% symbol loss during "transmission"
3. Attempt recovery using remaining symbols
4. Verify perfect data reconstruction despite losses

**Loss Recovery Properties:**
- Configurable loss rate simulation
- Repair symbol effectiveness
- Recovery success rate tracking
- Performance under varying loss conditions

### `test_frame_boundary_edge_cases()`
**Boundary Condition Handling**

Tests frame boundary edge cases:
1. Set frame size just above chunk size
2. Create data resulting in exact boundary alignment
3. Verify no boundary corruption or misalignment
4. Test edge cases like partial frames

**Boundary Edge Cases:**
- Exact frame-length boundaries
- Partial final chunks
- Empty chunk handling
- Frame header/payload boundaries

### `test_different_content_types()`
**Content Type Preservation**

Tests metadata preservation across content types:
1. Upload files with different MIME types (JPEG, PDF, JSON)
2. Verify content type metadata preserved
3. Confirm content type doesn't affect data integrity
4. Test binary vs. text content handling

**Content Type Properties:**
- MIME type preservation through pipeline
- Binary data handling accuracy
- Text encoding neutrality
- Metadata roundtrip integrity

### `test_pipeline_under_concurrent_load()`
**Concurrent Upload Processing**

Tests pipeline performance under load:
1. Create 10 concurrent simulated uploads
2. Process all uploads through complete pipeline
3. Verify no cross-upload interference
4. Confirm all uploads recover correctly

**Concurrency Properties:**
- Independent upload processing
- No state contamination between uploads
- Resource usage scaling
- Throughput under concurrent load

### `test_empty_and_minimal_files()`
**Edge Case File Handling**

Tests edge cases with minimal/empty files:
1. Process empty file (0 bytes)
2. Process minimal file (1 byte)
3. Verify graceful handling of edge cases
4. Test boundary conditions

**Minimal File Properties:**
- Empty file graceful handling
- Single-byte file processing
- Minimal overhead for small files
- Error handling for degenerate cases

### `test_large_file_streaming()`
**Large File Memory Efficiency**

Tests streaming behavior with large files:
1. Create 1MB test file
2. Process with 16KB chunks
3. Verify memory-efficient streaming
4. Test symbol generation scaling

**Streaming Properties:**
- Memory usage bounded by chunk size
- Symbol generation scaling
- Chunk processing independence  
- Large file handling efficiency

### `test_corruption_detection_and_recovery()`
**Data Corruption Resilience**

Tests corruption detection and recovery:
1. Process file through pipeline
2. Introduce bit corruption in symbols
3. Attempt recovery via repair symbols
4. Verify corruption detection and handling

**Corruption Handling:**
- Bit-level corruption detection
- Repair symbol-based recovery
- Graceful degradation under severe corruption
- Error reporting and diagnostics

## Test Infrastructure

### `MockMultipartUpload`
Simulated multipart file upload:
- Configurable field names and filenames
- Content type simulation
- Chunk size configuration
- Binary data pattern generation

### `FileUploadPipeline`
Complete integration pipeline:
- Length-delimited codec with configurable frame sizes
- RaptorQ systematic encoder/decoder integration
- Statistics tracking for performance analysis
- Symbol loss simulation for robustness testing

### `ProcessedUpload`
Upload processing result container:
- Original data preservation for verification
- Intermediate representation tracking (chunks, frames, symbols)
- Metadata preservation throughout pipeline
- Processing statistics and diagnostics

### `PipelineStats`
Performance and processing statistics:
- File/chunk/frame/symbol counting
- Bytes processed tracking
- Loss and recovery statistics
- Performance metric collection

## Real-Service E2E Benefits

### No Mock-Reality Divergence
- Uses actual `LengthDelimitedCodec` with real frame parsing
- Authentic `RaptorQ` systematic encoding algorithms
- Production-representative multipart parsing
- Real error correction and boundary preservation

### Integration Bug Detection
- Frame boundary corruption during encoding/decoding
- Multipart metadata loss through processing pipeline
- RaptorQ symbol corruption affecting chunk reconstruction
- Memory leaks or inefficiency in streaming large files

### Production Scenario Modeling
- Realistic file upload sizes and patterns
- Authentic network loss simulation
- Production-scale concurrent upload handling
- Real-world error correction requirements

## Key Properties Verified

### Data Integrity
- Byte-for-byte identical reconstruction
- No data corruption through pipeline stages
- Metadata preservation throughout processing
- Error detection and correction effectiveness

### Boundary Preservation
- Chunk boundaries maintained through framing
- Frame boundaries preserved during symbol encoding
- Symbol boundaries respected during recovery
- End-to-end boundary consistency

### Error Correction
- Symbol loss recovery up to theoretical limits
- Repair symbol effectiveness verification
- Graceful degradation under extreme loss
- Performance scaling with protection level

### Memory Efficiency
- Bounded memory usage independent of file size
- Streaming processing for large files
- Minimal memory overhead per pipeline stage
- Efficient chunk and symbol buffering

## Usage

Run the e2e tests with:

```bash
# Run all web-multipart-codec-raptorq e2e tests
cargo test --lib --features real-service-e2e real_web_multipart_codec_raptorq_e2e_tests

# Run specific pipeline test
cargo test --lib --features real-service-e2e test_multi_chunk_upload_pipeline

# Run symbol loss recovery test
cargo test --lib --features real-service-e2e test_symbol_loss_recovery

# Run with detailed logging
cargo test --lib --features real-service-e2e test_pipeline_under_concurrent_load -- --nocapture
```

### Debugging Failed Tests

When upload pipeline integration fails, the structured logging provides:
- Per-stage processing metrics (chunks, frames, symbols)
- Boundary preservation verification at each stage
- Symbol loss and recovery statistics
- Data integrity checksums throughout pipeline

Example debugging workflow:
1. Review chunk segmentation logs for boundary issues
2. Check frame encoding/decoding for size mismatches
3. Verify RaptorQ symbol generation and recovery rates
4. Analyze end-to-end data integrity verification

## Advanced Scenarios

### Variable Chunk Size Optimization
Tests optimal chunk sizing for different file types:
- Small files with minimal chunking overhead
- Large files with efficient streaming chunks
- Adaptive chunk sizing based on file characteristics
- Performance optimization across file size ranges

### Content-Aware Processing
Tests content-specific optimizations:
- Text vs. binary content handling
- Compression-friendly chunk alignment
- Content type specific symbol sizing
- MIME type preservation and validation

### Network Simulation Integration
Tests realistic network conditions:
- Variable latency and bandwidth simulation
- Burst loss patterns mimicking real networks
- Congestion control interaction
- Quality-of-Service prioritization

### Performance Under Scale
Tests pipeline scaling characteristics:
- Large file handling (GB+ files)
- High-throughput concurrent uploads
- Memory usage profiling and optimization
- CPU usage efficiency analysis

This comprehensive e2e testing ensures that the runtime's file upload processing pipeline maintains data integrity and chunk boundary preservation across all encoding/decoding stages, with robust error correction and efficient resource utilization under realistic operational conditions.