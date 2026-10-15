# FS/Uring ↔ RaptorQ Encoder E2E Integration

This document describes the comprehensive e2e test implementation for fs/uring ↔ raptorq encoder integration, focusing on uring-driven file reads feeding RaptorQ encoder with deterministic block boundaries.

## Module Integration

Located in: `src/real_fs_uring_raptorq_encoder_e2e_tests.rs`

### Core Subsystems

1. **`fs::uring`** - io_uring-based asynchronous file I/O
   - High-performance async file reading via Linux io_uring
   - Deterministic chunking with configurable block sizes
   - Memory-bounded streaming for large files
   - Resource management and cancellation support

2. **`raptorq::encoder`** - RaptorQ systematic encoding
   - Forward error correction encoding (RFC 6330)
   - Systematic encoding preserving original data blocks
   - Configurable source block parameters (K, T)
   - Repair symbol generation for redundancy

## Key Integration Features

### File-to-RaptorQ Pipeline

Tests complete file-read-to-encode processing:
1. **File Opening** → Open file for async reading via io_uring interface
2. **Chunked Reading** → Read file in deterministic 8KB chunks
3. **Block Alignment** → Ensure chunk boundaries align with RaptorQ source blocks
4. **Systematic Encoding** → Feed chunks into RaptorQ encoder preserving block structure
5. **Symbol Generation** → Generate both systematic and repair symbols
6. **Resource Cleanup** → File handles and memory allocations properly released

### Deterministic Boundary Preservation

**Boundary Flow:** `File Chunks → RaptorQ Source Blocks → Systematic Symbols → Verifiable Reconstruction`

**Boundary Patterns:**
- **8KB Chunking**: Consistent chunk size regardless of io_uring batch behavior
- **Block Alignment**: File chunks align perfectly with RaptorQ K parameter
- **Symbol Integrity**: Original file chunks preserved in systematic symbols
- **Memory Bounds**: Streaming prevents OOM on large files (GB+ sizes)

### Async I/O Integration

Verifies proper integration of io_uring and RaptorQ systematic encoding:
- **Submission Queue**: File read operations submitted asynchronously 
- **Completion Queue**: Read completions feed directly into encoder
- **Cancellation Support**: File reads and encoding support cancellation
- **Resource Bounds**: Memory and file descriptor usage bounded under load

## Test Scenarios

### `test_basic_file_to_raptorq_encoding()`
**Simple File-to-Encode Integration**

Tests basic file reading triggering RaptorQ encoding:
1. Create test file with known pattern (8KB, aligned to RaptorQ K=8)
2. Open file for async reading via io_uring
3. Read file chunks and feed into RaptorQ encoder
4. Verify systematic symbols match original file chunks
5. Confirm repair symbols generated for redundancy

**Verification Points:**
- File chunks read in deterministic 8KB blocks
- RaptorQ source blocks correctly constructed from file chunks
- Systematic symbols preserve original file data
- Repair symbols provide forward error correction
- Resource usage tracked and bounded

### `test_deterministic_boundary_preservation()`
**Block Boundary Consistency**

Tests boundary preservation through async I/O and encoding:
1. Create file with specific boundary markers every 8KB
2. Configure RaptorQ with K=8 (8 source symbols per block)
3. Read file via io_uring with deterministic chunking
4. Verify chunk boundaries align with RaptorQ source blocks
5. Confirm boundary markers preserved in systematic symbols

**Boundary Properties:**
- File chunks maintain exact 8KB boundaries
- RaptorQ source blocks align with file chunks
- Boundary markers preserved through encoding
- No data corruption at chunk boundaries
- Deterministic reconstruction of original file

### `test_large_file_streaming_memory_bounds()`
**Large File Memory Management**

Tests memory-bounded streaming for large files:
1. Create large test file (1MB+ with multiple RaptorQ blocks)
2. Configure streaming with bounded memory usage
3. Process file in chunks without loading entire file
4. Verify memory usage remains bounded throughout
5. Confirm complete file processed correctly

**Streaming Properties:**
- Memory usage independent of total file size
- Chunks processed and released promptly
- No memory leaks during long-running operations
- Large file processing completes successfully
- Resource cleanup after processing completion

### `test_concurrent_file_processing()`
**Concurrent File Operations**

Tests multiple simultaneous file processing operations:
1. Create multiple test files with different patterns
2. Process files concurrently via separate io_uring instances
3. Verify no cross-file interference or corruption
4. Confirm proper resource isolation between operations
5. Validate all files processed correctly

**Concurrency Properties:**
- Independent file processing without interference
- io_uring resources efficiently shared or isolated
- File descriptor management under concurrent load
- No data corruption between concurrent operations
- Proper completion signaling for each operation

### `test_file_read_error_handling()`
**File I/O Error Management**

Tests error handling when file operations fail:
1. Attempt to read non-existent or corrupted files
2. Trigger various I/O error conditions
3. Verify errors properly propagated to encoder
4. Check graceful degradation and cleanup
5. Validate error statistics and logging

**Error Handling Properties:**
- File system errors properly detected and reported
- RaptorQ encoder handles incomplete data gracefully
- Resource cleanup occurs even on error paths
- Error messages provide useful diagnostic information
- Service remains stable after error conditions

### `test_raptorq_encoding_parameter_validation()`
**RaptorQ Configuration Validation**

Tests proper RaptorQ parameter configuration:
1. Test various K values (source symbols per block)
2. Verify T values (symbol size) compatibility
3. Test boundary conditions and edge cases
4. Confirm parameter validation and error reporting
5. Validate encoding quality and redundancy levels

**Parameter Properties:**
- K values properly validated against file size
- T values aligned with file chunk boundaries
- Invalid parameter combinations rejected
- Encoding quality meets redundancy requirements
- Parameter changes don't corrupt encoding process

### `test_pipeline_cancellation_and_cleanup()`
**Cancellation and Resource Management**

Tests cancellation and cleanup throughout the pipeline:
1. Start file processing with RaptorQ encoding
2. Cancel operation at various stages (read, encode, symbol generation)
3. Verify proper cleanup of all resources
4. Check file handles closed and memory released
5. Confirm no resource leaks after cancellation

**Cancellation Properties:**
- io_uring operations canceled promptly
- RaptorQ encoder cleanup completes successfully
- File descriptors properly closed
- Memory allocations released on cancellation
- No orphaned resources or processes

### `test_boundary_alignment_verification()`
**Block Boundary Mathematical Verification**

Tests mathematical correctness of boundary alignment:
1. Create files with known mathematical patterns
2. Process through complete pipeline
3. Verify systematic symbols maintain mathematical relationships
4. Check repair symbols provide correct redundancy
5. Confirm reconstruction properties preserved

**Mathematical Properties:**
- Systematic symbols are exact copies of original blocks
- Repair symbols satisfy RaptorQ mathematical properties
- File reconstruction is bit-perfect
- Boundary alignment preserved through all transformations
- No data loss or corruption in the encoding process

## Test Infrastructure

### `UringFileReader`
Async file reader using io_uring with deterministic chunking:
- Configurable chunk size (default 8KB for RaptorQ alignment)
- Memory-bounded operation preventing OOM
- Cancellation support with proper resource cleanup
- Statistics tracking for performance analysis

### `FileToRaptorQPipeline`
Integration harness connecting file I/O to RaptorQ encoding:
- Streaming interface between io_uring and encoder
- Boundary preservation and verification
- Error propagation and recovery
- Performance monitoring and logging

### `TestFileGenerator`
Test file creation with specific patterns:
- Configurable file sizes and patterns
- Boundary marker insertion for verification
- Mathematical pattern generation
- Large file creation for stress testing

### `RaptorQBoundaryValidator`
Verification utilities for boundary correctness:
- Chunk boundary verification
- Systematic symbol validation
- Mathematical property checking
- Reconstruction verification

## Real-Service E2E Benefits

### No Mock-Reality Divergence
- Uses actual io_uring submission/completion semantics
- Authentic RaptorQ encoding with real systematic symbols
- Production-representative memory management
- Real file system interaction and error conditions

### Integration Bug Detection
- io_uring completion order affecting chunk boundaries
- Memory management issues under streaming load
- RaptorQ parameter misalignment with file chunks
- Resource leaks in cancellation paths

### Production Scenario Modeling
- Realistic file sizes and access patterns
- Authentic async I/O timing and batching behavior
- Production-scale memory constraints
- Real-world error conditions and recovery

## Key Properties Verified

### Boundary Preservation
- File chunks maintain exact boundaries through pipeline
- RaptorQ source blocks align perfectly with file chunks
- Systematic symbols preserve original file structure
- Mathematical properties maintained throughout

### Resource Management
- Memory usage bounded independent of file size
- File descriptors properly managed and cleaned up
- io_uring resources efficiently utilized
- No resource leaks under error conditions

### Performance Characteristics
- Streaming performance scales with file size
- Memory usage remains constant for large files
- io_uring batching improves throughput
- RaptorQ encoding efficiency maintained

### Error Handling
- File system errors properly propagated and handled
- RaptorQ encoding errors detected and reported
- Resource cleanup completes under all error conditions
- Service stability maintained during error scenarios

## Usage

Run the e2e tests with:

```bash
# Run all FS-RaptorQ e2e tests
cargo test --lib --features real-service-e2e real_fs_uring_raptorq_encoder_e2e_tests

# Run specific boundary preservation test
cargo test --lib --features real-service-e2e test_deterministic_boundary_preservation

# Run large file streaming test
cargo test --lib --features real-service-e2e test_large_file_streaming_memory_bounds

# Run with detailed logging
cargo test --lib --features real-service-e2e test_concurrent_file_processing -- --nocapture
```

### Debugging Failed Tests

When FS-RaptorQ integration fails, the structured logging provides:
- File I/O operation timing and completion status
- RaptorQ encoding parameter validation and symbol generation
- Boundary alignment verification and chunk processing
- Resource usage patterns and memory allocation tracking

Example debugging workflow:
1. Review file I/O logs for read errors or timing issues
2. Check RaptorQ parameter logs for configuration problems
3. Verify boundary alignment logs for chunk corruption
4. Analyze resource usage patterns for memory leaks

## Advanced Scenarios

### Dynamic File Size Handling
Tests adaptation to various file sizes:
- Small files (< RaptorQ block size)
- Exact block multiples
- Files with partial final blocks
- Empty files and error conditions

### Performance Optimization
Tests optimal configuration for different use cases:
- io_uring queue depth tuning
- RaptorQ parameter optimization
- Memory usage minimization
- Throughput maximization

### Platform Compatibility
Tests integration across different environments:
- Various Linux kernel versions (io_uring evolution)
- Different file systems and storage types
- Memory-constrained environments
- High-throughput scenarios

### Fault Tolerance
Tests resilience under various failure conditions:
- Storage device failures and corruption
- Memory pressure and allocation failures
- Process termination and restart scenarios
- Network-attached storage connectivity issues

This comprehensive e2e testing ensures that the runtime's fs/uring and RaptorQ encoder integration maintains proper boundary preservation, efficient memory management, and robust error handling under all realistic operational scenarios.