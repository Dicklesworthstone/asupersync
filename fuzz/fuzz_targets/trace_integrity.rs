#![no_main]

//! Fuzz target for trace integrity verification and tamper detection.
//!
//! This fuzz target generates malformed and tampered trace blobs to exercise
//! the tamper-detection paths in `src/trace/integrity.rs`. It focuses on:
//!
//! - **Header tampering**: Magic bytes, version, flags corruption
//! - **Metadata attacks**: Invalid lengths, corrupted MessagePack, schema mismatch
//! - **Event corruption**: Malformed events, non-monotonic timeline, truncation
//! - **Size attacks**: Oversized metadata/events to trigger OOM protection
//! - **Hash-chain breaks**: Event sequence integrity violations
//! - **Boundary conditions**: Empty files, minimal files, large files

use arbitrary::{Arbitrary, Result, Unstructured};
use asupersync::trace::integrity::{verify_trace, VerificationOptions};
use asupersync::trace::replay::{ReplayEvent, TraceMetadata, CompactTaskId};
use libfuzzer_sys::fuzz_target;
use std::fs::{self, File};
use std::env;

// =============================================================================
// Constants from trace/file.rs
// =============================================================================

const TRACE_MAGIC: &[u8; 11] = b"ASUP_TRACE\0";
const TRACE_FILE_VERSION: u16 = 2;
const FLAG_COMPRESSED: u16 = 1;
const HEADER_SIZE: usize = 16; // magic(11) + version(2) + flags(2) + compression(1)

// Fuzzing limits to prevent timeouts
const MAX_EVENTS: usize = 100;
const MAX_BLOB_SIZE: usize = 1_048_576; // 1MB max to prevent memory exhaustion

// =============================================================================
// Fuzz Input Structure
// =============================================================================

#[derive(Debug, Arbitrary)]
struct TraceIntegrityFuzz {
    operation: IntegrityOperation,
}

#[derive(Debug, Arbitrary)]
enum IntegrityOperation {
    /// Test with completely random blob
    RandomBlob {
        #[arbitrary(with = bounded_blob)]
        data: Vec<u8>
    },

    /// Tamper with header components
    HeaderTamper {
        tamper_magic: bool,
        tamper_version: Option<u16>,
        tamper_flags: Option<u16>,
        tamper_compression: Option<u8>,
        #[arbitrary(with = bounded_blob)]
        trailing_data: Vec<u8>,
    },

    /// Corrupt metadata section
    MetadataTamper {
        valid_header: bool,
        metadata_op: MetadataOperation,
    },

    /// Generate corrupted event streams
    EventTamper {
        valid_header: bool,
        valid_metadata: bool,
        event_op: EventOperation,
    },

    /// Size-based attacks (oversized components)
    SizeAttack {
        attack_type: SizeAttackType,
        size_multiplier: u16, // 1-65535x multiplier
    },

    /// Truncation attacks at various points
    Truncation {
        truncate_at: TruncationPoint,
        #[arbitrary(with = small_offset)]
        offset: usize,
    },
}

#[derive(Debug, Arbitrary)]
enum MetadataOperation {
    InvalidLength { length: u32 },
    CorruptedMsgPack {
        #[arbitrary(with = bounded_blob)]
        corrupt_data: Vec<u8>
    },
    SchemaMismatch { version: u32 },
    ValidMetadata { replay_id: u64 },
}

#[derive(Debug, Arbitrary)]
enum EventOperation {
    NonMonotonicTimeline { event_count: u8 },
    CorruptedEventLength { corrupt_length: u32 },
    CorruptedEventData {
        event_count: u8,
        corrupt_index: u8,
        #[arbitrary(with = bounded_blob)]
        corrupt_data: Vec<u8>,
    },
    EventCountMismatch {
        declared_count: u64,
        actual_count: u8
    },
    ValidEvents { count: u8 },
}

#[derive(Debug, Arbitrary)]
enum SizeAttackType {
    OversizedMetadata,
    OversizedEvent,
    OversizedFile,
}

#[derive(Debug, Arbitrary)]
enum TruncationPoint {
    InHeader,
    InMetadataLength,
    InMetadata,
    InEventCount,
    InEventLength,
    InEventData,
}

// =============================================================================
// Arbitrary Helpers
// =============================================================================

fn bounded_blob(u: &mut Unstructured) -> Result<Vec<u8>> {
    let len = u.int_in_range(0..=4096)?; // Reasonable size for fuzzing
    let mut data = vec![0u8; len];
    u.fill_buffer(&mut data)?;
    Ok(data)
}

fn small_offset(u: &mut Unstructured) -> Result<usize> {
    Ok(u.int_in_range(0..=1024)?)
}

// =============================================================================
// Fuzz Target Implementation
// =============================================================================

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_BLOB_SIZE {
        return; // Skip oversized inputs
    }

    let mut u = Unstructured::new(data);
    let fuzz_input = match TraceIntegrityFuzz::arbitrary(&mut u) {
        Ok(input) => input,
        Err(_) => return, // Skip invalid arbitrary input
    };

    // Create a temporary file path
    let temp_path = format!("/tmp/trace_fuzz_{}", std::process::id());
    let path = std::path::Path::new(&temp_path);

    // Generate the trace blob based on fuzzing operation
    if let Err(_) = generate_trace_blob(&fuzz_input.operation, path) {
        return; // Skip on generation failure
    }

    // Test different verification modes
    test_verification_modes(path);
});

fn generate_trace_blob(operation: &IntegrityOperation, path: &std::path::Path) -> std::io::Result<()> {
    match operation {
        IntegrityOperation::RandomBlob { data } => {
            fs::write(path, data)?;
        }

        IntegrityOperation::HeaderTamper {
            tamper_magic,
            tamper_version,
            tamper_flags,
            tamper_compression,
            trailing_data,
        } => {
            let mut blob = Vec::new();

            // Magic bytes (tampered or valid)
            if *tamper_magic {
                blob.extend_from_slice(b"BADMAGIC123"); // Wrong magic
            } else {
                blob.extend_from_slice(TRACE_MAGIC);
            }

            // Version (tampered or valid)
            let version = tamper_version.unwrap_or(TRACE_FILE_VERSION);
            blob.extend_from_slice(&version.to_le_bytes());

            // Flags (tampered or valid)
            let flags = tamper_flags.unwrap_or(0);
            blob.extend_from_slice(&flags.to_le_bytes());

            // Compression byte (version 2+)
            if version >= 2 {
                let compression = tamper_compression.unwrap_or(0);
                blob.push(compression);
            }

            // Add some trailing data
            blob.extend_from_slice(trailing_data);

            fs::write(path, blob)?;
        }

        IntegrityOperation::MetadataTamper { valid_header, metadata_op } => {
            let mut blob = Vec::new();

            if *valid_header {
                write_valid_header(&mut blob);
            } else {
                write_corrupted_header(&mut blob);
            }

            match metadata_op {
                MetadataOperation::InvalidLength { length } => {
                    blob.extend_from_slice(&length.to_le_bytes());
                    // Don't write actual metadata data to trigger read error
                }

                MetadataOperation::CorruptedMsgPack { corrupt_data } => {
                    blob.extend_from_slice(&(corrupt_data.len() as u32).to_le_bytes());
                    blob.extend_from_slice(corrupt_data);
                }

                MetadataOperation::SchemaMismatch { version } => {
                    let metadata = TraceMetadata {
                        version: *version,
                        seed: 42,
                        recorded_at: 0,
                        config_hash: 0,
                        description: None,
                    };
                    let meta_bytes = rmp_serde::to_vec(&metadata).unwrap_or_default();
                    blob.extend_from_slice(&(meta_bytes.len() as u32).to_le_bytes());
                    blob.extend_from_slice(&meta_bytes);
                }

                MetadataOperation::ValidMetadata { replay_id } => {
                    let metadata = TraceMetadata::new(*replay_id);
                    let meta_bytes = rmp_serde::to_vec(&metadata).unwrap_or_default();
                    blob.extend_from_slice(&(meta_bytes.len() as u32).to_le_bytes());
                    blob.extend_from_slice(&meta_bytes);
                }
            }

            fs::write(path, blob)?;
        }

        IntegrityOperation::EventTamper { valid_header, valid_metadata, event_op } => {
            let mut blob = Vec::new();

            if *valid_header {
                write_valid_header(&mut blob);
            } else {
                write_corrupted_header(&mut blob);
                fs::write(path, blob)?;
                return Ok(());
            }

            if *valid_metadata {
                write_valid_metadata(&mut blob);
            } else {
                write_corrupted_metadata(&mut blob);
                fs::write(path, blob)?;
                return Ok(());
            }

            match event_op {
                EventOperation::NonMonotonicTimeline { event_count } => {
                    let count = (*event_count).min(MAX_EVENTS as u8) as u64;
                    blob.extend_from_slice(&count.to_le_bytes());

                    // Generate non-monotonic events
                    for i in 0..count {
                        let timestamp = if i == 1 { 50 } else { i * 100 }; // Event 1 goes backwards
                        let event = ReplayEvent::TaskScheduled {
                            task: CompactTaskId(i),
                            at_tick: timestamp,
                        };
                        write_event(&mut blob, &event);
                    }
                }

                EventOperation::CorruptedEventLength { corrupt_length } => {
                    blob.extend_from_slice(&1u64.to_le_bytes()); // 1 event
                    blob.extend_from_slice(&corrupt_length.to_le_bytes()); // Corrupt length
                    // Write some data but wrong length
                    blob.extend_from_slice(b"short");
                }

                EventOperation::CorruptedEventData { event_count, corrupt_index, corrupt_data } => {
                    let count = (*event_count).min(MAX_EVENTS as u8) as u64;
                    blob.extend_from_slice(&count.to_le_bytes());

                    for i in 0..count {
                        if i == *corrupt_index as u64 {
                            // Write corrupted event
                            blob.extend_from_slice(&(corrupt_data.len() as u32).to_le_bytes());
                            blob.extend_from_slice(corrupt_data);
                        } else {
                            // Write valid event
                            let event = ReplayEvent::TaskScheduled {
                                task: CompactTaskId(i),
                                at_tick: i * 100,
                            };
                            write_event(&mut blob, &event);
                        }
                    }
                }

                EventOperation::EventCountMismatch { declared_count, actual_count } => {
                    blob.extend_from_slice(&declared_count.to_le_bytes());

                    let actual = (*actual_count).min(MAX_EVENTS as u8) as u64;
                    for i in 0..actual {
                        let event = ReplayEvent::TaskScheduled {
                            task: CompactTaskId(i),
                            at_tick: i * 100,
                        };
                        write_event(&mut blob, &event);
                    }
                }

                EventOperation::ValidEvents { count } => {
                    let count = (*count).min(MAX_EVENTS as u8) as u64;
                    blob.extend_from_slice(&count.to_le_bytes());

                    for i in 0..count {
                        let event = ReplayEvent::TaskScheduled {
                            task: CompactTaskId(i),
                            at_tick: i * 100,
                        };
                        write_event(&mut blob, &event);
                    }
                }
            }

            fs::write(path, blob)?;
        }

        IntegrityOperation::SizeAttack { attack_type, size_multiplier } => {
            let mut blob = Vec::new();
            write_valid_header(&mut blob);

            let size = (*size_multiplier as usize * 1024).min(MAX_BLOB_SIZE / 2);

            match attack_type {
                SizeAttackType::OversizedMetadata => {
                    // Claim huge metadata size
                    blob.extend_from_slice(&(size as u32).to_le_bytes());
                    blob.resize(blob.len() + size.min(8192), 0xAA); // Cap actual size
                }

                SizeAttackType::OversizedEvent => {
                    write_valid_metadata(&mut blob);
                    blob.extend_from_slice(&1u64.to_le_bytes()); // 1 event
                    blob.extend_from_slice(&(size as u32).to_le_bytes()); // Huge event size
                    blob.resize(blob.len() + size.min(8192), 0xBB);
                }

                SizeAttackType::OversizedFile => {
                    write_valid_metadata(&mut blob);
                    blob.extend_from_slice(&(size as u64).to_le_bytes()); // Many events
                    for i in 0..(size.min(100)) {
                        let event = ReplayEvent::TaskScheduled {
                            task: CompactTaskId(i as u64),
                            at_tick: i as u64 * 100,
                        };
                        write_event(&mut blob, &event);
                    }
                }
            }

            fs::write(path, blob)?;
        }

        IntegrityOperation::Truncation { truncate_at, offset } => {
            let mut blob = Vec::new();
            write_valid_header(&mut blob);
            write_valid_metadata(&mut blob);
            blob.extend_from_slice(&10u64.to_le_bytes()); // 10 events

            // Write a few events
            for i in 0..5 {
                let event = ReplayEvent::TaskScheduled {
                    task: CompactTaskId(i),
                    at_tick: i * 100,
                };
                write_event(&mut blob, &event);
            }

            // Determine truncation point
            let truncate_pos = match truncate_at {
                TruncationPoint::InHeader => (*offset).min(HEADER_SIZE - 1),
                TruncationPoint::InMetadataLength => HEADER_SIZE + (*offset).min(3),
                TruncationPoint::InMetadata => HEADER_SIZE + 4 + offset,
                TruncationPoint::InEventCount => {
                    let meta_len = get_metadata_length();
                    HEADER_SIZE + 4 + meta_len + (*offset).min(7)
                }
                TruncationPoint::InEventLength => blob.len().saturating_sub(100) + (*offset).min(50),
                TruncationPoint::InEventData => blob.len().saturating_sub(50) + (*offset).min(30),
            };

            // Truncate the blob
            if truncate_pos < blob.len() {
                blob.truncate(truncate_pos);
            }

            fs::write(path, blob)?;
        }
    }

    Ok(())
}

fn write_valid_header(blob: &mut Vec<u8>) {
    blob.extend_from_slice(TRACE_MAGIC);
    blob.extend_from_slice(&TRACE_FILE_VERSION.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes()); // No flags
    blob.push(0); // No compression
}

fn write_corrupted_header(blob: &mut Vec<u8>) {
    blob.extend_from_slice(b"BAD_MAGIC__");
    blob.extend_from_slice(&999u16.to_le_bytes()); // Invalid version
    blob.extend_from_slice(&0xFFFFu16.to_le_bytes()); // Invalid flags
    blob.push(255); // Invalid compression
}

fn write_valid_metadata(blob: &mut Vec<u8>) {
    let metadata = TraceMetadata::new(42);
    let meta_bytes = rmp_serde::to_vec(&metadata).unwrap_or_default();
    blob.extend_from_slice(&(meta_bytes.len() as u32).to_le_bytes());
    blob.extend_from_slice(&meta_bytes);
}

fn write_corrupted_metadata(blob: &mut Vec<u8>) {
    blob.extend_from_slice(&10u32.to_le_bytes());
    blob.extend_from_slice(b"CORRUPT123"); // Invalid MessagePack
}

fn write_event(blob: &mut Vec<u8>, event: &ReplayEvent) {
    let event_bytes = rmp_serde::to_vec(event).unwrap_or_default();
    blob.extend_from_slice(&(event_bytes.len() as u32).to_le_bytes());
    blob.extend_from_slice(&event_bytes);
}

fn get_metadata_length() -> usize {
    let metadata = TraceMetadata::new(42);
    rmp_serde::to_vec(&metadata).map_or(0, |v| v.len())
}

fn test_verification_modes(path: &std::path::Path) {
    // Test all verification modes - errors are expected and should not panic
    let _ = verify_trace(path, &VerificationOptions::default());
    let _ = verify_trace(path, &VerificationOptions::quick());
    let _ = verify_trace(path, &VerificationOptions::strict());

    // Test with custom options
    let custom_opts = VerificationOptions::default()
        .with_monotonicity(true)
        .with_fail_fast(false);
    let _ = verify_trace(path, &custom_opts);

    // Test utility functions
    let _ = asupersync::trace::integrity::is_trace_valid_quick(path);
    let _ = asupersync::trace::integrity::find_first_corruption(path);

    // Clean up temp file
    let _ = std::fs::remove_file(path);
}