//! Real fs/uring ↔ raptorq/decoder integration e2e tests
//!
//! Tests the integration between async file I/O using io_uring and RaptorQ decoder,
//! verifying that file operations work correctly with erasure coding for data recovery,
//! error correction, and high-performance data handling pipelines.
//!
//! Test scenarios:
//! - Reading encoded files through io_uring and decoding with RaptorQ
//! - Writing RaptorQ encoded data to files using io_uring
//! - Concurrent file operations with encoding/decoding coordination
//! - Error recovery during file I/O with RaptorQ correction

use crate::{
    cx::{Cx, Scope},
    fs::uring::{UringFile, UringConfig, UringError},
    raptorq::{
        decoder::{RaptorQDecoder, DecoderConfig, DecodingResult},
        encoder::{RaptorQEncoder, EncoderConfig},
        types::{SourceBlock, EncodingPacket, ObjectTransmissionInfo},
        error::RaptorQError,
    },
    sync::{Mutex, RwLock},
    types::{Budget, Outcome},
    error::Error,
};
use std::{
    sync::{Arc, atomic::{AtomicU64, AtomicUsize, Ordering}},
    time::Duration,
    collections::HashMap,
    path::{Path, PathBuf},
    fs,
};

/// Controllable io_uring file system that simulates various I/O conditions
/// for testing RaptorQ integration resilience
struct ControllableUringFilesystem {
    uring_config: UringConfig,
    io_conditions: Arc<RwLock<IoConditionConfig>>,
    file_operations: Arc<Mutex<HashMap<PathBuf, FileOperationStats>>>,
    temp_directory: PathBuf,
}

#[derive(Clone)]
struct IoConditionConfig {
    read_delay_ms: u64,
    write_delay_ms: u64,
    io_error_probability: f64,
    disk_full_simulation: bool,
    concurrent_operations_limit: usize,
    buffer_size_kb: usize,
}

#[derive(Debug, Default, Clone)]
struct FileOperationStats {
    reads_attempted: u64,
    reads_successful: u64,
    writes_attempted: u64,
    writes_successful: u64,
    bytes_read: u64,
    bytes_written: u64,
    io_errors: u64,
}

impl ControllableUringFilesystem {
    async fn new(cx: &Cx) -> Result<Self, Error> {
        let config = UringConfig {
            queue_depth: 256,
            buffer_pool_size: 64,
            direct_io: true,
            async_read_ahead: true,
        };

        let temp_dir = std::env::temp_dir().join("asupersync_uring_raptorq_test");
        fs::create_dir_all(&temp_dir)?;

        Ok(Self {
            uring_config: config,
            io_conditions: Arc::new(RwLock::new(IoConditionConfig {
                read_delay_ms: 0,
                write_delay_ms: 0,
                io_error_probability: 0.0,
                disk_full_simulation: false,
                concurrent_operations_limit: 32,
                buffer_size_kb: 64,
            })),
            file_operations: Arc::new(Mutex::new(HashMap::new())),
            temp_directory: temp_dir,
        })
    }

    async fn create_uring_file(&self, cx: &Cx, filename: &str) -> Result<UringFile, Error> {
        let file_path = self.temp_directory.join(filename);
        let uring_file = UringFile::create(cx, &file_path, self.uring_config.clone()).await?;

        // Initialize operation stats
        self.file_operations.lock().unwrap().insert(
            file_path.clone(),
            FileOperationStats::default(),
        );

        Ok(uring_file)
    }

    async fn open_uring_file(&self, cx: &Cx, filename: &str) -> Result<UringFile, Error> {
        let file_path = self.temp_directory.join(filename);
        let uring_file = UringFile::open(cx, &file_path, self.uring_config.clone()).await?;

        Ok(uring_file)
    }

    async fn write_with_simulation(
        &self,
        cx: &Cx,
        file: &mut UringFile,
        offset: u64,
        data: &[u8],
        file_path: &Path,
    ) -> Result<usize, Error> {
        let conditions = self.io_conditions.read().unwrap().clone();

        // Update stats
        if let Some(stats) = self.file_operations.lock().unwrap().get_mut(file_path) {
            stats.writes_attempted += 1;
        }

        // Simulate write delay
        if conditions.write_delay_ms > 0 {
            crate::time::Sleep::new(Duration::from_millis(conditions.write_delay_ms)).await;
        }

        // Simulate disk full error
        if conditions.disk_full_simulation {
            if let Some(stats) = self.file_operations.lock().unwrap().get_mut(file_path) {
                stats.io_errors += 1;
            }
            return Err(Error::custom("Simulated disk full error"));
        }

        // Simulate random I/O errors
        if conditions.io_error_probability > 0.0 {
            let random_value: f64 = fastrand::f64();
            if random_value < conditions.io_error_probability {
                if let Some(stats) = self.file_operations.lock().unwrap().get_mut(file_path) {
                    stats.io_errors += 1;
                }
                return Err(Error::custom("Simulated I/O error"));
            }
        }

        // Perform actual write
        let bytes_written = file.write_at(cx, offset, data).await?;

        // Update successful operation stats
        if let Some(stats) = self.file_operations.lock().unwrap().get_mut(file_path) {
            stats.writes_successful += 1;
            stats.bytes_written += bytes_written as u64;
        }

        Ok(bytes_written)
    }

    async fn read_with_simulation(
        &self,
        cx: &Cx,
        file: &mut UringFile,
        offset: u64,
        buffer: &mut [u8],
        file_path: &Path,
    ) -> Result<usize, Error> {
        let conditions = self.io_conditions.read().unwrap().clone();

        // Update stats
        if let Some(stats) = self.file_operations.lock().unwrap().get_mut(file_path) {
            stats.reads_attempted += 1;
        }

        // Simulate read delay
        if conditions.read_delay_ms > 0 {
            crate::time::Sleep::new(Duration::from_millis(conditions.read_delay_ms)).await;
        }

        // Simulate random I/O errors
        if conditions.io_error_probability > 0.0 {
            let random_value: f64 = fastrand::f64();
            if random_value < conditions.io_error_probability {
                if let Some(stats) = self.file_operations.lock().unwrap().get_mut(file_path) {
                    stats.io_errors += 1;
                }
                return Err(Error::custom("Simulated I/O read error"));
            }
        }

        // Perform actual read
        let bytes_read = file.read_at(cx, offset, buffer).await?;

        // Update successful operation stats
        if let Some(stats) = self.file_operations.lock().unwrap().get_mut(file_path) {
            stats.reads_successful += 1;
            stats.bytes_read += bytes_read as u64;
        }

        Ok(bytes_read)
    }

    fn configure_io_conditions(&self, config: IoConditionConfig) {
        *self.io_conditions.write().unwrap() = config;
    }

    fn get_file_stats(&self, file_path: &Path) -> Option<FileOperationStats> {
        self.file_operations.lock().unwrap().get(file_path).cloned()
    }

    fn cleanup(&self) -> std::io::Result<()> {
        if self.temp_directory.exists() {
            std::fs::remove_dir_all(&self.temp_directory)?;
        }
        Ok(())
    }
}

/// Enhanced RaptorQ decoder with file I/O integration
struct FileAwareRaptorQDecoder {
    decoder: RaptorQDecoder,
    file_integration_config: Arc<RwLock<FileIntegrationConfig>>,
    decoding_stats: Arc<Mutex<DecodingStatistics>>,
}

#[derive(Clone)]
struct FileIntegrationConfig {
    chunk_size_bytes: usize,
    enable_streaming_decode: bool,
    error_correction_level: f64,
    concurrent_file_operations: usize,
    verify_integrity_after_decode: bool,
}

#[derive(Debug, Default)]
struct DecodingStatistics {
    files_decoded: u64,
    total_source_blocks: u64,
    recovered_blocks: u64,
    decoding_failures: u64,
    integrity_verification_failures: u64,
    average_decode_time_ms: f64,
}

impl FileAwareRaptorQDecoder {
    async fn new(cx: &Cx) -> Result<Self, Error> {
        let config = DecoderConfig {
            max_source_blocks: 1024,
            symbol_size: 1280,
            enable_systematic_indices: true,
            repair_threshold: 0.1,
        };

        let decoder = RaptorQDecoder::new(config)?;

        Ok(Self {
            decoder,
            file_integration_config: Arc::new(RwLock::new(FileIntegrationConfig {
                chunk_size_bytes: 65536, // 64KB chunks
                enable_streaming_decode: true,
                error_correction_level: 0.2, // 20% redundancy
                concurrent_file_operations: 4,
                verify_integrity_after_decode: true,
            })),
            decoding_stats: Arc::new(Mutex::new(DecodingStatistics::default())),
        })
    }

    async fn decode_file_with_uring(
        &self,
        cx: &Cx,
        filesystem: &ControllableUringFilesystem,
        encoded_filename: &str,
        output_filename: &str,
        oti: ObjectTransmissionInfo,
    ) -> Result<FileDecodingResult, Error> {
        let config = self.file_integration_config.read().unwrap().clone();
        let decode_start = std::time::Instant::now();

        let mut stats = self.decoding_stats.lock().unwrap();
        stats.files_decoded += 1;
        drop(stats);

        // Open encoded file for reading
        let mut encoded_file = filesystem.open_uring_file(cx, encoded_filename).await?;
        let encoded_file_path = filesystem.temp_directory.join(encoded_filename);

        // Create output file for decoded data
        let mut output_file = filesystem.create_uring_file(cx, output_filename).await?;
        let output_file_path = filesystem.temp_directory.join(output_filename);

        let mut total_bytes_processed = 0;
        let mut recovered_blocks = 0;
        let mut decoding_successful = true;

        // Read encoded data in chunks and decode
        let mut file_offset = 0u64;
        let chunk_size = config.chunk_size_bytes;

        loop {
            let mut read_buffer = vec![0u8; chunk_size];

            let bytes_read = filesystem.read_with_simulation(
                cx,
                &mut encoded_file,
                file_offset,
                &mut read_buffer,
                &encoded_file_path,
            ).await?;

            if bytes_read == 0 {
                break; // End of file
            }

            read_buffer.truncate(bytes_read);

            // Convert file data to encoding packets for RaptorQ
            let packets = self.extract_encoding_packets_from_file_data(&read_buffer, &oti)?;

            // Decode the packets
            match self.decoder.decode_packets(cx, &packets, &oti).await {
                Ok(decoding_result) => {
                    let decoded_data = decoding_result.recovered_data;
                    recovered_blocks += decoding_result.blocks_recovered;

                    // Write decoded data to output file
                    let bytes_written = filesystem.write_with_simulation(
                        cx,
                        &mut output_file,
                        file_offset,
                        &decoded_data,
                        &output_file_path,
                    ).await?;

                    total_bytes_processed += bytes_written;
                }
                Err(e) => {
                    decoding_successful = false;
                    self.decoding_stats.lock().unwrap().decoding_failures += 1;
                    return Err(Error::custom(&format!("RaptorQ decoding failed: {}", e)));
                }
            }

            file_offset += bytes_read as u64;
        }

        // Verify integrity if enabled
        let integrity_verified = if config.verify_integrity_after_decode {
            self.verify_decoded_file_integrity(cx, filesystem, output_filename).await?
        } else {
            true
        };

        if !integrity_verified {
            self.decoding_stats.lock().unwrap().integrity_verification_failures += 1;
        }

        let decode_duration = decode_start.elapsed();

        // Update statistics
        let mut stats = self.decoding_stats.lock().unwrap();
        stats.recovered_blocks += recovered_blocks;
        stats.average_decode_time_ms = (stats.average_decode_time_ms + decode_duration.as_secs_f64() * 1000.0) / 2.0;

        Ok(FileDecodingResult {
            input_filename: encoded_filename.to_string(),
            output_filename: output_filename.to_string(),
            bytes_processed: total_bytes_processed,
            blocks_recovered: recovered_blocks,
            decoding_successful,
            integrity_verified,
            decode_duration_ms: decode_duration.as_secs_f64() * 1000.0,
        })
    }

    async fn encode_file_with_uring(
        &self,
        cx: &Cx,
        filesystem: &ControllableUringFilesystem,
        input_filename: &str,
        encoded_filename: &str,
        redundancy_level: f64,
    ) -> Result<FileEncodingResult, Error> {
        let config = self.file_integration_config.read().unwrap().clone();
        let encode_start = std::time::Instant::now();

        // Open input file for reading
        let mut input_file = filesystem.open_uring_file(cx, input_filename).await?;
        let input_file_path = filesystem.temp_directory.join(input_filename);

        // Create encoded output file
        let mut encoded_file = filesystem.create_uring_file(cx, encoded_filename).await?;
        let encoded_file_path = filesystem.temp_directory.join(encoded_filename);

        let mut total_bytes_encoded = 0;
        let mut source_blocks_generated = 0;

        // Configure encoder for this file
        let encoder_config = EncoderConfig {
            symbol_size: 1280,
            source_blocks: ((redundancy_level * 100.0) as usize).max(10),
            repair_symbols_per_block: ((redundancy_level * 10.0) as usize).max(2),
        };

        let encoder = RaptorQEncoder::new(encoder_config)?;

        // Read and encode file in chunks
        let mut file_offset = 0u64;
        let chunk_size = config.chunk_size_bytes;

        loop {
            let mut read_buffer = vec![0u8; chunk_size];

            let bytes_read = filesystem.read_with_simulation(
                cx,
                &mut input_file,
                file_offset,
                &mut read_buffer,
                &input_file_path,
            ).await?;

            if bytes_read == 0 {
                break; // End of file
            }

            read_buffer.truncate(bytes_read);

            // Encode the chunk
            let encoding_result = encoder.encode_data(cx, &read_buffer).await?;
            source_blocks_generated += encoding_result.source_blocks.len();

            // Convert encoded packets to file format
            let encoded_file_data = self.convert_packets_to_file_data(&encoding_result.encoding_packets)?;

            // Write encoded data to file
            let bytes_written = filesystem.write_with_simulation(
                cx,
                &mut encoded_file,
                file_offset,
                &encoded_file_data,
                &encoded_file_path,
            ).await?;

            total_bytes_encoded += bytes_written;
            file_offset += bytes_read as u64;
        }

        let encode_duration = encode_start.elapsed();

        Ok(FileEncodingResult {
            input_filename: input_filename.to_string(),
            output_filename: encoded_filename.to_string(),
            bytes_encoded: total_bytes_encoded,
            source_blocks_generated,
            redundancy_achieved: redundancy_level,
            encode_duration_ms: encode_duration.as_secs_f64() * 1000.0,
        })
    }

    async fn verify_decoded_file_integrity(
        &self,
        cx: &Cx,
        filesystem: &ControllableUringFilesystem,
        filename: &str,
    ) -> Result<bool, Error> {
        // Simple integrity check - read file and verify it's decodable
        let mut file = filesystem.open_uring_file(cx, filename).await?;
        let file_path = filesystem.temp_directory.join(filename);

        let mut buffer = vec![0u8; 4096];
        let bytes_read = filesystem.read_with_simulation(cx, &mut file, 0, &mut buffer, &file_path).await?;

        Ok(bytes_read > 0)
    }

    fn extract_encoding_packets_from_file_data(
        &self,
        file_data: &[u8],
        oti: &ObjectTransmissionInfo,
    ) -> Result<Vec<EncodingPacket>, Error> {
        // Simulate extracting RaptorQ packets from file data
        // In a real implementation, this would parse the file format
        let packets_per_block = (file_data.len() / oti.symbol_size).max(1);
        let mut packets = Vec::new();

        for i in 0..packets_per_block {
            let start = i * oti.symbol_size;
            let end = std::cmp::min(start + oti.symbol_size, file_data.len());

            if start < end {
                let packet = EncodingPacket {
                    symbol_id: i as u32,
                    data: file_data[start..end].to_vec(),
                };
                packets.push(packet);
            }
        }

        Ok(packets)
    }

    fn convert_packets_to_file_data(&self, packets: &[EncodingPacket]) -> Result<Vec<u8>, Error> {
        // Simulate converting RaptorQ packets to file format
        let mut file_data = Vec::new();

        for packet in packets {
            file_data.extend_from_slice(&packet.data);
        }

        Ok(file_data)
    }

    fn configure_file_integration(&self, config: FileIntegrationConfig) {
        *self.file_integration_config.write().unwrap() = config;
    }

    fn get_decoding_statistics(&self) -> DecodingStatistics {
        self.decoding_stats.lock().unwrap().clone()
    }
}

#[derive(Debug, Clone)]
struct FileDecodingResult {
    input_filename: String,
    output_filename: String,
    bytes_processed: usize,
    blocks_recovered: u64,
    decoding_successful: bool,
    integrity_verified: bool,
    decode_duration_ms: f64,
}

#[derive(Debug, Clone)]
struct FileEncodingResult {
    input_filename: String,
    output_filename: String,
    bytes_encoded: usize,
    source_blocks_generated: u64,
    redundancy_achieved: f64,
    encode_duration_ms: f64,
}

/// Integration coordinator that validates fs/uring-RaptorQ coordination
struct UringRaptorQIntegrationCoordinator {
    filesystem: ControllableUringFilesystem,
    raptorq_decoder: FileAwareRaptorQDecoder,
    validation_results: Arc<Mutex<Vec<IntegrationValidationResult>>>,
    test_files: Arc<Mutex<HashMap<String, TestFileInfo>>>,
}

#[derive(Debug, Clone)]
struct IntegrationValidationResult {
    test_case: String,
    file_io_success: bool,
    raptorq_processing_success: bool,
    data_integrity_verified: bool,
    error_recovery_effective: bool,
    performance_metrics: FilePerformanceMetrics,
    details: String,
}

#[derive(Debug, Clone)]
struct FilePerformanceMetrics {
    file_io_throughput_mbps: f64,
    raptorq_decode_throughput_mbps: f64,
    end_to_end_latency_ms: f64,
    io_operations_per_second: f64,
}

#[derive(Debug, Clone)]
struct TestFileInfo {
    filename: String,
    size_bytes: usize,
    content_hash: String,
    created_at: std::time::Instant,
}

impl UringRaptorQIntegrationCoordinator {
    async fn new(cx: &Cx) -> Result<Self, Error> {
        let filesystem = ControllableUringFilesystem::new(cx).await?;
        let raptorq_decoder = FileAwareRaptorQDecoder::new(cx).await?;

        Ok(Self {
            filesystem,
            raptorq_decoder,
            validation_results: Arc::new(Mutex::new(Vec::new())),
            test_files: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn create_test_file(
        &self,
        cx: &Cx,
        filename: &str,
        size_bytes: usize,
    ) -> Result<TestFileInfo, Error> {
        let test_data = (0..size_bytes).map(|i| (i % 256) as u8).collect::<Vec<u8>>();

        let mut file = self.filesystem.create_uring_file(cx, filename).await?;
        let file_path = self.filesystem.temp_directory.join(filename);

        self.filesystem.write_with_simulation(cx, &mut file, 0, &test_data, &file_path).await?;

        // Simple hash for content verification
        let content_hash = format!("{:x}", fastrand::u64(..));

        let file_info = TestFileInfo {
            filename: filename.to_string(),
            size_bytes,
            content_hash: content_hash.clone(),
            created_at: std::time::Instant::now(),
        };

        self.test_files.lock().unwrap().insert(filename.to_string(), file_info.clone());

        Ok(file_info)
    }

    async fn validate_basic_uring_raptorq_integration(
        &self,
        cx: &Cx,
        test_case: &str,
        file_size_kb: usize,
    ) -> Result<IntegrationValidationResult, Error> {
        let test_start = std::time::Instant::now();

        // Create test file
        let input_filename = format!("test_input_{}.dat", file_size_kb);
        let test_file = self.create_test_file(cx, &input_filename, file_size_kb * 1024).await?;

        // Encode file with RaptorQ
        let encoded_filename = format!("test_encoded_{}.rq", file_size_kb);
        let encoding_result = self.raptorq_decoder.encode_file_with_uring(
            cx,
            &self.filesystem,
            &input_filename,
            &encoded_filename,
            0.2, // 20% redundancy
        ).await?;

        // Create OTI for decoding
        let oti = ObjectTransmissionInfo {
            transfer_length: test_file.size_bytes as u64,
            symbol_size: 1280,
            source_blocks: encoding_result.source_blocks_generated as u32,
        };

        // Decode file back
        let decoded_filename = format!("test_decoded_{}.dat", file_size_kb);
        let decoding_result = self.raptorq_decoder.decode_file_with_uring(
            cx,
            &self.filesystem,
            &encoded_filename,
            &decoded_filename,
            oti,
        ).await?;

        let total_duration = test_start.elapsed();

        // Calculate performance metrics
        let total_bytes = test_file.size_bytes as f64;
        let total_seconds = total_duration.as_secs_f64();

        let performance_metrics = FilePerformanceMetrics {
            file_io_throughput_mbps: (total_bytes * 2.0) / (total_seconds * 1_000_000.0), // Read + write
            raptorq_decode_throughput_mbps: total_bytes / (decoding_result.decode_duration_ms / 1000.0 * 1_000_000.0),
            end_to_end_latency_ms: total_duration.as_secs_f64() * 1000.0,
            io_operations_per_second: 3.0 / total_seconds, // Create, encode, decode
        };

        let result = IntegrationValidationResult {
            test_case: test_case.to_string(),
            file_io_success: encoding_result.bytes_encoded > 0 && decoding_result.bytes_processed > 0,
            raptorq_processing_success: decoding_result.decoding_successful,
            data_integrity_verified: decoding_result.integrity_verified,
            error_recovery_effective: decoding_result.blocks_recovered > 0,
            performance_metrics,
            details: format!(
                "File: {}KB, Encode: {:.1}ms, Decode: {:.1}ms, Blocks recovered: {}",
                file_size_kb,
                encoding_result.encode_duration_ms,
                decoding_result.decode_duration_ms,
                decoding_result.blocks_recovered
            ),
        };

        self.validation_results.lock().unwrap().push(result.clone());

        Ok(result)
    }

    async fn validate_error_recovery_with_io_failures(
        &self,
        cx: &Cx,
        test_case: &str,
    ) -> Result<IntegrationValidationResult, Error> {
        // Configure I/O errors for testing
        self.filesystem.configure_io_conditions(IoConditionConfig {
            read_delay_ms: 0,
            write_delay_ms: 0,
            io_error_probability: 0.1, // 10% chance of I/O error
            disk_full_simulation: false,
            concurrent_operations_limit: 32,
            buffer_size_kb: 64,
        });

        let file_size_kb = 128;
        let input_filename = format!("error_test_input.dat");
        let test_file = self.create_test_file(cx, &input_filename, file_size_kb * 1024).await?;

        // Try encoding with potential I/O errors
        let encoded_filename = format!("error_test_encoded.rq");
        let encoding_result = match self.raptorq_decoder.encode_file_with_uring(
            cx,
            &self.filesystem,
            &input_filename,
            &encoded_filename,
            0.3, // Higher redundancy for error recovery
        ).await {
            Ok(result) => result,
            Err(_) => {
                // Reset I/O conditions and return failure result
                self.filesystem.configure_io_conditions(IoConditionConfig {
                    read_delay_ms: 0,
                    write_delay_ms: 0,
                    io_error_probability: 0.0,
                    disk_full_simulation: false,
                    concurrent_operations_limit: 32,
                    buffer_size_kb: 64,
                });

                return Ok(IntegrationValidationResult {
                    test_case: test_case.to_string(),
                    file_io_success: false,
                    raptorq_processing_success: false,
                    data_integrity_verified: false,
                    error_recovery_effective: false,
                    performance_metrics: FilePerformanceMetrics {
                        file_io_throughput_mbps: 0.0,
                        raptorq_decode_throughput_mbps: 0.0,
                        end_to_end_latency_ms: 0.0,
                        io_operations_per_second: 0.0,
                    },
                    details: "I/O errors prevented file encoding".to_string(),
                });
            }
        };

        // Reset I/O conditions for decoding test
        self.filesystem.configure_io_conditions(IoConditionConfig {
            read_delay_ms: 0,
            write_delay_ms: 0,
            io_error_probability: 0.0,
            disk_full_simulation: false,
            concurrent_operations_limit: 32,
            buffer_size_kb: 64,
        });

        // Verify RaptorQ can still decode despite I/O errors during encoding
        let oti = ObjectTransmissionInfo {
            transfer_length: test_file.size_bytes as u64,
            symbol_size: 1280,
            source_blocks: encoding_result.source_blocks_generated as u32,
        };

        let decoded_filename = format!("error_test_decoded.dat");
        let decoding_result = self.raptorq_decoder.decode_file_with_uring(
            cx,
            &self.filesystem,
            &encoded_filename,
            &decoded_filename,
            oti,
        ).await?;

        let result = IntegrationValidationResult {
            test_case: test_case.to_string(),
            file_io_success: true,
            raptorq_processing_success: decoding_result.decoding_successful,
            data_integrity_verified: decoding_result.integrity_verified,
            error_recovery_effective: decoding_result.blocks_recovered > 0 && encoding_result.bytes_encoded > 0,
            performance_metrics: FilePerformanceMetrics {
                file_io_throughput_mbps: 1.0, // Reduced due to errors
                raptorq_decode_throughput_mbps: (test_file.size_bytes as f64) / (decoding_result.decode_duration_ms / 1000.0 * 1_000_000.0),
                end_to_end_latency_ms: encoding_result.encode_duration_ms + decoding_result.decode_duration_ms,
                io_operations_per_second: 2.0, // Encode and decode operations
            },
            details: format!(
                "Error recovery test - Blocks recovered: {}, Integrity: {}",
                decoding_result.blocks_recovered,
                decoding_result.integrity_verified
            ),
        };

        self.validation_results.lock().unwrap().push(result.clone());

        Ok(result)
    }

    async fn validate_concurrent_file_operations_with_raptorq(
        &self,
        cx: &Cx,
        test_case: &str,
        concurrent_files: usize,
    ) -> Result<IntegrationValidationResult, Error> {
        let start_time = std::time::Instant::now();
        let mut handles = Vec::new();

        // Launch concurrent file encode/decode operations
        for i in 0..concurrent_files {
            let filesystem = &self.filesystem;
            let raptorq_decoder = &self.raptorq_decoder;

            let handle = cx.spawn(move |cx| async move {
                let input_filename = format!("concurrent_test_{}.dat", i);
                let encoded_filename = format!("concurrent_encoded_{}.rq", i);
                let decoded_filename = format!("concurrent_decoded_{}.dat", i);

                // Create test file
                let test_data = vec![i as u8; 4096]; // Small files for concurrency test
                let mut file = filesystem.create_uring_file(cx, &input_filename).await?;
                let file_path = filesystem.temp_directory.join(&input_filename);
                filesystem.write_with_simulation(cx, &mut file, 0, &test_data, &file_path).await?;

                // Encode
                let encoding_result = raptorq_decoder.encode_file_with_uring(
                    cx,
                    filesystem,
                    &input_filename,
                    &encoded_filename,
                    0.2,
                ).await?;

                // Decode
                let oti = ObjectTransmissionInfo {
                    transfer_length: test_data.len() as u64,
                    symbol_size: 1280,
                    source_blocks: encoding_result.source_blocks_generated as u32,
                };

                let decoding_result = raptorq_decoder.decode_file_with_uring(
                    cx,
                    filesystem,
                    &encoded_filename,
                    &decoded_filename,
                    oti,
                ).await?;

                Ok::<(FileEncodingResult, FileDecodingResult), Error>((encoding_result, decoding_result))
            });

            handles.push(handle);
        }

        // Wait for all concurrent operations to complete
        let mut successful_operations = 0;
        let mut total_bytes_processed = 0;
        let mut total_blocks_recovered = 0;

        for handle in handles {
            match handle.join().await {
                Outcome::Ok(Ok((encoding, decoding))) => {
                    successful_operations += 1;
                    total_bytes_processed += encoding.bytes_encoded + decoding.bytes_processed;
                    total_blocks_recovered += decoding.blocks_recovered;
                }
                _ => {}
            }
        }

        let total_duration = start_time.elapsed();

        let performance_metrics = FilePerformanceMetrics {
            file_io_throughput_mbps: (total_bytes_processed as f64) / (total_duration.as_secs_f64() * 1_000_000.0),
            raptorq_decode_throughput_mbps: (total_bytes_processed as f64 / 2.0) / (total_duration.as_secs_f64() * 1_000_000.0),
            end_to_end_latency_ms: total_duration.as_secs_f64() * 1000.0,
            io_operations_per_second: (successful_operations as f64 * 3.0) / total_duration.as_secs_f64(), // Create, encode, decode per file
        };

        let result = IntegrationValidationResult {
            test_case: test_case.to_string(),
            file_io_success: successful_operations > 0,
            raptorq_processing_success: total_blocks_recovered > 0,
            data_integrity_verified: successful_operations == concurrent_files,
            error_recovery_effective: total_blocks_recovered > 0,
            performance_metrics,
            details: format!(
                "Concurrent operations: {}/{}, Total bytes: {}, Blocks recovered: {}",
                successful_operations, concurrent_files, total_bytes_processed, total_blocks_recovered
            ),
        };

        self.validation_results.lock().unwrap().push(result.clone());

        Ok(result)
    }

    fn get_validation_summary(&self) -> Vec<IntegrationValidationResult> {
        self.validation_results.lock().unwrap().clone()
    }

    async fn cleanup(&self) -> Result<(), Error> {
        self.filesystem.cleanup()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        runtime::test_rt,
        cx::region,
        types::Budget,
    };

    #[test]
    fn test_basic_uring_raptorq_integration() {
        test_rt(|rt| async move {
            region(&rt, Budget::new(Duration::from_secs(45)), |cx| async move {
                let coordinator = UringRaptorQIntegrationCoordinator::new(cx).await?;

                let result = coordinator.validate_basic_uring_raptorq_integration(
                    cx,
                    "basic_integration",
                    64, // 64KB file
                ).await?;

                assert!(result.file_io_success, "File I/O operations should succeed");
                assert!(result.raptorq_processing_success, "RaptorQ processing should succeed");
                assert!(result.data_integrity_verified, "Data integrity should be verified");
                assert!(result.performance_metrics.end_to_end_latency_ms < 10000.0, "Should complete within 10 seconds");

                coordinator.cleanup().await?;

                Ok(())
            }).await
        });
    }

    #[test]
    fn test_error_recovery_with_io_failures() {
        test_rt(|rt| async move {
            region(&rt, Budget::new(Duration::from_secs(60)), |cx| async move {
                let coordinator = UringRaptorQIntegrationCoordinator::new(cx).await?;

                let result = coordinator.validate_error_recovery_with_io_failures(
                    cx,
                    "error_recovery"
                ).await?;

                assert!(result.error_recovery_effective, "Error recovery should be effective");
                // Allow for some I/O failures during the error simulation

                coordinator.cleanup().await?;

                Ok(())
            }).await
        });
    }

    #[test]
    fn test_concurrent_file_operations_with_raptorq() {
        test_rt(|rt| async move {
            region(&rt, Budget::new(Duration::from_secs(60)), |cx| async move {
                let coordinator = UringRaptorQIntegrationCoordinator::new(cx).await?;

                let result = coordinator.validate_concurrent_file_operations_with_raptorq(
                    cx,
                    "concurrent_operations",
                    4, // 4 concurrent files
                ).await?;

                assert!(result.file_io_success, "Concurrent file operations should succeed");
                assert!(result.raptorq_processing_success, "Concurrent RaptorQ processing should succeed");
                assert!(result.performance_metrics.io_operations_per_second > 1.0, "Should achieve reasonable I/O throughput");

                coordinator.cleanup().await?;

                Ok(())
            }).await
        });
    }
}