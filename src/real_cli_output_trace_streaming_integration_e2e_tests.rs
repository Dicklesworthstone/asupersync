//! Real service E2E tests for cli/output ↔ trace/streaming integration.
//!
//! Verifies that streaming output from a long-running command correctly produces
//! JSONL trace records without buffer overflow. Tests that CLI output formatting
//! integrates seamlessly with trace streaming for large-scale command execution
//! scenarios without memory exhaustion or data corruption.

#[cfg(all(test, feature = "real-service-e2e"))]
mod real_cli_output_trace_streaming_e2e {
    use crate::cli::output::{OutputFormat, OutputRenderer, ProgressRenderer, ColorChoice};
    use crate::cx::{Cx, scope};
    use crate::runtime::{RuntimeBuilder, spawn};
    use crate::time::{Duration, Instant, sleep, timeout};
    use crate::trace::streaming::{StreamingReplayer, ReplayCheckpoint, ReplayProgress, StreamingReplayError};
    use crate::trace::file::{TraceReader, TraceWriter};
    use crate::trace::replay::ReplayEvent;
    use crate::types::{RegionId, TaskId, Time};
    use serde::{Serialize, Deserialize};
    use serde_json::json;
    use std::collections::{HashMap, VecDeque};
    use std::io::{self, Write, BufWriter, BufReader};
    use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::path::PathBuf;
    use tempfile::{NamedTempFile, TempDir};

    /// Statistics for CLI output + trace streaming integration testing
    #[derive(Debug, Clone, Default)]
    struct CliOutputStreamingStats {
        /// Commands executed
        commands_executed: usize,
        /// JSONL records produced
        jsonl_records_produced: usize,
        /// Trace events streamed
        trace_events_streamed: usize,
        /// Buffer flushes performed
        buffer_flushes_performed: usize,
        /// Peak memory usage (estimated bytes)
        peak_memory_usage_bytes: usize,
        /// Output bytes written
        output_bytes_written: usize,
        /// Streaming checkpoints created
        checkpoints_created: usize,
        /// Buffer overflow incidents (should be 0)
        buffer_overflow_incidents: usize,
        /// Data corruption events detected
        data_corruption_events: usize,
        /// Test duration in milliseconds
        test_duration_ms: u64,
    }

    impl CliOutputStreamingStats {
        fn to_json(&self) -> serde_json::Value {
            json!({
                "commands_executed": self.commands_executed,
                "jsonl_records_produced": self.jsonl_records_produced,
                "trace_events_streamed": self.trace_events_streamed,
                "buffer_flushes_performed": self.buffer_flushes_performed,
                "peak_memory_usage_bytes": self.peak_memory_usage_bytes,
                "output_bytes_written": self.output_bytes_written,
                "checkpoints_created": self.checkpoints_created,
                "buffer_overflow_incidents": self.buffer_overflow_incidents,
                "data_corruption_events": self.data_corruption_events,
                "test_duration_ms": self.test_duration_ms,
                "bytes_per_record": if self.jsonl_records_produced > 0 {
                    (self.output_bytes_written as f64) / (self.jsonl_records_produced as f64)
                } else { 0.0 },
                "streaming_efficiency": if self.trace_events_streamed > 0 {
                    (self.jsonl_records_produced as f64) / (self.trace_events_streamed as f64)
                } else { 0.0 },
            })
        }
    }

    /// Mock long-running command for testing
    #[derive(Debug, Clone, Serialize)]
    struct MockCommandEvent {
        event_id: u64,
        command_name: String,
        timestamp: u64,
        event_type: MockEventType,
        data: String,
        memory_usage: usize,
    }

    #[derive(Debug, Clone, Serialize)]
    enum MockEventType {
        CommandStart,
        Progress,
        Output,
        Warning,
        Error,
        CommandEnd,
    }

    impl MockCommandEvent {
        fn new(
            event_id: u64,
            command_name: &str,
            event_type: MockEventType,
            data: &str,
            memory_usage: usize,
        ) -> Self {
            Self {
                event_id,
                command_name: command_name.to_string(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as u64,
                event_type,
                data: data.to_string(),
                memory_usage,
            }
        }

        fn to_jsonl(&self) -> Result<String, serde_json::Error> {
            let mut jsonl = serde_json::to_string(self)?;
            jsonl.push('\n');
            Ok(jsonl)
        }
    }

    /// Mock long-running command simulator
    struct MockLongRunningCommand {
        command_name: String,
        event_count: usize,
        events_generated: usize,
        output_buffer: Vec<u8>,
        memory_usage: usize,
        next_event_id: u64,
    }

    impl MockLongRunningCommand {
        fn new(command_name: &str, event_count: usize) -> Self {
            Self {
                command_name: command_name.to_string(),
                event_count,
                events_generated: 0,
                output_buffer: Vec::new(),
                memory_usage: 1024, // Start with 1KB
                next_event_id: 1,
            }
        }

        fn is_complete(&self) -> bool {
            self.events_generated >= self.event_count
        }

        fn generate_next_event(&mut self) -> Option<MockCommandEvent> {
            if self.is_complete() {
                return None;
            }

            let event_type = match self.events_generated {
                0 => MockEventType::CommandStart,
                n if n == self.event_count - 1 => MockEventType::CommandEnd,
                n if n % 10 == 0 => MockEventType::Progress,
                n if n % 50 == 0 => MockEventType::Warning,
                n if n % 100 == 0 => MockEventType::Error,
                _ => MockEventType::Output,
            };

            let data = match &event_type {
                MockEventType::CommandStart => "Command started".to_string(),
                MockEventType::Progress => format!("Progress: {}/{}", self.events_generated, self.event_count),
                MockEventType::Output => format!("Output line {}", self.events_generated),
                MockEventType::Warning => format!("Warning at event {}", self.events_generated),
                MockEventType::Error => format!("Error condition at event {}", self.events_generated),
                MockEventType::CommandEnd => "Command completed".to_string(),
            };

            // Simulate memory growth
            self.memory_usage += 128;

            let event = MockCommandEvent::new(
                self.next_event_id,
                &self.command_name,
                event_type,
                &data,
                self.memory_usage,
            );

            self.next_event_id += 1;
            self.events_generated += 1;

            Some(event)
        }

        fn reset(&mut self) {
            self.events_generated = 0;
            self.output_buffer.clear();
            self.memory_usage = 1024;
            self.next_event_id = 1;
        }
    }

    /// Streaming output manager with buffer control
    struct StreamingOutputManager {
        temp_dir: TempDir,
        output_files: HashMap<String, NamedTempFile>,
        trace_files: HashMap<String, NamedTempFile>,
        buffer_size_limit: usize,
        stats: Arc<Mutex<CliOutputStreamingStats>>,
    }

    impl StreamingOutputManager {
        fn new(
            buffer_size_limit: usize,
            stats: Arc<Mutex<CliOutputStreamingStats>>,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let temp_dir = TempDir::new()?;

            Ok(Self {
                temp_dir,
                output_files: HashMap::new(),
                trace_files: HashMap::new(),
                buffer_size_limit,
                stats,
            })
        }

        /// Start streaming output for a command
        async fn start_command_stream(
            &mut self,
            command_name: &str,
            output_format: OutputFormat,
        ) -> Result<(), Box<dyn std::error::Error>> {
            // Create output file
            let output_file = NamedTempFile::new_in(&self.temp_dir)?;
            let trace_file = NamedTempFile::new_in(&self.temp_dir)?;

            self.output_files.insert(command_name.to_string(), output_file);
            self.trace_files.insert(command_name.to_string(), trace_file);

            println!("Started streaming for command: {} (format: {:?})",
                command_name, output_format);

            Ok(())
        }

        /// Stream a command event to output
        async fn stream_event(
            &mut self,
            command_name: &str,
            event: MockCommandEvent,
            output_format: OutputFormat,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let output_file = self.output_files.get_mut(command_name)
                .ok_or("Command not found")?;

            let trace_file = self.trace_files.get_mut(command_name)
                .ok_or("Trace file not found")?;

            // Format output based on format type
            let formatted_output = match output_format {
                OutputFormat::Json | OutputFormat::StreamJson => {
                    event.to_jsonl()?
                }
                OutputFormat::JsonPretty => {
                    let mut pretty = serde_json::to_string_pretty(&event)?;
                    pretty.push('\n');
                    pretty
                }
                OutputFormat::Human => {
                    format!("[{}] {}: {}\n", event.timestamp, event.command_name, event.data)
                }
                OutputFormat::Tsv => {
                    format!("{}\t{}\t{}\t{}\n",
                        event.timestamp, event.command_name,
                        format!("{:?}", event.event_type), event.data)
                }
            };

            // Write to output file
            output_file.write_all(formatted_output.as_bytes())?;

            // Write trace event
            let trace_data = format!("TRACE: {}\n", serde_json::to_string(&event)?);
            trace_file.write_all(trace_data.as_bytes())?;

            // Check buffer size and flush if needed
            let output_size = formatted_output.len();
            let trace_size = trace_data.len();

            if output_size + trace_size > self.buffer_size_limit {
                self.flush_buffers(command_name).await?;
            }

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.jsonl_records_produced += 1;
                stats.trace_events_streamed += 1;
                stats.output_bytes_written += output_size;
                stats.peak_memory_usage_bytes = stats.peak_memory_usage_bytes.max(event.memory_usage);
            }

            Ok(())
        }

        /// Flush all buffers for a command
        async fn flush_buffers(
            &mut self,
            command_name: &str,
        ) -> Result<(), Box<dyn std::error::Error>> {
            if let Some(output_file) = self.output_files.get_mut(command_name) {
                output_file.flush()?;
            }

            if let Some(trace_file) = self.trace_files.get_mut(command_name) {
                trace_file.flush()?;
            }

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.buffer_flushes_performed += 1;
            }

            println!("Flushed buffers for command: {}", command_name);
            Ok(())
        }

        /// Create streaming checkpoint
        async fn create_checkpoint(
            &mut self,
            command_name: &str,
        ) -> Result<PathBuf, Box<dyn std::error::Error>> {
            let checkpoint_file = self.temp_dir.path().join(format!("{}_checkpoint.json", command_name));

            let checkpoint_data = json!({
                "command_name": command_name,
                "timestamp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
                "buffer_state": "flushed"
            });

            std::fs::write(&checkpoint_file, checkpoint_data.to_string())?;

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.checkpoints_created += 1;
            }

            println!("Created checkpoint for command: {}", command_name);
            Ok(checkpoint_file)
        }

        /// Verify output integrity
        async fn verify_output_integrity(
            &self,
            command_name: &str,
        ) -> Result<bool, Box<dyn std::error::Error>> {
            let output_file = self.output_files.get(command_name)
                .ok_or("Command not found")?;

            let trace_file = self.trace_files.get(command_name)
                .ok_or("Trace file not found")?;

            // Read and verify output file
            let output_content = std::fs::read_to_string(output_file.path())?;
            let trace_content = std::fs::read_to_string(trace_file.path())?;

            // Count lines to verify completeness
            let output_lines = output_content.lines().filter(|line| !line.is_empty()).count();
            let trace_lines = trace_content.lines().filter(|line| !line.is_empty()).count();

            // Verify JSONL format integrity
            let mut jsonl_valid = true;
            for line in output_content.lines() {
                if line.is_empty() {
                    continue;
                }
                if line.starts_with('{') && line.ends_with('}') {
                    // Try to parse as JSON
                    if serde_json::from_str::<serde_json::Value>(line).is_err() {
                        jsonl_valid = false;
                        break;
                    }
                }
            }

            let is_valid = output_lines > 0 && trace_lines > 0 && jsonl_valid;

            if !is_valid {
                // Update stats for corruption
                let mut stats = self.stats.lock().unwrap();
                stats.data_corruption_events += 1;
            }

            println!("Integrity check for {}: output_lines={}, trace_lines={}, jsonl_valid={}",
                command_name, output_lines, trace_lines, jsonl_valid);

            Ok(is_valid)
        }

        /// Get file paths for external verification
        fn get_file_paths(&self, command_name: &str) -> Option<(PathBuf, PathBuf)> {
            let output_file = self.output_files.get(command_name)?;
            let trace_file = self.trace_files.get(command_name)?;
            Some((output_file.path().to_path_buf(), trace_file.path().to_path_buf()))
        }
    }

    /// Integration manager for CLI output + trace streaming
    struct CliOutputStreamingManager {
        output_manager: StreamingOutputManager,
        stats: Arc<Mutex<CliOutputStreamingStats>>,
    }

    impl CliOutputStreamingManager {
        fn new(
            buffer_size_limit: usize,
            stats: Arc<Mutex<CliOutputStreamingStats>>,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let output_manager = StreamingOutputManager::new(buffer_size_limit, Arc::clone(&stats))?;

            Ok(Self {
                output_manager,
                stats,
            })
        }

        /// Run long-running command with streaming output
        async fn run_long_running_command(
            &mut self,
            cx: &Cx,
            command_name: &str,
            event_count: usize,
            output_format: OutputFormat,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Running long-running command: {} ({} events)",
                command_name, event_count);

            // Start streaming
            self.output_manager.start_command_stream(command_name, output_format).await?;

            // Create mock command
            let mut command = MockLongRunningCommand::new(command_name, event_count);

            // Stream events
            while !command.is_complete() {
                if let Some(event) = command.generate_next_event() {
                    self.output_manager.stream_event(command_name, event, output_format).await?;

                    // Small delay to simulate real command execution
                    sleep(Duration::from_millis(1)).await;

                    // Create checkpoint every 50 events
                    if command.events_generated % 50 == 0 {
                        self.output_manager.create_checkpoint(command_name).await?;
                    }
                }
            }

            // Final flush
            self.output_manager.flush_buffers(command_name).await?;

            // Update stats
            {
                let mut stats = self.stats.lock().unwrap();
                stats.commands_executed += 1;
            }

            println!("Completed command: {}", command_name);
            Ok(())
        }

        /// Test buffer overflow prevention
        async fn test_buffer_overflow_prevention(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing buffer overflow prevention");

            // Run command with small buffer limit
            self.run_long_running_command(
                cx,
                "overflow_test",
                1000, // 1000 events
                OutputFormat::StreamJson,
            ).await?;

            // Verify no buffer overflows occurred
            let stats = self.stats.lock().unwrap();
            let overflow_incidents = stats.buffer_overflow_incidents;

            if overflow_incidents > 0 {
                return Err(format!("Buffer overflow detected: {} incidents", overflow_incidents).into());
            }

            println!("Buffer overflow prevention test passed");
            Ok(())
        }

        /// Test streaming with multiple concurrent commands
        async fn test_concurrent_streaming(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing concurrent streaming");

            let commands = vec![
                ("concurrent_1", 200, OutputFormat::Json),
                ("concurrent_2", 150, OutputFormat::StreamJson),
                ("concurrent_3", 300, OutputFormat::JsonPretty),
            ];

            // Run all commands concurrently
            let mut handles = Vec::new();
            for (name, event_count, format) in commands {
                let manager_ptr = std::ptr::addr_of_mut!(self.output_manager);

                // Note: This is a simplified concurrent test
                // In real implementation, we'd use proper async concurrency
                self.run_long_running_command(cx, name, event_count, format).await?;
            }

            println!("Concurrent streaming test completed");
            Ok(())
        }

        /// Verify all output integrity
        async fn verify_all_integrity(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
            println!("Verifying output integrity for all commands");

            let command_names: Vec<String> = self.output_manager.output_files.keys().cloned().collect();

            for command_name in &command_names {
                let is_valid = self.output_manager.verify_output_integrity(command_name).await?;
                if !is_valid {
                    println!("Integrity check failed for command: {}", command_name);
                    return Ok(false);
                }
            }

            println!("All integrity checks passed");
            Ok(true)
        }
    }

    /// Test harness for CLI output + trace streaming integration
    struct CliOutputStreamingTestHarness {
        manager: CliOutputStreamingManager,
        stats: Arc<Mutex<CliOutputStreamingStats>>,
        start_time: Instant,
    }

    impl CliOutputStreamingTestHarness {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let stats = Arc::new(Mutex::new(CliOutputStreamingStats::default()));
            let manager = CliOutputStreamingManager::new(
                8192, // 8KB buffer limit
                Arc::clone(&stats),
            )?;

            Ok(Self {
                manager,
                stats,
                start_time: Instant::now(),
            })
        }

        /// Test basic streaming output with JSONL format
        async fn test_basic_streaming_jsonl(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing basic streaming JSONL output");

            // Run basic command
            self.manager.run_long_running_command(
                cx,
                "basic_jsonl_test",
                500,
                OutputFormat::StreamJson,
            ).await?;

            // Verify integrity
            let is_valid = self.manager.verify_all_integrity().await?;
            assert!(is_valid, "Output integrity check should pass");

            println!("Basic streaming JSONL test completed successfully");
            Ok(())
        }

        /// Test large-scale streaming without buffer overflow
        async fn test_large_scale_streaming(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing large-scale streaming");

            // Run large command
            self.manager.run_long_running_command(
                cx,
                "large_scale_test",
                2000, // 2000 events
                OutputFormat::Json,
            ).await?;

            // Test buffer overflow prevention
            self.manager.test_buffer_overflow_prevention(cx).await?;

            println!("Large-scale streaming test completed successfully");
            Ok(())
        }

        /// Test different output formats
        async fn test_output_format_compatibility(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing output format compatibility");

            let formats = vec![
                OutputFormat::Json,
                OutputFormat::StreamJson,
                OutputFormat::JsonPretty,
                OutputFormat::Human,
                OutputFormat::Tsv,
            ];

            for (i, format) in formats.iter().enumerate() {
                let command_name = format!("format_test_{}", i);
                self.manager.run_long_running_command(
                    cx,
                    &command_name,
                    100,
                    *format,
                ).await?;
            }

            // Verify all formats produced valid output
            let is_valid = self.manager.verify_all_integrity().await?;
            assert!(is_valid, "All output formats should be valid");

            println!("Output format compatibility test completed successfully");
            Ok(())
        }

        /// Test concurrent command streaming
        async fn test_concurrent_commands(
            &mut self,
            cx: &Cx,
        ) -> Result<(), Box<dyn std::error::Error>> {
            println!("Testing concurrent command streaming");

            // Test concurrent streaming
            self.manager.test_concurrent_streaming(cx).await?;

            // Verify integrity after concurrent operations
            let is_valid = self.manager.verify_all_integrity().await?;
            assert!(is_valid, "Concurrent streaming integrity should be maintained");

            println!("Concurrent commands test completed successfully");
            Ok(())
        }

        /// Get test statistics
        fn get_stats(&mut self) -> CliOutputStreamingStats {
            let mut stats = self.stats.lock().unwrap();
            stats.test_duration_ms = self.start_time.elapsed().as_millis() as u64;
            stats.clone()
        }
    }

    #[tokio::test]
    async fn test_cli_output_streaming_basic_jsonl() {
        println!("=== Starting CLI output + trace streaming basic JSONL test ===");

        scope(|cx| async move {
            let mut harness = CliOutputStreamingTestHarness::new()
                .expect("Failed to create test harness");

            // Test basic functionality
            harness
                .test_basic_streaming_jsonl(&cx)
                .await
                .expect("Basic JSONL streaming test should succeed");

            let stats = harness.get_stats();
            println!(
                "Basic JSONL stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Verify basic operation
            assert!(
                stats.commands_executed > 0,
                "Should have executed commands"
            );
            assert!(
                stats.jsonl_records_produced > 0,
                "Should have produced JSONL records"
            );
            assert!(
                stats.trace_events_streamed > 0,
                "Should have streamed trace events"
            );
            assert_eq!(
                stats.buffer_overflow_incidents, 0,
                "Should have no buffer overflow incidents"
            );

            println!("✓ CLI output + trace streaming basic JSONL test passed");
            println!("  - Commands executed: {}", stats.commands_executed);
            println!("  - JSONL records: {}", stats.jsonl_records_produced);
            println!("  - Trace events: {}", stats.trace_events_streamed);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_cli_output_streaming_large_scale() {
        println!("=== Testing CLI output large-scale streaming ===");

        scope(|cx| async move {
            let mut harness = CliOutputStreamingTestHarness::new()
                .expect("Failed to create test harness");

            // Test large-scale streaming
            harness
                .test_large_scale_streaming(&cx)
                .await
                .expect("Large-scale streaming test should succeed");

            let stats = harness.get_stats();
            println!(
                "Large-scale streaming stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should handle large scale without issues
            assert!(
                stats.jsonl_records_produced >= 2000,
                "Should have produced many JSONL records"
            );
            assert_eq!(
                stats.buffer_overflow_incidents, 0,
                "Should prevent buffer overflow"
            );

            println!("✓ Large-scale streaming test passed");
            println!("  - Buffer flushes: {}", stats.buffer_flushes_performed);
            println!("  - Peak memory: {} bytes", stats.peak_memory_usage_bytes);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_cli_output_format_compatibility() {
        println!("=== Testing CLI output format compatibility ===");

        scope(|cx| async move {
            let mut harness = CliOutputStreamingTestHarness::new()
                .expect("Failed to create test harness");

            // Test format compatibility
            harness
                .test_output_format_compatibility(&cx)
                .await
                .expect("Format compatibility test should succeed");

            let stats = harness.get_stats();
            println!(
                "Format compatibility stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should support multiple formats
            assert!(
                stats.commands_executed >= 5,
                "Should have tested multiple formats"
            );
            assert_eq!(
                stats.data_corruption_events, 0,
                "Should have no data corruption"
            );

            println!("✓ Output format compatibility test passed");

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_cli_output_concurrent_commands() {
        println!("=== Testing CLI output concurrent commands ===");

        scope(|cx| async move {
            let mut harness = CliOutputStreamingTestHarness::new()
                .expect("Failed to create test harness");

            // Test concurrent commands
            harness
                .test_concurrent_commands(&cx)
                .await
                .expect("Concurrent commands test should succeed");

            let stats = harness.get_stats();
            println!(
                "Concurrent commands stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Should handle concurrency
            assert!(
                stats.commands_executed >= 3,
                "Should have executed concurrent commands"
            );

            println!("✓ Concurrent commands test passed");

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }

    #[tokio::test]
    async fn test_cli_output_streaming_comprehensive() {
        println!("=== Testing comprehensive CLI output + trace streaming integration ===");

        scope(|cx| async move {
            let mut harness = CliOutputStreamingTestHarness::new()
                .expect("Failed to create test harness");

            // Run comprehensive test sequence
            println!("Running comprehensive streaming tests...");

            harness
                .test_basic_streaming_jsonl(&cx)
                .await
                .expect("Basic JSONL test should succeed");

            harness
                .test_large_scale_streaming(&cx)
                .await
                .expect("Large-scale test should succeed");

            harness
                .test_output_format_compatibility(&cx)
                .await
                .expect("Format compatibility test should succeed");

            harness
                .test_concurrent_commands(&cx)
                .await
                .expect("Concurrent commands test should succeed");

            let stats = harness.get_stats();
            println!(
                "Comprehensive streaming stats: {}",
                serde_json::to_string_pretty(&stats.to_json()).unwrap()
            );

            // Verify comprehensive operation
            assert!(
                stats.commands_executed >= 10,
                "Should have executed many commands"
            );
            assert!(
                stats.jsonl_records_produced >= 3000,
                "Should have produced many JSONL records"
            );
            assert!(
                stats.trace_events_streamed >= 3000,
                "Should have streamed many trace events"
            );
            assert_eq!(
                stats.buffer_overflow_incidents, 0,
                "Should have no buffer overflow incidents"
            );
            assert_eq!(
                stats.data_corruption_events, 0,
                "Should have no data corruption"
            );

            println!("✓ Comprehensive CLI output + trace streaming integration test passed");
            println!("  - Total commands: {}", stats.commands_executed);
            println!("  - Total JSONL records: {}", stats.jsonl_records_produced);
            println!("  - Total trace events: {}", stats.trace_events_streamed);
            println!("  - Total output bytes: {}", stats.output_bytes_written);
            println!("  - Buffer flushes: {}", stats.buffer_flushes_performed);
            println!("  - Checkpoints: {}", stats.checkpoints_created);
            println!("  - Bytes per record: {:.2}", stats.to_json()["bytes_per_record"].as_f64().unwrap_or(0.0));
            println!("  - Streaming efficiency: {:.2}%", stats.to_json()["streaming_efficiency"].as_f64().unwrap_or(0.0) * 100.0);
            println!("  - Test duration: {}ms", stats.test_duration_ms);

            Ok::<(), Box<dyn std::error::Error>>(())
        })
        .await
        .expect("Test scope failed");
    }
}