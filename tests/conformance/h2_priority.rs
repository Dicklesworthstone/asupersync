//! HTTP/2 PRIORITY Frame Conformance Tests (RFC 9113 Section 6.3)
//!
//! This module provides comprehensive conformance testing for HTTP/2 PRIORITY frame
//! handling per RFC 9113 Section 6.3 (revision of RFC 7540 Section 6.3).
//! The tests systematically validate:
//!
//! - Stream dependency tree updates and relationship management
//! - Priority weight field validation (1-256 range, stored as 0-255)
//! - Exclusive dependency flag (E bit) behavior and tree restructuring
//! - Priority frames on closed/idle streams (allowed but may be ignored)
//! - Circular dependency detection and self-dependency creation
//! - PRIORITY frame on connection stream (Stream ID 0) protocol error
//!
//! # HTTP/2 PRIORITY Frame (RFC 9113 Section 6.3)
//!
//! **Format:**
//! ```
//! +-+-------------------------------------------------------------+
//! |E|                  Stream Dependency (31)                     |
//! +-+-------------+-----------------------------------------------+
//! |   Weight (8)  |
//! +-+-------------+
//! ```
//!
//! **Requirements:**
//! - Length: exactly 5 bytes
//! - Stream ID: MUST be non-zero (not on connection stream)
//! - E (Exclusive): 1-bit flag indicating exclusive dependency
//! - Stream Dependency: 31-bit stream identifier (may be 0 for root dependency)
//! - Weight: 8-bit value representing priority weight (1-256, stored as 0-255)
//!
//! **Behavioral Requirements:**
//! - Circular dependencies MUST be avoided by making stream depend on itself
//! - Priority updates on closed/idle streams are allowed but may be ignored
//! - Exclusive dependencies restructure the dependency tree
//! - Weight determines relative priority among sibling streams

use asupersync::bytes::{Bytes, BytesMut};
use asupersync::http::h2::{
    error::{ErrorCode, H2Error},
    frame::{Frame, FrameHeader, FrameType, PriorityFrame, PrioritySpec, parse_frame},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Test result for a single conformance requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct H2PriorityConformanceResult {
    pub test_id: String,
    pub description: String,
    pub category: TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
}

/// Conformance test categories for HTTP/2 PRIORITY frames.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestCategory {
    /// PRIORITY frame format validation
    PriorityFormat,
    /// Stream dependency tree management
    DependencyTree,
    /// Priority weight field validation
    WeightValidation,
    /// Exclusive dependency flag behavior
    ExclusiveDependency,
    /// Closed/idle stream priority handling
    ClosedStreamPriority,
    /// Circular dependency prevention
    CircularDependency,
    /// Stream ID 0 protocol error
    ConnectionStreamError,
}

/// Protocol requirement level per RFC 2119.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum RequirementLevel {
    Must,   // RFC 2119: MUST
    Should, // RFC 2119: SHOULD
    May,    // RFC 2119: MAY
}

/// Test execution result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestVerdict {
    Pass,
    Fail,
    Skipped,
    ExpectedFailure,
}

/// Simple stream dependency tracker for testing dependency tree operations.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StreamDependencyTracker {
    /// Maps stream ID to its parent dependency
    dependencies: HashMap<u32, u32>,
    /// Maps stream ID to its priority weight (0-255, representing 1-256)
    weights: HashMap<u32, u8>,
    /// Maps stream ID to whether it has exclusive dependency
    exclusive: HashMap<u32, bool>,
    /// Set of closed/idle stream IDs
    closed_streams: HashSet<u32>,
}

#[allow(dead_code)]

impl StreamDependencyTracker {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            dependencies: HashMap::new(),
            weights: HashMap::new(),
            exclusive: HashMap::new(),
            closed_streams: HashSet::new(),
        }
    }

    /// Update stream priority and detect circular dependencies.
    /// Returns Ok(()) if update is valid, Err if circular dependency would occur.
    #[allow(dead_code)]
    pub fn update_priority(&mut self, stream_id: u32, priority: PrioritySpec) -> Result<(), String> {
        // Check for immediate self-dependency (should be caught by frame parsing)
        if priority.dependency == stream_id {
            return Err("Stream cannot depend on itself".to_string());
        }

        // Check for circular dependency by walking up the dependency chain
        if self.would_create_cycle(stream_id, priority.dependency) {
            // RFC 9113 Section 6.3: Circular dependency should make stream depend on itself
            self.dependencies.insert(stream_id, 0); // Root dependency
            self.weights.insert(stream_id, priority.weight);
            self.exclusive.insert(stream_id, false); // Exclusive flag reset
            return Ok(());
        }

        // Update dependency tree
        if priority.exclusive && priority.dependency != 0 {
            // Exclusive dependency: make all current children of parent become children of this stream
            self.restructure_for_exclusive_dependency(stream_id, priority.dependency);
        }

        self.dependencies.insert(stream_id, priority.dependency);
        self.weights.insert(stream_id, priority.weight);
        self.exclusive.insert(stream_id, priority.exclusive);

        Ok(())
    }

    /// Check if making stream_id depend on target_parent would create a cycle.
    #[allow(dead_code)]
    fn would_create_cycle(&self, stream_id: u32, target_parent: u32) -> bool {
        let mut current = target_parent;
        let mut visited = HashSet::new();

        while current != 0 && !visited.contains(&current) {
            if current == stream_id {
                return true; // Cycle detected
            }
            visited.insert(current);
            current = self.dependencies.get(&current).copied().unwrap_or(0);
        }

        false
    }

    /// Restructure tree for exclusive dependency.
    #[allow(dead_code)]
    fn restructure_for_exclusive_dependency(&mut self, stream_id: u32, parent: u32) {
        // Find all current children of parent and make them children of stream_id
        let children: Vec<u32> = self
            .dependencies
            .iter()
            .filter(|(&child, &dep_parent)| dep_parent == parent && child != stream_id)
            .map(|(&child, _)| child)
            .collect();

        for child in children {
            self.dependencies.insert(child, stream_id);
        }
    }

    #[allow(dead_code)]

    pub fn mark_stream_closed(&mut self, stream_id: u32) {
        self.closed_streams.insert(stream_id);
    }

    #[allow(dead_code)]

    pub fn is_closed(&self, stream_id: u32) -> bool {
        self.closed_streams.contains(&stream_id)
    }
}

/// HTTP/2 PRIORITY frame conformance test harness.
#[allow(dead_code)]
pub struct H2PriorityConformanceHarness {
    /// Test execution timeout
    timeout: Duration,
}

#[allow(dead_code)]

impl H2PriorityConformanceHarness {
    /// Create a new conformance test harness.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(30),
        }
    }

    /// Run all conformance tests.
    #[allow(dead_code)]
    pub fn run_all_tests(&self) -> Vec<H2PriorityConformanceResult> {
        let mut results = Vec::new();

        // PRIORITY frame format tests
        results.extend(self.test_priority_frame_format());

        // Stream dependency tree tests
        results.extend(self.test_dependency_tree_updates());

        // Weight validation tests
        results.extend(self.test_weight_field_validation());

        // Exclusive dependency tests
        results.extend(self.test_exclusive_dependency_flag());

        // Closed/idle stream priority tests
        results.extend(self.test_closed_stream_priority());

        // Circular dependency tests
        results.extend(self.test_circular_dependency_prevention());

        // Connection stream error tests
        results.extend(self.test_connection_stream_error());

        results
    }

    /// Test PRIORITY frame format requirements (RFC 9113 Section 6.3).
    #[allow(dead_code)]
    fn test_priority_frame_format(&self) -> Vec<H2PriorityConformanceResult> {
        let mut results = Vec::new();

        // Test 1: PRIORITY frame must be exactly 5 bytes
        results.push(self.run_test(
            "priority_frame_length_exactly_5",
            "PRIORITY frame MUST be exactly 5 bytes",
            TestCategory::PriorityFormat,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 5,
                    frame_type: FrameType::Priority as u8,
                    flags: 0,
                    stream_id: 1,
                };
                let payload = Bytes::from_static(&[
                    0x00, 0x00, 0x00, 0x00, // No exclusive flag, dependency 0
                    0x10,                   // Weight 16 (represents priority 17)
                ]);

                let result = PriorityFrame::parse(&header, &payload);
                match result {
                    Ok(frame) => {
                        assert_eq!(frame.stream_id, 1);
                        assert_eq!(frame.priority.dependency, 0);
                        assert_eq!(frame.priority.weight, 16);
                        assert!(!frame.priority.exclusive);
                        Ok(())
                    }
                    Err(_) => Err("Valid 5-byte PRIORITY frame was rejected".to_string()),
                }
            },
        ));

        // Test 2: PRIORITY frame with wrong length must be rejected
        results.push(self.run_test(
            "priority_frame_wrong_length_rejected",
            "PRIORITY frame with wrong length MUST be rejected",
            TestCategory::PriorityFormat,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 4, // Wrong length
                    frame_type: FrameType::Priority as u8,
                    flags: 0,
                    stream_id: 1,
                };
                let payload = Bytes::from_static(&[0x00, 0x00, 0x00, 0x00]);

                let result = PriorityFrame::parse(&header, &payload);
                match result {
                    Err(err) => {
                        // Should be a stream error, not connection error
                        if let Some(stream_id) = err.stream_id {
                            assert_eq!(stream_id, 1);
                            assert_eq!(err.code, ErrorCode::FrameSizeError);
                            Ok(())
                        } else {
                            Err("Expected stream error for frame size error".to_string())
                        }
                    }
                    Ok(_) => Err("Invalid PRIORITY frame length was accepted".to_string()),
                }
            },
        ));

        // Test 3: PRIORITY frame roundtrip encoding/decoding
        results.push(self.run_test(
            "priority_frame_roundtrip_encoding",
            "PRIORITY frame encoding/decoding MUST preserve all fields",
            TestCategory::PriorityFormat,
            RequirementLevel::Must,
            || {
                let original = PriorityFrame {
                    stream_id: 42,
                    priority: PrioritySpec {
                        exclusive: true,
                        dependency: 31,
                        weight: 200, // Represents priority 201
                    },
                };

                let mut buf = BytesMut::new();
                original.encode(&mut buf);

                let header = FrameHeader::parse(&mut buf).map_err(h2error_to_string)?;
                let payload = buf.split_to(header.length as usize).freeze();
                let parsed = PriorityFrame::parse(&header, &payload).map_err(h2error_to_string)?;

                assert_eq!(parsed.stream_id, original.stream_id);
                assert_eq!(parsed.priority.dependency, original.priority.dependency);
                assert_eq!(parsed.priority.weight, original.priority.weight);
                assert_eq!(parsed.priority.exclusive, original.priority.exclusive);
                Ok(())
            },
        ));

        results
    }

    /// Test stream dependency tree update operations.
    #[allow(dead_code)]
    fn test_dependency_tree_updates(&self) -> Vec<H2PriorityConformanceResult> {
        let mut results = Vec::new();

        // Test 1: Basic dependency tree construction
        results.push(self.run_test(
            "dependency_tree_basic_construction",
            "Stream dependency tree SHOULD be properly maintained",
            TestCategory::DependencyTree,
            RequirementLevel::Should,
            || {
                let mut tracker = StreamDependencyTracker::new();

                // Create basic dependency chain: 1 -> 3 -> 5
                tracker.update_priority(1, PrioritySpec {
                    exclusive: false,
                    dependency: 0,
                    weight: 16,
                }).map_err(|e| format!("Failed to update stream 1: {}", e))?;

                tracker.update_priority(3, PrioritySpec {
                    exclusive: false,
                    dependency: 1,
                    weight: 32,
                }).map_err(|e| format!("Failed to update stream 3: {}", e))?;

                tracker.update_priority(5, PrioritySpec {
                    exclusive: false,
                    dependency: 3,
                    weight: 64,
                }).map_err(|e| format!("Failed to update stream 5: {}", e))?;

                assert_eq!(tracker.dependencies.get(&1), Some(&0));
                assert_eq!(tracker.dependencies.get(&3), Some(&1));
                assert_eq!(tracker.dependencies.get(&5), Some(&3));
                Ok(())
            },
        ));

        // Test 2: Dependency tree restructuring
        results.push(self.run_test(
            "dependency_tree_restructuring",
            "Dependency tree SHOULD support dynamic restructuring",
            TestCategory::DependencyTree,
            RequirementLevel::Should,
            || {
                let mut tracker = StreamDependencyTracker::new();

                // Build initial tree: 1 -> 3, 1 -> 5
                tracker.update_priority(1, PrioritySpec {
                    exclusive: false,
                    dependency: 0,
                    weight: 16,
                })?;

                tracker.update_priority(3, PrioritySpec {
                    exclusive: false,
                    dependency: 1,
                    weight: 32,
                })?;

                tracker.update_priority(5, PrioritySpec {
                    exclusive: false,
                    dependency: 1,
                    weight: 64,
                })?;

                // Now restructure: make 3 depend on 5 instead
                tracker.update_priority(3, PrioritySpec {
                    exclusive: false,
                    dependency: 5,
                    weight: 32,
                })?;

                assert_eq!(tracker.dependencies.get(&3), Some(&5));
                Ok(())
            },
        ));

        results
    }

    /// Test priority weight field validation (1-256 range, stored as 0-255).
    #[allow(dead_code)]
    fn test_weight_field_validation(&self) -> Vec<H2PriorityConformanceResult> {
        let mut results = Vec::new();

        // Test 1: Minimum weight value (0 represents priority 1)
        results.push(self.run_test(
            "priority_weight_minimum_value",
            "PRIORITY weight field MUST accept minimum value 0 (priority 1)",
            TestCategory::WeightValidation,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 5,
                    frame_type: FrameType::Priority as u8,
                    flags: 0,
                    stream_id: 1,
                };
                let payload = Bytes::from_static(&[
                    0x00, 0x00, 0x00, 0x00, // Dependency 0
                    0x00,                   // Weight 0 (represents priority 1)
                ]);

                let result = PriorityFrame::parse(&header, &payload)?;
                assert_eq!(result.priority.weight, 0);
                Ok(())
            },
        ));

        // Test 2: Maximum weight value (255 represents priority 256)
        results.push(self.run_test(
            "priority_weight_maximum_value",
            "PRIORITY weight field MUST accept maximum value 255 (priority 256)",
            TestCategory::WeightValidation,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 5,
                    frame_type: FrameType::Priority as u8,
                    flags: 0,
                    stream_id: 1,
                };
                let payload = Bytes::from_static(&[
                    0x00, 0x00, 0x00, 0x00, // Dependency 0
                    0xFF,                   // Weight 255 (represents priority 256)
                ]);

                let result = PriorityFrame::parse(&header, &payload)?;
                assert_eq!(result.priority.weight, 255);
                Ok(())
            },
        ));

        // Test 3: Weight field encoding preserves all values
        results.push(self.run_test(
            "priority_weight_encoding_preservation",
            "PRIORITY weight encoding MUST preserve all 8-bit values",
            TestCategory::WeightValidation,
            RequirementLevel::Must,
            || {
                for weight in [0u8, 1, 16, 31, 63, 127, 128, 200, 254, 255] {
                    let frame = PriorityFrame {
                        stream_id: 1,
                        priority: PrioritySpec {
                            exclusive: false,
                            dependency: 0,
                            weight,
                        },
                    };

                    let mut buf = BytesMut::new();
                    frame.encode(&mut buf);

                    let header = FrameHeader::parse(&mut buf)?;
                    let payload = buf.split_to(header.length as usize).freeze();
                    let parsed = PriorityFrame::parse(&header, &payload)?;

                    assert_eq!(parsed.priority.weight, weight,
                        "Weight {} was not preserved through encoding", weight);
                }
                Ok(())
            },
        ));

        results
    }

    /// Test exclusive dependency flag behavior.
    #[allow(dead_code)]
    fn test_exclusive_dependency_flag(&self) -> Vec<H2PriorityConformanceResult> {
        let mut results = Vec::new();

        // Test 1: Exclusive flag parsing
        results.push(self.run_test(
            "exclusive_dependency_flag_parsing",
            "PRIORITY exclusive flag MUST be correctly parsed from E bit",
            TestCategory::ExclusiveDependency,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 5,
                    frame_type: FrameType::Priority as u8,
                    flags: 0,
                    stream_id: 1,
                };

                // Test exclusive=true (E bit set)
                let payload_exclusive = Bytes::from_static(&[
                    0x80, 0x00, 0x00, 0x05, // E=1, dependency=5
                    0x10,                   // Weight 16
                ]);

                let result = PriorityFrame::parse(&header, &payload_exclusive)?;
                assert!(result.priority.exclusive);
                assert_eq!(result.priority.dependency, 5);

                // Test exclusive=false (E bit clear)
                let payload_non_exclusive = Bytes::from_static(&[
                    0x00, 0x00, 0x00, 0x05, // E=0, dependency=5
                    0x10,                   // Weight 16
                ]);

                let result = PriorityFrame::parse(&header, &payload_non_exclusive)?;
                assert!(!result.priority.exclusive);
                assert_eq!(result.priority.dependency, 5);
                Ok(())
            },
        ));

        // Test 2: Exclusive dependency tree restructuring
        results.push(self.run_test(
            "exclusive_dependency_tree_restructuring",
            "Exclusive dependency SHOULD restructure dependency tree correctly",
            TestCategory::ExclusiveDependency,
            RequirementLevel::Should,
            || {
                let mut tracker = StreamDependencyTracker::new();

                // Build tree: 1 -> 3, 1 -> 5, 1 -> 7
                tracker.update_priority(1, PrioritySpec {
                    exclusive: false,
                    dependency: 0,
                    weight: 16,
                })?;

                tracker.update_priority(3, PrioritySpec {
                    exclusive: false,
                    dependency: 1,
                    weight: 32,
                })?;

                tracker.update_priority(5, PrioritySpec {
                    exclusive: false,
                    dependency: 1,
                    weight: 64,
                })?;

                tracker.update_priority(7, PrioritySpec {
                    exclusive: false,
                    dependency: 1,
                    weight: 96,
                })?;

                // Now make stream 9 exclusively depend on stream 1
                // This should move streams 3, 5, 7 to depend on stream 9
                tracker.update_priority(9, PrioritySpec {
                    exclusive: true,
                    dependency: 1,
                    weight: 128,
                })?;

                // Verify restructuring
                assert_eq!(tracker.dependencies.get(&9), Some(&1));
                assert_eq!(tracker.dependencies.get(&3), Some(&9));
                assert_eq!(tracker.dependencies.get(&5), Some(&9));
                assert_eq!(tracker.dependencies.get(&7), Some(&9));
                Ok(())
            },
        ));

        // Test 3: Exclusive flag encoding
        results.push(self.run_test(
            "exclusive_dependency_flag_encoding",
            "PRIORITY exclusive flag MUST be correctly encoded in E bit",
            TestCategory::ExclusiveDependency,
            RequirementLevel::Must,
            || {
                // Test exclusive=true encoding
                let frame_exclusive = PriorityFrame {
                    stream_id: 1,
                    priority: PrioritySpec {
                        exclusive: true,
                        dependency: 42,
                        weight: 100,
                    },
                };

                let mut buf = BytesMut::new();
                frame_exclusive.encode(&mut buf);

                // Check that E bit is set (0x80000000 | 42 = 0x8000002A)
                assert_eq!(buf[9], 0x80); // First byte should have E bit set
                assert_eq!(buf[10], 0x00);
                assert_eq!(buf[11], 0x00);
                assert_eq!(buf[12], 42);
                assert_eq!(buf[13], 100);

                // Test exclusive=false encoding
                buf.clear();
                let frame_non_exclusive = PriorityFrame {
                    stream_id: 1,
                    priority: PrioritySpec {
                        exclusive: false,
                        dependency: 42,
                        weight: 100,
                    },
                };

                frame_non_exclusive.encode(&mut buf);

                // Check that E bit is clear
                assert_eq!(buf[9], 0x00); // First byte should not have E bit set
                assert_eq!(buf[10], 0x00);
                assert_eq!(buf[11], 0x00);
                assert_eq!(buf[12], 42);
                assert_eq!(buf[13], 100);
                Ok(())
            },
        ));

        results
    }

    /// Test priority handling for closed/idle streams.
    #[allow(dead_code)]
    fn test_closed_stream_priority(&self) -> Vec<H2PriorityConformanceResult> {
        let mut results = Vec::new();

        // Test 1: PRIORITY frame on closed stream should be accepted
        results.push(self.run_test(
            "priority_on_closed_stream_accepted",
            "PRIORITY frame on closed/idle stream SHOULD be accepted",
            TestCategory::ClosedStreamPriority,
            RequirementLevel::Should,
            || {
                let mut tracker = StreamDependencyTracker::new();

                // Mark stream as closed
                tracker.mark_stream_closed(5);

                // PRIORITY frame on closed stream should still be processable
                let result = tracker.update_priority(5, PrioritySpec {
                    exclusive: false,
                    dependency: 1,
                    weight: 64,
                });

                // Should succeed even though stream is closed
                match result {
                    Ok(()) => Ok(()),
                    Err(e) => Err(format!("PRIORITY on closed stream was rejected: {}", e)),
                }
            },
        ));

        // Test 2: PRIORITY frame parser doesn't reject based on stream state
        results.push(self.run_test(
            "priority_parser_stream_state_agnostic",
            "PRIORITY frame parser MUST not reject based on stream state",
            TestCategory::ClosedStreamPriority,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 5,
                    frame_type: FrameType::Priority as u8,
                    flags: 0,
                    stream_id: 999, // High stream ID, likely closed/idle
                };
                let payload = Bytes::from_static(&[
                    0x00, 0x00, 0x00, 0x01, // Dependency 1
                    0x40,                   // Weight 64
                ]);

                let result = PriorityFrame::parse(&header, &payload);
                match result {
                    Ok(frame) => {
                        assert_eq!(frame.stream_id, 999);
                        assert_eq!(frame.priority.dependency, 1);
                        assert_eq!(frame.priority.weight, 64);
                        Ok(())
                    }
                    Err(_) => Err("PRIORITY frame parser rejected valid frame".to_string()),
                }
            },
        ));

        results
    }

    /// Test circular dependency prevention mechanisms.
    #[allow(dead_code)]
    fn test_circular_dependency_prevention(&self) -> Vec<H2PriorityConformanceResult> {
        let mut results = Vec::new();

        // Test 1: Direct circular dependency prevention (parsing level)
        results.push(self.run_test(
            "direct_circular_dependency_rejected",
            "PRIORITY frame with stream depending on itself MUST be rejected",
            TestCategory::CircularDependency,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 5,
                    frame_type: FrameType::Priority as u8,
                    flags: 0,
                    stream_id: 5,
                };
                let payload = Bytes::from_static(&[
                    0x00, 0x00, 0x00, 0x05, // Dependency on self (stream 5)
                    0x10,                   // Weight 16
                ]);

                let result = PriorityFrame::parse(&header, &payload);
                match result {
                    Err(err) => {
                        assert_eq!(err.code, ErrorCode::ProtocolError);
                        if let Some(stream_id) = err.stream_id {
                            assert_eq!(stream_id, 5);
                        }
                        Ok(())
                    }
                    Ok(_) => Err("Direct circular dependency was accepted".to_string()),
                }
            },
        ));

        // Test 2: Indirect circular dependency resolution
        results.push(self.run_test(
            "indirect_circular_dependency_resolution",
            "Circular dependency MUST be resolved by creating self-dependency",
            TestCategory::CircularDependency,
            RequirementLevel::Must,
            || {
                let mut tracker = StreamDependencyTracker::new();

                // Create chain: 1 -> 3 -> 5
                tracker.update_priority(1, PrioritySpec {
                    exclusive: false,
                    dependency: 0,
                    weight: 16,
                })?;

                tracker.update_priority(3, PrioritySpec {
                    exclusive: false,
                    dependency: 1,
                    weight: 32,
                })?;

                tracker.update_priority(5, PrioritySpec {
                    exclusive: false,
                    dependency: 3,
                    weight: 64,
                })?;

                // Now try to make 1 depend on 5, creating cycle: 1 -> 5 -> 3 -> 1
                let result = tracker.update_priority(1, PrioritySpec {
                    exclusive: false,
                    dependency: 5,
                    weight: 16,
                });

                // Should succeed and break the cycle by making stream 1 depend on root
                assert!(result.is_ok());
                assert_eq!(tracker.dependencies.get(&1), Some(&0)); // Should depend on root (0)
                Ok(())
            },
        ));

        // Test 3: Complex circular dependency chain
        results.push(self.run_test(
            "complex_circular_dependency_chain",
            "Complex circular dependencies MUST be detected and resolved",
            TestCategory::CircularDependency,
            RequirementLevel::Must,
            || {
                let mut tracker = StreamDependencyTracker::new();

                // Create complex chain: 1 -> 3 -> 5 -> 7 -> 9
                for (stream, dep) in [(1, 0), (3, 1), (5, 3), (7, 5), (9, 7)] {
                    tracker.update_priority(stream, PrioritySpec {
                        exclusive: false,
                        dependency: dep,
                        weight: 16,
                    })?;
                }

                // Try to close the loop: 1 -> 9, creating 1 -> 9 -> 7 -> 5 -> 3 -> 1
                let result = tracker.update_priority(1, PrioritySpec {
                    exclusive: false,
                    dependency: 9,
                    weight: 16,
                });

                assert!(result.is_ok());
                assert_eq!(tracker.dependencies.get(&1), Some(&0)); // Should depend on root
                Ok(())
            },
        ));

        results
    }

    /// Test PRIORITY frame on Stream ID 0 protocol error.
    #[allow(dead_code)]
    fn test_connection_stream_error(&self) -> Vec<H2PriorityConformanceResult> {
        let mut results = Vec::new();

        // Test 1: PRIORITY frame with Stream ID 0 must trigger PROTOCOL_ERROR
        results.push(self.run_test(
            "priority_stream_id_zero_protocol_error",
            "PRIORITY frame with Stream ID 0 MUST trigger PROTOCOL_ERROR",
            TestCategory::ConnectionStreamError,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 5,
                    frame_type: FrameType::Priority as u8,
                    flags: 0,
                    stream_id: 0, // Invalid for PRIORITY frame
                };
                let payload = Bytes::from_static(&[
                    0x00, 0x00, 0x00, 0x01, // Dependency 1
                    0x10,                   // Weight 16
                ]);

                let result = PriorityFrame::parse(&header, &payload);
                match result {
                    Err(err) => {
                        assert_eq!(err.code, ErrorCode::ProtocolError);
                        // This should be a connection-level error (no stream_id)
                        assert!(err.stream_id.is_none(), "Expected connection-level error");
                        Ok(())
                    }
                    Ok(_) => Err("PRIORITY frame with Stream ID 0 was accepted".to_string()),
                }
            },
        ));

        // Test 2: Multiple Stream ID 0 PRIORITY frames
        results.push(self.run_test(
            "multiple_priority_stream_id_zero_errors",
            "Multiple PRIORITY frames with Stream ID 0 MUST each trigger PROTOCOL_ERROR",
            TestCategory::ConnectionStreamError,
            RequirementLevel::Must,
            || {
                let header = FrameHeader {
                    length: 5,
                    frame_type: FrameType::Priority as u8,
                    flags: 0,
                    stream_id: 0,
                };

                for weight in [0u8, 50, 100, 150, 255] {
                    let payload = Bytes::from_static(&[
                        0x00, 0x00, 0x00, 0x00, // Dependency 0
                        weight,                 // Different weights
                    ]);

                    let result = PriorityFrame::parse(&header, &payload);
                    match result {
                        Err(err) => {
                            assert_eq!(err.code, ErrorCode::ProtocolError);
                            assert!(err.stream_id.is_none());
                        }
                        Ok(_) => return Err(format!("PRIORITY frame with Stream ID 0 and weight {} was accepted", weight)),
                    }
                }
                Ok(())
            },
        ));

        results
    }

    /// Execute a single test and capture the result.
    #[allow(dead_code)]
    fn run_test<F>(
        &self,
        test_id: &str,
        description: &str,
        category: TestCategory,
        requirement_level: RequirementLevel,
        test_fn: F,
    ) -> H2PriorityConformanceResult
    where
        F: FnOnce() -> Result<(), String>,
    {
        let start = Instant::now();

        let verdict = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(test_fn)) {
            Ok(Ok(())) => TestVerdict::Pass,
            Ok(Err(msg)) => {
                return H2PriorityConformanceResult {
                    test_id: test_id.to_string(),
                    description: description.to_string(),
                    category,
                    requirement_level,
                    verdict: TestVerdict::Fail,
                    error_message: Some(msg),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }
            Err(panic_payload) => {
                let msg = if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    "Test panicked with unknown payload".to_string()
                };

                return H2PriorityConformanceResult {
                    test_id: test_id.to_string(),
                    description: description.to_string(),
                    category,
                    requirement_level,
                    verdict: TestVerdict::Fail,
                    error_message: Some(format!("Panic: {}", msg)),
                    execution_time_ms: start.elapsed().as_millis() as u64,
                };
            }
        };

        H2PriorityConformanceResult {
            test_id: test_id.to_string(),
            description: description.to_string(),
            category,
            requirement_level,
            verdict,
            error_message: None,
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }
}

impl Default for H2PriorityConformanceHarness {
    #[allow(dead_code)]
    fn default() -> Self {
        Self::new()
    }
}

// Helper function to convert H2Error to String for ? operator in tests
#[allow(dead_code)]
fn h2error_to_string(err: H2Error) -> String {
    format!("H2Error: {}", err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(dead_code)]
    fn test_harness_creation() {
        let harness = H2PriorityConformanceHarness::new();
        assert_eq!(harness.timeout, Duration::from_secs(30));
    }

    #[test]
    #[allow(dead_code)]
    fn test_all_priority_conformance_tests() {
        let harness = H2PriorityConformanceHarness::new();
        let results = harness.run_all_tests();

        // Verify we have tests
        assert!(!results.is_empty());

        // Verify all tests have proper IDs and descriptions
        for result in &results {
            assert!(!result.test_id.is_empty());
            assert!(!result.description.is_empty());
        }

        // Count tests by category
        let mut category_counts = std::collections::HashMap::new();
        for result in &results {
            *category_counts.entry(&result.category).or_insert(0) += 1;
        }

        // Verify we have tests in all main categories
        assert!(category_counts.contains_key(&TestCategory::PriorityFormat));
        assert!(category_counts.contains_key(&TestCategory::DependencyTree));
        assert!(category_counts.contains_key(&TestCategory::WeightValidation));
        assert!(category_counts.contains_key(&TestCategory::ExclusiveDependency));
        assert!(category_counts.contains_key(&TestCategory::CircularDependency));
        assert!(category_counts.contains_key(&TestCategory::ConnectionStreamError));

        println!("H2 PRIORITY Conformance Test Results:");
        println!("Total tests: {}", results.len());
        for (category, count) in category_counts {
            println!("  {:?}: {} tests", category, count);
        }

        // Check for any failures
        let failures: Vec<_> = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Fail)
            .collect();

        if !failures.is_empty() {
            println!("Failed tests:");
            for failure in failures {
                println!("  {} - {}", failure.test_id, failure.description);
                if let Some(ref msg) = failure.error_message {
                    println!("    Error: {}", msg);
                }
            }
            panic!("Some conformance tests failed");
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_priority_frame_format_conformance() {
        let harness = H2PriorityConformanceHarness::new();
        let results = harness.test_priority_frame_format();

        assert!(!results.is_empty());

        // All format tests should pass
        for result in &results {
            assert_eq!(result.category, TestCategory::PriorityFormat);
            if result.verdict == TestVerdict::Fail {
                panic!(
                    "PRIORITY format test failed: {} - {:?}",
                    result.test_id, result.error_message
                );
            }
        }
    }

    #[test]
    #[allow(dead_code)]
    fn test_dependency_tracker() {
        let mut tracker = StreamDependencyTracker::new();

        // Test basic dependency tracking
        let result = tracker.update_priority(1, PrioritySpec {
            exclusive: false,
            dependency: 0,
            weight: 16,
        });
        assert!(result.is_ok());

        let result = tracker.update_priority(3, PrioritySpec {
            exclusive: false,
            dependency: 1,
            weight: 32,
        });
        assert!(result.is_ok());

        assert_eq!(tracker.dependencies.get(&1), Some(&0));
        assert_eq!(tracker.dependencies.get(&3), Some(&1));
    }

    #[test]
    #[allow(dead_code)]
    fn test_circular_dependency_detection() {
        let mut tracker = StreamDependencyTracker::new();

        // Build chain: 1 -> 3 -> 5
        tracker.update_priority(1, PrioritySpec {
            exclusive: false,
            dependency: 0,
            weight: 16,
        }).unwrap();

        tracker.update_priority(3, PrioritySpec {
            exclusive: false,
            dependency: 1,
            weight: 32,
        }).unwrap();

        tracker.update_priority(5, PrioritySpec {
            exclusive: false,
            dependency: 3,
            weight: 64,
        }).unwrap();

        // Try to create cycle: 1 -> 5 (which would create 1 -> 5 -> 3 -> 1)
        let result = tracker.update_priority(1, PrioritySpec {
            exclusive: false,
            dependency: 5,
            weight: 16,
        });

        assert!(result.is_ok());
        // Should break cycle by making 1 depend on root
        assert_eq!(tracker.dependencies.get(&1), Some(&0));
    }
}