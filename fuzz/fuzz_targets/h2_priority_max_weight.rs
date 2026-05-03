#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};
use std::collections::HashMap;

/// HTTP/2 PRIORITY frame weight encoding validation testing.
/// Per RFC 7540 §6.3, weight field is 8-bit (0-255) but actual weight
/// is encoded value + 1, giving range 1-256. Tests correct +1 offset
/// application and effective weight storage.
///
/// Tests:
/// - PRIORITY with weight=255 (wire) → effective weight 256 (max valid)
/// - PRIORITY with weight=0 (wire) → effective weight 1 (min valid)
/// - Various weight values and their +1 offset application
/// - Weight storage and retrieval verification
/// - Valid PRIORITY frame structure
/// - Stream dependency validation with different weights

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// PRIORITY frame to test
    priority_frame: PriorityFrame,
}

#[derive(Arbitrary, Debug, Clone)]
struct PriorityFrame {
    /// Stream ID (must be > 0)
    stream_id: u32,
    /// Frame flags (should be 0 for PRIORITY)
    flags: u8,
    /// Exclusive dependency flag
    exclusive: bool,
    /// Stream dependency
    stream_dependency: u32,
    /// Weight (wire format: 0-255, actual weight: 1-256)
    weight_wire: u8,
}

/// Priority information with effective weight
#[derive(Debug, Clone, PartialEq)]
struct PriorityInfo {
    /// Stream that this priority applies to
    stream_id: u32,
    /// Exclusive dependency flag
    exclusive: bool,
    /// Stream dependency (with exclusive bit cleared)
    dependency: u32,
    /// Effective weight (wire value + 1, range: 1-256)
    effective_weight: u16,
}

/// Mock HTTP/2 PRIORITY frame parser with weight encoding validation
struct MockH2PriorityWeightParser {
    /// Stored priority information by stream ID
    priorities: HashMap<u32, PriorityInfo>,
    /// Processing errors
    errors: Vec<String>,
}

impl MockH2PriorityWeightParser {
    fn new() -> Self {
        Self {
            priorities: HashMap::new(),
            errors: Vec::new(),
        }
    }

    /// Parse PRIORITY frame with weight encoding validation
    fn parse_priority_frame(&mut self, frame: &PriorityFrame) -> Result<(), String> {
        // Validate stream ID
        if frame.stream_id == 0 {
            return Err("PROTOCOL_ERROR: PRIORITY frame stream ID must not be 0".into());
        }

        // Validate frame flags
        if frame.flags != 0 {
            return Err("PROTOCOL_ERROR: PRIORITY frame flags must be 0".into());
        }

        // Extract dependency (clear exclusive bit if encoded in dependency)
        let dependency = frame.stream_dependency & 0x7FFFFFFF;

        // Self-dependency check
        if dependency == frame.stream_id {
            return Err(format!(
                "PROTOCOL_ERROR: stream {} cannot depend on itself",
                frame.stream_id
            ));
        }

        // Calculate effective weight: wire value + 1
        let effective_weight = (frame.weight_wire as u16) + 1;

        // Validate weight range (should be 1-256 after +1 offset)
        if effective_weight < 1 || effective_weight > 256 {
            return Err(format!(
                "PROTOCOL_ERROR: invalid effective weight {} (must be 1-256)",
                effective_weight
            ));
        }

        // Store priority information
        let priority_info = PriorityInfo {
            stream_id: frame.stream_id,
            exclusive: frame.exclusive,
            dependency,
            effective_weight,
        };

        self.priorities.insert(frame.stream_id, priority_info);

        Ok(())
    }

    /// Get priority information for a stream
    fn get_priority(&self, stream_id: u32) -> Option<&PriorityInfo> {
        self.priorities.get(&stream_id)
    }

    /// Get effective weight for a stream
    fn get_effective_weight(&self, stream_id: u32) -> Option<u16> {
        self.priorities.get(&stream_id).map(|p| p.effective_weight)
    }

    /// Validate weight encoding: wire value + 1 = effective weight
    fn validate_weight_encoding(&self, wire_value: u8, expected_effective: u16) -> bool {
        (wire_value as u16) + 1 == expected_effective
    }

    /// Get all stored priorities
    fn get_all_priorities(&self) -> &HashMap<u32, PriorityInfo> {
        &self.priorities
    }

    /// Get processing errors
    fn get_errors(&self) -> &[String] {
        &self.errors
    }

    /// Calculate weight ratio for resource allocation simulation
    fn calculate_weight_ratio(&self, stream_id: u32, total_weight: u16) -> Option<f64> {
        self.get_effective_weight(stream_id)
            .map(|weight| weight as f64 / total_weight as f64)
    }

    /// Simulate priority-based resource allocation
    fn simulate_bandwidth_allocation(&self, available_bandwidth: u64) -> HashMap<u32, u64> {
        let mut allocations = HashMap::new();

        if self.priorities.is_empty() {
            return allocations;
        }

        // Calculate total weight
        let total_weight: u32 = self.priorities.values()
            .map(|p| p.effective_weight as u32)
            .sum();

        // Allocate bandwidth proportionally
        for (stream_id, priority) in &self.priorities {
            let allocation = (available_bandwidth as f64
                * (priority.effective_weight as f64 / total_weight as f64)) as u64;
            allocations.insert(*stream_id, allocation);
        }

        allocations
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Bound stream IDs to reasonable range
    if input.priority_frame.stream_id > 1_000_000 ||
       input.priority_frame.stream_dependency > 1_000_000 {
        return;
    }

    let mut parser = MockH2PriorityWeightParser::new();
    let result = parser.parse_priority_frame(&input.priority_frame);

    let frame = &input.priority_frame;

    // Test 1: Stream ID validation
    if frame.stream_id == 0 {
        assert!(result.is_err(),
            "PRIORITY frame with stream ID 0 should be rejected");
        return;
    }

    // Test 2: Frame flags validation
    if frame.flags != 0 {
        assert!(result.is_err(),
            "PRIORITY frame with non-zero flags should be rejected");
        return;
    }

    // Test 3: Self-dependency validation
    let dependency = frame.stream_dependency & 0x7FFFFFFF;
    if dependency == frame.stream_id {
        assert!(result.is_err(),
            "Self-dependency should be rejected");
        return;
    }

    // For valid frames, test weight encoding
    if result.is_ok() {
        // Test 4: Weight encoding validation (+1 offset)
        let expected_effective_weight = (frame.weight_wire as u16) + 1;

        assert!(parser.validate_weight_encoding(frame.weight_wire, expected_effective_weight),
            "Weight encoding validation failed: {} + 1 != {}",
            frame.weight_wire, expected_effective_weight);

        // Test 5: Stored weight verification
        if let Some(stored_weight) = parser.get_effective_weight(frame.stream_id) {
            assert_eq!(stored_weight, expected_effective_weight,
                "Stored effective weight {} doesn't match expected {}",
                stored_weight, expected_effective_weight);
        }

        // Test 6: Weight bounds verification (1-256)
        let effective_weight = parser.get_effective_weight(frame.stream_id).unwrap();
        assert!(effective_weight >= 1 && effective_weight <= 256,
            "Effective weight {} out of valid range 1-256", effective_weight);

        // Test 7: Specific weight values
        match frame.weight_wire {
            0 => {
                assert_eq!(effective_weight, 1,
                    "Wire weight 0 should result in effective weight 1");
            }
            255 => {
                assert_eq!(effective_weight, 256,
                    "Wire weight 255 should result in effective weight 256");
            }
            _ => {
                assert_eq!(effective_weight, (frame.weight_wire as u16) + 1,
                    "Wire weight {} should result in effective weight {}",
                    frame.weight_wire, (frame.weight_wire as u16) + 1);
            }
        }

        // Test 8: Priority information completeness
        if let Some(priority_info) = parser.get_priority(frame.stream_id) {
            assert_eq!(priority_info.stream_id, frame.stream_id);
            assert_eq!(priority_info.exclusive, frame.exclusive);
            assert_eq!(priority_info.dependency, dependency);
            assert_eq!(priority_info.effective_weight, expected_effective_weight);
        }

        // Test 9: Bandwidth allocation simulation
        let bandwidth_allocation = parser.simulate_bandwidth_allocation(1000);
        if let Some(&allocated) = bandwidth_allocation.get(&frame.stream_id) {
            // Should allocate some bandwidth proportional to weight
            if effective_weight > 0 {
                assert!(allocated > 0,
                    "Stream with weight {} should get some bandwidth allocation", effective_weight);
            }
        }
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weight_encoding_min() {
        let frame = PriorityFrame {
            stream_id: 1,
            flags: 0,
            exclusive: false,
            stream_dependency: 0,
            weight_wire: 0, // Min wire value
        };

        let mut parser = MockH2PriorityWeightParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_ok());
        assert_eq!(parser.get_effective_weight(1), Some(1)); // 0 + 1 = 1
    }

    #[test]
    fn test_weight_encoding_max() {
        let frame = PriorityFrame {
            stream_id: 1,
            flags: 0,
            exclusive: false,
            stream_dependency: 0,
            weight_wire: 255, // Max wire value
        };

        let mut parser = MockH2PriorityWeightParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_ok());
        assert_eq!(parser.get_effective_weight(1), Some(256)); // 255 + 1 = 256
    }

    #[test]
    fn test_weight_encoding_middle() {
        let frame = PriorityFrame {
            stream_id: 1,
            flags: 0,
            exclusive: false,
            stream_dependency: 0,
            weight_wire: 127, // Middle value
        };

        let mut parser = MockH2PriorityWeightParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_ok());
        assert_eq!(parser.get_effective_weight(1), Some(128)); // 127 + 1 = 128
    }

    #[test]
    fn test_weight_validation_function() {
        let parser = MockH2PriorityWeightParser::new();

        assert!(parser.validate_weight_encoding(0, 1));
        assert!(parser.validate_weight_encoding(127, 128));
        assert!(parser.validate_weight_encoding(255, 256));

        assert!(!parser.validate_weight_encoding(0, 0));
        assert!(!parser.validate_weight_encoding(255, 255));
        assert!(!parser.validate_weight_encoding(100, 102));
    }

    #[test]
    fn test_priority_info_storage() {
        let frame = PriorityFrame {
            stream_id: 5,
            flags: 0,
            exclusive: true,
            stream_dependency: 0x80000003, // Stream 3 with exclusive bit
            weight_wire: 200,
        };

        let mut parser = MockH2PriorityWeightParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_ok());

        let priority = parser.get_priority(5).unwrap();
        assert_eq!(priority.stream_id, 5);
        assert_eq!(priority.exclusive, true);
        assert_eq!(priority.dependency, 3); // Exclusive bit cleared
        assert_eq!(priority.effective_weight, 201); // 200 + 1
    }

    #[test]
    fn test_bandwidth_allocation_single_stream() {
        let frame = PriorityFrame {
            stream_id: 1,
            flags: 0,
            exclusive: false,
            stream_dependency: 0,
            weight_wire: 99, // Effective weight 100
        };

        let mut parser = MockH2PriorityWeightParser::new();
        assert!(parser.parse_priority_frame(&frame).is_ok());

        let allocation = parser.simulate_bandwidth_allocation(1000);
        assert_eq!(allocation.get(&1), Some(&1000)); // Gets all bandwidth
    }

    #[test]
    fn test_bandwidth_allocation_multiple_streams() {
        let frames = vec![
            PriorityFrame {
                stream_id: 1,
                flags: 0,
                exclusive: false,
                stream_dependency: 0,
                weight_wire: 49, // Effective weight 50
            },
            PriorityFrame {
                stream_id: 3,
                flags: 0,
                exclusive: false,
                stream_dependency: 0,
                weight_wire: 149, // Effective weight 150
            },
        ];

        let mut parser = MockH2PriorityWeightParser::new();
        for frame in frames {
            assert!(parser.parse_priority_frame(&frame).is_ok());
        }

        let allocation = parser.simulate_bandwidth_allocation(2000);

        // Total weight = 50 + 150 = 200
        // Stream 1: (50/200) * 2000 = 500
        // Stream 3: (150/200) * 2000 = 1500
        assert_eq!(allocation.get(&1), Some(&500));
        assert_eq!(allocation.get(&3), Some(&1500));
    }

    #[test]
    fn test_self_dependency_error() {
        let frame = PriorityFrame {
            stream_id: 5,
            flags: 0,
            exclusive: false,
            stream_dependency: 5, // Self-dependency
            weight_wire: 100,
        };

        let mut parser = MockH2PriorityWeightParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot depend on itself"));
    }

    #[test]
    fn test_invalid_stream_id() {
        let frame = PriorityFrame {
            stream_id: 0, // Invalid
            flags: 0,
            exclusive: false,
            stream_dependency: 1,
            weight_wire: 50,
        };

        let mut parser = MockH2PriorityWeightParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("stream ID must not be 0"));
    }

    #[test]
    fn test_invalid_flags() {
        let frame = PriorityFrame {
            stream_id: 1,
            flags: 1, // Invalid for PRIORITY
            exclusive: false,
            stream_dependency: 0,
            weight_wire: 50,
        };

        let mut parser = MockH2PriorityWeightParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("flags must be 0"));
    }

    #[test]
    fn test_weight_range_validation() {
        // Test various weight values
        for wire_weight in 0u8..=255u8 {
            let frame = PriorityFrame {
                stream_id: wire_weight as u32 + 1, // Unique stream ID
                flags: 0,
                exclusive: false,
                stream_dependency: 0,
                weight_wire: wire_weight,
            };

            let mut parser = MockH2PriorityWeightParser::new();
            let result = parser.parse_priority_frame(&frame);

            assert!(result.is_ok(), "Wire weight {} should be valid", wire_weight);

            let effective_weight = parser.get_effective_weight(wire_weight as u32 + 1).unwrap();
            let expected = (wire_weight as u16) + 1;

            assert_eq!(effective_weight, expected,
                "Wire weight {} should give effective weight {}, got {}",
                wire_weight, expected, effective_weight);

            assert!(effective_weight >= 1 && effective_weight <= 256,
                "Effective weight {} out of range for wire weight {}",
                effective_weight, wire_weight);
        }
    }

    #[test]
    fn test_exclusive_dependency_handling() {
        let frame = PriorityFrame {
            stream_id: 7,
            flags: 0,
            exclusive: true,
            stream_dependency: 0x80000001, // Stream 1 with exclusive bit set
            weight_wire: 63, // Effective weight 64
        };

        let mut parser = MockH2PriorityWeightParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_ok());

        let priority = parser.get_priority(7).unwrap();
        assert_eq!(priority.dependency, 1); // Exclusive bit should be cleared
        assert_eq!(priority.exclusive, true); // But exclusive flag preserved
        assert_eq!(priority.effective_weight, 64);
    }
}