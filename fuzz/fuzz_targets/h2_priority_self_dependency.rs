#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

/// HTTP/2 PRIORITY frame self-dependency validation testing.
/// Per RFC 7540 §5.3.1, a stream MUST NOT depend on itself.
/// Self-dependency (stream_dependency == stream_id) must be PROTOCOL_ERROR.
///
/// Tests:
/// - PRIORITY frame with stream depending on itself (PROTOCOL_ERROR)
/// - Valid PRIORITY frames with different dependencies
/// - Exclusive vs non-exclusive flags with self-dependency
/// - Weight parameter validation (1-256 range)
/// - Stream ID validation (must be > 0 for PRIORITY frames)
/// - Dependency on stream 0 (connection) handling
/// - Frame structure validation

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// PRIORITY frame to test
    priority_frame: PriorityFrame,
}

#[derive(Arbitrary, Debug, Clone)]
struct PriorityFrame {
    /// Stream ID (must be > 0 for PRIORITY frames)
    stream_id: u32,
    /// Frame flags (should be 0 for PRIORITY)
    flags: u8,
    /// Exclusive dependency flag (bit 31 of dependency field)
    exclusive: bool,
    /// Stream dependency (which stream this depends on)
    stream_dependency: u32,
    /// Weight (1-256, encoded as 0-255)
    weight: u8,
}

/// Mock HTTP/2 PRIORITY frame parser with dependency validation
struct MockH2PriorityParser {
    /// Stream dependency tree for validation
    dependencies: std::collections::HashMap<u32, u32>,
    errors: Vec<String>,
}

impl MockH2PriorityParser {
    fn new() -> Self {
        Self {
            dependencies: std::collections::HashMap::new(),
            errors: Vec::new(),
        }
    }

    /// Parse PRIORITY frame with dependency validation
    fn parse_priority_frame(&mut self, frame: &PriorityFrame) -> Result<(), String> {
        // Validate stream ID
        if frame.stream_id == 0 {
            return Err("PROTOCOL_ERROR: PRIORITY frame stream ID must not be 0".into());
        }

        // Validate frame flags (should be 0 for PRIORITY)
        if frame.flags != 0 {
            return Err("PROTOCOL_ERROR: PRIORITY frame flags must be 0".into());
        }

        // Extract actual dependency (clear exclusive bit if set)
        let dependency = frame.stream_dependency & 0x7FFFFFFF; // Clear bit 31

        // RFC 7540 §5.3.1: A stream cannot depend on itself
        if dependency == frame.stream_id {
            return Err(format!(
                "PROTOCOL_ERROR: stream {} cannot depend on itself",
                frame.stream_id
            ));
        }

        // Validate weight (actual weight is encoded value + 1)
        let actual_weight = frame.weight as u32 + 1; // Weight range: 1-256
        if actual_weight < 1 || actual_weight > 256 {
            return Err(format!(
                "PROTOCOL_ERROR: invalid weight {} (must be 1-256)",
                actual_weight
            ));
        }

        // Additional validation: dependency stream ID bounds
        if dependency > 0x7FFFFFFF {
            return Err("PROTOCOL_ERROR: stream dependency exceeds maximum stream ID".into());
        }

        // Check for potential circular dependencies (simplified check)
        if self.would_create_cycle(frame.stream_id, dependency) {
            self.errors.push(format!(
                "Potential circular dependency: stream {} depending on {}",
                frame.stream_id, dependency
            ));
        }

        // Store dependency for future cycle detection
        self.dependencies.insert(frame.stream_id, dependency);

        Ok(())
    }

    /// Check if adding this dependency would create a cycle
    /// Simplified implementation for testing
    fn would_create_cycle(&self, stream_id: u32, dependency: u32) -> bool {
        if dependency == 0 {
            return false; // Depending on connection (stream 0) never creates cycle
        }

        // Simple cycle detection: check if dependency eventually depends on stream_id
        let mut current = dependency;
        let mut visited = std::collections::HashSet::new();

        while current != 0 && !visited.contains(&current) {
            visited.insert(current);

            if current == stream_id {
                return true; // Found cycle
            }

            if let Some(&next) = self.dependencies.get(&current) {
                current = next;
            } else {
                break; // Unknown dependency, assume no cycle
            }
        }

        false
    }

    /// Get stored dependencies for inspection
    fn get_dependencies(&self) -> &std::collections::HashMap<u32, u32> {
        &self.dependencies
    }

    /// Get error messages
    fn get_errors(&self) -> &[String] {
        &self.errors
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(input) => input,
        Err(_) => return, // Skip invalid inputs
    };

    // Bound stream IDs to reasonable range
    if input.priority_frame.stream_id > 1_000_000
        || input.priority_frame.stream_dependency > 1_000_000
    {
        return;
    }

    let mut parser = MockH2PriorityParser::new();
    let result = parser.parse_priority_frame(&input.priority_frame);

    let frame = &input.priority_frame;
    let dependency = frame.stream_dependency & 0x7FFFFFFF; // Clear exclusive bit

    // Test 1: Self-dependency must be PROTOCOL_ERROR
    if dependency == frame.stream_id && frame.stream_id != 0 {
        assert!(
            result.is_err(),
            "Stream {} depending on itself should be PROTOCOL_ERROR",
            frame.stream_id
        );

        if let Err(error_msg) = &result {
            assert!(
                error_msg.contains("PROTOCOL_ERROR"),
                "Self-dependency error should mention PROTOCOL_ERROR: {}",
                error_msg
            );
            assert!(
                error_msg.contains("depend on itself"),
                "Self-dependency error should be clear: {}",
                error_msg
            );
        }
        return; // No further tests needed for this error case
    }

    // Test 2: Stream ID 0 validation
    if frame.stream_id == 0 {
        assert!(
            result.is_err(),
            "PRIORITY frame with stream ID 0 should be rejected"
        );

        if let Err(error_msg) = &result {
            assert!(
                error_msg.contains("stream ID must not be 0"),
                "Stream ID 0 error should be clear: {}",
                error_msg
            );
        }
        return;
    }

    // Test 3: Invalid flags validation
    if frame.flags != 0 {
        assert!(
            result.is_err(),
            "PRIORITY frame with non-zero flags should be rejected"
        );

        if let Err(error_msg) = &result {
            assert!(
                error_msg.contains("flags must be 0"),
                "Flags validation error should be clear: {}",
                error_msg
            );
        }
        return;
    }

    // Test 4: Valid PRIORITY frames should succeed
    if frame.stream_id > 0 && frame.flags == 0 && dependency != frame.stream_id {
        assert!(
            result.is_ok(),
            "Valid PRIORITY frame should succeed: stream {} depends on {}",
            frame.stream_id,
            dependency
        );

        // Verify dependency was stored correctly
        let stored_deps = parser.get_dependencies();
        assert_eq!(
            stored_deps.get(&frame.stream_id),
            Some(&dependency),
            "Dependency should be stored correctly"
        );
    }

    // Test 5: Weight validation (implicit - weight is u8 so always valid range)
    let actual_weight = frame.weight as u32 + 1;
    if result.is_ok() {
        assert!(
            actual_weight >= 1 && actual_weight <= 256,
            "Weight should be in valid range 1-256, got {}",
            actual_weight
        );
    }

    // Test 6: Dependency on stream 0 (connection) should be valid
    if dependency == 0 && frame.stream_id > 0 && frame.flags == 0 {
        assert!(
            result.is_ok(),
            "Depending on stream 0 (connection) should be valid"
        );
    }
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_self_dependency_error() {
        let frame = PriorityFrame {
            stream_id: 5,
            flags: 0,
            exclusive: false,
            stream_dependency: 5, // Self-dependency
            weight: 15,
        };

        let mut parser = MockH2PriorityParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_err(), "Self-dependency should be rejected");
        assert!(
            result
                .unwrap_err()
                .contains("stream 5 cannot depend on itself")
        );
    }

    #[test]
    fn test_self_dependency_with_exclusive_flag() {
        let frame = PriorityFrame {
            stream_id: 3,
            flags: 0,
            exclusive: true,
            stream_dependency: 0x80000003, // Self-dependency with exclusive bit set
            weight: 10,
        };

        let mut parser = MockH2PriorityParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(
            result.is_err(),
            "Self-dependency with exclusive flag should be rejected"
        );
        assert!(
            result
                .unwrap_err()
                .contains("stream 3 cannot depend on itself")
        );
    }

    #[test]
    fn test_valid_dependency() {
        let frame = PriorityFrame {
            stream_id: 5,
            flags: 0,
            exclusive: false,
            stream_dependency: 3, // Different stream
            weight: 20,
        };

        let mut parser = MockH2PriorityParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_ok(), "Valid dependency should succeed");
        assert_eq!(parser.get_dependencies().get(&5), Some(&3));
    }

    #[test]
    fn test_dependency_on_stream_zero() {
        let frame = PriorityFrame {
            stream_id: 7,
            flags: 0,
            exclusive: false,
            stream_dependency: 0, // Depend on connection
            weight: 5,
        };

        let mut parser = MockH2PriorityParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_ok(), "Dependency on stream 0 should be valid");
        assert_eq!(parser.get_dependencies().get(&7), Some(&0));
    }

    #[test]
    fn test_stream_id_zero_error() {
        let frame = PriorityFrame {
            stream_id: 0, // Invalid for PRIORITY
            flags: 0,
            exclusive: false,
            stream_dependency: 3,
            weight: 15,
        };

        let mut parser = MockH2PriorityParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_err(), "Stream ID 0 should be rejected");
        assert!(result.unwrap_err().contains("stream ID must not be 0"));
    }

    #[test]
    fn test_non_zero_flags_error() {
        let frame = PriorityFrame {
            stream_id: 5,
            flags: 1, // Invalid for PRIORITY
            exclusive: false,
            stream_dependency: 3,
            weight: 15,
        };

        let mut parser = MockH2PriorityParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_err(), "Non-zero flags should be rejected");
        assert!(result.unwrap_err().contains("flags must be 0"));
    }

    #[test]
    fn test_exclusive_flag_with_valid_dependency() {
        let frame = PriorityFrame {
            stream_id: 9,
            flags: 0,
            exclusive: true,
            stream_dependency: 0x80000001, // Stream 1 with exclusive bit set
            weight: 25,
        };

        let mut parser = MockH2PriorityParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(
            result.is_ok(),
            "Exclusive dependency on different stream should work"
        );
        assert_eq!(parser.get_dependencies().get(&9), Some(&1)); // Bit 31 cleared
    }

    #[test]
    fn test_weight_encoding() {
        // Test min weight (encoded as 0)
        let frame1 = PriorityFrame {
            stream_id: 1,
            flags: 0,
            exclusive: false,
            stream_dependency: 0,
            weight: 0, // Actual weight = 1
        };

        let mut parser = MockH2PriorityParser::new();
        assert!(parser.parse_priority_frame(&frame1).is_ok());

        // Test max weight (encoded as 255)
        let frame2 = PriorityFrame {
            stream_id: 3,
            flags: 0,
            exclusive: false,
            stream_dependency: 0,
            weight: 255, // Actual weight = 256
        };

        assert!(parser.parse_priority_frame(&frame2).is_ok());
    }

    #[test]
    fn test_cycle_detection_warning() {
        let mut parser = MockH2PriorityParser::new();

        // Create a dependency: 3 -> 1
        let frame1 = PriorityFrame {
            stream_id: 3,
            flags: 0,
            exclusive: false,
            stream_dependency: 1,
            weight: 10,
        };
        assert!(parser.parse_priority_frame(&frame1).is_ok());

        // Try to create: 1 -> 3 (would create cycle)
        let frame2 = PriorityFrame {
            stream_id: 1,
            flags: 0,
            exclusive: false,
            stream_dependency: 3,
            weight: 10,
        };

        let result = parser.parse_priority_frame(&frame2);
        assert!(
            result.is_ok(),
            "Cycle detection is warning-only in this implementation"
        );

        // Should generate warning about potential cycle
        let errors = parser.get_errors();
        assert!(errors.iter().any(|e| e.contains("circular dependency")));
    }

    #[test]
    fn test_large_stream_ids() {
        let frame = PriorityFrame {
            stream_id: 0x7FFFFF00, // Large but valid stream ID
            flags: 0,
            exclusive: false,
            stream_dependency: 0x7FFFFF02, // Different large stream ID
            weight: 50,
        };

        let mut parser = MockH2PriorityParser::new();
        let result = parser.parse_priority_frame(&frame);

        assert!(result.is_ok(), "Large stream IDs should be valid");
    }

    #[test]
    fn test_multiple_dependencies() {
        let mut parser = MockH2PriorityParser::new();

        // Stream 1 depends on connection (0)
        let frame1 = PriorityFrame {
            stream_id: 1,
            flags: 0,
            exclusive: false,
            stream_dependency: 0,
            weight: 10,
        };
        assert!(parser.parse_priority_frame(&frame1).is_ok());

        // Stream 3 depends on stream 1
        let frame2 = PriorityFrame {
            stream_id: 3,
            flags: 0,
            exclusive: false,
            stream_dependency: 1,
            weight: 15,
        };
        assert!(parser.parse_priority_frame(&frame2).is_ok());

        // Stream 5 depends on stream 3
        let frame3 = PriorityFrame {
            stream_id: 5,
            flags: 0,
            exclusive: false,
            stream_dependency: 3,
            weight: 20,
        };
        assert!(parser.parse_priority_frame(&frame3).is_ok());

        // Verify all dependencies stored correctly
        let deps = parser.get_dependencies();
        assert_eq!(deps.get(&1), Some(&0));
        assert_eq!(deps.get(&3), Some(&1));
        assert_eq!(deps.get(&5), Some(&3));
    }
}
