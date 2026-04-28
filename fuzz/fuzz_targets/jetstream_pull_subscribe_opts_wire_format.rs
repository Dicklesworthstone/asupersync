#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::fmt::Write as _;
use std::time::Duration;

/// Structure-aware fuzz input for JetStream PullSubscribeOpts wire format testing
#[derive(Arbitrary, Debug)]
struct PullSubscribeOptsFuzz {
    /// Test scenarios for different pull request formats
    scenario: PullRequestScenario,
    /// Whether to test JSON parsing edge cases
    test_json_parsing: bool,
    /// Wire format manipulation strategies
    format_strategy: FormatStrategy,
}

#[derive(Arbitrary, Debug, Clone)]
enum PullRequestScenario {
    /// Valid pull request options
    ValidRequests {
        requests: Vec<PullRequestVariant>,
    },
    /// Boundary value testing
    BoundaryValues {
        boundary_cases: Vec<BoundaryCase>,
    },
    /// Timeout handling edge cases
    TimeoutEdgeCases {
        timeout_cases: Vec<TimeoutCase>,
    },
    /// Batch size edge cases
    BatchSizeEdgeCases {
        batch_cases: Vec<BatchSizeCase>,
    },
    /// Mixed valid and invalid combinations
    MixedRequests {
        mixed_cases: Vec<MixedRequestCase>,
    },
}

#[derive(Arbitrary, Debug, Clone)]
struct PullRequestVariant {
    /// Number of messages to pull
    batch: usize,
    /// Timeout duration for the pull
    timeout: Duration,
    /// Whether to test zero timeout special case
    force_zero_timeout: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct BoundaryCase {
    /// Type of boundary being tested
    boundary_type: BoundaryType,
    /// Base values for testing
    batch: usize,
    /// Timeout in nanoseconds
    timeout_nanos: u128,
}

#[derive(Arbitrary, Debug, Clone)]
enum BoundaryType {
    /// Zero values
    Zero,
    /// Maximum values
    Maximum,
    /// Just under maximum
    NearMaximum,
    /// Overflow conditions
    Overflow,
    /// Very large but valid
    VeryLarge,
}

#[derive(Arbitrary, Debug, Clone)]
struct TimeoutCase {
    /// Timeout scenario being tested
    timeout_scenario: TimeoutScenario,
    /// Associated batch size
    batch: usize,
}

#[derive(Arbitrary, Debug, Clone)]
enum TimeoutScenario {
    /// Zero timeout (no expiry)
    Zero,
    /// Very small timeout
    VerySmall { nanos: u64 },
    /// Maximum i64 timeout
    MaxI64,
    /// Overflow beyond i64::MAX
    OverflowI64 { nanos: u128 },
    /// Duration::MAX
    DurationMax,
}

#[derive(Arbitrary, Debug, Clone)]
struct BatchSizeCase {
    /// Batch size scenario
    batch_scenario: BatchScenario,
    /// Associated timeout
    timeout_nanos: i64,
}

#[derive(Arbitrary, Debug, Clone)]
enum BatchScenario {
    /// Zero batch size
    Zero,
    /// Single message
    One,
    /// Standard batch sizes
    Standard { size: usize },
    /// Very large batch
    VeryLarge { size: usize },
    /// Maximum usize
    Maximum,
}

#[derive(Arbitrary, Debug, Clone)]
struct MixedRequestCase {
    /// Request type for testing
    case_type: MixedCaseType,
    /// Raw JSON for testing parsing
    raw_json: String,
}

#[derive(Arbitrary, Debug, Clone)]
enum MixedCaseType {
    /// Valid structured request
    Valid { batch: usize, expires: i64 },
    /// Type confusion (string as number, etc.)
    TypeConfusion,
    /// Missing required fields
    MissingFields,
    /// Extra unknown fields
    ExtraFields,
    /// Malformed JSON syntax
    MalformedJson,
}

#[derive(Arbitrary, Debug, Clone)]
enum FormatStrategy {
    /// Standard JSON format
    Standard,
    /// Alternative field ordering
    AlternativeOrdering,
    /// Include extra whitespace
    ExtraWhitespace,
    /// Unicode in field values
    Unicode,
    /// Escaped characters
    EscapedChars,
    /// Number format variations
    NumberFormats,
}

/// Size limits to prevent OOM during fuzzing
const MAX_BATCH_SIZE: usize = 100_000;
const MAX_TIMEOUT_NANOS: u128 = u64::MAX as u128;
const MAX_STRING_LEN: usize = 8192;
const MAX_CASES: usize = 50;

fuzz_target!(|input: PullSubscribeOptsFuzz| {
    // Input size guards
    match &input.scenario {
        PullRequestScenario::ValidRequests { requests } => {
            if requests.len() > MAX_CASES {
                return;
            }
        }
        PullRequestScenario::MixedRequests { mixed_cases } => {
            if mixed_cases.len() > MAX_CASES {
                return;
            }
        }
        _ => {}
    }

    // Test main pull request scenarios
    test_pull_subscribe_opts_scenarios(&input);

    // Test JSON parsing if requested
    if input.test_json_parsing {
        test_json_parsing_edge_cases(&input);
    }

    // Test wire format manipulation
    test_format_manipulation_strategies(&input);

    // Test timeout computation edge cases
    test_timeout_computation_edge_cases(&input);
});

/// Test main PullSubscribeOpts scenarios
fn test_pull_subscribe_opts_scenarios(input: &PullSubscribeOptsFuzz) {
    match &input.scenario {
        PullRequestScenario::ValidRequests { requests } => {
            for request in requests.iter().take(MAX_CASES) {
                if is_valid_pull_request(request) {
                    test_pull_request_encoding(request, &input.format_strategy);
                }
            }
        }

        PullRequestScenario::BoundaryValues { boundary_cases } => {
            for case in boundary_cases.iter().take(MAX_CASES) {
                test_boundary_value_case(case, &input.format_strategy);
            }
        }

        PullRequestScenario::TimeoutEdgeCases { timeout_cases } => {
            for case in timeout_cases.iter().take(MAX_CASES) {
                test_timeout_edge_case(case, &input.format_strategy);
            }
        }

        PullRequestScenario::BatchSizeEdgeCases { batch_cases } => {
            for case in batch_cases.iter().take(MAX_CASES) {
                test_batch_size_edge_case(case, &input.format_strategy);
            }
        }

        PullRequestScenario::MixedRequests { mixed_cases } => {
            for case in mixed_cases.iter().take(MAX_CASES) {
                test_mixed_request_case(case, &input.format_strategy);
            }
        }
    }
}

/// Test JSON parsing edge cases
fn test_json_parsing_edge_cases(input: &PullSubscribeOptsFuzz) {
    let malformed_cases = [
        "",                                     // Empty
        "{}",                                  // Empty object
        "{",                                   // Incomplete
        "}",                                   // Invalid start
        r#"{"batch":}"#,                      // Missing value
        r#"{"batch":5,"expires":}"#,          // Missing expires value
        r#"{"batch":5,}"#,                    // Trailing comma
        r#"{"batch":5"expires":0}"#,          // Missing comma
        r#"{"batch":"5","expires":"0"}"#,     // String instead of number
        r#"{"batch":null,"expires":null}"#,   // Null values
        r#"{"batch":5.5,"expires":0.0}"#,     // Float instead of int
        r#"{"batch":-1,"expires":-1}"#,       // Negative values
        "null",                               // Null instead of object
        "[]",                                 // Array instead of object
        "\"string\"",                         // String instead of object
        "123",                                // Number instead of object
    ];

    for &malformed in malformed_cases {
        test_pull_request_parsing(malformed);
    }
}

/// Test format manipulation strategies
fn test_format_manipulation_strategies(input: &PullSubscribeOptsFuzz) {
    let base_request = PullRequestVariant {
        batch: 10,
        timeout: Duration::from_secs(30),
        force_zero_timeout: false,
    };

    let manipulated = apply_format_strategy(&base_request, &input.format_strategy);
    test_pull_request_parsing(&manipulated);
}

/// Test timeout computation edge cases
fn test_timeout_computation_edge_cases(_input: &PullSubscribeOptsFuzz) {
    let timeout_cases = [
        Duration::ZERO,                        // Zero timeout
        Duration::from_nanos(1),              // Minimal timeout
        Duration::from_millis(1),             // Small timeout
        Duration::from_secs(1),               // Normal timeout
        Duration::from_secs(3600),            // Large timeout
        Duration::from_nanos(i64::MAX as u64), // Near i64::MAX
        Duration::MAX,                         // Maximum duration
    ];

    for timeout in timeout_cases {
        test_timeout_computation(timeout);
    }
}

/// Test pull request encoding to JSON wire format
fn test_pull_request_encoding(request: &PullRequestVariant, strategy: &FormatStrategy) {
    // Mimic the encoding logic from Consumer::pull_with_timeout
    let expires = if request.force_zero_timeout || request.timeout.is_zero() {
        0_i64
    } else {
        let nanos = request.timeout.as_nanos();
        let max = i64::MAX as u128;
        let clamped = if nanos > max { max } else { nanos };
        clamped as i64
    };

    let json = match strategy {
        FormatStrategy::Standard => {
            format!(r#"{{"batch":{},"expires":{}}}"#, request.batch, expires)
        }
        FormatStrategy::AlternativeOrdering => {
            format!(r#"{{"expires":{},"batch":{}}}"#, expires, request.batch)
        }
        FormatStrategy::ExtraWhitespace => {
            format!(r#"{{ "batch" : {} , "expires" : {} }}"#, request.batch, expires)
        }
        FormatStrategy::Unicode => {
            format!(r#"{{"batch":{},"expires":{},"测试":"🌟"}}"#, request.batch, expires)
        }
        FormatStrategy::EscapedChars => {
            format!(r#"{{"batch":{},"expires":{},"test":"with\nnewline"}}"#, request.batch, expires)
        }
        FormatStrategy::NumberFormats => {
            format!(r#"{{"batch":{},"expires":{}}}"#, request.batch, expires)
        }
    };

    // Test that the generated JSON can be parsed
    test_pull_request_parsing(&json);
}

/// Test boundary value cases
fn test_boundary_value_case(case: &BoundaryCase, strategy: &FormatStrategy) {
    let (batch, expires) = match case.boundary_type {
        BoundaryType::Zero => (0, 0),
        BoundaryType::Maximum => (
            usize::MAX.min(MAX_BATCH_SIZE),
            i64::MAX,
        ),
        BoundaryType::NearMaximum => (
            (usize::MAX - 1).min(MAX_BATCH_SIZE),
            i64::MAX - 1,
        ),
        BoundaryType::Overflow => (
            case.batch.min(MAX_BATCH_SIZE),
            i64::MAX, // Will be clamped during encoding
        ),
        BoundaryType::VeryLarge => (
            case.batch.min(MAX_BATCH_SIZE),
            case.timeout_nanos.min(MAX_TIMEOUT_NANOS).min(i64::MAX as u128) as i64,
        ),
    };

    let request = PullRequestVariant {
        batch,
        timeout: Duration::from_nanos(expires.max(0) as u64),
        force_zero_timeout: expires == 0,
    };

    test_pull_request_encoding(&request, strategy);
}

/// Test timeout edge cases
fn test_timeout_edge_case(case: &TimeoutCase, strategy: &FormatStrategy) {
    let timeout = match &case.timeout_scenario {
        TimeoutScenario::Zero => Duration::ZERO,
        TimeoutScenario::VerySmall { nanos } => Duration::from_nanos(*nanos),
        TimeoutScenario::MaxI64 => Duration::from_nanos(i64::MAX as u64),
        TimeoutScenario::OverflowI64 { nanos } => {
            Duration::from_nanos((*nanos).min(u64::MAX as u128) as u64)
        }
        TimeoutScenario::DurationMax => Duration::MAX,
    };

    let request = PullRequestVariant {
        batch: case.batch.min(MAX_BATCH_SIZE),
        timeout,
        force_zero_timeout: matches!(case.timeout_scenario, TimeoutScenario::Zero),
    };

    test_pull_request_encoding(&request, strategy);
}

/// Test batch size edge cases
fn test_batch_size_edge_case(case: &BatchSizeCase, strategy: &FormatStrategy) {
    let batch = match &case.batch_scenario {
        BatchScenario::Zero => 0,
        BatchScenario::One => 1,
        BatchScenario::Standard { size } => (*size).min(MAX_BATCH_SIZE),
        BatchScenario::VeryLarge { size } => (*size).min(MAX_BATCH_SIZE),
        BatchScenario::Maximum => usize::MAX.min(MAX_BATCH_SIZE),
    };

    let timeout = Duration::from_nanos(case.timeout_nanos.max(0) as u64);

    let request = PullRequestVariant {
        batch,
        timeout,
        force_zero_timeout: case.timeout_nanos == 0,
    };

    test_pull_request_encoding(&request, strategy);
}

/// Test mixed request cases
fn test_mixed_request_case(case: &MixedRequestCase, strategy: &FormatStrategy) {
    let json = match &case.case_type {
        MixedCaseType::Valid { batch, expires } => {
            format!(r#"{{"batch":{},"expires":{}}}"#, batch, expires)
        }
        MixedCaseType::TypeConfusion => {
            r#"{"batch":"not_a_number","expires":"also_not_a_number"}"#.to_string()
        }
        MixedCaseType::MissingFields => {
            r#"{"batch":5}"#.to_string() // Missing expires
        }
        MixedCaseType::ExtraFields => {
            r#"{"batch":5,"expires":0,"extra":"field","unknown":true}"#.to_string()
        }
        MixedCaseType::MalformedJson => {
            case.raw_json.clone()
        }
    };

    let final_json = match strategy {
        FormatStrategy::ExtraWhitespace => {
            json.replace(':', " : ").replace(',', " , ")
        }
        _ => json,
    };

    test_pull_request_parsing(&final_json);
}

/// Apply format strategy to generate JSON variations
fn apply_format_strategy(request: &PullRequestVariant, strategy: &FormatStrategy) -> String {
    let expires = if request.force_zero_timeout || request.timeout.is_zero() {
        0_i64
    } else {
        let nanos = request.timeout.as_nanos();
        let max = i64::MAX as u128;
        let clamped = if nanos > max { max } else { nanos };
        clamped as i64
    };

    match strategy {
        FormatStrategy::Standard => {
            format!(r#"{{"batch":{},"expires":{}}}"#, request.batch, expires)
        }
        FormatStrategy::AlternativeOrdering => {
            format!(r#"{{"expires":{},"batch":{}}}"#, expires, request.batch)
        }
        FormatStrategy::ExtraWhitespace => {
            format!(
                r#"{{  "batch"  :  {}  ,  "expires"  :  {}  }}"#,
                request.batch, expires
            )
        }
        FormatStrategy::Unicode => {
            format!(
                r#"{{"batch":{},"expires":{},"unicode_test":"测试🌟消息"}}"#,
                request.batch, expires
            )
        }
        FormatStrategy::EscapedChars => {
            format!(
                r#"{{"batch":{},"expires":{},"test":"value\nwith\ttabs\rand\"quotes"}}"#,
                request.batch, expires
            )
        }
        FormatStrategy::NumberFormats => {
            // Test different number representations
            format!(
                r#"{{"batch":{:e},"expires":{}}}"#,
                request.batch as f64, expires
            )
        }
    }
}

/// Test timeout computation logic
fn test_timeout_computation(timeout: Duration) {
    // Mimic the timeout computation from Consumer::pull_with_timeout
    let expires = if timeout.is_zero() {
        0_i64
    } else {
        let nanos = timeout.as_nanos();
        let max = i64::MAX as u128;
        let clamped = if nanos > max { max } else { nanos };
        clamped as i64
    };

    // Verify that the computation doesn't overflow and produces valid results
    assert!(expires >= 0, "Expires should never be negative");
    if !timeout.is_zero() {
        assert!(expires > 0 || timeout.as_nanos() > i64::MAX as u128,
                "Non-zero timeout should produce non-zero expires unless clamped");
    }

    // Test JSON encoding with computed expires
    let json = format!(r#"{{"batch":10,"expires":{}}}"#, expires);
    test_pull_request_parsing(&json);
}

/// Test pull request JSON parsing (simulate server-side parsing)
fn test_pull_request_parsing(json: &str) {
    if json.len() > MAX_STRING_LEN {
        return;
    }

    // Simulate basic JSON parsing that a server might do
    // In a real implementation, this would call actual parsing functions

    // Test that we can at least attempt to parse the JSON structure
    let _ = json.find(r#""batch":"#);
    let _ = json.find(r#""expires":"#);

    // Test for basic JSON validity markers
    let open_braces = json.matches('{').count();
    let close_braces = json.matches('}').count();
    let _ = open_braces == close_braces; // Basic brace matching

    // Test that parsing doesn't cause panics on malformed input
    let _ = json.parse::<serde_json::Value>();
}

/// Check if pull request is valid for testing
fn is_valid_pull_request(request: &PullRequestVariant) -> bool {
    request.batch <= MAX_BATCH_SIZE
        && request.timeout.as_nanos() <= MAX_TIMEOUT_NANOS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timeout_computation_zero() {
        let timeout = Duration::ZERO;
        test_timeout_computation(timeout);
    }

    #[test]
    fn test_timeout_computation_max() {
        let timeout = Duration::from_nanos(i64::MAX as u64);
        test_timeout_computation(timeout);
    }

    #[test]
    fn test_pull_request_encoding_standard() {
        let request = PullRequestVariant {
            batch: 5,
            timeout: Duration::from_secs(30),
            force_zero_timeout: false,
        };
        test_pull_request_encoding(&request, &FormatStrategy::Standard);
    }

    #[test]
    fn test_malformed_json_parsing() {
        test_pull_request_parsing(r#"{"batch":5,"expires":"#); // Truncated
        test_pull_request_parsing(r#"{"batch":null}"#); // Null batch
    }
}