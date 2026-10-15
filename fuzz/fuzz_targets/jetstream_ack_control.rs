#![no_main]

//! Dedicated structure-aware fuzz target for JetStream ack control token parser.
//!
//! br-asupersync-6ba4qs — This fuzz target exercises the JetStream ack/nak/term/
//! in-progress/release control token parser using intelligent input generation
//! to find edge cases in the protocol parsing logic.
//!
//! Control tokens tested:
//! - `+ACK` - acknowledge message
//! - `-NAK` - negative acknowledge (request redelivery)
//! - `+WPI` - work in progress (extend ack deadline)
//! - `+TERM` - terminate message
//! - Unknown/malformed tokens
//!
//! Usage: cargo fuzz run jetstream_ack_control

use arbitrary::{Arbitrary, Unstructured};
use asupersync::messaging::jetstream::{FuzzJsAckControl, fuzz_parse_ack_control};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

/// Maximum size for control token payload (reasonable upper bound)
const MAX_TOKEN_SIZE: usize = 256;
static FIXED_ACK_CONTROL_CANARIES: OnceLock<()> = OnceLock::new();

/// Structure-aware generator for JetStream ack control tokens
#[derive(Arbitrary, Debug, Clone)]
struct AckControlToken {
    /// The control token variant to generate
    variant: ControlTokenVariant,
    /// Additional fuzzing parameters
    params: FuzzParams,
}

/// All possible control token variants for structure-aware generation
#[derive(Arbitrary, Debug, Clone)]
enum ControlTokenVariant {
    /// Valid +ACK token
    Ack,
    /// Valid -NAK token
    Nak,
    /// Valid +WPI (work in progress) token
    InProgress,
    /// Valid +TERM token
    Term,
    /// Malformed tokens for edge case testing
    Malformed(MalformedToken),
}

/// Parameters for fuzzing edge cases and protocol violations
#[derive(Arbitrary, Debug, Clone)]
struct FuzzParams {
    /// Add leading whitespace/control chars
    leading_junk: Vec<u8>,
    /// Add trailing garbage
    trailing_junk: Vec<u8>,
    /// Use wrong case (lowercase/mixed)
    wrong_case: bool,
    /// Insert null bytes
    null_injection: bool,
    /// Repeat the token multiple times
    repetition_count: u8,
}

/// Malformed token variants for boundary testing
#[derive(Arbitrary, Debug, Clone)]
enum MalformedToken {
    /// Empty token
    Empty,
    /// Only prefix (+ or -)
    OnlyPrefix,
    /// Invalid prefix character
    InvalidPrefix(u8),
    /// Valid prefix but unknown command
    UnknownCommand(Vec<u8>),
    /// Extremely long token
    VeryLong(Vec<u8>),
    /// Binary garbage
    BinaryGarbage(Vec<u8>),
    /// Unicode/UTF-8 sequences
    Unicode(String),
    /// SQL injection style
    SqlInjection,
    /// Shell command injection style
    ShellInjection,
}

impl AckControlToken {
    fn repeat_count(&self) -> usize {
        usize::from(self.params.repetition_count % 10) + 1
    }

    /// Generate the raw bytes for this token configuration
    fn materialize(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Add leading junk if specified
        result.extend_from_slice(&self.params.leading_junk);

        // Generate the base token
        let base_token = match &self.variant {
            ControlTokenVariant::Ack => {
                if self.params.wrong_case {
                    b"+ack".to_vec()
                } else {
                    b"+ACK".to_vec()
                }
            }
            ControlTokenVariant::Nak => {
                if self.params.wrong_case {
                    b"-nak".to_vec()
                } else {
                    b"-NAK".to_vec()
                }
            }
            ControlTokenVariant::InProgress => {
                if self.params.wrong_case {
                    b"+wpi".to_vec()
                } else {
                    b"+WPI".to_vec()
                }
            }
            ControlTokenVariant::Term => {
                if self.params.wrong_case {
                    b"+term".to_vec()
                } else {
                    b"+TERM".to_vec()
                }
            }
            ControlTokenVariant::Malformed(malformed) => self.materialize_malformed(malformed),
        };

        // Apply repetition if specified
        for _ in 0..self.repeat_count() {
            result.extend_from_slice(&base_token);

            // Add null injection between repetitions
            if self.params.null_injection {
                result.push(0);
            }
        }

        // Add trailing junk if specified
        result.extend_from_slice(&self.params.trailing_junk);

        // Ensure reasonable size limit
        result.truncate(MAX_TOKEN_SIZE);

        result
    }

    /// Generate malformed token bytes for boundary testing
    fn materialize_malformed(&self, malformed: &MalformedToken) -> Vec<u8> {
        match malformed {
            MalformedToken::Empty => Vec::new(),
            MalformedToken::OnlyPrefix => b"+".to_vec(),
            MalformedToken::InvalidPrefix(prefix) => vec![*prefix],
            MalformedToken::UnknownCommand(cmd) => {
                let mut result = b"+".to_vec();
                result.extend_from_slice(cmd);
                result
            }
            MalformedToken::VeryLong(data) => {
                let mut result = b"+".to_vec();
                result.extend_from_slice(data);
                result
            }
            MalformedToken::BinaryGarbage(data) => data.clone(),
            MalformedToken::Unicode(s) => s.as_bytes().to_vec(),
            MalformedToken::SqlInjection => b"+'; DROP TABLE acks; --".to_vec(),
            MalformedToken::ShellInjection => b"+ACK; rm -rf /".to_vec(),
        }
    }

    /// Determine the expected parse result for this token
    fn expected_result(&self) -> FuzzJsAckControl {
        match &self.variant {
            ControlTokenVariant::Ack if !self.params.wrong_case => FuzzJsAckControl::Ack,
            ControlTokenVariant::Nak if !self.params.wrong_case => FuzzJsAckControl::Nak,
            ControlTokenVariant::InProgress if !self.params.wrong_case => {
                FuzzJsAckControl::InProgress
            }
            ControlTokenVariant::Term if !self.params.wrong_case => FuzzJsAckControl::Term,
            // Everything else should parse as Unknown
            _ => FuzzJsAckControl::Unknown,
        }
    }
}

fuzz_target!(|data: &[u8]| {
    FIXED_ACK_CONTROL_CANARIES.get_or_init(run_fixed_ack_control_canaries);

    // Limit input size to prevent excessive memory usage
    if data.len() > MAX_TOKEN_SIZE {
        return;
    }

    // Test 1: Direct raw bytes fuzzing (classic approach)
    let raw_result = observe_ack_control(data, "raw");

    // Verify the result is one of the valid enum variants
    match raw_result {
        FuzzJsAckControl::Ack
        | FuzzJsAckControl::Nak
        | FuzzJsAckControl::InProgress
        | FuzzJsAckControl::Term
        | FuzzJsAckControl::Unknown => {
            // Valid result, continue
        }
    }

    // Test 2: Structure-aware fuzzing if we can parse the input
    let mut u = Unstructured::new(data);
    if let Ok(token) = AckControlToken::arbitrary(&mut u) {
        let generated_bytes = token.materialize();

        // Don't fuzz empty tokens (not interesting)
        if generated_bytes.is_empty() {
            return;
        }

        let structured_result = observe_ack_control(&generated_bytes, "structured");
        let expected = token.expected_result();

        // For well-formed tokens, verify the parser behaves correctly
        if !token.params.leading_junk.is_empty()
            || !token.params.trailing_junk.is_empty()
            || token.params.null_injection
            || token.repeat_count() > 1
        {
            // Malformed due to extra junk - should be Unknown
            assert_eq!(
                structured_result,
                FuzzJsAckControl::Unknown,
                "Junk-padded token should parse as Unknown: {:?}",
                String::from_utf8_lossy(&generated_bytes)
            );
        } else {
            // Clean token - should match expected result
            assert_eq!(
                structured_result,
                expected,
                "Clean token parse mismatch: {:?} -> expected {:?}, got {:?}",
                String::from_utf8_lossy(&generated_bytes),
                expected,
                structured_result
            );
        }
    }

    // Test 3: Boundary condition fuzzing
    fuzz_boundary_conditions(data);
});

/// Test specific boundary conditions and edge cases
fn fuzz_boundary_conditions(data: &[u8]) {
    // Test very short inputs
    if data.len() <= 8 {
        observe_ack_control(data, "short");
    }

    // Test exact valid token lengths
    let valid_tokens: [&[u8]; 4] = [b"+ACK", b"-NAK", b"+WPI", b"+TERM"];
    for token in valid_tokens {
        if data.len() >= token.len() {
            let mut modified = token.to_vec();
            // Corrupt the token using input data
            for (i, &byte) in data.iter().enumerate().take(token.len()) {
                modified[i] ^= byte; // XOR corruption
            }
            observe_ack_control(&modified, "corrupted-valid-token");
        }
    }

    // Test prefix-only inputs
    if !data.is_empty() {
        let prefix_only = vec![data[0]];
        observe_ack_control(&prefix_only, "prefix-only");
    }

    // Test null-terminated variants
    if data.len() > 4 {
        let mut null_term = data[..4].to_vec();
        null_term.push(0);
        observe_ack_control(&null_term, "null-terminated");
    }
}

fn run_fixed_ack_control_canaries() {
    for (bytes, expected) in [
        (&b"+ACK"[..], FuzzJsAckControl::Ack),
        (&b"-NAK"[..], FuzzJsAckControl::Nak),
        (&b"+WPI"[..], FuzzJsAckControl::InProgress),
        (&b"+TERM"[..], FuzzJsAckControl::Term),
        (&b"+ack"[..], FuzzJsAckControl::Unknown),
        (&b"+ACK\0"[..], FuzzJsAckControl::Unknown),
        (&b" +ACK"[..], FuzzJsAckControl::Unknown),
        (&b"+ACK+ACK"[..], FuzzJsAckControl::Unknown),
        (&b"+"[..], FuzzJsAckControl::Unknown),
        (&b""[..], FuzzJsAckControl::Unknown),
    ] {
        let actual = observe_ack_control(bytes, "fixed-canary");
        assert_eq!(actual, expected);
    }
}

fn observe_ack_control(payload: &[u8], context: &str) -> FuzzJsAckControl {
    let result = fuzz_parse_ack_control(payload);
    let expected = expected_ack_control(payload);
    assert_eq!(
        result,
        expected,
        "{context} JetStream ack control parse mismatch for {:?}",
        String::from_utf8_lossy(payload)
    );
    result
}

fn expected_ack_control(payload: &[u8]) -> FuzzJsAckControl {
    match payload {
        b"+ACK" => FuzzJsAckControl::Ack,
        b"-NAK" => FuzzJsAckControl::Nak,
        b"+WPI" => FuzzJsAckControl::InProgress,
        b"+TERM" => FuzzJsAckControl::Term,
        _ => FuzzJsAckControl::Unknown,
    }
}
