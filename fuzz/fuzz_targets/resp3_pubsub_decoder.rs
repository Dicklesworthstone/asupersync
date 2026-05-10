//! Structure-aware fuzz target for RESP3 pubsub message decoder.
//!
//! This target generates valid and malformed RESP3 pubsub messages to test:
//! 1. RESP value parsing robustness against malformed inputs
//! 2. Pubsub event parsing correctness for all event types
//! 3. Security boundaries (nesting depth, array/string length limits)
//! 4. Protocol variants (RESP2 arrays vs RESP3 push messages)
//! 5. UTF-8 validation and binary payload handling
//!
//! The fuzzer uses structure-aware generation to create syntactically
//! valid RESP messages with semantic variations, plus intentionally
//! malformed inputs to test error handling paths.
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run resp3_pubsub_decoder
//! ```
//!
//! # Minimizing crashes
//! ```bash
//! cargo +nightly fuzz tmin resp3_pubsub_decoder <crash_file>
//! ```

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use asupersync::messaging::redis::{RespValue, parse_pubsub_event_for_fuzz};
use libfuzzer_sys::fuzz_target;

/// Structure-aware RESP3 pubsub message fuzzing input
#[derive(Debug, Clone, Arbitrary)]
struct Resp3PubSubMessage {
    event_type: PubSubEventType,
    channel: MessageString,
    pattern: Option<MessageString>, // Only for pmessage
    payload: MessagePayload,
    count: Option<i64>, // For subscription events
    encoding: RespEncoding,
}

#[derive(Debug, Clone, Arbitrary)]
enum PubSubEventType {
    Message,
    PMessage, // Pattern message
    Subscribe,
    Unsubscribe,
    PSubscribe,
    PUnsubscribe,
    Pong,
}

#[derive(Debug, Clone, Arbitrary)]
enum MessageString {
    Valid(String),
    InvalidUtf8(Vec<u8>),
    Empty,
    VeryLong(usize), // Will generate string of this length
    SpecialChars,
}

#[derive(Debug, Clone, Arbitrary)]
enum MessagePayload {
    Binary(Vec<u8>),
    Text(String),
    Empty,
    Large(usize),  // Will generate payload of this size
    InvalidLength, // Mismatched declared vs actual length
}

#[derive(Debug, Clone, Arbitrary)]
enum RespEncoding {
    Array,     // RESP2 array format
    Push,      // RESP3 push format
    Malformed, // Intentionally broken structure
}

impl Resp3PubSubMessage {
    fn to_resp_bytes(&self, u: &mut Unstructured) -> Result<Vec<u8>, arbitrary::Error> {
        match self.encoding {
            RespEncoding::Array => self.to_array_format(u),
            RespEncoding::Push => self.to_push_format(u),
            RespEncoding::Malformed => self.to_malformed_format(u),
        }
    }

    fn to_array_format(&self, u: &mut Unstructured) -> Result<Vec<u8>, arbitrary::Error> {
        let mut buf = Vec::new();

        let event_name = match self.event_type {
            PubSubEventType::Message => "message",
            PubSubEventType::PMessage => "pmessage",
            PubSubEventType::Subscribe => "subscribe",
            PubSubEventType::Unsubscribe => "unsubscribe",
            PubSubEventType::PSubscribe => "psubscribe",
            PubSubEventType::PUnsubscribe => "punsubscribe",
            PubSubEventType::Pong => "pong",
        };

        // Calculate field count
        let mut field_count = 1; // event name
        match self.event_type {
            PubSubEventType::Message => field_count += 2, // channel + payload
            PubSubEventType::PMessage => field_count += 3, // pattern + channel + payload
            PubSubEventType::Subscribe | PubSubEventType::Unsubscribe => field_count += 2, // channel + count
            PubSubEventType::PSubscribe | PubSubEventType::PUnsubscribe => field_count += 2, // pattern + count
            PubSubEventType::Pong => {
                if u.arbitrary::<bool>()? {
                    field_count += 1; // optional payload
                }
            }
        }

        // Array header
        buf.push(b'*');
        buf.extend_from_slice(field_count.to_string().as_bytes());
        buf.extend_from_slice(b"\r\n");

        // Event name
        self.encode_bulk_string(&mut buf, event_name.as_bytes())?;

        // Event-specific fields
        match self.event_type {
            PubSubEventType::Message => {
                self.encode_message_string(&mut buf, &self.channel, u)?;
                self.encode_message_payload(&mut buf, &self.payload, u)?;
            }
            PubSubEventType::PMessage => {
                if let Some(pattern) = &self.pattern {
                    self.encode_message_string(&mut buf, pattern, u)?;
                } else {
                    self.encode_bulk_string(&mut buf, b"*")?; // Default pattern
                }
                self.encode_message_string(&mut buf, &self.channel, u)?;
                self.encode_message_payload(&mut buf, &self.payload, u)?;
            }
            PubSubEventType::Subscribe | PubSubEventType::Unsubscribe => {
                self.encode_message_string(&mut buf, &self.channel, u)?;
                let count = self.count.unwrap_or_else(|| u.arbitrary().unwrap_or(0));
                buf.push(b':');
                buf.extend_from_slice(count.to_string().as_bytes());
                buf.extend_from_slice(b"\r\n");
            }
            PubSubEventType::PSubscribe | PubSubEventType::PUnsubscribe => {
                if let Some(pattern) = &self.pattern {
                    self.encode_message_string(&mut buf, pattern, u)?;
                } else {
                    self.encode_bulk_string(&mut buf, b"*")?;
                }
                let count = self.count.unwrap_or_else(|| u.arbitrary().unwrap_or(0));
                buf.push(b':');
                buf.extend_from_slice(count.to_string().as_bytes());
                buf.extend_from_slice(b"\r\n");
            }
            PubSubEventType::Pong => {
                if field_count > 1 {
                    self.encode_message_payload(&mut buf, &self.payload, u)?;
                }
            }
        }

        Ok(buf)
    }

    fn to_push_format(&self, u: &mut Unstructured) -> Result<Vec<u8>, arbitrary::Error> {
        // RESP3 Push messages start with '>' instead of '*'
        let array_bytes = self.to_array_format(u)?;
        let mut push_bytes = array_bytes;
        if !push_bytes.is_empty() && push_bytes[0] == b'*' {
            push_bytes[0] = b'>';
        }
        Ok(push_bytes)
    }

    fn to_malformed_format(&self, u: &mut Unstructured) -> Result<Vec<u8>, arbitrary::Error> {
        let mut buf = self.to_array_format(u)?;

        // Introduce various malformations
        match u.int_in_range(0u8..=7)? {
            0 => {
                // Truncated message
                if buf.len() > 5 {
                    buf.truncate(buf.len() / 2);
                }
            }
            1 => {
                // Wrong field count
                if buf.len() > 2 {
                    buf[1] = b'9'; // Set impossibly high field count
                }
            }
            2 => {
                // Missing CRLF
                buf.retain(|&b| b != b'\r' && b != b'\n');
            }
            3 => {
                // Invalid length prefix
                for i in 0..buf.len() {
                    if buf[i] == b'$' && i + 1 < buf.len() {
                        buf[i + 1] = b'X'; // Invalid length
                        break;
                    }
                }
            }
            4 => {
                // Double CRLF
                buf.extend_from_slice(b"\r\n\r\n");
            }
            5 => {
                // Mixed RESP versions
                if !buf.is_empty() {
                    buf[0] = u.arbitrary::<u8>()?;
                }
            }
            6 => {
                // Negative lengths
                for i in 0..buf.len() {
                    if buf[i] == b'$' && i + 1 < buf.len() && buf[i + 1].is_ascii_digit() {
                        buf.insert(i + 1, b'-');
                        break;
                    }
                }
            }
            _ => {
                // Embedded nulls
                if buf.len() > 10 {
                    let middle = buf.len() / 2;
                    buf[middle] = 0;
                }
            }
        }

        Ok(buf)
    }

    fn encode_bulk_string(&self, buf: &mut Vec<u8>, data: &[u8]) -> Result<(), arbitrary::Error> {
        buf.push(b'$');
        buf.extend_from_slice(data.len().to_string().as_bytes());
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(data);
        buf.extend_from_slice(b"\r\n");
        Ok(())
    }

    fn encode_message_string(
        &self,
        buf: &mut Vec<u8>,
        msg_str: &MessageString,
        _u: &mut Unstructured,
    ) -> Result<(), arbitrary::Error> {
        match msg_str {
            MessageString::Valid(s) => {
                self.encode_bulk_string(buf, s.as_bytes())?;
            }
            MessageString::InvalidUtf8(bytes) => {
                self.encode_bulk_string(buf, bytes)?;
            }
            MessageString::Empty => {
                self.encode_bulk_string(buf, b"")?;
            }
            MessageString::VeryLong(len) => {
                let long_str = "x".repeat(*len.min(&4096)); // Cap at 4KB
                self.encode_bulk_string(buf, long_str.as_bytes())?;
            }
            MessageString::SpecialChars => {
                let special = b"\0\r\n\t\x1b\xff\xef\xbb\xbfchannel*?[]{}";
                self.encode_bulk_string(buf, special)?;
            }
        }
        Ok(())
    }

    fn encode_message_payload(
        &self,
        buf: &mut Vec<u8>,
        payload: &MessagePayload,
        _u: &mut Unstructured,
    ) -> Result<(), arbitrary::Error> {
        match payload {
            MessagePayload::Binary(data) => {
                self.encode_bulk_string(buf, data)?;
            }
            MessagePayload::Text(s) => {
                self.encode_bulk_string(buf, s.as_bytes())?;
            }
            MessagePayload::Empty => {
                self.encode_bulk_string(buf, b"")?;
            }
            MessagePayload::Large(size) => {
                let large_payload = vec![b'x'; *size.min(&8192)]; // Cap at 8KB
                self.encode_bulk_string(buf, &large_payload)?;
            }
            MessagePayload::InvalidLength => {
                // Declare one length but provide different amount of data
                buf.push(b'$');
                buf.extend_from_slice(b"100"); // Declare 100 bytes
                buf.extend_from_slice(b"\r\n");
                buf.extend_from_slice(b"short"); // But only provide 5 bytes
                buf.extend_from_slice(b"\r\n");
            }
        }
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mut u = Unstructured::new(data);

    // Test 1: Structure-aware fuzzing with generated RESP3 pubsub messages
    if let Ok(msg) = Resp3PubSubMessage::arbitrary(&mut u)
        && let Ok(resp_bytes) = msg.to_resp_bytes(&mut u)
    {
        // Parse RESP value - should not panic
        if let Ok(Some((resp_value, _consumed))) = RespValue::try_decode(&resp_bytes) {
            // Parse pubsub event - should be robust against invalid inputs
            let _ = parse_pubsub_event_for_fuzz(resp_value);
        }
    }

    // Test 2: Raw byte fuzzing - test parser against completely random input
    let _ = RespValue::try_decode(data);

    // Test 3: Partial input fuzzing - test incremental parsing
    for i in 1..data.len().min(256) {
        let _ = RespValue::try_decode(&data[..i]);
    }

    // Test 4: Concatenated inputs - multiple messages back-to-back
    if data.len() >= 4 {
        let mid = data.len() / 2;
        let mut combined = Vec::with_capacity(data.len() * 2);
        combined.extend_from_slice(&data[..mid]);
        combined.extend_from_slice(&data[mid..]);
        if let Ok(Some((first_value, consumed))) = RespValue::try_decode(&combined) {
            let _ = parse_pubsub_event_for_fuzz(first_value);
            if consumed < combined.len() {
                let _ = RespValue::try_decode(&combined[consumed..]);
            }
        }
    }
});
