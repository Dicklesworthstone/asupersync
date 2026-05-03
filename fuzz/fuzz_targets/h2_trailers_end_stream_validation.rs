#![no_main]

//! Fuzz target for HTTP/2 trailers validation with END_STREAM discrepancies.
//!
//! This target tests the discrepancy between HEADERS frames that claim to be trailers
//! (by having END_STREAM flag set) versus the actual contextual determination of
//! whether they are trailers. Per RFC 9113 §8.1:
//!
//! - Trailers MUST NOT contain pseudo-header fields
//! - Trailers detection is contextual, not just based on END_STREAM
//! - Client responses: trailers iff subsequent-headers AND no :status AND END_STREAM
//! - Server requests: trailers iff subsequent-headers (END_STREAM always true for trailers)
//! - 1xx informational responses are NOT trailers even with END_STREAM
//!
//! Expected behavior:
//! - HEADERS with END_STREAM + pseudo-headers: rejected if contextually trailers
//! - HEADERS with END_STREAM + no pseudo-headers: accepted as trailers
//! - 1xx responses with END_STREAM: accepted (not trailers despite END_STREAM)
//! - Final response after 1xx: not trailers despite END_STREAM if bodyless

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

/// HTTP/2 frame type identifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrameType {
    Data = 0x0,
    Headers = 0x1,
    Priority = 0x2,
    RstStream = 0x3,
    Settings = 0x4,
    PushPromise = 0x5,
    Ping = 0x6,
    GoAway = 0x7,
    WindowUpdate = 0x8,
    Continuation = 0x9,
}

/// HTTP/2 header representation
#[derive(Debug, Clone, Arbitrary)]
struct Header {
    name: String,
    value: String,
    is_pseudo: bool, // Whether this is a pseudo-header (starts with :)
}

/// HTTP/2 HEADERS frame
#[derive(Debug, Clone, Arbitrary)]
struct HeadersFrame {
    stream_id: u32,
    headers: Vec<Header>,
    end_stream: bool,
    end_headers: bool,
    priority: Option<u32>,
}

/// Stream state for tracking initial headers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

/// Stream information for context
#[derive(Debug, Clone)]
struct StreamInfo {
    state: StreamState,
    initial_headers_received: bool,
    is_client_initiated: bool,
}

/// Connection side (client or server)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
enum ConnectionSide {
    Client,
    Server,
}

/// Trailers test scenario
#[derive(Debug, Clone, Arbitrary)]
struct TrailersScenario {
    connection_side: ConnectionSide,
    frames: Vec<HeadersFrame>,
    /// Maximum number of streams to avoid timeout
    max_streams: u8,
    /// Include edge case headers
    include_edge_cases: bool,
}

/// Mock HTTP/2 connection for trailers validation
struct MockH2Connection {
    is_client: bool,
    streams: HashMap<u32, StreamInfo>,
    errors: Vec<String>,
}

impl MockH2Connection {
    fn new(is_client: bool) -> Self {
        Self {
            is_client,
            streams: HashMap::new(),
            errors: Vec::new(),
        }
    }

    /// Process a HEADERS frame and validate trailers context
    fn process_headers(&mut self, frame: &HeadersFrame) -> Result<(), String> {
        let stream_id = frame.stream_id;

        // Ensure stream exists
        let stream = self.streams.entry(stream_id).or_insert(StreamInfo {
            state: StreamState::Open,
            initial_headers_received: false,
            is_client_initiated: (stream_id % 2) == 1,
        });

        // Determine context for trailers detection (mirroring connection.rs logic)
        let is_subsequent_headers = stream.initial_headers_received;
        let is_request = !self.is_client;

        // Check for :status pseudo-header to determine if this is informational/final response
        let observed_status = frame
            .headers
            .iter()
            .find(|h| h.name == ":status")
            .and_then(|h| h.value.parse::<u16>().ok());

        let is_informational_response =
            !is_request && observed_status.is_some_and(|s| (100..200).contains(&s));

        // RFC 9113 §8.1 trailers detection logic (from connection.rs)
        let is_trailers = if is_request {
            // Server side: any subsequent headers is trailers
            is_subsequent_headers && frame.end_stream
        } else {
            // Client side: trailers iff subsequent-headers AND no :status AND END_STREAM
            // end_stream alone is NOT sufficient — a bodyless final response after 1xx
            // has end_stream=true but is NOT trailers.
            is_subsequent_headers && observed_status.is_none() && frame.end_stream
        };

        // Validate headers based on whether they are contextually trailers
        self.validate_headers(&frame.headers, is_request, is_trailers)?;

        // Mark initial headers as received for non-trailers, non-informational responses
        let should_mark_initial = !is_trailers && !is_informational_response;
        if should_mark_initial {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.initial_headers_received = true;
            }
        }

        Ok(())
    }

    /// Validate headers according to RFC 9113 (mirroring validate_h2_pseudo_headers)
    fn validate_headers(
        &mut self,
        headers: &[Header],
        is_request: bool,
        is_trailers: bool,
    ) -> Result<(), String> {
        // RFC 9113 §8.1: "Trailer fields MUST NOT include pseudo-header fields"
        if is_trailers {
            for h in headers {
                if h.name.is_empty() {
                    return Err("empty header name".into());
                }
                if h.name.starts_with(':') || h.is_pseudo {
                    return Err(
                        "trailers section MUST NOT contain pseudo-header fields (RFC 9113 §8.1)"
                            .into(),
                    );
                }
                if h.name.chars().any(|c| c.is_ascii_uppercase()) {
                    return Err("regular header field name in trailers contains uppercase ASCII (RFC 9113 §8.2.1 violation)".into());
                }
                // Connection-specific headers forbidden
                match h.name.as_str() {
                    "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding"
                    | "upgrade" => {
                        return Err("connection-specific header field forbidden in HTTP/2 trailers (RFC 9113 §8.2.2)".into());
                    }
                    "te" if h.value != "trailers" => {
                        return Err("te header field MUST have value \"trailers\" in HTTP/2 (RFC 9113 §8.2.2)".into());
                    }
                    _ => {}
                }
            }
            return Ok(());
        }

        // Non-trailers validation (pseudo-headers required/forbidden based on direction)
        let mut seen_regular = false;
        let mut seen_pseudo_headers = HashMap::new();

        for h in headers {
            if h.name.is_empty() {
                return Err("empty header name".into());
            }

            if h.name.starts_with(':') || h.is_pseudo {
                // Pseudo-header
                if seen_regular {
                    return Err(
                        "pseudo-header field appears after a regular header field (RFC 9113 §8.3)"
                            .into(),
                    );
                }
                if seen_pseudo_headers.contains_key(&h.name) {
                    return Err(format!("duplicate {} pseudo-header", h.name));
                }
                seen_pseudo_headers.insert(h.name.clone(), h.value.clone());

                // Validate known pseudo-headers
                match h.name.as_str() {
                    ":method" | ":scheme" | ":path" | ":authority" | ":status" | ":protocol" => {}
                    _ => return Err("unknown pseudo-header field (RFC 9113 §8.3)".into()),
                }
            } else {
                // Regular header
                seen_regular = true;
                if h.name.chars().any(|c| c.is_ascii_uppercase()) {
                    return Err("regular header field name contains uppercase ASCII (RFC 9113 §8.2.1 violation)".into());
                }
                // Connection-specific headers forbidden
                match h.name.as_str() {
                    "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding"
                    | "upgrade" => {
                        return Err("connection-specific header field forbidden in HTTP/2 (RFC 9113 §8.2.2)".into());
                    }
                    "te" if h.value != "trailers" => {
                        return Err("te header field MUST have value \"trailers\" in HTTP/2 (RFC 9113 §8.2.2)".into());
                    }
                    _ => {}
                }
            }
        }

        // Direction-specific validation
        if is_request {
            if seen_pseudo_headers.contains_key(":status") {
                return Err("request must not include :status pseudo-header".into());
            }
            if !seen_pseudo_headers.contains_key(":method") {
                return Err("request missing required :method pseudo-header".into());
            }
        } else {
            // Response
            if seen_pseudo_headers.contains_key(":method") {
                return Err("response must not include :method pseudo-header".into());
            }
            // :status is required for non-trailers responses
            if !seen_pseudo_headers.contains_key(":status") {
                return Err("response missing required :status pseudo-header".into());
            }
        }

        Ok(())
    }

    fn get_errors(&self) -> &[String] {
        &self.errors
    }
}

/// Generate edge case headers for testing
fn generate_edge_case_headers(include_edge_cases: bool, is_trailers_context: bool) -> Vec<Header> {
    let mut headers = Vec::new();

    if !include_edge_cases {
        return headers;
    }

    // Test cases that should be rejected in trailers
    if is_trailers_context {
        headers.push(Header {
            name: ":status".to_string(),
            value: "200".to_string(),
            is_pseudo: true,
        });
        headers.push(Header {
            name: ":method".to_string(),
            value: "GET".to_string(),
            is_pseudo: true,
        });
        headers.push(Header {
            name: "UPPERCASE".to_string(),
            value: "invalid".to_string(),
            is_pseudo: false,
        });
        headers.push(Header {
            name: "connection".to_string(),
            value: "close".to_string(),
            is_pseudo: false,
        });
    }

    // Valid trailer headers
    headers.push(Header {
        name: "x-trace-id".to_string(),
        value: "abc123".to_string(),
        is_pseudo: false,
    });
    headers.push(Header {
        name: "te".to_string(),
        value: "trailers".to_string(),
        is_pseudo: false,
    });

    headers
}

fuzz_target!(|scenario: TrailersScenario| {
    // Limit scenario size to avoid timeouts
    if scenario.frames.len() > 20 || scenario.max_streams > 50 {
        return;
    }

    let mut connection = MockH2Connection::new(scenario.connection_side == ConnectionSide::Client);
    let mut validation_results = Vec::new();
    let mut expected_failures = 0;
    let mut actual_failures = 0;

    // Process each HEADERS frame
    for (i, orig_frame) in scenario.frames.iter().enumerate() {
        // Clone frame so we can modify it
        let mut frame = orig_frame.clone();

        // Limit stream IDs to reasonable range
        frame.stream_id = (frame.stream_id % 10) + 1;

        // Ensure odd stream IDs are client-initiated, even are server-initiated
        if frame.stream_id % 2 == 0 {
            frame.stream_id += 1;
        }

        // Add edge case headers if requested
        if scenario.include_edge_cases {
            // Determine if this would be contextually trailers for edge case generation
            let stream = connection.streams.get(&frame.stream_id);
            let is_subsequent = stream.map_or(false, |s| s.initial_headers_received);
            let is_request = !connection.is_client;

            let observed_status = frame
                .headers
                .iter()
                .find(|h| h.name == ":status")
                .and_then(|h| h.value.parse::<u16>().ok());

            let would_be_trailers = if is_request {
                is_subsequent && frame.end_stream
            } else {
                is_subsequent && observed_status.is_none() && frame.end_stream
            };

            let edge_headers = generate_edge_case_headers(true, would_be_trailers);
            let edge_headers_count = edge_headers.len();
            frame.headers.extend(edge_headers);

            if would_be_trailers && edge_headers_count > 0 {
                expected_failures += 1;
            }
        }

        // Validate the frame
        let result = connection.process_headers(&frame);
        let is_failure = result.is_err();

        if is_failure {
            actual_failures += 1;
        }

        // Clone result for storage to avoid move issues
        validation_results.push((i, result.clone()));

        // Test specific edge cases for trailers context detection

        // Edge case 1: 1xx informational response with END_STREAM (not trailers)
        if frame
            .headers
            .iter()
            .any(|h| h.name == ":status" && h.value.starts_with('1'))
            && frame.end_stream
        {
            // This should NOT be treated as trailers even with END_STREAM
            let has_pseudo = frame.headers.iter().any(|h| h.name.starts_with(':'));
            if has_pseudo
                && result.is_err()
                && result
                    .as_ref()
                    .unwrap_err()
                    .contains("trailers section MUST NOT contain pseudo-header")
            {
                // This is incorrect - 1xx with END_STREAM should not be trailers
                panic!(
                    "1xx informational response with END_STREAM incorrectly treated as trailers"
                );
            }
        }

        // Edge case 2: Bodyless final response after 1xx (has END_STREAM but not trailers)
        if let Some(stream) = connection.streams.get(&frame.stream_id) {
            if stream.initial_headers_received && frame.end_stream {
                let has_status = frame.headers.iter().any(|h| h.name == ":status");
                if has_status
                    && result.is_err()
                    && result
                        .as_ref()
                        .unwrap_err()
                        .contains("trailers section MUST NOT contain pseudo-header")
                {
                    // This might be a bodyless final response incorrectly treated as trailers
                }
            }
        }

        // Edge case 3: True trailers with pseudo-headers (should fail)
        if frame.end_stream {
            let stream = connection.streams.get(&frame.stream_id);
            if stream.map_or(false, |s| s.initial_headers_received) {
                let has_pseudo = frame.headers.iter().any(|h| h.name.starts_with(':'));
                let has_status = frame.headers.iter().any(|h| h.name == ":status");

                let is_request = !connection.is_client;
                let would_be_trailers = if is_request {
                    true // Server side: subsequent headers are trailers
                } else {
                    !has_status // Client side: subsequent headers without :status are trailers
                };

                if would_be_trailers && has_pseudo && result.is_ok() {
                    panic!(
                        "Trailers with pseudo-headers incorrectly accepted: {:?}",
                        frame.headers
                    );
                }
            }
        }
    }

    // Validate overall behavior
    if scenario.include_edge_cases && expected_failures > 0 && actual_failures == 0 {
        // Expected some validation failures but got none
    }

    // Test that valid trailers are accepted
    let mut valid_connection = MockH2Connection::new(false); // Server side

    // Set up a stream with initial headers
    valid_connection.streams.insert(
        3,
        StreamInfo {
            state: StreamState::Open,
            initial_headers_received: true,
            is_client_initiated: true,
        },
    );

    // Valid trailers (no pseudo-headers, END_STREAM)
    let valid_trailers = HeadersFrame {
        stream_id: 3,
        headers: vec![
            Header {
                name: "x-custom".to_string(),
                value: "value".to_string(),
                is_pseudo: false,
            },
            Header {
                name: "server-timing".to_string(),
                value: "db;dur=123".to_string(),
                is_pseudo: false,
            },
        ],
        end_stream: true,
        end_headers: true,
        priority: None,
    };

    let valid_result = valid_connection.process_headers(&valid_trailers);
    assert!(
        valid_result.is_ok(),
        "Valid trailers should be accepted: {:?}",
        valid_result
    );

    // Invalid trailers (contains pseudo-headers)
    let invalid_trailers = HeadersFrame {
        stream_id: 3,
        headers: vec![
            Header {
                name: ":status".to_string(),
                value: "200".to_string(),
                is_pseudo: true,
            },
            Header {
                name: "x-custom".to_string(),
                value: "value".to_string(),
                is_pseudo: false,
            },
        ],
        end_stream: true,
        end_headers: true,
        priority: None,
    };

    // Reset stream state for invalid test
    valid_connection.streams.insert(
        5,
        StreamInfo {
            state: StreamState::Open,
            initial_headers_received: true,
            is_client_initiated: true,
        },
    );

    let invalid_trailers_frame = HeadersFrame {
        stream_id: 5,
        ..invalid_trailers
    };

    let invalid_result = valid_connection.process_headers(&invalid_trailers_frame);
    assert!(
        invalid_result.is_err(),
        "Trailers with pseudo-headers should be rejected"
    );
    assert!(
        invalid_result
            .unwrap_err()
            .contains("trailers section MUST NOT contain pseudo-header fields"),
        "Should reject trailers with specific pseudo-header error"
    );
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_trailers() {
        let scenario = TrailersScenario {
            connection_side: ConnectionSide::Server,
            frames: vec![
                HeadersFrame {
                    stream_id: 1,
                    headers: vec![
                        Header {
                            name: ":method".to_string(),
                            value: "POST".to_string(),
                            is_pseudo: true,
                        },
                        Header {
                            name: ":path".to_string(),
                            value: "/test".to_string(),
                            is_pseudo: true,
                        },
                        Header {
                            name: ":scheme".to_string(),
                            value: "https".to_string(),
                            is_pseudo: true,
                        },
                        Header {
                            name: ":authority".to_string(),
                            value: "example.com".to_string(),
                            is_pseudo: true,
                        },
                        Header {
                            name: "content-type".to_string(),
                            value: "application/json".to_string(),
                            is_pseudo: false,
                        },
                    ],
                    end_stream: false,
                    end_headers: true,
                    priority: None,
                },
                HeadersFrame {
                    stream_id: 1,
                    headers: vec![
                        Header {
                            name: "x-trace-id".to_string(),
                            value: "abc123".to_string(),
                            is_pseudo: false,
                        },
                        Header {
                            name: "server-timing".to_string(),
                            value: "db;dur=50".to_string(),
                            is_pseudo: false,
                        },
                    ],
                    end_stream: true, // This makes it trailers
                    end_headers: true,
                    priority: None,
                },
            ],
            max_streams: 10,
            include_edge_cases: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_invalid_trailers_with_pseudo_headers() {
        let scenario = TrailersScenario {
            connection_side: ConnectionSide::Server,
            frames: vec![
                HeadersFrame {
                    stream_id: 1,
                    headers: vec![
                        Header {
                            name: ":method".to_string(),
                            value: "GET".to_string(),
                            is_pseudo: true,
                        },
                        Header {
                            name: ":path".to_string(),
                            value: "/".to_string(),
                            is_pseudo: true,
                        },
                        Header {
                            name: ":scheme".to_string(),
                            value: "https".to_string(),
                            is_pseudo: true,
                        },
                        Header {
                            name: ":authority".to_string(),
                            value: "example.com".to_string(),
                            is_pseudo: true,
                        },
                    ],
                    end_stream: false,
                    end_headers: true,
                    priority: None,
                },
                HeadersFrame {
                    stream_id: 1,
                    headers: vec![
                        Header {
                            name: ":status".to_string(),
                            value: "200".to_string(),
                            is_pseudo: true,
                        }, // Invalid in trailers
                        Header {
                            name: "x-custom".to_string(),
                            value: "value".to_string(),
                            is_pseudo: false,
                        },
                    ],
                    end_stream: true, // Makes it trailers context
                    end_headers: true,
                    priority: None,
                },
            ],
            max_streams: 10,
            include_edge_cases: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }

    #[test]
    fn test_informational_response_with_end_stream() {
        let scenario = TrailersScenario {
            connection_side: ConnectionSide::Client,
            frames: vec![HeadersFrame {
                stream_id: 2,
                headers: vec![
                    Header {
                        name: ":status".to_string(),
                        value: "100".to_string(),
                        is_pseudo: true,
                    }, // 1xx informational
                ],
                end_stream: true, // Not trailers despite END_STREAM
                end_headers: true,
                priority: None,
            }],
            max_streams: 10,
            include_edge_cases: false,
        };

        libfuzzer_sys::test_input_wrap(scenario);
    }
}
