//! Fuzz target for `src/web/sse.rs` SSE framing.
//!
//! Exercises `SseEvent`/`Sse` wire rendering against a small reference parser
//! and malformed raw streams to cover:
//! 1. Comment/data/ID/event sanitization and CR normalization
//! 2. Last-Event-ID injection on the terminal event only
//! 3. Retry field numeric parsing
//! 4. Malformed UTF-8 / retry handling without panics
//! 5. Maximum event-size rejection on oversized raw streams

#![no_main]

use arbitrary::Arbitrary;
use asupersync::web::sse::{Sse, SseEvent};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

const MAX_EVENTS: usize = 16;
const MAX_FIELD_CHARS: usize = 256;
const MAX_RAW_BYTES: usize = 8 * 1024;
const MAX_EVENT_SIZE: usize = 4 * 1024;

#[derive(Debug, Clone, Arbitrary)]
enum FuzzInput {
    Structured(StructuredStream),
    Raw { bytes: Vec<u8>, max_event_size: u16 },
}

#[derive(Debug, Clone, Arbitrary)]
struct StructuredStream {
    keep_alive: bool,
    last_event_id: Option<String>,
    events: Vec<EventSpec>,
}

#[derive(Debug, Clone, Arbitrary)]
struct EventSpec {
    event: Option<String>,
    data: Option<String>,
    id: Option<String>,
    retry: RetrySpec,
    comment: Option<String>,
}

#[derive(Debug, Clone, Arbitrary)]
enum RetrySpec {
    None,
    Millis(u64),
    DurationMillis(u32),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ParsedEvent {
    event: Option<String>,
    data: Option<String>,
    id: Option<String>,
    retry: Option<u64>,
}

#[derive(Debug, Clone, Default)]
struct PartialEvent {
    event: Option<String>,
    data_lines: Vec<String>,
    id: Option<String>,
    retry: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseError {
    InvalidUtf8,
    InvalidRetry,
    InvalidId,
    EventTooLarge,
}

fuzz_target!(|input: FuzzInput| {
    fuzz_web_sse(input);
});

fn fuzz_web_sse(input: FuzzInput) {
    match input {
        FuzzInput::Structured(stream) => exercise_structured_stream(stream),
        FuzzInput::Raw {
            bytes,
            max_event_size,
        } => exercise_raw_stream(bytes, usize::from(max_event_size).clamp(1, MAX_EVENT_SIZE)),
    }
}

fn exercise_structured_stream(mut stream: StructuredStream) {
    stream.last_event_id = stream
        .last_event_id
        .map(|value| truncate_text(&value, MAX_FIELD_CHARS));
    stream.events.truncate(MAX_EVENTS);

    let sse = build_sse(&stream);
    let body = sse.to_body();
    assert!(
        !body.contains('\r'),
        "SSE rendering must normalize CR/CRLF to LF-only framing"
    );

    let parsed = parse_sse_stream(body.as_bytes(), MAX_EVENT_SIZE)
        .expect("library-produced SSE output must parse cleanly");
    assert_eq!(parsed, expected_events(&stream));

    let reparsed = parse_sse_stream(render_parsed_stream(&parsed).as_bytes(), MAX_EVENT_SIZE)
        .expect("canonical parsed SSE render must reparse");
    assert_eq!(parsed, reparsed);
}

fn exercise_raw_stream(bytes: Vec<u8>, max_event_size: usize) {
    let bytes = truncate_bytes(bytes, MAX_RAW_BYTES);

    match parse_sse_stream(&bytes, max_event_size) {
        Ok(parsed) => {
            let rendered = render_parsed_stream(&parsed);
            assert!(
                !rendered.contains('\r'),
                "canonical SSE rendering must be LF-only"
            );
            let reparsed = parse_sse_stream(rendered.as_bytes(), MAX_EVENT_SIZE)
                .expect("canonical render must be reparsable");
            assert_eq!(parsed, reparsed);
        }
        Err(ParseError::EventTooLarge) => {
            let _ = parse_sse_stream(&bytes, MAX_EVENT_SIZE);
        }
        Err(ParseError::InvalidUtf8 | ParseError::InvalidRetry | ParseError::InvalidId) => {}
    }
}

fn build_sse(stream: &StructuredStream) -> Sse {
    let events = stream
        .events
        .iter()
        .map(build_event)
        .collect::<Vec<SseEvent>>();

    let mut sse = Sse::new(events);
    if stream.keep_alive {
        sse = sse.keep_alive();
    }
    if let Some(last_event_id) = stream.last_event_id.as_deref() {
        sse = sse.last_event_id(last_event_id);
    }
    sse
}

fn build_event(spec: &EventSpec) -> SseEvent {
    let mut event = SseEvent::default();

    if let Some(name) = spec.event.as_deref() {
        event = event.event(truncate_text(name, MAX_FIELD_CHARS));
    }
    if let Some(data) = spec.data.as_deref() {
        event = event.data(truncate_text(data, MAX_FIELD_CHARS));
    }
    if let Some(id) = spec.id.as_deref() {
        event = event.id(truncate_text(id, MAX_FIELD_CHARS));
    }
    if let Some(comment) = spec.comment.as_deref() {
        event = event.comment(truncate_text(comment, MAX_FIELD_CHARS));
    }

    match spec.retry {
        RetrySpec::None => event,
        RetrySpec::Millis(millis) => event.retry(millis),
        RetrySpec::DurationMillis(millis) => {
            event.retry_duration(Duration::from_millis(u64::from(millis)))
        }
    }
}

fn expected_events(stream: &StructuredStream) -> Vec<ParsedEvent> {
    let mut specs = stream.events.clone();
    specs.truncate(MAX_EVENTS);

    match (
        stream
            .last_event_id
            .as_ref()
            .filter(|last_event_id| !last_event_id.contains('\0')),
        specs.last_mut(),
    ) {
        (Some(last_event_id), Some(last)) => {
            let built_id = sanitize_id(last.id.as_deref().unwrap_or_default());
            if built_id.is_none() {
                last.id = Some(last_event_id.clone());
            }
        }
        _ => {}
    }

    specs
        .iter()
        .filter_map(expected_event_from_spec)
        .collect::<Vec<_>>()
}

fn expected_event_from_spec(spec: &EventSpec) -> Option<ParsedEvent> {
    let event = spec
        .event
        .as_deref()
        .map(|value| strip_field_breaks(&truncate_text(value, MAX_FIELD_CHARS)));

    let data = spec
        .data
        .as_deref()
        .map(|value| normalize_lines(&truncate_text(value, MAX_FIELD_CHARS)).join("\n"));

    let id = spec
        .id
        .as_deref()
        .and_then(|value| sanitize_id(&truncate_text(value, MAX_FIELD_CHARS)));

    let retry = match spec.retry {
        RetrySpec::None => None,
        RetrySpec::Millis(millis) => Some(millis),
        RetrySpec::DurationMillis(millis) => Some(u64::from(millis)),
    };

    let has_fields = event.is_some() || data.is_some() || id.is_some() || retry.is_some();
    has_fields.then_some(ParsedEvent {
        event,
        data,
        id,
        retry,
    })
}

fn parse_sse_stream(bytes: &[u8], max_event_size: usize) -> Result<Vec<ParsedEvent>, ParseError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ParseError::InvalidUtf8)?;
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");

    let mut parsed = Vec::new();
    let mut current = PartialEvent::default();
    let mut event_size = 0usize;
    let mut saw_field = false;

    for line in normalized.split('\n') {
        event_size += line.len() + 1;
        if event_size > max_event_size {
            return Err(ParseError::EventTooLarge);
        }

        if line.is_empty() {
            if saw_field {
                parsed.push(finish_event(&mut current));
                saw_field = false;
            }
            event_size = 0;
            continue;
        }

        if line.starts_with(':') {
            continue;
        }

        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);

        match field {
            "event" => {
                current.event = Some(value.to_string());
                saw_field = true;
            }
            "data" => {
                current.data_lines.push(value.to_string());
                saw_field = true;
            }
            "id" => {
                if value.contains('\0') {
                    return Err(ParseError::InvalidId);
                }
                current.id = Some(value.to_string());
                saw_field = true;
            }
            "retry" => {
                current.retry = Some(value.parse::<u64>().map_err(|_| ParseError::InvalidRetry)?);
                saw_field = true;
            }
            _ => {}
        }
    }

    if saw_field {
        parsed.push(finish_event(&mut current));
    }

    Ok(parsed)
}

fn finish_event(current: &mut PartialEvent) -> ParsedEvent {
    let data = (!current.data_lines.is_empty()).then(|| current.data_lines.join("\n"));
    let parsed = ParsedEvent {
        event: current.event.take(),
        data,
        id: current.id.take(),
        retry: current.retry.take(),
    };
    current.data_lines.clear();
    parsed
}

fn render_parsed_stream(events: &[ParsedEvent]) -> String {
    let mut out = String::new();

    for event in events {
        if let Some(name) = event.event.as_deref() {
            out.push_str("event:");
            out.push_str(name);
            out.push('\n');
        }
        if let Some(data) = event.data.as_deref() {
            for line in data.split('\n') {
                out.push_str("data:");
                out.push_str(line);
                out.push('\n');
            }
        }
        if let Some(id) = event.id.as_deref() {
            out.push_str("id:");
            out.push_str(id);
            out.push('\n');
        }
        if let Some(retry) = event.retry {
            out.push_str("retry:");
            out.push_str(&retry.to_string());
            out.push('\n');
        }
        out.push('\n');
    }

    out
}

fn sanitize_id(value: &str) -> Option<String> {
    (!value.contains('\0')).then(|| strip_field_breaks(value))
}

fn strip_field_breaks(value: &str) -> String {
    value.replace(['\r', '\n'], "")
}

fn normalize_lines(value: &str) -> Vec<String> {
    value
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .map(ToString::to_string)
        .collect()
}

fn truncate_text(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn truncate_bytes(mut bytes: Vec<u8>, max_len: usize) -> Vec<u8> {
    bytes.truncate(max_len);
    bytes
}
