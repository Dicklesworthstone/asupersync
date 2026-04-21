#![no_main]

use arbitrary::Arbitrary;
use asupersync::observability::otel::span_semantics::{SpanConformanceConfig, TestSpan};
use libfuzzer_sys::fuzz_target;
use opentelemetry::trace::SpanKind;
use std::collections::{BTreeMap, HashMap};

const MAX_OPERATIONS: usize = 64;
const MAX_EVENT_ATTRIBUTES: usize = 8;
const MAX_VALUE_CHARS: usize = 32;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    max_attributes: u8,
    max_events: u8,
    max_attribute_length: Option<u8>,
    operations: Vec<Operation>,
}

#[derive(Arbitrary, Debug)]
enum Operation {
    SetAttribute(AttributeInput),
    AddEvent(EventInput),
}

#[derive(Arbitrary, Debug)]
struct AttributeInput {
    slot: u8,
    value: AttributeValue,
}

#[derive(Arbitrary, Debug)]
struct EventInput {
    slot: u8,
    attributes: Vec<AttributeInput>,
}

#[derive(Arbitrary, Debug)]
enum AttributeValue {
    Text(String),
    Bool(bool),
    Signed(i16),
    Unsigned(u16),
    Float(f32),
    Jsonish(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Default)]
struct ShadowSpan {
    attributes: BTreeMap<String, String>,
    events: Vec<ShadowEvent>,
}

#[derive(Debug)]
struct ShadowEvent {
    name: String,
    attributes: BTreeMap<String, String>,
}

fuzz_target!(|input: FuzzInput| {
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    let config = SpanConformanceConfig {
        max_attributes: usize::from(input.max_attributes % 9),
        max_events: usize::from(input.max_events % 9),
        max_attribute_length: input
            .max_attribute_length
            .map(|limit| usize::from(limit % 17)),
        test_sampling: true,
        test_context_propagation: true,
    };

    let mut span = TestSpan::new_with_config("otel_span_attributes", SpanKind::Internal, &config);
    let mut shadow = ShadowSpan::default();

    for operation in input.operations {
        match operation {
            Operation::SetAttribute(attribute) => {
                let key = attribute_key(attribute.slot);
                let value = attribute.value.encode();
                span.set_attribute(&key, &value);
                shadow_set_attribute(&mut shadow, &config, key, value);
            }
            Operation::AddEvent(event) => {
                let name = event_name(event.slot);
                let attributes = event_attributes(event.attributes);
                span.add_event(&name, attributes.clone());
                shadow_add_event(&mut shadow, &config, name, attributes);
            }
        }

        assert_matches_shadow(&span, &shadow, config.max_attribute_length);
    }
});

fn attribute_key(slot: u8) -> String {
    format!("attr.{}", slot % 6)
}

fn event_name(slot: u8) -> String {
    format!("event.{}", slot % 4)
}

impl AttributeValue {
    fn encode(self) -> String {
        match self {
            Self::Text(text) => format!("text:{}", bounded_text(&text)),
            Self::Bool(value) => format!("bool:{value}"),
            Self::Signed(value) => format!("i16:{value}"),
            Self::Unsigned(value) => format!("u16:{value}"),
            Self::Float(value) => format!("f32:{value:?}"),
            Self::Jsonish(text) => format!("json:{{\"text\":{:?}}}", bounded_text(&text)),
            Self::Bytes(bytes) => {
                let bounded: Vec<u8> = bytes.into_iter().take(MAX_VALUE_CHARS).collect();
                format!("bytes:{bounded:?}")
            }
        }
    }
}

fn bounded_text(text: &str) -> String {
    text.chars().take(MAX_VALUE_CHARS).collect()
}

fn truncate_value(value: &str, max_len: Option<usize>) -> String {
    match max_len {
        Some(limit) => value.chars().take(limit).collect(),
        None => value.to_string(),
    }
}

fn event_attributes(attributes: Vec<AttributeInput>) -> HashMap<String, String> {
    let mut encoded = HashMap::new();
    for attribute in attributes.into_iter().take(MAX_EVENT_ATTRIBUTES) {
        encoded.insert(attribute_key(attribute.slot), attribute.value.encode());
    }
    encoded
}

fn shadow_set_attribute(
    shadow: &mut ShadowSpan,
    config: &SpanConformanceConfig,
    key: String,
    value: String,
) {
    let value = truncate_value(&value, config.max_attribute_length);
    if shadow.attributes.contains_key(&key) || shadow.attributes.len() < config.max_attributes {
        shadow.attributes.insert(key, value);
    }
}

fn shadow_add_event(
    shadow: &mut ShadowSpan,
    config: &SpanConformanceConfig,
    name: String,
    attributes: HashMap<String, String>,
) {
    if shadow.events.len() >= config.max_events {
        return;
    }

    let attributes = attributes
        .into_iter()
        .map(|(key, value)| (key, truncate_value(&value, config.max_attribute_length)))
        .collect();
    shadow.events.push(ShadowEvent { name, attributes });
}

fn assert_matches_shadow(
    span: &TestSpan,
    shadow: &ShadowSpan,
    max_attribute_length: Option<usize>,
) {
    assert_eq!(span.attributes.len(), shadow.attributes.len());
    for (key, expected) in &shadow.attributes {
        let actual = span
            .attributes
            .get(key)
            .expect("shadowed span attribute must exist");
        assert_eq!(actual, expected);
        assert_within_limit(actual, max_attribute_length);
    }

    assert_eq!(span.events.len(), shadow.events.len());
    let mut last_timestamp = span.start_time;
    for (actual, expected) in span.events.iter().zip(&shadow.events) {
        assert_eq!(actual.name, expected.name);
        assert!(actual.timestamp >= last_timestamp);
        last_timestamp = actual.timestamp;

        assert_eq!(actual.attributes.len(), expected.attributes.len());
        for (key, expected_value) in &expected.attributes {
            let actual_value = actual
                .attributes
                .get(key)
                .expect("shadowed event attribute must exist");
            assert_eq!(actual_value, expected_value);
            assert_within_limit(actual_value, max_attribute_length);
        }
    }
}

fn assert_within_limit(value: &str, max_attribute_length: Option<usize>) {
    if let Some(limit) = max_attribute_length {
        assert!(value.chars().count() <= limit);
    }
}
