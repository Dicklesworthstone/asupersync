#![no_main]

//! Focused fuzz target for JetStream PubAck duplicate detection.
//!
//! The production parser is intentionally exposed through `fuzz_parse_pub_ack`.
//! This target drives that parser directly instead of shadowing its
//! `"duplicate"` extraction logic with a local mock.

use arbitrary::{Arbitrary, Unstructured};
use asupersync::messaging::jetstream::fuzz_parse_pub_ack;
use libfuzzer_sys::fuzz_target;

/// Maximum payload size for reasonable fuzzing performance.
const MAX_PAYLOAD_SIZE: usize = 4096;
const MAX_STRING_CHARS: usize = 128;
const MAX_REPEATED_FIELDS: usize = 4;

#[derive(Arbitrary, Debug, Clone)]
struct PubAckFuzzCase {
    duplicate_variant: DuplicateFieldVariant,
    base_fields: BaseFields,
    corruption: JsonCorruption,
}

#[derive(Arbitrary, Debug, Clone)]
enum DuplicateFieldVariant {
    StandardTrue,
    StandardFalse,
    TitleCaseTrue,
    UpperCaseFalse,
    MixedCase,
    Zero,
    One,
    Null,
    String(String),
    Missing,
    Multiple(Vec<DuplicateFieldLiteral>),
    SpacedBeforeColonTrue,
    EscapedTrueString,
}

#[derive(Arbitrary, Debug, Clone)]
struct BaseFields {
    stream: String,
    seq: u64,
    include_error: bool,
}

#[derive(Arbitrary, Debug, Clone)]
struct JsonCorruption {
    extra_whitespace: WhitespaceVariant,
    field_order: FieldOrder,
    syntax_variant: JsonSyntaxVariant,
}

#[derive(Arbitrary, Debug, Clone)]
enum WhitespaceVariant {
    None,
    Spaces,
    Tabs,
    Newlines,
    Mixed,
}

#[derive(Arbitrary, Debug, Clone)]
enum FieldOrder {
    First,
    Middle,
    Last,
}

#[derive(Arbitrary, Debug, Clone)]
enum JsonSyntaxVariant {
    Standard,
    ExtraCommas,
    NoCommas,
    ExtraQuotes,
    MixedQuotes,
}

#[derive(Arbitrary, Debug, Clone)]
enum DuplicateFieldLiteral {
    True,
    False,
    Zero,
    One,
    Null,
    String(String),
}

impl PubAckFuzzCase {
    fn generate_json(&self) -> String {
        let mut json = String::new();
        json.push('{');

        let mut fields = Vec::new();
        if !self.base_fields.include_error {
            fields.push(format!(
                "\"stream\":\"{}\"",
                escape_json(&self.base_fields.stream)
            ));
            fields.push(format!("\"seq\":{}", self.base_fields.seq));
        } else {
            fields.push("\"error\":{\"code\":500,\"description\":\"fuzz\"}".to_string());
        }

        self.insert_duplicate_fields(&mut fields);

        let separator = match self.corruption.syntax_variant {
            JsonSyntaxVariant::Standard => ",",
            JsonSyntaxVariant::ExtraCommas => ",,",
            JsonSyntaxVariant::NoCommas => "",
            JsonSyntaxVariant::ExtraQuotes => ",\"",
            JsonSyntaxVariant::MixedQuotes => "',",
        };

        json.push_str(&fields.join(separator));
        json.push('}');

        json
    }

    fn insert_duplicate_fields(&self, fields: &mut Vec<String>) {
        let duplicate_fields = self.generate_duplicate_fields();
        if duplicate_fields.is_empty() {
            return;
        }

        match self.corruption.field_order {
            FieldOrder::First => {
                for field in duplicate_fields.into_iter().rev() {
                    fields.insert(0, field);
                }
            }
            FieldOrder::Middle => {
                let mid = fields.len() / 2;
                for (offset, field) in duplicate_fields.into_iter().enumerate() {
                    fields.insert(mid + offset, field);
                }
            }
            FieldOrder::Last => fields.extend(duplicate_fields),
        }
    }

    fn generate_duplicate_fields(&self) -> Vec<String> {
        let whitespace = self.value_whitespace();

        match &self.duplicate_variant {
            DuplicateFieldVariant::StandardTrue => vec![format!("\"duplicate\":{whitespace}true")],
            DuplicateFieldVariant::StandardFalse => {
                vec![format!("\"duplicate\":{whitespace}false")]
            }
            DuplicateFieldVariant::TitleCaseTrue => {
                vec![format!("\"duplicate\":{whitespace}True")]
            }
            DuplicateFieldVariant::UpperCaseFalse => {
                vec![format!("\"duplicate\":{whitespace}FALSE")]
            }
            DuplicateFieldVariant::MixedCase => vec![format!("\"duplicate\":{whitespace}tRuE")],
            DuplicateFieldVariant::Zero => vec![format!("\"duplicate\":{whitespace}0")],
            DuplicateFieldVariant::One => vec![format!("\"duplicate\":{whitespace}1")],
            DuplicateFieldVariant::Null => vec![format!("\"duplicate\":{whitespace}null")],
            DuplicateFieldVariant::String(value) => {
                vec![format!(
                    "\"duplicate\":{whitespace}\"{}\"",
                    escape_json(value)
                )]
            }
            DuplicateFieldVariant::Missing => Vec::new(),
            DuplicateFieldVariant::Multiple(values) => values
                .iter()
                .take(MAX_REPEATED_FIELDS)
                .map(|value| format!("\"duplicate\":{whitespace}{}", value.as_json_value()))
                .collect(),
            DuplicateFieldVariant::SpacedBeforeColonTrue => {
                vec![format!("\"duplicate\" :{whitespace}true")]
            }
            DuplicateFieldVariant::EscapedTrueString => {
                vec![format!(
                    "\"duplicate\":{whitespace}\"\\u0074\\u0072\\u0075\\u0065\""
                )]
            }
        }
    }

    fn expected_duplicate_for_canonical_shape(&self) -> Option<bool> {
        if self.base_fields.include_error {
            return None;
        }
        if !matches!(self.corruption.syntax_variant, JsonSyntaxVariant::Standard) {
            return None;
        }

        match &self.duplicate_variant {
            DuplicateFieldVariant::StandardTrue | DuplicateFieldVariant::SpacedBeforeColonTrue => {
                Some(true)
            }
            DuplicateFieldVariant::StandardFalse | DuplicateFieldVariant::Missing => Some(false),
            DuplicateFieldVariant::TitleCaseTrue
            | DuplicateFieldVariant::UpperCaseFalse
            | DuplicateFieldVariant::MixedCase
            | DuplicateFieldVariant::Zero
            | DuplicateFieldVariant::One
            | DuplicateFieldVariant::Null
            | DuplicateFieldVariant::String(_)
            | DuplicateFieldVariant::Multiple(_)
            | DuplicateFieldVariant::EscapedTrueString => None,
        }
    }

    fn value_whitespace(&self) -> &'static str {
        match self.corruption.extra_whitespace {
            WhitespaceVariant::None => "",
            WhitespaceVariant::Spaces => "   ",
            WhitespaceVariant::Tabs => "\t\t",
            WhitespaceVariant::Newlines => "\n\n",
            WhitespaceVariant::Mixed => " \t\n ",
        }
    }
}

impl DuplicateFieldLiteral {
    fn as_json_value(&self) -> String {
        match self {
            Self::True => "true".to_string(),
            Self::False => "false".to_string(),
            Self::Zero => "0".to_string(),
            Self::One => "1".to_string(),
            Self::Null => "null".to_string(),
            Self::String(value) => format!("\"{}\"", escape_json(value)),
        }
    }
}

fn escape_json(input: &str) -> String {
    let mut escaped = String::new();
    for ch in input.chars().take(MAX_STRING_CHARS) {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn exercise_parser(payload: &[u8]) {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return;
    }

    let _ = fuzz_parse_pub_ack(payload);
}

fn exercise_structured_case(case: &PubAckFuzzCase) {
    let generated_json = case.generate_json();
    let result = fuzz_parse_pub_ack(generated_json.as_bytes());

    if let Some(expected_duplicate) = case.expected_duplicate_for_canonical_shape() {
        let ack = result.expect("canonical generated PubAck should parse");
        assert_eq!(ack.seq, case.base_fields.seq);
        assert_eq!(ack.duplicate, expected_duplicate);
    }
}

fn exercise_curated_cases() {
    let cases: &[(&[u8], bool)] = &[
        (br#"{"stream":"ORDERS","seq":42,"duplicate":true}"#, true),
        (br#"{"stream":"ORDERS","seq":42,"duplicate" : true}"#, true),
        (br#"{"stream":"ORDERS","seq":42,"duplicate":   true}"#, true),
        (br#"{"stream":"ORDERS","seq":42,"duplicate":false}"#, false),
        (br#"{"stream":"ORDERS","seq":42}"#, false),
        (br#"{"stream":"ORDERS","seq":42,"duplicated":true}"#, false),
    ];

    for (payload, expected_duplicate) in cases {
        let ack = fuzz_parse_pub_ack(payload).expect("curated PubAck fixture should parse");
        assert_eq!(ack.duplicate, *expected_duplicate);
    }

    assert!(fuzz_parse_pub_ack(br#"{"error":{"code":500,"description":"fuzz"}}"#).is_err());
}

fuzz_target!(|data: &[u8]| {
    exercise_curated_cases();
    exercise_parser(data);

    let mut u = Unstructured::new(data);
    if let Ok(fuzz_case) = PubAckFuzzCase::arbitrary(&mut u) {
        exercise_structured_case(&fuzz_case);
    }
});
