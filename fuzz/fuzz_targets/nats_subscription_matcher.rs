//! Structure-aware fuzz target for NATS wildcard subscription matching.
//!
//! This target exercises NATS subject wildcard semantics with adversarial
//! token layouts, invalid wildcard placement, empty segments, and long
//! subjects. The production matcher is checked against a small reference
//! implementation so malformed wildcard forms fail closed instead of being
//! silently accepted.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::nats::subscription_matches_subject;
use libfuzzer_sys::fuzz_target;

const MAX_TOKENS: usize = 24;
const MAX_LITERAL_LEN: usize = 32;
const MAX_REPEAT_TAIL: usize = 48;

#[derive(Arbitrary, Debug, Clone)]
enum PatternTokenSpec {
    Literal(String),
    SingleWildcard,
    TailWildcard,
    InvalidWildcardPlacement(String),
    Empty,
}

#[derive(Arbitrary, Debug, Clone)]
enum SubjectTokenSpec {
    Literal(String),
    WildcardLike(u8),
    Empty,
}

#[derive(Arbitrary, Debug, Clone)]
struct MatcherFuzzInput {
    pattern_tokens: Vec<PatternTokenSpec>,
    subject_tokens: Vec<SubjectTokenSpec>,
    pattern_prefix_dot: bool,
    pattern_suffix_dot: bool,
    subject_prefix_dot: bool,
    subject_suffix_dot: bool,
    repeat_tail_segments: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RefPatternToken<'a> {
    Literal(&'a str),
    SingleWildcard,
    TailWildcard,
}

fn sanitize_literal(raw: &str) -> String {
    let filtered: String = raw
        .chars()
        .filter(|ch| {
            !ch.is_ascii_control() && !ch.is_whitespace() && *ch != '.' && *ch != '*' && *ch != '>'
        })
        .take(MAX_LITERAL_LEN)
        .collect();

    if filtered.is_empty() {
        "x".to_string()
    } else {
        filtered
    }
}

fn render_pattern_token(token: &PatternTokenSpec) -> String {
    match token {
        PatternTokenSpec::Literal(value) => sanitize_literal(value),
        PatternTokenSpec::SingleWildcard => "*".to_string(),
        PatternTokenSpec::TailWildcard => ">".to_string(),
        PatternTokenSpec::InvalidWildcardPlacement(value) => {
            let literal = sanitize_literal(value);
            format!("{literal}*tail")
        }
        PatternTokenSpec::Empty => String::new(),
    }
}

fn render_subject_token(token: &SubjectTokenSpec) -> String {
    match token {
        SubjectTokenSpec::Literal(value) => sanitize_literal(value),
        SubjectTokenSpec::WildcardLike(selector) => match selector % 3 {
            0 => "*".to_string(),
            1 => ">".to_string(),
            _ => "foo*bar".to_string(),
        },
        SubjectTokenSpec::Empty => String::new(),
    }
}

fn render_pattern(input: &MatcherFuzzInput) -> String {
    let mut rendered: Vec<String> = input
        .pattern_tokens
        .iter()
        .take(MAX_TOKENS)
        .map(render_pattern_token)
        .collect();
    if rendered.is_empty() && input.pattern_suffix_dot {
        rendered.push(String::new());
    }

    let mut pattern = rendered.join(".");
    if input.pattern_prefix_dot {
        pattern.insert(0, '.');
    }
    if input.pattern_suffix_dot {
        pattern.push('.');
    }
    pattern
}

fn render_subject(input: &MatcherFuzzInput) -> String {
    let mut rendered: Vec<String> = input
        .subject_tokens
        .iter()
        .take(MAX_TOKENS)
        .map(render_subject_token)
        .collect();

    for _ in 0..usize::from(input.repeat_tail_segments.min(MAX_REPEAT_TAIL as u8)) {
        rendered.push("tail".to_string());
    }

    let mut subject = rendered.join(".");
    if input.subject_prefix_dot {
        subject.insert(0, '.');
    }
    if input.subject_suffix_dot {
        subject.push('.');
    }
    subject
}

fn ref_valid_segment(token: &str) -> bool {
    !token.is_empty()
        && !token
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
}

fn ref_parse_pattern(pattern: &str) -> Option<Vec<RefPatternToken<'_>>> {
    if pattern.is_empty() {
        return None;
    }

    let raw_tokens: Vec<_> = pattern.split('.').collect();
    let raw_len = raw_tokens.len();
    if raw_tokens.iter().any(|token| !ref_valid_segment(token)) {
        return None;
    }

    let mut parsed = Vec::with_capacity(raw_tokens.len());
    for (index, token) in raw_tokens.into_iter().enumerate() {
        match token {
            "*" => parsed.push(RefPatternToken::SingleWildcard),
            ">" if index + 1 == raw_len => parsed.push(RefPatternToken::TailWildcard),
            ">" => return None,
            _ if token.contains('*') || token.contains('>') => return None,
            _ => parsed.push(RefPatternToken::Literal(token)),
        }
    }

    Some(parsed)
}

fn ref_parse_subject(subject: &str) -> Option<Vec<&str>> {
    if subject.is_empty() {
        return None;
    }

    let tokens: Vec<_> = subject.split('.').collect();
    if tokens
        .iter()
        .any(|token| !ref_valid_segment(token) || token.contains('*') || token.contains('>'))
    {
        return None;
    }

    Some(tokens)
}

fn reference_match(pattern: &str, subject: &str) -> bool {
    let Some(pattern_tokens) = ref_parse_pattern(pattern) else {
        return false;
    };
    let Some(subject_tokens) = ref_parse_subject(subject) else {
        return false;
    };

    let mut subject_index = 0usize;
    for token in pattern_tokens {
        match token {
            RefPatternToken::Literal(literal) => {
                if subject_tokens.get(subject_index) != Some(&literal) {
                    return false;
                }
                subject_index += 1;
            }
            RefPatternToken::SingleWildcard => {
                if subject_tokens.get(subject_index).is_none() {
                    return false;
                }
                subject_index += 1;
            }
            RefPatternToken::TailWildcard => {
                return subject_index < subject_tokens.len();
            }
        }
    }

    subject_index == subject_tokens.len()
}

fuzz_target!(|input: MatcherFuzzInput| {
    let pattern = render_pattern(&input);
    let subject = render_subject(&input);

    let actual = subscription_matches_subject(&pattern, &subject);
    let expected = reference_match(&pattern, &subject);

    assert_eq!(actual, expected, "pattern={pattern:?} subject={subject:?}");

    if !pattern.contains('*')
        && !pattern.contains('>')
        && ref_parse_subject(&pattern).is_some()
        && ref_parse_subject(&subject).is_some()
    {
        assert_eq!(actual, pattern == subject);
    }
});
