#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::jetstream::{
    JsError, fuzz_parse_api_error, fuzz_validate_consumer_config,
};
use libfuzzer_sys::fuzz_target;

const MAX_NAME_BYTES: usize = 64;
const MAX_FILTERS: usize = 4;
const MAX_TOKEN_BYTES: usize = 16;

#[derive(Debug, Arbitrary)]
struct DurableRecreateInput {
    durable_name: Vec<u8>,
    first_filters: FilterSetInput,
    second_filters: FilterSetInput,
    filter_relation: FieldRelation,
    first_replay_policy: ReplayPolicyInput,
    second_replay_policy: ReplayPolicyInput,
    replay_relation: FieldRelation,
    alias_mode: AliasMode,
}

#[derive(Debug, Arbitrary)]
struct FilterSetInput {
    subjects: Vec<SubjectInput>,
    mode: FilterMode,
}

#[derive(Debug, Arbitrary)]
struct SubjectInput {
    first: Vec<u8>,
    second: Vec<u8>,
    variant: SubjectVariant,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum SubjectVariant {
    Literal,
    SingleWildcard,
    TailWildcard,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FilterMode {
    None,
    FirstOnly,
    All,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum FieldRelation {
    Same,
    Conflict,
    Independent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Arbitrary)]
enum ReplayPolicyInput {
    Instant,
    Original,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum AliasMode {
    Name,
    DurableName,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DurableConsumerShape {
    name: String,
    filters: Vec<String>,
    replay_policy: ReplayPolicyInput,
}

fuzz_target!(|input: DurableRecreateInput| {
    let name = materialize_name(&input.durable_name);
    let first_filters = input.first_filters.materialize();
    let mut second_filters = input.second_filters.materialize();
    match input.filter_relation {
        FieldRelation::Same => second_filters = first_filters.clone(),
        FieldRelation::Conflict => force_filter_conflict(&first_filters, &mut second_filters),
        FieldRelation::Independent => {}
    }

    let first_replay_policy = input.first_replay_policy;
    let mut second_replay_policy = input.second_replay_policy;
    match input.replay_relation {
        FieldRelation::Same => second_replay_policy = first_replay_policy,
        FieldRelation::Conflict => second_replay_policy = first_replay_policy.other(),
        FieldRelation::Independent => {}
    }

    let first = DurableConsumerShape {
        name: name.clone(),
        filters: first_filters,
        replay_policy: first_replay_policy,
    };
    let second = DurableConsumerShape {
        name,
        filters: second_filters,
        replay_policy: second_replay_policy,
    };

    validate_shape(&first, input.alias_mode);
    validate_shape(&second, input.alias_mode);

    match classify_recreate(&first, &second) {
        Ok(()) => {
            assert_eq!(first.name, second.name);
            assert_eq!(first.filters, second.filters);
            assert_eq!(first.replay_policy, second.replay_policy);
        }
        Err(conflict_field) => {
            let err = fuzz_parse_api_error(&conflict_api_error_json(conflict_field));
            match err {
                JsError::Api { code, description } => {
                    assert_eq!(code, 409);
                    assert!(
                        description.contains(conflict_field),
                        "conflicting durable recreate error must identify {conflict_field}: {description}"
                    );
                }
                other => panic!("conflicting durable recreate must parse as API error: {other}"),
            }
        }
    }
});

impl FilterSetInput {
    fn materialize(&self) -> Vec<String> {
        let mut filters = match self.mode {
            FilterMode::None => Vec::new(),
            FilterMode::FirstOnly => self
                .subjects
                .first()
                .map(SubjectInput::materialize)
                .into_iter()
                .collect(),
            FilterMode::All => self
                .subjects
                .iter()
                .take(MAX_FILTERS)
                .map(SubjectInput::materialize)
                .collect(),
        };
        filters.sort();
        filters.dedup();
        filters
    }
}

impl SubjectInput {
    fn materialize(&self) -> String {
        let first = materialize_subject_token(&self.first);
        let second = materialize_subject_token(&self.second);
        match self.variant {
            SubjectVariant::Literal => format!("{first}.{second}"),
            SubjectVariant::SingleWildcard => format!("{first}.*"),
            SubjectVariant::TailWildcard => format!("{first}.>"),
        }
    }
}

impl ReplayPolicyInput {
    fn other(self) -> Self {
        match self {
            Self::Instant => Self::Original,
            Self::Original => Self::Instant,
        }
    }
}

fn validate_shape(shape: &DurableConsumerShape, alias_mode: AliasMode) {
    let first_filter = shape.filters.first().map(String::as_str);
    let (name, durable_name) = match alias_mode {
        AliasMode::Name => (Some(shape.name.as_str()), None),
        AliasMode::DurableName => (None, Some(shape.name.as_str())),
        AliasMode::Both => (Some(shape.name.as_str()), Some(shape.name.as_str())),
    };
    let canonical = fuzz_validate_consumer_config(name, durable_name, first_filter)
        .expect("materialized durable consumer config should validate");
    assert_eq!(canonical.as_deref(), Some(shape.name.as_str()));

    for filter in &shape.filters {
        fuzz_validate_consumer_config(Some(shape.name.as_str()), None, Some(filter.as_str()))
            .expect("materialized filter subject should validate");
    }
}

fn classify_recreate(
    existing: &DurableConsumerShape,
    requested: &DurableConsumerShape,
) -> Result<(), &'static str> {
    assert_eq!(
        existing.name, requested.name,
        "this target exercises same-name durable recreates"
    );
    if existing.filters != requested.filters {
        return Err("filter_subjects");
    }
    if existing.replay_policy != requested.replay_policy {
        return Err("replay_policy");
    }
    Ok(())
}

fn conflict_api_error_json(field: &str) -> String {
    format!(
        "{{\"error\":{{\"code\":409,\"err_code\":10013,\"description\":\"durable consumer already exists with conflicting {field}\"}}}}"
    )
}

fn force_filter_conflict(existing: &[String], requested: &mut Vec<String>) {
    if existing.is_empty() {
        if requested.is_empty() {
            requested.push("a.b".to_string());
        }
        return;
    }

    if requested == existing {
        requested.push("conflict.subject".to_string());
    }
    requested.sort();
    requested.dedup();
    if requested == existing {
        requested.clear();
    }
}

fn materialize_name(raw: &[u8]) -> String {
    raw.iter()
        .copied()
        .chain(std::iter::repeat(b'a'))
        .take(raw.len().clamp(1, MAX_NAME_BYTES))
        .map(name_char)
        .collect()
}

fn name_char(byte: u8) -> char {
    match byte % 64 {
        0..=25 => char::from(b'a' + (byte % 26)),
        26..=51 => char::from(b'A' + (byte % 26)),
        52..=61 => char::from(b'0' + (byte % 10)),
        62 => '-',
        _ => '_',
    }
}

fn materialize_subject_token(raw: &[u8]) -> String {
    raw.iter()
        .copied()
        .chain(std::iter::repeat(b'a'))
        .take(raw.len().clamp(1, MAX_TOKEN_BYTES))
        .map(|byte| match byte % 63 {
            0..=25 => char::from(b'a' + (byte % 26)),
            26..=51 => char::from(b'A' + (byte % 26)),
            52..=61 => char::from(b'0' + (byte % 10)),
            _ => '_',
        })
        .collect()
}
