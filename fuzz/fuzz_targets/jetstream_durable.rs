#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::jetstream::fuzz_normalize_consumer_identity;
use libfuzzer_sys::fuzz_target;

const MAX_NAME_CHARS: usize = 64;

#[derive(Arbitrary, Debug, Clone)]
struct DurableIdentityInput {
    name: NameField,
    durable_name: NameField,
    relation: AliasRelation,
}

#[derive(Arbitrary, Debug, Clone)]
struct NameField {
    present: bool,
    raw: String,
    mutation: NameMutation,
}

#[derive(Arbitrary, Debug, Clone)]
enum AliasRelation {
    Independent,
    CopyNameToDurable,
    CopyDurableToName,
    ForceEqual,
    ForceMismatch,
    NameOnly,
    DurableOnly,
}

#[derive(Arbitrary, Debug, Clone)]
enum NameMutation {
    None,
    ValidAlnum,
    Empty,
    AppendSpace,
    AppendDot,
    AppendWildcard,
    AppendGreaterThan,
    AppendSlash,
    AppendBackslash,
    AppendControl,
}

impl DurableIdentityInput {
    fn materialize(&self) -> (Option<String>, Option<String>) {
        let mut name = self.name.materialize();
        let mut durable_name = self.durable_name.materialize();

        match self.relation {
            AliasRelation::Independent => {}
            AliasRelation::CopyNameToDurable => {
                if let Some(existing) = name.clone() {
                    durable_name = Some(existing);
                }
            }
            AliasRelation::CopyDurableToName => {
                if let Some(existing) = durable_name.clone() {
                    name = Some(existing);
                }
            }
            AliasRelation::ForceEqual => {
                let shared = name
                    .clone()
                    .or_else(|| durable_name.clone())
                    .unwrap_or_else(|| "worker".to_string());
                name = Some(shared.clone());
                durable_name = Some(shared);
            }
            AliasRelation::ForceMismatch => match (&mut name, &mut durable_name) {
                (Some(existing_name), Some(existing_durable)) => {
                    if existing_name == existing_durable {
                        existing_durable.push('x');
                    }
                }
                (Some(existing_name), None) => {
                    durable_name = Some(format!("{existing_name}x"));
                }
                (None, Some(existing_durable)) => {
                    name = Some(format!("{existing_durable}x"));
                }
                (None, None) => {
                    name = Some("worker-a".to_string());
                    durable_name = Some("worker-b".to_string());
                }
            },
            AliasRelation::NameOnly => {
                durable_name = None;
            }
            AliasRelation::DurableOnly => {
                name = None;
            }
        }

        (name, durable_name)
    }
}

impl NameField {
    fn materialize(&self) -> Option<String> {
        if !self.present {
            return None;
        }

        let mut value = truncate_chars(&self.raw, MAX_NAME_CHARS);

        match self.mutation {
            NameMutation::None => {}
            NameMutation::ValidAlnum => {
                value = value
                    .chars()
                    .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-' || *ch == '_')
                    .collect();
                if value.is_empty() {
                    value.push('a');
                }
            }
            NameMutation::Empty => value.clear(),
            NameMutation::AppendSpace => value.push(' '),
            NameMutation::AppendDot => value.push('.'),
            NameMutation::AppendWildcard => value.push('*'),
            NameMutation::AppendGreaterThan => value.push('>'),
            NameMutation::AppendSlash => value.push('/'),
            NameMutation::AppendBackslash => value.push('\\'),
            NameMutation::AppendControl => value.push('\u{0007}'),
        }

        Some(value)
    }
}

fn truncate_chars(input: &str, max_chars: usize) -> String {
    input.chars().take(max_chars).collect()
}

fn model_validate(value: Option<&str>) -> Result<Option<String>, ()> {
    let Some(value) = value else {
        return Ok(None);
    };

    if value.is_empty() {
        return Err(());
    }

    if value.chars().any(|ch| {
        ch.is_whitespace() || matches!(ch, '.' | '*' | '>' | '/' | '\\') || ch.is_control()
    }) {
        return Err(());
    }

    Ok(Some(value.to_string()))
}

fn model_canonical(name: Option<&str>, durable_name: Option<&str>) -> Result<Option<String>, ()> {
    let name = model_validate(name)?;
    let durable_name = model_validate(durable_name)?;

    match (name, durable_name) {
        (Some(name), Some(durable_name)) if name != durable_name => Err(()),
        (Some(name), _) => Ok(Some(name)),
        (None, Some(durable_name)) => Ok(Some(durable_name)),
        (None, None) => Ok(None),
    }
}

fn reparse_canonical(canonical: &Option<String>) -> Option<String> {
    canonical.as_ref().and_then(|value| {
        fuzz_normalize_consumer_identity(Some(value.as_str()), None)
            .ok()
            .flatten()
    })
}

fuzz_target!(|input: DurableIdentityInput| {
    let (name, durable_name) = input.materialize();
    let expected = model_canonical(name.as_deref(), durable_name.as_deref());
    let actual = fuzz_normalize_consumer_identity(name.as_deref(), durable_name.as_deref());

    match (actual, expected) {
        (Ok(actual), Ok(expected)) => {
            assert_eq!(actual, expected);

            // The canonical string form is the normalized durable consumer name.
            let stringified = actual.clone();
            assert_eq!(stringified, expected);
            assert_eq!(reparse_canonical(&stringified), stringified);

            if let Some(canonical) = stringified {
                let deprecated_alias = fuzz_normalize_consumer_identity(None, Some(&canonical))
                    .expect("canonical durable alias should remain valid");
                assert_eq!(deprecated_alias, Some(canonical));
            }
        }
        (Err(_), Err(())) => {}
        (Ok(actual), Err(())) => {
            panic!(
                "unexpected success for name={name:?} durable_name={durable_name:?}: {actual:?}"
            );
        }
        (Err(err), Ok(expected)) => {
            panic!(
                "unexpected error for name={name:?} durable_name={durable_name:?}: expected {expected:?}, got {err:?}"
            );
        }
    }
});
