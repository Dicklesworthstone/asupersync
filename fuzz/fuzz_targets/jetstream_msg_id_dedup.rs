#![no_main]

//! Structure-aware fuzz target for JetStream `Nats-Msg-Id` dedup-window
//! semantics.
//!
//! JetStream rejects a repeated `Nats-Msg-Id` while the prior publish is still
//! inside the stream's duplicate window. At the expiry boundary the recorded id
//! is no longer in-window, matching the crate's local dedup-retention convention.

use arbitrary::Arbitrary;
use asupersync::messaging::jetstream::fuzz_parse_pub_ack;
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeMap;

const MAX_MSG_ID_LEN: usize = 128;
const MAX_SUBJECT_LEN: usize = 128;
const MAX_PAYLOAD_LEN: usize = 256;
const MAX_STEPS: usize = 16;

#[derive(Arbitrary, Debug)]
struct Scenario {
    stream: String,
    subject: String,
    msg_id: String,
    payload: Vec<u8>,
    window_nanos: u64,
    first_publish_at: u64,
    boundary: BoundaryCase,
    extra_steps: Vec<ExtraStep>,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum BoundaryCase {
    /// Re-publish strictly before the configured dedup window expires.
    JustBeforeWindow,
    /// Re-publish exactly when the configured dedup window expires.
    ExactlyAtWindow,
    /// Re-publish strictly after the configured dedup window expires.
    JustPastWindow,
}

#[derive(Arbitrary, Debug)]
struct ExtraStep {
    msg_id_suffix: u8,
    subject_suffix: u8,
    payload_suffix: u8,
    advance_nanos: u64,
    reuse_primary_msg_id: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishClass {
    Accepted { seq: u64 },
    Duplicate { existing_seq: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DedupKey {
    stream: String,
    msg_id: String,
}

#[derive(Debug, Clone, Copy)]
struct SeenPublish {
    first_seen_at: u64,
    seq: u64,
}

#[derive(Debug)]
struct JetStreamDedupModel {
    window_nanos: u64,
    next_seq: u64,
    seen: BTreeMap<DedupKey, SeenPublish>,
}

impl JetStreamDedupModel {
    fn new(window_nanos: u64) -> Self {
        Self {
            window_nanos,
            next_seq: 1,
            seen: BTreeMap::new(),
        }
    }

    fn publish(&mut self, stream: &str, msg_id: &str, now: u64) -> PublishClass {
        let window_nanos = self.window_nanos;
        self.seen
            .retain(|_, seen| now.saturating_sub(seen.first_seen_at) < window_nanos);

        let key = DedupKey {
            stream: stream.to_owned(),
            msg_id: msg_id.to_owned(),
        };

        if let Some(seen) = self.seen.get(&key) {
            return PublishClass::Duplicate {
                existing_seq: seen.seq,
            };
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.seen.insert(
            key,
            SeenPublish {
                first_seen_at: now,
                seq,
            },
        );
        PublishClass::Accepted { seq }
    }
}

fuzz_target!(|scenario: Scenario| {
    let stream = bounded_token(scenario.stream, "S");
    let subject = bounded_token(scenario.subject, "events.created");
    let msg_id = bounded_token(scenario.msg_id, "msg-id");
    let payload = bounded_payload(scenario.payload);
    let window_nanos = scenario.window_nanos.min(u64::MAX / 4).max(1);
    let first_publish_at = scenario.first_publish_at % (u64::MAX / 2);

    let mut model = JetStreamDedupModel::new(window_nanos);

    let first = model.publish(&stream, &msg_id, first_publish_at);
    assert_eq!(
        first,
        PublishClass::Accepted { seq: 1 },
        "first publish for a Msg-Id must be accepted"
    );
    assert_pub_ack_round_trips(&stream, first);

    let second_publish_at = match scenario.boundary {
        BoundaryCase::JustBeforeWindow => {
            first_publish_at.saturating_add(window_nanos.saturating_sub(1))
        }
        BoundaryCase::ExactlyAtWindow => first_publish_at.saturating_add(window_nanos),
        BoundaryCase::JustPastWindow => first_publish_at
            .saturating_add(window_nanos)
            .saturating_add(1),
    };
    let second = model.publish(&stream, &msg_id, second_publish_at);
    let expected_duplicate = matches!(scenario.boundary, BoundaryCase::JustBeforeWindow);
    assert_eq!(
        matches!(second, PublishClass::Duplicate { .. }),
        expected_duplicate,
        "same Nats-Msg-Id classification diverged at {:?}: window={window_nanos}, \
         first_at={first_publish_at}, second_at={second_publish_at}, subject={subject:?}, \
         payload_len={}",
        scenario.boundary,
        payload.len()
    );
    assert_pub_ack_round_trips(&stream, second);

    let mut now = second_publish_at;
    for step in scenario.extra_steps.into_iter().take(MAX_STEPS) {
        now = now.saturating_add(step.advance_nanos);
        let extra_msg_id = if step.reuse_primary_msg_id {
            msg_id.clone()
        } else {
            format!("{msg_id}.{}", step.msg_id_suffix)
        };
        let extra_stream = stream.clone();
        let extra_subject = format!("{subject}.{}", step.subject_suffix);
        let mut extra_payload = payload.clone();
        extra_payload.push(step.payload_suffix);

        let result = model.publish(&extra_stream, &extra_msg_id, now);
        assert_pub_ack_round_trips(&extra_stream, result);

        if extra_msg_id != msg_id {
            assert!(
                matches!(result, PublishClass::Accepted { .. }),
                "a distinct Nats-Msg-Id must not be rejected as a duplicate: \
                 msg_id={extra_msg_id:?}, subject={extra_subject:?}, payload_len={}",
                extra_payload.len()
            );
        }
    }
});

fn bounded_token(mut token: String, fallback: &str) -> String {
    token.retain(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'));
    if token.is_empty() {
        token.push_str(fallback);
    }
    token.truncate(MAX_MSG_ID_LEN.min(MAX_SUBJECT_LEN));
    token
}

fn bounded_payload(mut payload: Vec<u8>) -> Vec<u8> {
    payload.truncate(MAX_PAYLOAD_LEN);
    payload
}

fn assert_pub_ack_round_trips(stream: &str, class: PublishClass) {
    let (seq, duplicate) = match class {
        PublishClass::Accepted { seq } => (seq, false),
        PublishClass::Duplicate { existing_seq } => (existing_seq, true),
    };
    let ack_json = format!(
        r#"{{"stream":"{}","seq":{},"duplicate":{}}}"#,
        escape_json(stream),
        seq,
        duplicate
    );

    let parsed = fuzz_parse_pub_ack(ack_json.as_bytes()).expect("modeled PubAck must parse");
    assert_eq!(parsed.stream, stream);
    assert_eq!(parsed.seq, seq);
    assert_eq!(parsed.duplicate, duplicate);
}

fn escape_json(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            _ => vec![ch],
        })
        .collect()
}
