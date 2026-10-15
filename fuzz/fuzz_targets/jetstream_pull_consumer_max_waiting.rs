#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::jetstream::{JsError, fuzz_parse_api_error};
use libfuzzer_sys::fuzz_target;

const MAX_WAITING_FUZZ_LIMIT: usize = 64;
const MAX_DESCRIPTION_BYTES: usize = 96;

#[derive(Debug, Arbitrary)]
struct Scenario {
    max_waiting_seed: u8,
    request_shape: PullRequestShape,
    response_shape: TimeoutResponseShape,
    description_bytes: Vec<u8>,
}

#[derive(Debug, Arbitrary, Clone, Copy)]
struct PullRequestShape {
    batch_seed: u16,
    expires_seed: u32,
    no_wait: bool,
}

#[derive(Debug, Arbitrary, Clone, Copy)]
enum TimeoutResponseShape {
    NestedError,
    TopLevelError,
    ConsumerMsgNextResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingPull {
    batch: usize,
    expires_nanos: u64,
    no_wait: bool,
}

#[derive(Debug)]
struct PullConsumerServerModel {
    max_waiting: usize,
    waiting: Vec<PendingPull>,
}

#[derive(Debug, PartialEq, Eq)]
struct MaxWaitingRejected {
    limit: usize,
    current_waiting: usize,
}

fuzz_target!(|scenario: Scenario| {
    let max_waiting = usize::from(scenario.max_waiting_seed % MAX_WAITING_FUZZ_LIMIT as u8) + 1;
    let mut server = PullConsumerServerModel::new(max_waiting);
    let pull = materialize_pull(scenario.request_shape);

    for accepted_index in 0..max_waiting {
        server.accept_pull(pull.clone()).unwrap_or_else(|err| {
            panic!("pull {accepted_index} below MaxWaiting rejected: {err:?}")
        });
        assert_eq!(server.waiting_count(), accepted_index + 1);
    }

    let rejection = server
        .accept_pull(pull)
        .expect_err("exactly N+1 concurrent pulls must exceed MaxWaiting");
    assert_eq!(
        rejection,
        MaxWaitingRejected {
            limit: max_waiting,
            current_waiting: max_waiting,
        }
    );
    assert_eq!(server.waiting_count(), max_waiting);

    let json = max_waiting_timeout_response_json(
        scenario.response_shape,
        rejection.limit,
        rejection.current_waiting,
        &scenario.description_bytes,
    );
    assert_timeout_rejection(fuzz_parse_api_error(&json), max_waiting);
});

impl PullConsumerServerModel {
    fn new(max_waiting: usize) -> Self {
        assert!(max_waiting > 0);
        Self {
            max_waiting,
            waiting: Vec::with_capacity(max_waiting),
        }
    }

    fn waiting_count(&self) -> usize {
        self.waiting.len()
    }

    fn accept_pull(&mut self, request: PendingPull) -> Result<(), MaxWaitingRejected> {
        if self.waiting.len() >= self.max_waiting {
            return Err(MaxWaitingRejected {
                limit: self.max_waiting,
                current_waiting: self.waiting.len(),
            });
        }

        self.waiting.push(request);
        Ok(())
    }
}

fn materialize_pull(shape: PullRequestShape) -> PendingPull {
    PendingPull {
        batch: usize::from(shape.batch_seed % 1024) + 1,
        expires_nanos: u64::from(shape.expires_seed).saturating_add(1),
        no_wait: shape.no_wait,
    }
}

fn max_waiting_timeout_response_json(
    shape: TimeoutResponseShape,
    limit: usize,
    current_waiting: usize,
    description_bytes: &[u8],
) -> String {
    let description = timeout_description(limit, current_waiting, description_bytes);
    match shape {
        TimeoutResponseShape::NestedError => {
            format!(r#"{{"error":{{"code":408,"err_code":10078,"description":"{description}"}}}}"#)
        }
        TimeoutResponseShape::TopLevelError => {
            format!(r#"{{"code":408,"err_code":10078,"description":"{description}"}}"#)
        }
        TimeoutResponseShape::ConsumerMsgNextResponse => format!(
            r#"{{"type":"io.nats.jetstream.api.v1.consumer_msg_next_response","error":{{"description":"{description}","err_code":10078,"code":408}}}}"#
        ),
    }
}

fn timeout_description(limit: usize, current_waiting: usize, bytes: &[u8]) -> String {
    let mut suffix = String::new();
    for byte in bytes.iter().take(MAX_DESCRIPTION_BYTES) {
        let mut printable = 32 + (byte % 95);
        if printable == b'"' || printable == b'\\' {
            printable = b'_';
        }
        suffix.push(char::from(printable));
    }

    if suffix.is_empty() {
        format!("Request Timeout: max waiting exceeded ({current_waiting}/{limit})")
    } else {
        format!("Request Timeout: max waiting exceeded ({current_waiting}/{limit}) {suffix}")
    }
}

fn assert_timeout_rejection(err: JsError, max_waiting: usize) {
    assert!(
        err.is_timeout(),
        "MaxWaiting rejection must be a timeout: {err:?}"
    );
    assert!(
        err.is_transient(),
        "MaxWaiting rejection must be retryable/transient: {err:?}"
    );
    assert!(
        err.is_retryable(),
        "MaxWaiting rejection must remain retryable: {err:?}"
    );

    match err {
        JsError::Api { code, description } => {
            assert_eq!(code, 408, "MaxWaiting must map to HTTP-style 408");
            assert!(
                description.contains("Request Timeout"),
                "timeout description should preserve status text: {description}"
            );
            assert!(
                description.contains("max waiting"),
                "timeout description should identify MaxWaiting pressure: {description}"
            );
            assert!(
                description.contains(&max_waiting.to_string()),
                "timeout description should carry the configured limit: {description}"
            );
        }
        other => panic!("MaxWaiting rejection should parse as JetStream API timeout: {other:?}"),
    }
}
