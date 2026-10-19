use super::*;
use crate::channel::oneshot;
use crate::remote::{
    IdempotencyKey, RemoteCap, RemoteComputationDispatchError, RemotePeerAdmissionPolicy,
    RemoteProtocolVersion, SpawnRequest,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

struct Add;
impl TypedRemoteComputation for Add {
    const NAME: &'static str = "typed.add";
    type Input = (u64, u64);
    type Output = u64;
}

fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = Box::pin(future);
    match future.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("this codec/ready-handler fixture must not park"),
    }
}

fn dispatch(
    registry: &RemoteComputationRegistry,
    name: &'static str,
    bytes: Vec<u8>,
) -> Result<RemoteOutcome, RemoteComputationDispatchError> {
    let cx = Cx::for_testing();
    let peer = NodeId::new("typed-origin");
    let mut policy = RemotePeerAdmissionPolicy::new(
        RemoteProtocolVersion::V3,
        registry.schema_registry().clone(),
    );
    policy.grant_peer(peer.clone(), [name]).unwrap();
    let session = policy.admit(&policy.hello_for(peer.clone())).unwrap();
    ready(registry.dispatch(
        &cx,
        &session,
        SpawnRequest {
            remote_task_id: RemoteTaskId::from_raw(77),
            computation: ComputationName::new(name),
            input: RemoteInput::new(bytes),
            lease: std::time::Duration::from_secs(30),
            idempotency_key: IdempotencyKey::from_raw(42),
            budget: None,
            origin_node: peer,
            origin_region: cx.region_id(),
            origin_task: cx.task_id(),
        },
    ))
}

#[test]
fn typed_dispatch_decodes_and_executes_the_declared_signature() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut registry = RemoteComputationRegistry::new();
    registry
        .register_typed_json::<Add, _, _>(TypedRemoteLimits::default(), move |_, (left, right)| {
            observed.fetch_add(1, Ordering::SeqCst);
            async move { TypedRemoteOutcome::Success(left + right) }
        })
        .unwrap();
    let call = PreparedTypedRemoteCall::<Add>::encode(&(20, 22), TypedRemoteLimits::default())
        .unwrap();
    let RemoteOutcome::Success(bytes) = dispatch(&registry, Add::NAME, call.input.into_data()).unwrap()
    else {
        panic!("typed success must use the existing successful terminal");
    };
    let value: u64 = decode_value(
        Signature::of::<Add>().unwrap(),
        TypedRemoteStage::Response,
        &bytes,
        TypedRemoteLimits::default(),
    )
    .unwrap();
    assert_eq!(value, 42);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

static DECODE_CALLS: AtomicUsize = AtomicUsize::new(0);

#[derive(Serialize)]
struct DecodeProbe(u64);
impl HasSchema for DecodeProbe {
    fn schema() -> SchemaDescriptor {
        u64::schema()
    }
}
impl<'de> Deserialize<'de> for DecodeProbe {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        DECODE_CALLS.fetch_add(1, Ordering::SeqCst);
        u64::deserialize(deserializer).map(Self)
    }
}
struct Probe;
impl TypedRemoteComputation for Probe {
    const NAME: &'static str = "typed.probe";
    type Input = DecodeProbe;
    type Output = u64;
}

#[test]
fn metadata_refusal_precedes_custom_deserialization_and_handler_execution() {
    DECODE_CALLS.store(0, Ordering::SeqCst);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut registry = RemoteComputationRegistry::new();
    registry
        .register_typed_json::<Probe, _, _>(TypedRemoteLimits::default(), move |_, value| {
            observed.fetch_add(1, Ordering::SeqCst);
            async move { TypedRemoteOutcome::Success(value.0) }
        })
        .unwrap();
    let call = PreparedTypedRemoteCall::<Probe>::encode(&DecodeProbe(7), TypedRemoteLimits::default())
        .unwrap();
    let original: serde_json::Value = serde_json::from_slice(call.input.data()).unwrap();
    for (field, replacement, expected) in [
        ("version", serde_json::json!(2), "codec version"),
        ("computation", serde_json::json!("other"), "computation mismatch"),
        ("direction", serde_json::json!("response"), "direction mismatch"),
        ("input_schema", serde_json::json!(0), "request schema mismatch"),
        ("output_schema", serde_json::json!(0), "response schema mismatch"),
        ("unrecognized", serde_json::json!(1), "unknown field"),
    ] {
        let mut value = original.clone();
        value[field] = replacement;
        let result = dispatch(&registry, Probe::NAME, serde_json::to_vec(&value).unwrap());
        assert!(matches!(result,
            Err(RemoteComputationDispatchError::Execution(RemoteError::SerializationError(message)))
                if message.contains(expected)), "{field} must be refused by the typed adapter");
    }
    let duplicate = format!(
        "{{\"version\":1,{}",
        std::str::from_utf8(call.input.data()).unwrap().trim_start_matches('{')
    );
    assert!(matches!(dispatch(&registry, Probe::NAME, duplicate.into_bytes()),
        Err(RemoteComputationDispatchError::Execution(RemoteError::SerializationError(message)))
            if message.contains("duplicate field")));
    assert_eq!(DECODE_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(matches!(dispatch(&registry, Probe::NAME, call.input.into_data()),
        Ok(RemoteOutcome::Success(_))));
    assert_eq!(DECODE_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictInput {
    value: u64,
}
impl HasSchema for StrictInput {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::structure("StrictInput", vec![("value", u64::schema())])
    }
}
struct Strict;
impl TypedRemoteComputation for Strict {
    const NAME: &'static str = "typed.strict";
    type Input = StrictInput;
    type Output = u64;
}

#[test]
fn invalid_duplicate_and_unknown_payload_fields_never_invoke_the_handler() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut registry = RemoteComputationRegistry::new();
    registry
        .register_typed_json::<Strict, _, _>(TypedRemoteLimits::default(), move |_, input| {
            observed.fetch_add(1, Ordering::SeqCst);
            async move { TypedRemoteOutcome::Success(input.value) }
        })
        .unwrap();
    let signature = Signature::of::<Strict>().unwrap();
    for payload in [
        "{\"value\":\"wrong type\"}",
        "{\"value\":1,\"value\":2}",
        "{\"value\":1,\"extra\":2}",
        "{\"value\":1} trailing bytes",
    ] {
        let bytes = encode_bounded(
            &EncodeEnvelope {
                version: 1,
                computation: signature.name,
                direction: TypedRemoteStage::Request,
                input_schema: signature.input,
                output_schema: signature.output,
                payload,
            },
            TypedRemoteStage::Request,
            1024,
        )
        .unwrap();
        assert!(matches!(dispatch(&registry, Strict::NAME, bytes),
            Err(RemoteComputationDispatchError::Execution(RemoteError::SerializationError(_)))));
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn input_and_output_limits_include_json_expansion_and_metadata() {
    let signature = Signature::of::<Add>().unwrap();
    for stage in [TypedRemoteStage::Request, TypedRemoteStage::Response] {
        let value = "\\\"\n".repeat(40);
        let bytes = encode_value(signature, stage, &value, TypedRemoteLimits::default()).unwrap();
        let limit = bytes.len();
        let exact = TypedRemoteLimits::new(limit, limit);
        assert_eq!(encode_value(signature, stage, &value, exact).unwrap(), bytes);
        let narrow = TypedRemoteLimits::new(limit - 1, limit - 1);
        assert!(matches!(encode_value(signature, stage, &value, narrow),
            Err(TypedRemoteError::LimitExceeded { stage: actual, limit: cap })
                if actual == stage && cap == limit - 1));
        assert!(matches!(decode_value::<String>(signature, stage, &bytes, narrow),
            Err(TypedRemoteError::LimitExceeded { .. })));
        assert!(matches!(encode_value(signature, stage, &value, TypedRemoteLimits::new(0, 0)),
            Err(TypedRemoteError::LimitExceeded { .. })));
    }
}

#[test]
fn swallowed_serializer_write_errors_still_refuse_oversize_payloads() {
    struct SwallowedWriteError;

    impl Serialize for SwallowedWriteError {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;

            let mut sequence = serializer.serialize_seq(Some(1))?;
            let _ = sequence.serialize_element(&"x".repeat(1024));
            sequence.end()
        }
    }

    for stage in [TypedRemoteStage::Request, TypedRemoteStage::Response] {
        assert!(matches!(encode_bounded(&SwallowedWriteError, stage, 16),
            Err(TypedRemoteError::LimitExceeded { stage: actual, limit: 16 })
                if actual == stage));
    }
}

#[test]
fn typed_registration_is_atomic_and_distinct_from_raw_schema_advertisement() {
    let mut typed = RemoteComputationRegistry::new();
    typed
        .register_typed_json::<Add, _, _>(TypedRemoteLimits::default(), |_, (a, b)| async move {
            TypedRemoteOutcome::Success(a + b)
        })
        .unwrap();
    let fingerprint = typed.schema_registry().fingerprint();
    assert!(matches!(typed.register_typed_json::<Add, _, _>(
        TypedRemoteLimits::default(), |_, _| async { TypedRemoteOutcome::Success(0) }),
        Err(TypedRemoteError::Registration(_))));
    assert_eq!(typed.len(), 1);
    assert_eq!(typed.schema_registry().fingerprint(), fingerprint);
    let mut raw = RemoteComputationRegistry::new();
    raw.register::<(u64, u64), u64, _, _>(Add::NAME, |_, _| async {
        Ok(RemoteOutcome::Success(vec![42]))
    })
    .unwrap();
    assert_ne!(raw.schema_registry().fingerprint(), fingerprint);
}

fn pending_handle() -> (
    TypedRemoteHandle<Add>,
    oneshot::Sender<Result<RemoteOutcome, RemoteError>>,
) {
    let cx = Cx::for_testing();
    let (sender, receiver) = oneshot::channel();
    let plain = RemoteHandle {
        remote_task_id: RemoteTaskId::from_raw(88),
        local_task_id: None,
        origin_node: NodeId::new("origin"),
        node: NodeId::new("remote"),
        computation: ComputationName::new(Add::NAME),
        owner_region: cx.region_id(),
        runtime: None,
        receiver,
        sender_clock: cx.logical_clock_handle(),
        lease: std::time::Duration::from_secs(30),
        state: RemoteTaskState::Running,
        completed: false,
    };
    (
        TypedRemoteHandle {
            inner: Handle::Plain(plain),
            signature: Signature::of::<Add>().unwrap(),
            limits: TypedRemoteLimits::default(),
            marker: PhantomData,
        },
        sender,
    )
}

#[test]
fn cancelled_observation_retains_handle_and_output_refusal_consumes_only_once() {
    let (mut handle, sender) = pending_handle();
    let cancelled = Cx::for_testing();
    let reason = CancelReason::user("typed observation only");
    cancelled.set_cancel_reason(reason.clone());
    assert!(matches!(ready(handle.join(&cancelled)),
        Outcome::Err(TypedRemoteError::Remote(RemoteError::Cancelled(actual))) if actual == reason));
    assert!(handle.try_join().unwrap().is_none());
    let wrong = encode_value(
        Signature::of::<Add>().unwrap(),
        TypedRemoteStage::Request,
        &42_u64,
        TypedRemoteLimits::default(),
    )
    .unwrap();
    sender.send_blocking(Ok(RemoteOutcome::Success(wrong))).unwrap();
    assert!(matches!(ready(handle.join(&Cx::for_testing())),
        Outcome::Err(TypedRemoteError::Direction {
            expected: TypedRemoteStage::Response, actual: TypedRemoteStage::Request
        })));
    assert!(matches!(handle.try_join(),
        Err(TypedRemoteError::Remote(RemoteError::PolledAfterCompletion))));
}

#[test]
fn failure_cancel_and_panic_remain_distinct_remote_terminals() {
    let reason = CancelReason::user("remote terminal reason");
    for terminal in [
        RemoteOutcome::Failed("application failure".to_owned()),
        RemoteOutcome::Cancelled(reason.clone()),
        RemoteOutcome::Panicked("remote panic".to_owned()),
    ] {
        let (mut handle, sender) = pending_handle();
        sender.send_blocking(Ok(terminal.clone())).unwrap();
        let observed = ready(handle.close(&Cx::for_testing()));
        match (terminal, observed) {
            (RemoteOutcome::Failed(expected), Outcome::Ok(TypedRemoteOutcome::Failed(actual)))
            | (RemoteOutcome::Panicked(expected), Outcome::Ok(TypedRemoteOutcome::Panicked(actual))) => {
                assert_eq!(actual, expected);
            }
            (RemoteOutcome::Cancelled(expected), Outcome::Ok(TypedRemoteOutcome::Cancelled(actual))) => {
                assert_eq!(actual, expected);
            }
            other => panic!("typed adapter changed terminal shape: {other:?}"),
        }
    }
}

static ENCODE_CALLS: AtomicUsize = AtomicUsize::new(0);
#[derive(Deserialize)]
struct EncodeProbe;
impl Serialize for EncodeProbe {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ENCODE_CALLS.fetch_add(1, Ordering::SeqCst);
        serializer.serialize_unit()
    }
}
impl HasSchema for EncodeProbe {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::Unit
    }
}
struct Encoding;
impl TypedRemoteComputation for Encoding {
    const NAME: &'static str = "typed.encoding";
    type Input = EncodeProbe;
    type Output = ();
}

#[test]
fn missing_capability_or_cancellation_refuses_before_application_serialization() {
    ENCODE_CALLS.store(0, Ordering::SeqCst);
    assert!(matches!(spawn_remote_typed::<Encoding>(
        &Cx::for_testing(), NodeId::new("remote"), &EncodeProbe, TypedRemoteLimits::default()),
        Err(TypedRemoteError::Remote(RemoteError::NoCapability))));
    let cx = Cx::for_testing_with_remote(RemoteCap::new());
    let reason = CancelReason::user("cancel before typed encoding");
    cx.set_cancel_reason(reason.clone());
    assert!(matches!(spawn_remote_typed::<Encoding>(
        &cx, NodeId::new("remote"), &EncodeProbe, TypedRemoteLimits::default()),
        Err(TypedRemoteError::Remote(RemoteError::Cancelled(actual))) if actual == reason));
    assert_eq!(ENCODE_CALLS.load(Ordering::SeqCst), 0);
}
