use super::*;
use crate::cx::ChildRegionSpec;
use crate::distributed::remote_owned::{RemoteRunError, RemoteRunReply};
use crate::distributed::{HasSchema, SchemaDescriptor};
use crate::remote::RemoteCap;
use crate::types::PanicPayload;
use serde::{Deserialize, Serialize};
use std::time::Duration;

struct Value;
impl TypedRemoteComputation for Value {
    const NAME: &'static str = "typed.owned.value";
    type Input = ();
    type Output = u64;
}

fn report(bytes: Vec<u8>) -> RemoteRunReport {
    RemoteRunReport {
        trigger: RemoteRunTrigger::Finished,
        task: Ok(RemoteRunReply {
            remote_task_id: RemoteTaskId::from_raw(73),
            outcome: Outcome::Ok(RemoteOutcome::Success(bytes)),
            cancellation: None,
            settlement: RemoteLeaseSettlement::Committed,
        }),
        close: Ok(RemoteRunClose {
            region_id: Cx::for_testing().region_id(),
            outcome: Outcome::Ok(()),
            cleanup_outcome: None,
        }),
        cancel_error: None,
    }
}

#[test]
fn output_codec_refusal_keeps_the_committed_protocol_and_cleanup_receipt() {
    let raw = report(b"{malformed application envelope}".to_vec());
    let region = raw.close.as_ref().unwrap().region_id;
    let decoded = decode_report::<Value>(
        Signature::of::<Value>().unwrap(),
        TypedRemoteLimits::default(),
        raw,
    );
    assert!(!decoded.is_success());
    assert_eq!(decoded.close.unwrap().region_id, region);
    assert!(decoded.cancel_error.is_none());
    let reply = decoded.task.unwrap();
    assert_eq!(reply.remote_task_id, RemoteTaskId::from_raw(73));
    assert_eq!(reply.settlement, RemoteLeaseSettlement::Committed);
    assert!(reply.cancellation.is_none());
    assert!(matches!(
        reply.outcome,
        Outcome::Err(TypedRemoteError::Decode { stage: TypedRemoteStage::Response, .. }),
    ));
}

#[test]
fn a_valid_typed_payload_cannot_erase_cancellation_or_cleanup_failure() {
    let signature = Signature::of::<Value>().unwrap();
    let limits = TypedRemoteLimits::default();
    let bytes = super::super::encode_value(signature, TypedRemoteStage::Response, &42_u64, limits)
        .unwrap();
    let mut raw = report(bytes);
    let reason = CancelReason::user("cancelled while retiring");
    raw.trigger = RemoteRunTrigger::Cancelled(reason.clone());
    raw.task.as_mut().unwrap().cancellation = Some(reason.clone());
    raw.task.as_mut().unwrap().settlement = RemoteLeaseSettlement::Aborted;
    raw.close.as_mut().unwrap().cleanup_outcome =
        Some(Outcome::Panicked(PanicPayload::new("finalizer failed")));
    raw.cancel_error = Some(ChildRegionError::RuntimeUnavailable);
    let decoded = decode_report::<Value>(signature, limits, raw);
    assert!(!decoded.is_success());
    assert!(matches!(decoded.trigger, RemoteRunTrigger::Cancelled(actual) if actual == reason));
    assert!(matches!(decoded.cancel_error, Some(ChildRegionError::RuntimeUnavailable)));
    assert!(matches!(
        decoded.close.unwrap().cleanup_outcome,
        Some(Outcome::Panicked(payload)) if payload.message() == "finalizer failed",
    ));
    let reply = decoded.task.unwrap();
    assert_eq!(reply.cancellation, Some(reason));
    assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
    assert!(matches!(reply.outcome, Outcome::Ok(TypedRemoteOutcome::Success(42))));
}

#[derive(Deserialize)]
struct EncodingTripwire;
impl Serialize for EncodingTripwire {
    fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        panic!("unavailable remote authority must refuse before serialization");
    }
}
impl HasSchema for EncodingTripwire {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("encoding-tripwire")
    }
}
struct ProtectedInput;
impl TypedRemoteComputation for ProtectedInput {
    const NAME: &'static str = "typed.owned.protected";
    type Input = EncodingTripwire;
    type Output = u64;
}

#[test]
fn missing_or_unattached_remote_authority_never_calls_the_input_serializer() {
    for cx in [
        Cx::for_testing(),
        Cx::for_testing().with_remote_cap(RemoteCap::new()),
    ] {
        let error = spawn_remote_typed_owned::<ProtectedInput>(
            &cx,
            NodeId::new("worker"),
            &EncodingTripwire,
            TypedRemoteLimits::default(),
            RemoteRunConfig {
                timeout: Duration::from_secs(5),
                child: ChildRegionSpec::inherit(),
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            TypedRemoteRunError::Owned(RemoteRunHandleError::Run(
                RemoteRunError::NoCapability | RemoteRunError::NoRemoteRuntime,
            )),
        ));
    }
}
