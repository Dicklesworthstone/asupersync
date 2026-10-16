//! Authenticated membership decisions over the existing named-computation service.
//!
//! Register this capability only for a provisioned membership authority, using
//! the existing certificate-bound peer policy. An admitted peer must additionally
//! equal the controller's configured authority, and its statement must validate
//! under the independent membership key and epoch. Raw gossip never gets signed
//! or applied here. The controller and its runtime-obligation cleanup stay owned
//! by the embedding application; this service does not spawn work or drain leases.

use super::authority::{MAX_MEMBERSHIP_UPDATE_BYTES, MembershipLeaseController};
use crate::distributed::{ComputationSchemaRegistryError, HasSchema, SchemaDescriptor};
use crate::remote::{NodeId, RemoteComputationRegistry, RemoteOutcome};
use parking_lot::Mutex;
use std::sync::Arc;

/// Separate, versioned capability; existing remote envelopes/tags are unchanged.
pub const MEMBERSHIP_SERVICE_COMPUTATION: &str = "asupersync.distributed.membership-authority.v1";
struct MembershipRequest;
struct MembershipResponse;
impl HasSchema for MembershipRequest {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("asupersync.membership-authority.signed-statement.v1")
    }
}
impl HasSchema for MembershipResponse {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("asupersync.membership-authority.accepted-statement-echo.v1")
    }
}

fn apply_request(controller: &Mutex<MembershipLeaseController>, peer: &NodeId, bytes: &[u8]) -> RemoteOutcome {
    if !(73..=MAX_MEMBERSHIP_UPDATE_BYTES).contains(&bytes.len()) {
        return RemoteOutcome::Failed("invalid membership statement size".to_owned());
    }
    let result = {
        // An embedding owner can hold this mutex. Refuse instead of blocking an
        // executor worker behind external application work or acquiring a queue.
        let Some(mut state) = controller.try_lock() else {
            return RemoteOutcome::Failed("membership controller is busy".to_owned());
        };
        if peer != state.authority() {
            return RemoteOutcome::Failed("membership peer is not the configured authority".to_owned());
        }
        state.apply_authenticated(bytes)
    };
    match result {
        // Exact echo binds the receipt to the entire accepted authority decision.
        // This is not a lease-drain, current-liveness or persisted-state receipt.
        Ok(_) => RemoteOutcome::Success(bytes.to_vec()),
        Err(error) => RemoteOutcome::Failed(error.to_string()),
    }
}

/// Register a handler for explicit signed membership decisions.
///
/// This does not grant peers access. Configure `RemotePeerAdmissionPolicy` with
/// V1 and `grant_tls_peer` for the authority, then use the existing mTLS listener.
/// The controller rejects other admitted identities even if the surrounding
/// registry accidentally granted them this computation. Inline work is bounded
/// by statement size and the controller's lease limit. A busy controller refuses
/// without queuing. Revocation instructions remain available to the local owner.
///
/// Use V1 to avoid framework-retained V2/V3 receipts across controller replacement.
/// Lost acknowledgement can follow a committed in-memory transition; retrying
/// the latest identical statement is idempotent, older ones remain stale. Epoch
/// and sequence floors must be independently restored after process restart.
pub fn register_membership_service(
    registry: &mut RemoteComputationRegistry, controller: Arc<Mutex<MembershipLeaseController>>,
) -> Result<(), ComputationSchemaRegistryError> {
    registry.register::<MembershipRequest, MembershipResponse, _, _>(
        MEMBERSHIP_SERVICE_COMPUTATION,
        move |cx, invocation| {
            let controller = Arc::clone(&controller);
            async move {
                if cx.checkpoint().is_err() {
                    return Ok(cx.cancel_reason().map_or_else(
                        || RemoteOutcome::Failed("membership checkpoint refused".to_owned()),
                        RemoteOutcome::Cancelled,
                    ));
                }
                let outcome = apply_request(&controller, invocation.peer_node(), invocation.request().input.data());
                if cx.is_cancel_requested() {
                    return Ok(cx.cancel_reason().map_or_else(
                        || RemoteOutcome::Failed("membership cancellation observed after admission".to_owned()),
                        RemoteOutcome::Cancelled,
                    ));
                }
                Ok(outcome)
            }
        },
    )
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
mod native {
    use super::{MAX_MEMBERSHIP_UPDATE_BYTES, MEMBERSHIP_SERVICE_COMPUTATION};
    use crate::cx::Cx;
    use crate::remote::{
        ComputationName, IdempotencyKey, RemoteComputationClient, RemoteComputationClientError,
        RemoteInput, RemotePeerHello, RemoteProtocolVersion, RemoteServiceWireOutcome,
        RemoteServiceWireRequest, RemoteServiceWireResponse, RemoteTaskId, SpawnRequest,
    };

    /// Payload-free delivery refusal; no untrusted remote diagnostic is echoed.
    #[derive(Debug, thiserror::Error)]
    #[non_exhaustive]
    pub enum MembershipDeliveryError {
        /// Caller was cancelled before dispatch or before accepting a response.
        #[error("membership update cancelled")]
        Cancelled,
        /// Unsupported protocol or inadmissible statement size.
        #[error("invalid membership delivery configuration")]
        Configuration,
        /// Existing mTLS client connection/exchange failed.
        #[error("membership update transport failed")]
        Client(#[source] RemoteComputationClientError),
        /// Authenticated service refused the decision.
        #[error("membership authority decision was refused")]
        Refused,
        /// Successful response did not echo the exact submitted statement.
        #[error("membership update acknowledgement mismatch")]
        Receipt,
    }

    /// Deliver one explicitly signed decision using an already provisioned mTLS
    /// client. No discovery, destination changes, new retry policy or task spawn.
    ///
    /// The existing client's finite deadlines and pre-delivery retry rules apply.
    /// Success means the exact decision was admitted, NOT that revoked obligations
    /// have drained or that the member is currently reachable. Statement signing
    /// remains a separate local authority operation; bytes may be adversarial.
    pub async fn submit_membership_update(
        cx: &Cx, client: &RemoteComputationClient, hello: &RemotePeerHello, statement: &[u8],
    ) -> Result<(), MembershipDeliveryError> {
        if cx.is_cancel_requested() { return Err(MembershipDeliveryError::Cancelled); }
        if hello.protocol_version() != RemoteProtocolVersion::V1
            || !(73..=MAX_MEMBERSHIP_UPDATE_BYTES).contains(&statement.len())
        { return Err(MembershipDeliveryError::Configuration); }
        let task = RemoteTaskId::next();
        let request = SpawnRequest {
            remote_task_id: task, computation: ComputationName::new(MEMBERSHIP_SERVICE_COMPUTATION),
            input: RemoteInput::new(statement.to_vec()), lease: client.config().attempt_timeout(),
            idempotency_key: IdempotencyKey::from_raw(u128::from(task.raw())), budget: None,
            origin_node: hello.peer_node().clone(), origin_region: cx.region_id(), origin_task: cx.task_id(),
        };
        let wire = RemoteServiceWireRequest::from_spawn_request(hello.clone(), &request)
            .map_err(|_| MembershipDeliveryError::Configuration)?;
        drop(request);
        let response = client.call(cx, &wire).await.map_err(MembershipDeliveryError::Client)?;
        if cx.is_cancel_requested() { return Err(MembershipDeliveryError::Cancelled); }
        match response {
            RemoteServiceWireResponse::Outcome { outcome: RemoteServiceWireOutcome::Success(reply), .. } => {
                if reply == statement { Ok(()) } else { Err(MembershipDeliveryError::Receipt) }
            }
            _ => Err(MembershipDeliveryError::Refused),
        }
    }
}

#[cfg(all(feature = "tls", not(target_arch = "wasm32")))]
pub use native::{MembershipDeliveryError, submit_membership_update};

#[cfg(test)]
#[path = "service_inline_tests.rs"]
mod tests;

/// Register the same V1 capability with checked runtime-owned lease settlement.
///
/// This is an alternative to `register_membership_service`, not another wire
/// protocol. The existing certificate-bound peer policy and client remain in
/// force. The controller issues local checked aborts before returning an accepted
/// statement; the reply is still not a remote-quiescence or arena-drain receipt.
/// Start the controller's expiry driver in a separately owned application task.
/// No driver or other background work is spawned by this registration.
pub fn register_owned_membership_service(
    registry: &mut RemoteComputationRegistry,
    controller: super::owned::OwnedMembershipController,
) -> Result<(), ComputationSchemaRegistryError> {
    registry.register::<MembershipRequest, MembershipResponse, _, _>(
        MEMBERSHIP_SERVICE_COMPUTATION,
        move |cx, invocation| {
            let controller = controller.clone();
            async move {
                if cx.checkpoint().is_err() {
                    return Ok(cx.cancel_reason().map_or_else(
                        || RemoteOutcome::Failed("membership checkpoint refused".to_owned()),
                        RemoteOutcome::Cancelled,
                    ));
                }
                let bytes = invocation.request().input.data();
                if !(73..=MAX_MEMBERSHIP_UPDATE_BYTES).contains(&bytes.len()) {
                    return Ok(RemoteOutcome::Failed("invalid membership statement size".to_owned()));
                }
                let result = controller.apply_authenticated(invocation.peer_node(), bytes);
                if cx.is_cancel_requested() {
                    return Ok(cx.cancel_reason().map_or_else(
                        || RemoteOutcome::Failed("membership cancellation observed after admission".to_owned()),
                        RemoteOutcome::Cancelled,
                    ));
                }
                Ok(match result {
                    Ok(_) => RemoteOutcome::Success(bytes.to_vec()),
                    Err(error) => RemoteOutcome::Failed(error.to_string()),
                })
            }
        },
    )
}
