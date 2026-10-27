//! Authenticated global-name snapshots and exact-owner lookups.
//!
//! Register this separate capability in the existing V1 mTLS computation
//! service and grant it only to configured registry peers. The transport's
//! certificate-bound identity supplies the snapshot owner; payloads cannot
//! choose another owner. The registry's lifetime driver remains separately
//! owned by the application. This adapter starts no tasks and grants no
//! membership, actor, or cluster-wide uniqueness authority.

use super::wire::{self, MAX_GLOBAL_NAME_MESSAGE_BYTES};
use super::{GlobalNameError, GlobalNameRegistry};
use crate::cx::Cx;
use crate::distributed::{ComputationSchemaRegistryError, HasSchema, SchemaDescriptor};
use crate::remote::{NodeId, RemoteComputationRegistry, RemoteOutcome};

/// Separate, versioned named computation for global-name peer messages.
pub const GLOBAL_NAME_SERVICE_COMPUTATION: &str = "asupersync.distributed.global-names.v1";

struct GlobalNameRequest;
struct GlobalNameResponse;

impl HasSchema for GlobalNameRequest {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("asupersync.global-names.request.v1")
    }
}

impl HasSchema for GlobalNameResponse {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("asupersync.global-names.response.v1")
    }
}

fn apply_request(
    registry: &GlobalNameRegistry,
    cx: &Cx,
    peer: &NodeId,
    bytes: &[u8],
) -> Result<Vec<u8>, GlobalNameError> {
    if bytes.len() > MAX_GLOBAL_NAME_MESSAGE_BYTES {
        return Err(GlobalNameError::Format);
    }
    if bytes.starts_with(b"GNS1") {
        let receipt = registry.apply_authenticated_snapshot(cx, peer, bytes)?;
        // Bind the acknowledgement to the version and digest that the
        // registry actually admitted, including an identical replay.
        Ok(wire::snapshot_receipt(&receipt))
    } else if bytes.starts_with(b"GNL1") {
        let (incarnation, name) = wire::decode_lookup_request(bytes)?;
        // This hook reads the local catalog only. A replicated winner from
        // another owner must never substitute for this owner's answer.
        registry.authoritative_reply(cx, &name, incarnation)
    } else {
        Err(GlobalNameError::Format)
    }
}

fn checkpoint_refusal(cx: &Cx) -> RemoteOutcome {
    cx.cancel_reason().map_or_else(
        || RemoteOutcome::Failed("global-name checkpoint refused".to_owned()),
        RemoteOutcome::Cancelled,
    )
}

/// Register bounded snapshot propagation and exact-owner lookup handling.
///
/// This does not authorize peers. Configure the existing
/// `RemotePeerAdmissionPolicy` with V1 and `grant_tls_peer` for
/// `GLOBAL_NAME_SERVICE_COMPUTATION`, then bind the existing mTLS listener.
/// The registry's own peer allowlist is checked again before payload decoding.
///
/// A snapshot reply confirms admission of that exact in-memory catalog. It
/// does not certify durable storage, task drain, quorum acceptance or global
/// uniqueness. A lost/cancelled reply can follow an applied snapshot; the
/// registry's incarnation/sequence rules govern subsequent full snapshots.
/// Queries return this owner's observation only, and require its exact
/// incarnation. Run `GlobalNameRegistry::run` in an owned task before serving.
///
/// V1 avoids framework-retained V2/V3 receipts outliving a replaced registry.
/// No driver, discovery loop, or background propagation is started here.
///
/// # Errors
///
/// Returns the existing schema-registration error, including duplicate
/// registration of this computation.
pub fn register_global_name_service(
    computations: &mut RemoteComputationRegistry,
    registry: GlobalNameRegistry,
) -> Result<(), ComputationSchemaRegistryError> {
    computations.register::<GlobalNameRequest, GlobalNameResponse, _, _>(
        GLOBAL_NAME_SERVICE_COMPUTATION,
        move |cx, invocation| {
            let registry = registry.clone();
            async move {
                if cx.checkpoint().is_err() {
                    return Ok(checkpoint_refusal(&cx));
                }
                let peer = invocation.peer_node();
                if !registry.peers().any(|configured| configured == peer) {
                    return Ok(RemoteOutcome::Failed(
                        "global-name peer is not configured".to_owned(),
                    ));
                }
                let result = apply_request(
                    &registry,
                    &cx,
                    peer,
                    invocation.request().input.data(),
                );
                // Cancellation never claims rollback of a catalog already
                // admitted. Preserve the attributed cancellation outcome.
                if cx.checkpoint().is_err() {
                    return Ok(checkpoint_refusal(&cx));
                }
                Ok(match result {
                    Ok(reply) => RemoteOutcome::Success(reply),
                    Err(error) => RemoteOutcome::Failed(error.to_string()),
                })
            }
        },
    )
}
