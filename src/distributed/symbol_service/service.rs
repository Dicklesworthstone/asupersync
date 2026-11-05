//! Register storage in the existing authenticated named-computation service.

use super::{EncodedSymbolBatch, SymbolBatchKey, SymbolReplicaStore, SymbolStoreError};
use crate::cx::{ChildRegionSpec, Cx};
use crate::distributed::remote_owned::RemoteServiceAdmission;
use crate::distributed::{ComputationSchemaRegistryError, HasSchema, SchemaDescriptor};
#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
use crate::distributed::distribution::ReplicaAck;
use crate::remote::{RemoteComputationInvocation, RemoteComputationRegistry, RemoteError, RemoteOutcome};
use crate::types::{Time, symbol::ObjectId};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

/// Versioned named-computation capability required for both put and exact fetch.
pub const SYMBOL_SERVICE_COMPUTATION: &str = "asupersync.distributed.symbol-store.v1";
const GET: &[u8; 8] = b"ASUPGET\0";
const PUT: &[u8; 8] = b"ASUPPUT\0";
const ACK: &[u8; 8] = b"ASUPACK\0";

struct ServiceRequest;
struct ServiceResponse;
impl HasSchema for ServiceRequest {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("asupersync.symbol-service.request.canonical-binary.v1")
    }
}
impl HasSchema for ServiceResponse {
    fn schema() -> SchemaDescriptor {
        SchemaDescriptor::primitive("asupersync.symbol-service.response.canonical-binary.v1")
    }
}

// Registration only: all accounting, waiting and cancellation ownership remains
// in RemoteServiceAdmission. The direct path preserves existing handler behavior.
struct Admission<'a> {
    limiter: &'a RemoteServiceAdmission,
    child: ChildRegionSpec,
    wait_timeout: Option<Duration>,
}

fn register_handler<I, O, F, Fut>(
    registry: &mut RemoteComputationRegistry, name: &str,
    admission: Option<Admission<'_>>, handler: F,
) -> Result<(), ComputationSchemaRegistryError>
where
    I: HasSchema,
    O: HasSchema,
    F: Fn(Cx, RemoteComputationInvocation) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<RemoteOutcome, RemoteError>> + Send + 'static,
{
    match admission {
        None => registry.register::<I, O, _, _>(name, handler),
        Some(Admission { limiter, child, wait_timeout: None }) => {
            limiter.register::<I, O, _, _>(registry, name, child, handler)
        }
        Some(Admission { limiter, child, wait_timeout: Some(timeout) }) => {
            limiter.register_waiting::<I, O, _, _>(registry, name, child, timeout, handler)
        }
    }
}

/// Install put/fetch handlers; this does NOT grant any network peer authority.
///
/// Build the listener's admission policy from the resulting complete schema
/// registry, grant the named computation with `grant_tls_peer`, and serve it
/// through `RemoteComputationService` or `serve_tls_computation_once`. The stored
/// namespace comes only from the admitted invocation's peer, not the wire's
/// asserted origin. The handler performs bounded synchronous storage inline and
/// spawns nothing. Service frame/connection limits also bound transient work.
///
/// A put receipt means retained in-memory bytes, not fsync, region restoration,
/// or remote quiescence. Store success followed by connection loss is ambiguous
/// to the caller; the native client never automatically retries that delivery.
pub fn register_symbol_service(
    registry: &mut RemoteComputationRegistry, store: Arc<SymbolReplicaStore>,
) -> Result<(), ComputationSchemaRegistryError> {
    register_symbol_service_inner(registry, store, None)
}

/// Register the same put/fetch capability with shared authenticated-peer admission.
///
/// `admission` supplies global/per-peer invocation and original-input-byte limits.
/// Reuse the same admission object across symbol registrations to share its budget;
/// TLS grants and retained store limits remain independent. The admitted session's
/// peer selects both the quota and storage namespace, never the claimed origin.
///
/// `None` refuses saturation immediately. `Some(timeout)` uses the admission
/// object's bounded queue, which must be enabled with
/// [`RemoteServiceAdmission::new_queued`] (or its prioritized constructor). The
/// timeout must be positive and the context must supply a timer. Queue cancellation,
/// disconnect/drop or expiry removes the request before the handler parses, copies
/// or verifies it. Waiting does not extend the invocation's original deadline.
///
/// Execution runs in `child` and retains its charge until that region drains,
/// including after its dispatch waiter disappears. Runtime spawn capability is
/// required; there is no inline fallback. The original name, schemas, receipt and
/// storage semantics are unchanged. Admission counts input bytes, not response
/// buffers or retained batches; listener/frame and store bounds still apply.
pub fn register_symbol_service_with_admission(
    registry: &mut RemoteComputationRegistry, store: Arc<SymbolReplicaStore>,
    admission: &RemoteServiceAdmission, child: ChildRegionSpec, wait_timeout: Option<Duration>,
) -> Result<(), ComputationSchemaRegistryError> {
    register_symbol_service_inner(registry, store,
        Some(Admission { limiter: admission, child, wait_timeout }))
}

fn register_symbol_service_inner(
    registry: &mut RemoteComputationRegistry, store: Arc<SymbolReplicaStore>,
    admission: Option<Admission<'_>>,
) -> Result<(), ComputationSchemaRegistryError> {
    register_handler::<ServiceRequest, ServiceResponse, _, _>(
        registry,
        SYMBOL_SERVICE_COMPUTATION,
        admission,
        move |cx, invocation| {
            let store = Arc::clone(&store);
            async move {
                if cx.checkpoint().is_err() {
                    return Ok(cx.cancel_reason().map_or_else(
                        || RemoteOutcome::Failed("symbol service checkpoint refused".to_owned()),
                        RemoteOutcome::Cancelled,
                    ));
                }
                let peer = invocation.peer_node();
                let input = invocation.request().input.data();
                let result = split_request(input, store.replica_id()).and_then(|(get, body)| {
                    if get {
                        read_key(body).and_then(|key| store.get(peer, key)).map(|batch| {
                            // The frame writer also enforces its encoded response limit.
                            batch.as_ref().as_ref().to_vec()
                        })
                    } else {
                        store.put(peer, body).map(|batch| receipt(store.replica_id(), &batch, cx.now()))
                    }
                });
                Ok(match result {
                    Ok(bytes) => RemoteOutcome::Success(bytes),
                    Err(error) => RemoteOutcome::Failed(error.to_string()),
                })
            }
        },
    )
}

fn put_key(bytes: &mut Vec<u8>, key: SymbolBatchKey) {
    bytes.extend_from_slice(&key.object_id.as_u128().to_le_bytes());
    bytes.extend_from_slice(&key.digest);
}
fn read_key(bytes: &[u8]) -> Result<SymbolBatchKey, SymbolStoreError> {
    if bytes.len() != 48 { return Err(SymbolStoreError::Format); }
    Ok(SymbolBatchKey {
        object_id: ObjectId::from_u128(u128::from_le_bytes(bytes[..16].try_into().expect("object bytes"))),
        digest: bytes[16..].try_into().expect("digest bytes"),
    })
}

// Both requests carry a target, so a misconfigured route is refused BEFORE put.
// V1: magic[8], version:u32, target-length:u8, target UTF-8, then batch or key[48].
fn split_request<'a>(bytes: &'a [u8], replica: &str) -> Result<(bool, &'a [u8]), SymbolStoreError> {
    if bytes.len() < 13 || bytes[8..12] != 1_u32.to_le_bytes() { return Err(SymbolStoreError::Format); }
    let get = if &bytes[..8] == GET { true } else if &bytes[..8] == PUT { false }
        else { return Err(SymbolStoreError::Format); };
    let n = usize::from(bytes[12]);
    if n == 0 || bytes.len() < 13 + n { return Err(SymbolStoreError::Format); }
    if &bytes[13..13+n] != replica.as_bytes() { return Err(SymbolStoreError::Identity); }
    Ok((get, &bytes[13+n..]))
}

#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
fn request(magic: &[u8; 8], replica: &str, body: &[u8]) -> Result<Vec<u8>, SymbolStoreError> {
    if !super::valid_identity(replica) { return Err(SymbolStoreError::InvalidIdentity); }
    let size = body.len().checked_add(13 + replica.len()).ok_or(SymbolStoreError::Overflow)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| SymbolStoreError::Allocation)?;
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.push(replica.len() as u8);
    bytes.extend_from_slice(replica.as_bytes());
    bytes.extend_from_slice(body);
    Ok(bytes)
}
#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
pub(super) fn fetch_request(replica: &str, key: SymbolBatchKey) -> Result<Vec<u8>, SymbolStoreError> {
    let mut body = Vec::with_capacity(48);
    put_key(&mut body, key);
    request(GET, replica, &body)
}
#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
pub(super) fn put_request(replica: &str, body: &[u8]) -> Result<Vec<u8>, SymbolStoreError> {
    request(PUT, replica, body)
}

fn receipt(replica: &str, batch: &EncodedSymbolBatch, now: Time) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(74 + replica.len());
    bytes.extend_from_slice(ACK);
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&(replica.len() as u16).to_le_bytes());
    bytes.extend_from_slice(replica.as_bytes());
    put_key(&mut bytes, batch.key());
    bytes.extend_from_slice(&batch.symbol_count().to_le_bytes());
    bytes.extend_from_slice(&now.as_nanos().to_le_bytes());
    bytes
}

#[cfg(any(test, all(feature = "tls", not(target_arch = "wasm32"))))]
pub(super) fn validate_receipt(
    bytes: &[u8], replica: &str, key: SymbolBatchKey, count: u32,
) -> Result<ReplicaAck, SymbolStoreError> {
    if !(74..=329).contains(&bytes.len()) || &bytes[..8] != ACK || bytes[8..12] != 1_u32.to_le_bytes() {
        return Err(SymbolStoreError::Format);
    }
    let n = usize::from(u16::from_le_bytes(bytes[12..14].try_into().expect("name length")));
    if n == 0 || n > 255 || bytes.len() != 74 + n { return Err(SymbolStoreError::Format); }
    if &bytes[14..14+n] != replica.as_bytes() { return Err(SymbolStoreError::Identity); }
    let tail = &bytes[14+n..];
    if read_key(&tail[..48])? != key { return Err(SymbolStoreError::Identity); }
    if u32::from_le_bytes(tail[48..52].try_into().expect("count bytes")) != count {
        return Err(SymbolStoreError::Identity);
    }
    Ok(ReplicaAck {
        replica_id: replica.to_owned(), symbols_received: count,
        ack_time: Time::from_nanos(u64::from_le_bytes(tail[52..60].try_into().expect("time bytes"))),
    })
}

#[cfg(test)]
mod tests;

// The frame helpers are crate-internal by intent (the native symbol service
// uses them); this module's own visibility already caps them.
#[allow(clippy::redundant_pub_crate)]
pub(super) mod chunked;

#[cfg(not(target_arch = "wasm32"))]
mod durable;
#[cfg(not(target_arch = "wasm32"))]
pub use durable::{
    DurableSymbolServiceHandle, register_durable_symbol_service,
    register_durable_symbol_service_with_admission,
};

#[cfg(not(target_arch = "wasm32"))]
mod durable_chunked;
#[cfg(not(target_arch = "wasm32"))]
pub use durable_chunked::{
    DurableChunkedSymbolService, register_durable_chunked_symbol_service,
    register_durable_chunked_symbol_service_with_admission,
};
