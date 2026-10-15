use super::*;
use crate::distributed::symbol_service::{SymbolStoreLimits, SymbolStoreStats};
use crate::distributed::symbol_service::tests::{encoded, limits, storage};
use crate::remote::{
    ComputationName, IdempotencyKey, NodeId, RemoteComputationDispatchError,
    RemoteInput, RemotePeerAdmissionPolicy, RemoteProtocolVersion, RemoteTaskId, SpawnRequest,
};
use crate::{Cx, security::AuthKey};
use std::time::Duration;

fn setup() -> (Arc<SymbolReplicaStore>, RemoteComputationRegistry, RemotePeerAdmissionPolicy) {
    let store = Arc::new(SymbolReplicaStore::new("replica-a", AuthKey::from_seed(42), limits(), storage()).unwrap());
    let mut registry = RemoteComputationRegistry::new();
    register_symbol_service(&mut registry, Arc::clone(&store)).unwrap();
    let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    for peer in ["a", "b"] {
        policy.grant_peer(NodeId::new(peer), [SYMBOL_SERVICE_COMPUTATION]).unwrap();
    }
    (store, registry, policy)
}

fn dispatch(
    registry: &RemoteComputationRegistry, policy: &RemotePeerAdmissionPolicy,
    peer: &str, claimed_origin: &str, input: Vec<u8>,
) -> Result<RemoteOutcome, RemoteComputationDispatchError> {
    let cx = Cx::for_testing();
    let session = policy.admit(&policy.hello_for(NodeId::new(peer))).unwrap();
    futures_lite::future::block_on(registry.dispatch(&cx, &session, SpawnRequest {
        remote_task_id: RemoteTaskId::from_raw(1),
        computation: ComputationName::new(SYMBOL_SERVICE_COMPUTATION),
        input: RemoteInput::new(input), lease: Duration::from_secs(1),
        idempotency_key: IdempotencyKey::from_raw(1), budget: None,
        origin_node: NodeId::new(claimed_origin), origin_region: cx.region_id(), origin_task: cx.task_id(),
    }))
}

#[test]
fn registered_handler_stores_and_fetches_exact_authenticated_namespace() {
    let (store, registry, policy) = setup();
    let batch = encoded(1);
    let put = put_request("replica-a", batch.as_ref()).unwrap();
    let RemoteOutcome::Success(ack) = dispatch(&registry, &policy, "a", "b", put).unwrap()
        else { panic!("storage was refused") };
    validate_receipt(&ack, "replica-a", batch.key(), batch.symbol_count()).unwrap();
    // A forged request origin never controls the service's storage namespace.
    assert!(store.get(&NodeId::new("a"), batch.key()).is_ok());
    assert!(matches!(store.get(&NodeId::new("b"), batch.key()), Err(SymbolStoreError::NotFound)));
    let RemoteOutcome::Success(bytes) = dispatch(&registry, &policy, "a", "b", fetch_request("replica-a", batch.key()).unwrap()).unwrap()
        else { panic!("fetch was refused") };
    assert_eq!(bytes, batch.as_ref());
    assert!(matches!(dispatch(&registry, &policy, "b", "a", fetch_request("replica-a", batch.key()).unwrap()).unwrap(), RemoteOutcome::Failed(_)));
}

#[test]
fn wrong_target_is_rejected_before_storage() {
    let (store, registry, policy) = setup();
    let result = dispatch(&registry, &policy, "a", "a", put_request("other-replica", encoded(1).as_ref()).unwrap()).unwrap();
    assert!(matches!(result, RemoteOutcome::Failed(_)));
    assert_eq!(store.stats(), SymbolStoreStats { batches: 0, bytes: 0 });
}

#[test]
fn receipt_binds_target_object_digest_and_complete_symbol_count() {
    let batch = encoded(1);
    let ack = receipt("replica-a", &batch, Time::from_nanos(7));
    let parsed = validate_receipt(&ack, "replica-a", batch.key(), 3).unwrap();
    assert_eq!(parsed.ack_time, Time::from_nanos(7));
    assert!(validate_receipt(&ack, "replica-b", batch.key(), 3).is_err());
    assert!(validate_receipt(&ack, "replica-a", encoded(2).key(), 3).is_err());
    assert!(validate_receipt(&ack, "replica-a", batch.key(), 2).is_err());
    for end in 0..ack.len() { assert!(validate_receipt(&ack[..end], "replica-a", batch.key(), 3).is_err()); }
    let mut extra = ack; extra.push(0);
    assert!(validate_receipt(&extra, "replica-a", batch.key(), 3).is_err());
}

#[test]
fn malformed_fetch_is_refused_without_mutating_store() {
    let (store, registry, policy) = setup();
    let batch = encoded(1);
    let valid = fetch_request("replica-a", batch.key()).unwrap();
    for end in 0..valid.len() {
        assert!(matches!(dispatch(&registry, &policy, "a", "a", valid[..end].to_vec()).unwrap(), RemoteOutcome::Failed(_)));
    }
    assert_eq!(store.stats().batches, 0);
}

#[test]
fn unauthorized_computation_never_reaches_store() {
    let (store, registry, mut policy) = setup();
    policy.grant_peer(NodeId::new("a"), std::iter::empty::<&str>()).unwrap();
    let result = dispatch(&registry, &policy, "a", "a", put_request("replica-a", encoded(1).as_ref()).unwrap());
    assert!(matches!(result, Err(RemoteComputationDispatchError::Admission(_))));
    assert_eq!(store.stats().batches, 0);
}

#[test]
fn storage_capacity_cannot_be_acknowledged_as_success() {
    let store = Arc::new(SymbolReplicaStore::new("replica-a", AuthKey::from_seed(42), limits(), SymbolStoreLimits { max_batches: 0, ..storage() }).unwrap());
    let mut registry = RemoteComputationRegistry::new();
    register_symbol_service(&mut registry, Arc::clone(&store)).unwrap();
    let mut policy = RemotePeerAdmissionPolicy::new(RemoteProtocolVersion::V1, registry.schema_registry().clone());
    policy.grant_peer(NodeId::new("a"), [SYMBOL_SERVICE_COMPUTATION]).unwrap();
    assert!(matches!(dispatch(&registry, &policy, "a", "a", put_request("replica-a", encoded(1).as_ref()).unwrap()).unwrap(), RemoteOutcome::Failed(_)));
    assert_eq!(store.stats().batches, 0);
}
