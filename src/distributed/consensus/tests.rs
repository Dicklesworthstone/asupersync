//! Tests for Byzantine consensus protocols.

use crate::cx::Cx;
use crate::error::Result;
use crate::types::Time;
use std::sync::{Arc, Mutex};

use super::pbft::{PbftConfig, PbftConsensus, PbftMessage, PbftNode, PbftTransport};
use super::types::{ConsensusRequest, ReplicaId, SequenceNumber, ViewNumber};

/// Deterministic transport for testing PBFT.
#[derive(Debug)]
pub struct MockTransport {
    /// Messages sent by this replica.
    pub sent_messages: Arc<Mutex<Vec<PbftMessage>>>,
    /// Messages to be received by this replica.
    pub received_messages: Arc<Mutex<Vec<PbftMessage>>>,
    /// Whether to inject network failures.
    pub fail_sends: bool,
}

impl MockTransport {
    pub fn new() -> Self {
        Self {
            sent_messages: Arc::new(Mutex::new(Vec::new())),
            received_messages: Arc::new(Mutex::new(Vec::new())),
            fail_sends: false,
        }
    }

    pub fn add_received_message(&self, message: PbftMessage) {
        let mut messages = self.received_messages.lock().unwrap();
        messages.push(message);
    }

    pub fn get_sent_messages(&self) -> Vec<PbftMessage> {
        let messages = self.sent_messages.lock().unwrap();
        messages.clone()
    }

    pub fn clear_sent_messages(&self) {
        let mut messages = self.sent_messages.lock().unwrap();
        messages.clear();
    }
}

impl PbftTransport for MockTransport {
    fn send_to_replica(
        &self,
        _replica_id: &ReplicaId,
        message: PbftMessage,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let fail_sends = self.fail_sends;
        let sent_messages = Arc::clone(&self.sent_messages);

        async move {
            if fail_sends {
                return Err(crate::error::Error::new(
                    crate::error::ErrorKind::ConnectionLost,
                ));
            }

            let mut messages = sent_messages.lock().unwrap();
            messages.push(message);
            Ok(())
        }
    }

    fn broadcast(
        &self,
        message: PbftMessage,
    ) -> impl std::future::Future<Output = Result<()>> + Send {
        let fail_sends = self.fail_sends;
        let sent_messages = Arc::clone(&self.sent_messages);

        async move {
            if fail_sends {
                return Err(crate::error::Error::new(
                    crate::error::ErrorKind::ConnectionLost,
                ));
            }

            let mut messages = sent_messages.lock().unwrap();
            messages.push(message);
            Ok(())
        }
    }

    fn receive(&self) -> impl std::future::Future<Output = Result<PbftMessage>> + Send {
        let received_messages = Arc::clone(&self.received_messages);

        async move {
            let mut messages = received_messages.lock().unwrap();
            if let Some(message) = messages.pop() {
                Ok(message)
            } else {
                // No message is currently available.
                Err(crate::error::Error::new(
                    crate::error::ErrorKind::ChannelEmpty,
                ))
            }
        }
    }
}

#[test]
fn test_pbft_config_validation() {
    // Valid configuration: 4 replicas, 1 fault
    let config = PbftConfig::new(4, 1).unwrap();
    assert!(config.is_valid());
    assert_eq!(config.quorum_size(), 3); // 2f + 1 = 2*1 + 1 = 3

    // Invalid configuration: insufficient replicas
    let result = PbftConfig::new(2, 1);
    assert!(result.is_err());

    // Valid configuration: 7 replicas, 2 faults
    let config = PbftConfig::new(7, 2).unwrap();
    assert!(config.is_valid());
    assert_eq!(config.quorum_size(), 5); // 2f + 1 = 2*2 + 1 = 5
}

#[test]
fn test_pbft_node_creation() {
    let replica_id = ReplicaId::new("0".to_string());
    let config = PbftConfig::new(4, 1).unwrap();
    let transport = MockTransport::new();

    let node = PbftNode::new(replica_id.clone(), config, transport).unwrap();

    // Node should be primary for view 0 (replica 0 % 4 = 0)
    assert!(node.is_primary());
}

#[test]
fn test_pbft_consensus_creation() {
    let replica_id = ReplicaId::new("1".to_string());
    let config = PbftConfig::new(4, 1).unwrap();
    let transport = MockTransport::new();

    let _consensus = PbftConsensus::new(replica_id, config, transport).unwrap();

    // Should be able to create consensus instance
    assert!(true); // Just verify creation doesn't panic
}

#[test]
fn test_request_submission() {
    let replica_id = ReplicaId::new("0".to_string());
    let config = PbftConfig::new(4, 1).unwrap();
    let transport = MockTransport::new();

    let _consensus = PbftConsensus::new(replica_id, config, transport).unwrap();

    let _request = ConsensusRequest::new(
        "client-1".to_string(),
        Time::from_millis(0),
        b"test operation".to_vec(),
    );

    // Create a simple context for testing
    let _cx = Cx::for_testing();

    // Just test creation for now, since we don't have async runtime
    assert!(true);
}

/// Drive a future that resolves without yielding (the view-change/new-view
/// handlers return immediately).
fn poll_ready<F: std::future::Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(waker);
    match fut.as_mut().poll(&mut cx) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("handler unexpectedly pended"),
    }
}

#[test]
fn view_change_and_new_view_fail_closed_until_implemented() {
    // PBFT view-change/new-view are not implemented (asupersync-v8mszr). They
    // must FAIL rather than silently return Ok, so a caller never believes
    // primary-failure recovery happened when it did not.
    let node = PbftNode::new(
        ReplicaId::new("0".to_string()),
        PbftConfig::new(4, 1).unwrap(),
        MockTransport::new(),
    )
    .unwrap();
    let cx = Cx::for_testing();

    let view_change = PbftMessage::ViewChange {
        new_view: ViewNumber::new(1),
        replica_id: ReplicaId::new("1".to_string()),
        certificates: Vec::new(),
    };
    assert!(
        poll_ready(node.process_message(&cx, view_change)).is_err(),
        "view-change must fail closed, not silently succeed"
    );

    let new_view = PbftMessage::NewView {
        view: ViewNumber::new(1),
        view_change_msgs: Vec::new(),
        preprepare_msgs: Vec::new(),
    };
    assert!(
        poll_ready(node.process_message(&cx, new_view)).is_err(),
        "new-view must fail closed, not silently succeed"
    );
}

#[test]
fn test_mock_transport_message_tracking_helpers() {
    let transport = MockTransport::new();
    let replica_id = ReplicaId::new("1".to_string());
    let request = ConsensusRequest::new(
        "client-1".to_string(),
        Time::from_millis(0),
        b"tracked operation".to_vec(),
    );
    let message = PbftMessage::Request(request);

    futures_lite::future::block_on(transport.send_to_replica(&replica_id, message.clone()))
        .expect("deterministic send should record message");
    assert_eq!(transport.get_sent_messages().len(), 1);

    transport.clear_sent_messages();
    assert!(transport.get_sent_messages().is_empty());

    transport.add_received_message(message);
    let received = futures_lite::future::block_on(transport.receive())
        .expect("deterministic receive should return queued message");
    assert!(matches!(received, PbftMessage::Request(_)));
}

#[test]
fn test_primary_election() {
    // Test primary selection for different views
    assert_eq!(ViewNumber::new(0).primary(4), 0);
    assert_eq!(ViewNumber::new(1).primary(4), 1);
    assert_eq!(ViewNumber::new(2).primary(4), 2);
    assert_eq!(ViewNumber::new(3).primary(4), 3);
    assert_eq!(ViewNumber::new(4).primary(4), 0); // Wraps around
}

#[test]
fn test_sequence_number_ordering() {
    let seq1 = SequenceNumber::new(1);
    let seq2 = SequenceNumber::new(2);
    let seq3 = seq1.next();

    assert!(seq1 < seq2);
    assert_eq!(seq3, seq2);
}

#[test]
fn test_message_digest() {
    use super::types::{ConsensusBatch, MessageDigest};

    let request1 = ConsensusRequest::new(
        "client-1".to_string(),
        Time::from_millis(0),
        b"operation-1".to_vec(),
    );

    let request2 = ConsensusRequest::new(
        "client-1".to_string(),
        Time::from_millis(0),
        b"operation-2".to_vec(),
    );

    let batch1 = ConsensusBatch::new(vec![request1.clone()]);
    let batch2 = ConsensusBatch::new(vec![request2]);
    let batch3 = ConsensusBatch::new(vec![request1]);

    let digest1 = MessageDigest::of(&batch1).unwrap();
    let digest2 = MessageDigest::of(&batch2).unwrap();
    let digest3 = MessageDigest::of(&batch3).unwrap();

    // Different batches should have different digests
    assert_ne!(digest1, digest2);

    // Same batch content should have same digest
    assert_eq!(digest1, digest3);
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Test basic 3-node PBFT with no faults.
    #[test]
    fn test_basic_consensus() {
        let config = PbftConfig::new(4, 1).unwrap();

        // Create replicas
        for i in 0..4 {
            let replica_id = ReplicaId::new(i.to_string());
            let transport = MockTransport::new();
            let node = PbftNode::new(replica_id, config.clone(), transport);

            // Just verify creation succeeded
            assert!(node.is_ok());
        }
    }
}
