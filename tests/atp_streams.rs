//! ATP Stream Integration Tests
//!
//! Tests for ATP stream scheduling, flow control, reassembly, and lifecycle.

use asupersync::{
    bytes::Bytes,
    net::atp::streams::{
        AtpStream, ConnectionFlowControl, StreamId, StreamManager, StreamPriority, StreamScheduler,
    },
};

fn test_cx() -> asupersync::cx::Cx {
    asupersync::cx::Cx::for_testing()
}

#[test]
fn test_stream_manager_lifecycle() {
    let cx = test_cx();
    let mut manager = StreamManager::new(false); // Client

    // Open a bidirectional stream
    let stream_id = manager
        .open_stream(&cx, true, StreamPriority::Data)
        .unwrap();

    assert_eq!(stream_id, StreamId::new(0)); // First client bidi stream
    assert!(manager.get_stream(stream_id).is_some());

    // Close the stream
    manager.close_stream(&cx, stream_id).unwrap();

    // Clean up closed streams
    manager.cleanup_closed_streams();
}

#[test]
fn test_stream_priority_scheduling() {
    let mut scheduler = StreamScheduler::new();

    let control_stream = StreamId::new(0);
    let data_stream1 = StreamId::new(4);
    let data_stream2 = StreamId::new(8);
    let repair_stream = StreamId::new(12);

    // Register streams with different priorities
    scheduler.register_stream(repair_stream, StreamPriority::Repair);
    scheduler.register_stream(data_stream1, StreamPriority::Data);
    scheduler.register_stream(control_stream, StreamPriority::Control);
    scheduler.register_stream(data_stream2, StreamPriority::Data);

    // Control should come first (highest priority)
    assert_eq!(scheduler.next_stream(), Some(control_stream));

    // Data streams should come next (round-robin between them)
    let next1 = scheduler.next_stream().unwrap();
    let next2 = scheduler.next_stream().unwrap();
    assert!(next1 == data_stream1 || next1 == data_stream2);
    assert!(next2 == data_stream1 || next2 == data_stream2);
    assert_ne!(next1, next2);

    // Repair should come last
    assert_eq!(scheduler.next_stream(), Some(repair_stream));
}

#[test]
fn test_connection_flow_control() {
    let mut flow_control = ConnectionFlowControl::new(10000, 1000);
    let stream_id = StreamId::new(0);

    flow_control.init_stream(stream_id);

    // Should be able to send within limits
    assert!(flow_control.can_send(stream_id, 500));
    assert!(flow_control.reserve_send(stream_id, 500).is_ok());

    // Should be able to receive within limits
    assert!(flow_control.record_received(stream_id, 300).is_ok());

    // Should fail to send more than stream window allows
    let result = flow_control.reserve_send(stream_id, 600);
    assert!(result.is_err());
}

#[test]
fn test_stream_send_receive() {
    let cx = test_cx();
    let mut stream = AtpStream::new(StreamId::new(0), true, StreamPriority::Data, true);

    // Queue data for sending
    let data = Bytes::from("hello world");
    assert!(stream.queue_send(&cx, data.clone(), false).is_ok());
    assert!(stream.has_send_data());

    // Get data to send
    if let Some((offset, send_data, fin)) = stream.get_send_data(1000) {
        assert_eq!(offset, 0);
        assert_eq!(send_data, data);
        assert!(!fin);
    } else {
        panic!("Should have data to send");
    }

    // Receive the same data
    let received = stream.receive_data(&cx, 0, data, false).unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0], Bytes::from("hello world"));
}

#[test]
fn test_stream_out_of_order_reassembly() {
    let cx = test_cx();
    let mut stream = AtpStream::new(StreamId::new(4), true, StreamPriority::Data, false);

    // Receive data out of order - second chunk first
    let data2 = stream.receive_data(&cx, 5, Bytes::from("world"), false).unwrap();
    assert_eq!(data2.len(), 0); // Buffered, not delivered yet

    // Now receive first chunk - should deliver both
    let data1 = stream.receive_data(&cx, 0, Bytes::from("hello"), false).unwrap();
    assert_eq!(data1.len(), 2); // Both chunks delivered
    assert_eq!(data1[0], Bytes::from("hello"));
    assert_eq!(data1[1], Bytes::from("world"));
}

#[test]
fn test_stream_reset_handling() {
    let cx = test_cx();
    let mut manager = StreamManager::new(true); // Server

    // Accept an incoming stream
    let stream_id = StreamId::new(0);
    manager
        .accept_stream(&cx, stream_id, StreamPriority::Control)
        .unwrap();

    assert!(!manager.get_stream(stream_id).unwrap().is_closed());

    // Reset the stream
    use asupersync::net::atp::streams::StreamResetCode;
    manager
        .reset_stream(&cx, stream_id, StreamResetCode::ApplicationClose)
        .unwrap();

    assert!(manager.get_stream(stream_id).unwrap().is_closed());
}

#[test]
fn test_stream_fin_handling() {
    let cx = test_cx();
    let mut stream = AtpStream::new(StreamId::new(8), true, StreamPriority::Data, true);

    // Send with FIN
    let data = Bytes::from("final data");
    assert!(stream.queue_send(&cx, data.clone(), true).is_ok());

    // Get data should include FIN
    if let Some((offset, send_data, fin)) = stream.get_send_data(1000) {
        assert_eq!(offset, 0);
        assert_eq!(send_data, data);
        assert!(fin);
    } else {
        panic!("Should have data to send");
    }

    // Receive with FIN should complete stream on receive side
    let received = stream.receive_data(&cx, 0, data, true).unwrap();
    assert_eq!(received.len(), 1);

    // Stream should show proper receive state
    use asupersync::net::atp::streams::ReceiveState;
    let stats = stream.statistics();
    assert!(matches!(stats.receive_state, ReceiveState::DataRecvd));
}

#[test]
fn test_stream_stop_sending() {
    let cx = test_cx();
    let mut stream = AtpStream::new(StreamId::new(12), true, StreamPriority::Repair, false);

    // Queue some data
    let data = Bytes::from("data to stop");
    assert!(stream.queue_send(&cx, data, false).is_ok());
    assert!(stream.has_send_data());

    // Handle STOP_SENDING from peer
    use asupersync::net::atp::streams::StopSendingCode;
    stream.handle_stop_sending(StopSendingCode::ApplicationStop);

    // Should no longer have data to send
    assert!(!stream.has_send_data());
}

#[test]
fn test_stream_id_properties() {
    // Client-initiated bidirectional
    let client_bidi = StreamId::new(0);
    assert!(client_bidi.is_bidirectional());
    assert!(client_bidi.is_client_initiated());
    assert!(!client_bidi.is_unidirectional());
    assert!(!client_bidi.is_server_initiated());

    // Server-initiated bidirectional
    let server_bidi = StreamId::new(1);
    assert!(server_bidi.is_bidirectional());
    assert!(server_bidi.is_server_initiated());
    assert!(!server_bidi.is_unidirectional());
    assert!(!server_bidi.is_client_initiated());

    // Client-initiated unidirectional
    let client_uni = StreamId::new(2);
    assert!(client_uni.is_unidirectional());
    assert!(client_uni.is_client_initiated());
    assert!(!client_uni.is_bidirectional());
    assert!(!client_uni.is_server_initiated());

    // Server-initiated unidirectional
    let server_uni = StreamId::new(3);
    assert!(server_uni.is_unidirectional());
    assert!(server_uni.is_server_initiated());
    assert!(!server_uni.is_bidirectional());
    assert!(!server_uni.is_client_initiated());
}
