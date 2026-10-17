    use super::*;

    #[test]
    fn test_flow_control_window_basic() {
        let mut window = FlowControlWindow::new(1000, 1000);

        assert!(window.can_send(500));
        assert!(window.reserve_send(500).is_ok());
        assert_eq!(window.send_capacity(), 500);

        assert!(window.can_receive(300));
        assert!(window.record_received(300).is_ok());
        assert_eq!(window.receive_capacity(), 700);
    }

    #[test]
    fn test_flow_control_window_violation() {
        let mut window = FlowControlWindow::new(100, 100);

        // Should fail to send more than window allows
        let result = window.reserve_send(150);
        assert!(result.is_err());
        assert!(window.is_send_blocked());
    }

    #[test]
    fn test_connection_flow_control() {
        let mut flow_control = ConnectionFlowControl::new(10000, 1000);
        let stream_id = StreamId::new(0);

        flow_control.init_stream(stream_id);

        assert!(flow_control.can_send(stream_id, 500));
        assert!(flow_control.reserve_send(stream_id, 500).is_ok());

        // Should fail if stream doesn't exist
        let nonexistent_stream = StreamId::new(100);
        assert!(!flow_control.can_send(nonexistent_stream, 100));
    }
