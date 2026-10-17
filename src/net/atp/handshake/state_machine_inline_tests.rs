    use super::*;

    #[test]
    fn test_handshake_machine_creation() {
        let config = AtpPacketProtectionConfig::default();
        let timeout = Duration::from_secs(30);
        let machine = QuicHandshakeMachine::new(EndpointRole::Client, config, timeout);

        assert_eq!(machine.role, EndpointRole::Client);
        assert_eq!(machine.state, HandshakeState::Idle);
        assert!(!machine.is_complete());
        assert!(!machine.is_failed());
    }

    #[test]
    fn test_handshake_start_valid_version() {
        let mut machine = QuicHandshakeMachine::new(
            EndpointRole::Client,
            AtpPacketProtectionConfig::default(),
            Duration::from_secs(30),
        );

        let cx = Cx::for_testing();
        let result = machine.start(&cx, QuicVersion::V1 as u32);

        assert!(result.is_ok());
        assert!(matches!(machine.state, HandshakeState::Initial { .. }));
        assert_eq!(machine.trace_events.len(), 1);
    }

    #[test]
    fn test_handshake_start_invalid_version() {
        let mut machine = QuicHandshakeMachine::new(
            EndpointRole::Client,
            AtpPacketProtectionConfig::default(),
            Duration::from_secs(30),
        );

        let cx = Cx::for_testing();
        let result = machine.start(&cx, 0x12345678);

        assert!(result.is_err());
        assert!(machine.is_failed());
        assert_eq!(machine.trace_events.len(), 1);
    }

    #[test]
    fn test_packet_number_generation() {
        let mut machine = QuicHandshakeMachine::new(
            EndpointRole::Client,
            AtpPacketProtectionConfig::default(),
            Duration::from_secs(30),
        );

        assert_eq!(machine.next_packet_number(PacketSpace::Initial), 0);
        assert_eq!(machine.next_packet_number(PacketSpace::Initial), 1);
        assert_eq!(machine.next_packet_number(PacketSpace::Handshake), 0);
        assert_eq!(machine.next_packet_number(PacketSpace::Application), 0);
    }
