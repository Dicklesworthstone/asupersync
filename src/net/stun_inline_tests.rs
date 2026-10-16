    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn stun_client_creation() {
        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let client = StunClient::new(local_addr);
        assert_eq!(client.local_addr, local_addr);
        assert!(client.stun_servers.is_empty());
        assert!(client.candidates.is_empty());
    }

    #[test]
    fn add_stun_server() {
        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let mut client = StunClient::new(local_addr);

        let stun_server = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478));
        client.add_stun_server(stun_server);

        assert_eq!(client.stun_servers.len(), 1);
        assert_eq!(client.stun_servers[0], stun_server);
    }

    fn binding_success_response(
        transaction_id: [u8; STUN_TRANSACTION_ID_LEN],
        mapped_addr: SocketAddr,
    ) -> Vec<u8> {
        let mut attr_value = Vec::new();
        attr_value.push(0);
        match mapped_addr {
            SocketAddr::V4(addr) => {
                attr_value.push(0x01);
                attr_value.extend_from_slice(
                    &(addr.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes(),
                );
                for (octet, cookie) in addr
                    .ip()
                    .octets()
                    .iter()
                    .zip(STUN_MAGIC_COOKIE.to_be_bytes().iter())
                {
                    attr_value.push(*octet ^ *cookie);
                }
            }
            SocketAddr::V6(addr) => {
                attr_value.push(0x02);
                attr_value.extend_from_slice(
                    &(addr.port() ^ (STUN_MAGIC_COOKIE >> 16) as u16).to_be_bytes(),
                );
                let mut octets = addr.ip().octets();
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for index in 0..4 {
                    octets[index] ^= cookie[index];
                }
                for index in 0..STUN_TRANSACTION_ID_LEN {
                    octets[index + 4] ^= transaction_id[index];
                }
                attr_value.extend_from_slice(&octets);
            }
        }

        let message_len = 4 + attr_value.len();
        let mut response = Vec::with_capacity(STUN_HEADER_LEN + message_len);
        response.extend_from_slice(&STUN_BINDING_SUCCESS_RESPONSE.to_be_bytes());
        response.extend_from_slice(&(message_len as u16).to_be_bytes());
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&transaction_id);
        response.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&(attr_value.len() as u16).to_be_bytes());
        response.extend_from_slice(&attr_value);
        response
    }

    #[test]
    fn binding_request_header_is_rfc5389_canonical() {
        let transaction_id = [0xAB; STUN_TRANSACTION_ID_LEN];
        let request = encode_binding_request(transaction_id);

        assert_eq!(
            u16::from_be_bytes([request[0], request[1]]),
            STUN_BINDING_REQUEST
        );
        assert_eq!(u16::from_be_bytes([request[2], request[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([request[4], request[5], request[6], request[7]]),
            STUN_MAGIC_COOKIE
        );
        assert_eq!(&request[8..20], &transaction_id);
    }

    #[test]
    fn parses_xor_mapped_address_from_success_response() {
        let transaction_id = [0x42; STUN_TRANSACTION_ID_LEN];
        let mapped = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 54321));
        let response = binding_success_response(transaction_id, mapped);

        let parsed = parse_binding_response(&response, transaction_id).unwrap();

        assert_eq!(parsed, mapped);
    }

    #[test]
    fn gather_candidates_uses_real_udp_stun_exchange() {
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let server_addr = server.local_addr().unwrap();
        let mapped = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 20), 50000));

        let server_thread = std::thread::spawn(move || {
            let mut request = [0u8; STUN_MAX_MESSAGE_LEN];
            let (len, peer) = server.recv_from(&mut request).unwrap();
            assert!(len >= STUN_HEADER_LEN);
            assert_eq!(
                u16::from_be_bytes([request[0], request[1]]),
                STUN_BINDING_REQUEST
            );
            let mut transaction_id = [0u8; STUN_TRANSACTION_ID_LEN];
            transaction_id.copy_from_slice(&request[8..20]);
            let response = binding_success_response(transaction_id, mapped);
            server.send_to(&response, peer).unwrap();
        });

        let local_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
        let mut client = StunClient::new(local_addr);
        client.add_stun_server(server_addr);
        let cx = Cx::for_testing();

        let outcome = futures_lite::future::block_on(client.gather_candidates(&cx));
        server_thread.join().unwrap();

        let candidates = match outcome {
            Outcome::Ok(candidates) => candidates,
            other => panic!("expected gathered candidates, got {other:?}"),
        };
        assert!(candidates.iter().any(|candidate| {
            matches!(candidate.candidate_type, IceCandidateType::ServerReflexive)
                && candidate.address == mapped
        }));
    }

    // Golden Artifact Tests for STUN/ICE Serialization Stability

    #[test]
    fn golden_stun_message_types_serialization() {
        use insta::assert_json_snapshot;

        let message_types = vec![
            StunMessageType::BindingRequest,
            StunMessageType::BindingResponse,
            StunMessageType::BindingError,
        ];
        assert_json_snapshot!("stun_message_types", message_types);
    }

    #[test]
    fn golden_ice_candidate_types_serialization() {
        use insta::assert_json_snapshot;

        let candidate_types = vec![
            IceCandidateType::Host,
            IceCandidateType::ServerReflexive,
            IceCandidateType::PeerReflexive,
            IceCandidateType::Relay,
        ];
        assert_json_snapshot!("ice_candidate_types", candidate_types);
    }

    #[test]
    fn golden_ice_candidate_host_serialization() {
        use insta::assert_json_snapshot;

        let host_candidate = IceCandidate {
            foundation: "1".to_string(),
            component: 1,
            protocol: "udp".to_string(),
            priority: 126,
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 100), 5000)),
            candidate_type: IceCandidateType::Host,
            related_address: None,
        };
        assert_json_snapshot!("ice_candidate_host", host_candidate);
    }

    #[test]
    fn golden_ice_candidate_server_reflexive_serialization() {
        use insta::assert_json_snapshot;

        let reflexive_candidate = IceCandidate {
            foundation: "2".to_string(),
            component: 1,
            protocol: "udp".to_string(),
            priority: 100,
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 10), 54400)),
            candidate_type: IceCandidateType::ServerReflexive,
            related_address: Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(192, 168, 1, 100),
                5000,
            ))),
        };
        assert_json_snapshot!("ice_candidate_server_reflexive", reflexive_candidate);
    }

    #[test]
    fn golden_ice_candidate_relay_serialization() {
        use insta::assert_json_snapshot;

        let relay_candidate = IceCandidate {
            foundation: "3".to_string(),
            component: 1,
            protocol: "udp".to_string(),
            priority: 50,
            address: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 49152)),
            candidate_type: IceCandidateType::Relay,
            related_address: Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(203, 0, 113, 10),
                54400,
            ))),
        };
        assert_json_snapshot!("ice_candidate_relay", relay_candidate);
    }

    #[test]
    fn golden_stun_error_types_serialization() {
        use insta::assert_json_snapshot;

        let error_types = vec![
            StunError::Timeout,
            StunError::InvalidResponse,
            StunError::Protocol("Binding error".to_string()),
            StunError::Network("Connection refused".to_string()),
        ];
        assert_json_snapshot!("stun_error_types", error_types);
    }
