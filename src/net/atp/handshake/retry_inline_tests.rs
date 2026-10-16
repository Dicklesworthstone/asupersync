    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_retry_packet_roundtrip() {
        let retry_key = [0u8; 32];
        let packet = RetryPacket::new(
            QuicVersion::V1 as u32,
            Bytes::from_static(b"server_cid"),
            Bytes::from_static(b"client_cid"),
            Bytes::from_static(b"retry_token_data"),
        );

        let encoded = packet.encode(&retry_key).unwrap();
        let decoded = RetryPacket::decode(&encoded, &retry_key).unwrap();

        assert_eq!(decoded.version, packet.version);
        assert_eq!(decoded.source_cid, packet.source_cid);
        assert_eq!(decoded.dest_cid, packet.dest_cid);
        assert_eq!(decoded.retry_token, packet.retry_token);
    }

    #[test]
    fn test_retry_packet_rejects_oversized_connection_ids() {
        let retry_key = [0u8; 32];
        let oversized_cid = Bytes::from(vec![0xab; MAX_QUIC_V1_CONNECTION_ID_LEN + 1]);

        let oversized_dest = RetryPacket::new(
            QuicVersion::V1 as u32,
            Bytes::from_static(b"server_cid"),
            oversized_cid.clone(),
            Bytes::from_static(b"retry_token_data"),
        );
        assert!(oversized_dest.encode(&retry_key).is_err());

        let oversized_source = RetryPacket::new(
            QuicVersion::V1 as u32,
            oversized_cid,
            Bytes::from_static(b"client_cid"),
            Bytes::from_static(b"retry_token_data"),
        );
        assert!(oversized_source.encode(&retry_key).is_err());
    }

    #[test]
    fn test_retry_packet_decode_rejects_oversized_connection_ids() {
        let retry_key = [0u8; 32];
        let oversized_cid = vec![0xab; MAX_QUIC_V1_CONNECTION_ID_LEN + 1];

        let mut oversized_dest = BytesMut::new();
        oversized_dest.put_u8(0xf0);
        oversized_dest.put_u32(QuicVersion::V1 as u32);
        oversized_dest.put_u8(oversized_cid.len() as u8);
        oversized_dest.put_slice(&oversized_cid);
        oversized_dest.put_u8(0);
        oversized_dest.put_slice(&[0; 16]);
        assert!(RetryPacket::decode(&oversized_dest, &retry_key).is_err());

        let mut oversized_source = BytesMut::new();
        oversized_source.put_u8(0xf0);
        oversized_source.put_u32(QuicVersion::V1 as u32);
        oversized_source.put_u8(0);
        oversized_source.put_u8(oversized_cid.len() as u8);
        oversized_source.put_slice(&oversized_cid);
        oversized_source.put_slice(&[0; 16]);
        assert!(RetryPacket::decode(&oversized_source, &retry_key).is_err());
    }

    #[test]
    fn test_retry_token_roundtrip() {
        let secret_key = [1u8; 32];
        let handler = RetryTokenHandler::new(secret_key, 300); // 5 minute lifetime

        let client_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345);
        let original_dest_cid = b"original_cid";

        let token = handler
            .generate_token(client_addr, original_dest_cid)
            .unwrap();
        let result = handler.validate_token(&token, client_addr, original_dest_cid);

        assert!(result.is_ok());
    }

    #[test]
    fn test_retry_token_rejects_oversized_original_destination_cid() {
        let secret_key = [1u8; 32];
        let handler = RetryTokenHandler::new(secret_key, 300);
        let client_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345);
        let oversized_cid = [0xab; MAX_QUIC_V1_CONNECTION_ID_LEN + 1];

        assert!(handler.generate_token(client_addr, &oversized_cid).is_err());

        let forged_token = forge_retry_token(&secret_key, client_addr, &oversized_cid);
        assert!(
            handler
                .validate_token(&forged_token, client_addr, &oversized_cid)
                .is_err()
        );
    }

    #[test]
    fn test_retry_token_invalid_address() {
        let secret_key = [1u8; 32];
        let handler = RetryTokenHandler::new(secret_key, 300);

        let client_addr1 = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345);
        let client_addr2 = SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), 12345);
        let original_dest_cid = b"original_cid";

        let token = handler
            .generate_token(client_addr1, original_dest_cid)
            .unwrap();
        let result = handler.validate_token(&token, client_addr2, original_dest_cid);

        assert!(result.is_err());
    }

    #[test]
    fn test_retry_token_invalid_cid() {
        let secret_key = [1u8; 32];
        let handler = RetryTokenHandler::new(secret_key, 300);

        let client_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345);
        let original_dest_cid1 = b"original_cid1";
        let original_dest_cid2 = b"original_cid2";

        let token = handler
            .generate_token(client_addr, original_dest_cid1)
            .unwrap();
        let result = handler.validate_token(&token, client_addr, original_dest_cid2);

        assert!(result.is_err());
    }

    fn forge_retry_token(
        secret_key: &[u8; 32],
        client_addr: SocketAddr,
        original_dest_cid: &[u8],
    ) -> Bytes {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_secs();

        let mut token = BytesMut::new();
        token.put_u64(now);

        match client_addr {
            SocketAddr::V4(addr) => {
                token.put_u8(4);
                token.put_slice(&addr.ip().octets());
                token.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                token.put_u8(6);
                token.put_slice(&addr.ip().octets());
                token.put_u16(addr.port());
            }
        }

        token.put_u8(original_dest_cid.len() as u8);
        token.put_slice(original_dest_cid);

        let mut mac = HmacSha256::new_from_slice(secret_key).expect("valid hmac key");
        mac.update(&token);
        token.put_slice(&mac.finalize().into_bytes());

        token.freeze()
    }
