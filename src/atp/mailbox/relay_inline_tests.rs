    use super::*;
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    fn relay_test_credential(parts: &[&str]) -> String {
        parts.join("-")
    }

    #[test]
    fn test_relay_client_creation() -> TestResult {
        let endpoint: SocketAddr = "127.0.0.1:8080".parse()?;
        let client = RelayClient::new(endpoint);
        assert_eq!(client.endpoint, endpoint);
        Ok(())
    }

    #[test]
    fn test_relay_credentials() -> TestResult {
        let credentials = RelayCredentials {
            client_id: "test-client".to_string(),
            auth_token: relay_test_credential(&["credential", "fixture", "private"]),
        };

        let endpoint: SocketAddr = "127.0.0.1:8080".parse()?;
        let client = RelayClient::new(endpoint).with_credentials(credentials);

        assert!(client.credentials.is_some());
        Ok(())
    }

    #[test]
    fn relay_credentials_debug_redacts_auth_token() {
        let auth_token = relay_test_credential(&["private", "relay", "credential"]);
        let credentials = RelayCredentials {
            client_id: "test-client".to_string(),
            auth_token: auth_token.clone(),
        };

        let debug = format!("{credentials:?}");

        assert!(debug.contains("auth_token"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&auth_token));
    }

    #[test]
    fn relay_client_debug_redacts_credentials() -> TestResult {
        let auth_token = relay_test_credential(&["private", "relay", "client", "credential"]);
        let endpoint: SocketAddr = "127.0.0.1:8080".parse()?;
        let client = RelayClient::new(endpoint).with_credentials(RelayCredentials {
            client_id: "test-client".to_string(),
            auth_token: auth_token.clone(),
        });

        let debug = format!("{client:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&auth_token));
        Ok(())
    }

    #[test]
    fn test_relay_protocol_serialization() -> TestResult {
        let protocol = RelayProtocol::new("1.0".to_string());

        let message = RelayMessage::Status;
        let serialized = protocol
            .serialize_message(&message)
            .map_err(std::io::Error::other)?;
        let deserialized = protocol
            .deserialize_message(&serialized)
            .map_err(std::io::Error::other)?;

        assert!(matches!(deserialized, RelayMessage::Status));
        Ok(())
    }

    #[test]
    fn test_relay_features_default() {
        let features = RelayFeatures::default();
        assert!(features.max_transfer_size > 0);
        assert!(!features.encryption_algorithms.is_empty());
    }

    #[test]
    fn read_frame_rejects_oversized_response_length_without_allocating() -> TestResult {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let server = std::thread::spawn(move || -> TestResult {
            let (mut stream, _) = listener.accept()?;
            let oversized_len = u32::try_from(RELAY_MAX_FRAME_BYTES + 1)?;
            stream.write_all(&oversized_len.to_be_bytes())?;
            Ok(())
        });
        let mut stream = TcpStream::connect(endpoint)?;

        let result = read_frame(&mut stream);
        let _ = stream.shutdown(Shutdown::Both);

        let server_result = server
            .join()
            .map_err(|_| std::io::Error::other("relay test server thread panicked"))?;
        server_result?;
        assert!(
            matches!(result, Err(MailboxError::RelayError { message }) if message.contains("exceeds maximum frame size"))
        );
        Ok(())
    }

    #[test]
    fn test_relay_message_handling() -> TestResult {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let endpoint = listener.local_addr()?;
        let server = std::thread::spawn(move || -> MailboxResult<()> {
            let (mut stream, _) = listener
                .accept()
                .map_err(|err| MailboxError::NetworkError {
                    details: format!("failed to accept relay test connection: {err}"),
                })?;
            let request_payload = read_frame(&mut stream)?;
            let request: serde_json::Value =
                serde_json::from_slice(&request_payload).map_err(|err| {
                    MailboxError::RelayError {
                        message: format!("failed to decode relay test request: {err}"),
                    }
                })?;
            assert_eq!(request["version"], "1.0");
            assert_eq!(request["message"], "Status");

            let response = RelayResponse::StatusInfo {
                version: "1.0".to_string(),
                available_storage: 1_000_000_000,
                active_transfers: 0,
            };
            let payload =
                serde_json::to_vec(&response).map_err(|err| MailboxError::RelayError {
                    message: format!("failed to encode relay test response: {err}"),
                })?;
            write_frame(&mut stream, &payload)?;
            Ok(())
        });
        let client = RelayClient::new(endpoint);

        let response = futures_lite::future::block_on(client.send_message(RelayMessage::Status))?;
        let server_result = server
            .join()
            .map_err(|_| std::io::Error::other("relay test server thread panicked"))?;
        server_result?;

        if let RelayResponse::StatusInfo { version, .. } = response {
            assert_eq!(version.as_str(), "1.0");
        } else {
            return Err(std::io::Error::other("unexpected relay response type").into());
        }
        Ok(())
    }
