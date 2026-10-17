    use super::*;

    struct TestStream {
        sent_data: Vec<Vec<u8>>,
        can_send: bool,
    }

    impl DirectSend for TestStream {
        type Error = String;

        fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
            if !self.can_send {
                return Err("Cannot send".to_string());
            }
            self.sent_data.push(data.to_vec());
            Ok(())
        }

        fn capacity_error(&self) -> Self::Error {
            "Capacity exceeded".to_string()
        }
    }

    #[test]
    fn test_direct_send_trait() {
        let mut stream = TestStream {
            sent_data: Vec::new(),
            can_send: true,
        };

        assert!(stream.send(b"test").is_ok());
        assert_eq!(stream.sent_data.len(), 1);
        assert_eq!(stream.sent_data[0], b"test");
    }
