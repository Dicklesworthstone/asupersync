    use super::*;

    #[test]
    fn test_mailbox_key_generation() {
        let key = MailboxKey::generate();
        assert_eq!(key.as_bytes().len(), 32);
    }

    #[test]
    fn mailbox_key_debug_redacts_key_material() {
        let key = MailboxKey::from_bytes([0xab; 32]);
        let debug = format!("{key:?}");

        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("abababab"));
    }

    #[test]
    fn test_encryption_roundtrip() {
        let key = MailboxKey::generate();
        let data = b"test data";

        let encrypted = EncryptedChunk::encrypt(data, &key).unwrap();
        let decrypted = encrypted.decrypt(&key).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_chunk_nonce_generation() {
        let nonce = ChunkNonce::generate().unwrap();
        assert_eq!(nonce.bytes.len(), 12);
    }
