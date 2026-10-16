    use super::*;

    fn sample(auth: bool) -> QuicSymbolEnvelope {
        QuicSymbolEnvelope {
            transfer_tag: 0x0102_0304_0506_0708,
            entry: 7,
            sbn: 3,
            esi: 12345,
            is_repair: true,
            auth_tag: auth.then_some([0xABu8; TAG_SIZE]),
            payload: Bytes::from_static(b"the-raptorq-symbol-bytes"),
        }
    }

    #[test]
    fn roundtrip_without_auth() {
        let env = sample(false);
        let bytes = env.encode().unwrap();
        assert_eq!(bytes.len(), env.encoded_len());
        let back = QuicSymbolEnvelope::decode(&bytes, false).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn roundtrip_with_auth() {
        let env = sample(true);
        let bytes = env.encode().unwrap();
        assert_eq!(bytes.len(), AUTH_ENVELOPE_HEADER_LEN + env.payload.len());
        let back = QuicSymbolEnvelope::decode(&bytes, true).unwrap();
        assert_eq!(env, back);
        assert_eq!(back.auth_tag, Some([0xABu8; TAG_SIZE]));
    }

    #[test]
    fn header_layout_is_golden() {
        let env = sample(false);
        let b = env.encode().unwrap();
        assert_eq!(&b[0..4], &ATP_QUIC_SYMBOL_MAGIC.to_be_bytes());
        assert_eq!(&b[4..12], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&b[12..16], &7u32.to_be_bytes());
        assert_eq!(b[16], 3); // sbn
        assert_eq!(&b[17..21], &12345u32.to_be_bytes());
        assert_eq!(b[21], 1); // repair
        assert_eq!(&b[22..24], &(env.payload.len() as u16).to_be_bytes());
        assert_eq!(&b[ENVELOPE_HEADER_LEN..], env.payload.as_ref());
    }

    #[test]
    fn empty_payload_roundtrips() {
        let mut env = sample(false);
        env.payload = Bytes::new();
        let b = env.encode().unwrap();
        assert_eq!(b.len(), ENVELOPE_HEADER_LEN);
        assert_eq!(QuicSymbolEnvelope::decode(&b, false).unwrap(), env);
    }

    #[test]
    fn decode_rejects_short_buffer() {
        let err = QuicSymbolEnvelope::decode(&[0u8; 10], false).unwrap_err();
        assert!(
            matches!(err, QuicSymbolEnvelopeError::TooShort { need, .. } if need == ENVELOPE_HEADER_LEN)
        );
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut b = sample(false).encode().unwrap().to_vec();
        b[0] ^= 0xFF;
        assert!(matches!(
            QuicSymbolEnvelope::decode(&b, false),
            Err(QuicSymbolEnvelopeError::BadMagic { .. })
        ));
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        let b = sample(false).encode().unwrap();
        // Drop the last payload byte: declared length no longer matches.
        let truncated = &b[..b.len() - 1];
        assert!(matches!(
            QuicSymbolEnvelope::decode(truncated, false),
            Err(QuicSymbolEnvelopeError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn decode_rejects_invalid_repair_flag() {
        let mut b = sample(false).encode().unwrap().to_vec();
        b[21] = 2;
        assert!(matches!(
            QuicSymbolEnvelope::decode(&b, false),
            Err(QuicSymbolEnvelopeError::InvalidRepairFlag { byte: 2 })
        ));
    }

    #[test]
    fn auth_posture_mismatch_fails_closed() {
        // Encoded WITH auth but decoded as unauthenticated: the 32 tag bytes are
        // counted as payload, so the declared length no longer matches.
        let b = sample(true).encode().unwrap();
        assert!(QuicSymbolEnvelope::decode(&b, false).is_err());
        // Encoded WITHOUT auth but decoded as requiring auth: too short / mismatch.
        let b2 = sample(false).encode().unwrap();
        assert!(QuicSymbolEnvelope::decode(&b2, true).is_err());
    }

    #[test]
    fn metamorphic_field_change_changes_bytes() {
        let base = sample(false).encode().unwrap();
        let mut other = sample(false);
        other.esi += 1;
        assert_ne!(base, other.encode().unwrap());
    }
