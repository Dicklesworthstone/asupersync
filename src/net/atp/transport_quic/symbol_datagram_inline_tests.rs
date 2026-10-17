    use super::*;

    fn sym(object: u128, sbn: u8, esi: u32, repair: bool, data: &[u8]) -> Symbol {
        let kind = if repair {
            SymbolKind::Repair
        } else {
            SymbolKind::Source
        };
        Symbol::from_slice(
            SymbolId::new(ObjectId::from_u128(object), sbn, esi),
            data,
            kind,
        )
    }

    #[test]
    fn symbol_envelope_field_mapping_source_and_repair() {
        // `Symbol`/`SymbolId` do not derive `Debug`, so compare with `==`.
        for repair in [false, true] {
            let s = sym(0xABCD, 3, 42, repair, b"raptorq-symbol-bytes");
            let env = symbol_to_envelope(&s, 0x1122, 7, None);
            assert_eq!(env.sbn, 3);
            assert_eq!(env.esi, 42);
            assert_eq!(env.is_repair, repair);
            assert_eq!(env.transfer_tag, 0x1122);
            assert_eq!(env.entry, 7);
            assert_eq!(env.payload.as_ref(), b"raptorq-symbol-bytes");
            let back = envelope_to_symbol(&env, ObjectId::from_u128(0xABCD));
            assert!(back == s, "symbol round-trips through the envelope mapping");
        }
    }

    #[test]
    fn mapping_survives_wire_encode_decode() {
        let s = sym(1, 0, 0, false, b"abc");
        let env = symbol_to_envelope(&s, 9, 1, None);
        let bytes = env.encode().expect("encode");
        let decoded = QuicSymbolEnvelope::decode(&bytes, false).expect("decode");
        let back = envelope_to_symbol(&decoded, ObjectId::from_u128(1));
        assert_eq!(back, s);
    }

    #[test]
    fn auth_tag_is_carried_through_the_wire() {
        let s = sym(2, 1, 5, true, b"xy");
        let tag = [7u8; TAG_SIZE];
        let env = symbol_to_envelope(&s, 0, 0, Some(tag));
        let bytes = env.encode().expect("encode");
        // auth_required=true must accept an authed envelope and preserve the tag.
        let decoded = QuicSymbolEnvelope::decode(&bytes, true).expect("decode authed");
        assert_eq!(decoded.auth_tag, Some(tag));
    }

    #[test]
    fn empty_payload_symbol_round_trips() {
        let s = sym(3, 0, 0, false, b"");
        let env = symbol_to_envelope(&s, 0, 0, None);
        let bytes = env.encode().expect("encode");
        let decoded = QuicSymbolEnvelope::decode(&bytes, false).expect("decode");
        let back = envelope_to_symbol(&decoded, ObjectId::from_u128(3));
        assert_eq!(back, s);
    }
