use crate::common::*;
use asupersync::security::{AuthKey, AuthenticatedSymbol, AuthenticationTag, SecurityContext};
use asupersync::types::Symbol;
use proptest::prelude::*;

fn symbol_with(data: &[u8]) -> Symbol {
    Symbol::new_for_test(7, 0, 0, data)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn tag_verifies_for_original(seed in 0u64..1000, data in prop::collection::vec(any::<u8>(), 0..256)) {
        init_test_logging();
        test_phase!("tag_verifies_for_original");
        let key = AuthKey::from_seed(seed);
        let symbol = symbol_with(&data);
        let tag = AuthenticationTag::compute(&key, &symbol);

        prop_assert!(tag.verify(&key, &symbol));
    }

    #[test]
    fn tampering_invalidates_tag(seed in 0u64..1000, data in prop::collection::vec(any::<u8>(), 1..256)) {
        init_test_logging();
        test_phase!("tampering_invalidates_tag");
        let key = AuthKey::from_seed(seed);
        let symbol = symbol_with(&data);
        let tag = AuthenticationTag::compute(&key, &symbol);

        let mut tampered = data.clone();
        tampered[0] = tampered[0].wrapping_add(1);
        let tampered_symbol = symbol_with(&tampered);

        prop_assert!(!tag.verify(&key, &tampered_symbol));
    }

    #[test]
    fn security_context_sign_then_verify(seed in 0u64..1000, data in prop::collection::vec(any::<u8>(), 0..256)) {
        init_test_logging();
        test_phase!("security_context_sign_then_verify");
        let key = AuthKey::from_seed(seed);
        let ctx = SecurityContext::new(key);
        let symbol = symbol_with(&data);

        let signed = ctx.sign_symbol(&symbol);
        let mut received = AuthenticatedSymbol::from_parts(signed.clone().into_symbol(), *signed.tag());

        prop_assert!(ctx.verify_authenticated_symbol(&mut received).is_ok());
        prop_assert!(received.is_verified());
    }

    #[test]
    fn different_keys_produce_different_tags(
        seed1 in 0u64..1000,
        seed2 in 0u64..1000,
        data in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        init_test_logging();
        test_phase!("different_keys_produce_different_tags");
        prop_assume!(seed1 != seed2);
        let key1 = AuthKey::from_seed(seed1);
        let key2 = AuthKey::from_seed(seed2);
        let symbol = symbol_with(&data);

        let tag1 = AuthenticationTag::compute(&key1, &symbol);
        let tag2 = AuthenticationTag::compute(&key2, &symbol);

        prop_assert_ne!(tag1, tag2);
    }
}
