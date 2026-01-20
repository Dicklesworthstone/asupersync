use crate::common::*;
use asupersync::security::AuthKey;
use asupersync::util::DetRng;

#[test]
fn from_seed_is_deterministic() {
    init_test_logging();
    test_phase!("from_seed_is_deterministic");
    let key1 = AuthKey::from_seed(42);
    let key2 = AuthKey::from_seed(42);
    assert_with_log!(key1 == key2, "same seed should match", key1, key2);
    test_complete!("from_seed_is_deterministic");
}

#[test]
fn from_seed_varies_across_seeds() {
    init_test_logging();
    test_phase!("from_seed_varies_across_seeds");
    let key1 = AuthKey::from_seed(42);
    let key2 = AuthKey::from_seed(43);
    assert_with_log!(key1 != key2, "different seeds should differ", key1, key2);
    test_complete!("from_seed_varies_across_seeds");
}

#[test]
fn from_rng_produces_distinct_keys() {
    init_test_logging();
    test_phase!("from_rng_produces_distinct_keys");
    let mut rng = DetRng::new(7);
    let key1 = AuthKey::from_rng(&mut rng);
    let key2 = AuthKey::from_rng(&mut rng);
    assert_with_log!(key1 != key2, "rng should produce distinct keys", key1, key2);
    test_complete!("from_rng_produces_distinct_keys");
}

#[test]
fn from_bytes_roundtrip() {
    init_test_logging();
    test_phase!("from_bytes_roundtrip");
    let key = AuthKey::from_seed(99);
    let bytes = *key.as_bytes();
    let restored = AuthKey::from_bytes(bytes);
    assert_with_log!(
        key == restored,
        "roundtrip should preserve key",
        key,
        restored
    );
    test_complete!("from_bytes_roundtrip");
}

#[test]
fn derive_subkey_is_deterministic() {
    init_test_logging();
    test_phase!("derive_subkey_is_deterministic");
    let key = AuthKey::from_seed(123);
    let sub1 = key.derive_subkey(b"transport");
    let sub2 = key.derive_subkey(b"transport");
    assert_with_log!(sub1 == sub2, "same purpose should match", sub1, sub2);
    test_complete!("derive_subkey_is_deterministic");
}

#[test]
fn derive_subkey_changes_with_purpose() {
    init_test_logging();
    test_phase!("derive_subkey_changes_with_purpose");
    let key = AuthKey::from_seed(123);
    let sub1 = key.derive_subkey(b"transport");
    let sub2 = key.derive_subkey(b"storage");
    assert_with_log!(sub1 != sub2, "different purpose should differ", sub1, sub2);
    test_complete!("derive_subkey_changes_with_purpose");
}

#[test]
fn derive_subkey_differs_from_master() {
    init_test_logging();
    test_phase!("derive_subkey_differs_from_master");
    let key = AuthKey::from_seed(123);
    let derived = key.derive_subkey(b"subkey");
    assert_with_log!(
        key != derived,
        "derived should differ from master",
        key,
        derived
    );
    test_complete!("derive_subkey_differs_from_master");
}

#[test]
fn derive_subkey_with_empty_purpose_still_changes() {
    init_test_logging();
    test_phase!("derive_subkey_with_empty_purpose_still_changes");
    let key = AuthKey::from_seed(123);
    let derived = key.derive_subkey(b"");
    assert_with_log!(
        key != derived,
        "empty purpose should still differ",
        key,
        derived
    );
    test_complete!("derive_subkey_with_empty_purpose_still_changes");
}

#[test]
fn zero_seed_produces_nonzero_key() {
    init_test_logging();
    test_phase!("zero_seed_produces_nonzero_key");
    let key = AuthKey::from_seed(0);
    let any_nonzero = key.as_bytes().iter().any(|b| *b != 0);
    assert_with_log!(any_nonzero, "key should be non-zero", true, any_nonzero);
    test_complete!("zero_seed_produces_nonzero_key");
}

#[test]
fn debug_does_not_leak_full_key_material() {
    init_test_logging();
    test_phase!("debug_does_not_leak_full_key_material");
    let key = AuthKey::from_seed(7);
    let debug_output = format!("{key:?}");
    assert_with_log!(
        debug_output.starts_with("AuthKey("),
        "debug should start with AuthKey(",
        true,
        debug_output.starts_with("AuthKey(")
    );
    assert_with_log!(
        debug_output.ends_with("...)"),
        "debug should end with ...)",
        true,
        debug_output.ends_with("...)")
    );
    let short_enough = debug_output.len() < 32;
    assert_with_log!(
        short_enough,
        "debug should be abbreviated",
        "< 32",
        debug_output.len()
    );
    test_complete!("debug_does_not_leak_full_key_material");
}
