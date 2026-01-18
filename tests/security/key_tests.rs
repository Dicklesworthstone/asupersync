use asupersync::security::AuthKey;
use asupersync::util::DetRng;

#[test]
fn from_seed_is_deterministic() {
    let key1 = AuthKey::from_seed(42);
    let key2 = AuthKey::from_seed(42);
    assert_eq!(key1, key2);
}

#[test]
fn from_seed_varies_across_seeds() {
    let key1 = AuthKey::from_seed(42);
    let key2 = AuthKey::from_seed(43);
    assert_ne!(key1, key2);
}

#[test]
fn from_rng_produces_distinct_keys() {
    let mut rng = DetRng::new(7);
    let key1 = AuthKey::from_rng(&mut rng);
    let key2 = AuthKey::from_rng(&mut rng);
    assert_ne!(key1, key2);
}

#[test]
fn from_bytes_roundtrip() {
    let key = AuthKey::from_seed(99);
    let bytes = *key.as_bytes();
    let restored = AuthKey::from_bytes(bytes);
    assert_eq!(key, restored);
}

#[test]
fn derive_subkey_is_deterministic() {
    let key = AuthKey::from_seed(123);
    let sub1 = key.derive_subkey(b"transport");
    let sub2 = key.derive_subkey(b"transport");
    assert_eq!(sub1, sub2);
}

#[test]
fn derive_subkey_changes_with_purpose() {
    let key = AuthKey::from_seed(123);
    let sub1 = key.derive_subkey(b"transport");
    let sub2 = key.derive_subkey(b"storage");
    assert_ne!(sub1, sub2);
}

#[test]
fn derive_subkey_differs_from_master() {
    let key = AuthKey::from_seed(123);
    let derived = key.derive_subkey(b"subkey");
    assert_ne!(key, derived);
}

#[test]
fn derive_subkey_with_empty_purpose_still_changes() {
    let key = AuthKey::from_seed(123);
    let derived = key.derive_subkey(b"");
    assert_ne!(key, derived);
}

#[test]
fn zero_seed_produces_nonzero_key() {
    let key = AuthKey::from_seed(0);
    let any_nonzero = key.as_bytes().iter().any(|b| *b != 0);
    assert!(any_nonzero);
}

#[test]
fn debug_does_not_leak_full_key_material() {
    let key = AuthKey::from_seed(7);
    let debug = format!("{key:?}");
    assert!(debug.starts_with("AuthKey("));
    assert!(debug.ends_with("...)"));
    assert!(debug.len() < 32);
}
