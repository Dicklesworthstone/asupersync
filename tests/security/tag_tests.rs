#![allow(clippy::all)]
use crate::common::*;
use asupersync::security::{AuthKey, AuthenticationTag};
use asupersync::types::{Symbol, SymbolId, SymbolKind};

fn symbol_with(data: &[u8]) -> Symbol {
    Symbol::new_for_test(1, 0, 0, data)
}

#[test]
fn compute_is_deterministic() {
    init_test_logging();
    test_phase!("compute_is_deterministic");
    let key = AuthKey::from_seed(42);
    let symbol = symbol_with(&[1, 2, 3, 4]);

    let tag1 = AuthenticationTag::compute(&key, &symbol);
    let tag2 = AuthenticationTag::compute(&key, &symbol);

    assert_with_log!(tag1 == tag2, "tags should match", tag1, tag2);
    test_complete!("compute_is_deterministic");
}

#[test]
fn verify_accepts_valid_tag() {
    init_test_logging();
    test_phase!("verify_accepts_valid_tag");
    let key = AuthKey::from_seed(42);
    let symbol = symbol_with(&[1, 2, 3, 4]);

    let tag = AuthenticationTag::compute(&key, &symbol);
    let ok = tag.verify(&key, &symbol);
    assert_with_log!(ok, "valid tag should verify", true, ok);
    test_complete!("verify_accepts_valid_tag");
}

#[test]
fn verify_rejects_different_data() {
    init_test_logging();
    test_phase!("verify_rejects_different_data");
    let key = AuthKey::from_seed(42);
    let symbol = symbol_with(&[1, 2, 3, 4]);
    let tampered = symbol_with(&[1, 2, 3, 5]);

    let tag = AuthenticationTag::compute(&key, &symbol);
    let ok = tag.verify(&key, &tampered);
    assert_with_log!(!ok, "tampered data should fail", false, ok);
    test_complete!("verify_rejects_different_data");
}

#[test]
fn verify_rejects_different_object_id() {
    init_test_logging();
    test_phase!("verify_rejects_different_object_id");
    let key = AuthKey::from_seed(42);
    let symbol = symbol_with(&[1, 2, 3, 4]);
    let different_obj = Symbol::new_for_test(2, 0, 0, &[1, 2, 3, 4]);

    let tag = AuthenticationTag::compute(&key, &symbol);
    let ok = tag.verify(&key, &different_obj);
    assert_with_log!(!ok, "different object id should fail", false, ok);
    test_complete!("verify_rejects_different_object_id");
}

#[test]
fn verify_rejects_different_sbn() {
    init_test_logging();
    test_phase!("verify_rejects_different_sbn");
    let key = AuthKey::from_seed(42);
    let symbol = symbol_with(&[1, 2, 3, 4]);
    let different_sbn = Symbol::new_for_test(1, 1, 0, &[1, 2, 3, 4]);

    let tag = AuthenticationTag::compute(&key, &symbol);
    let ok = tag.verify(&key, &different_sbn);
    assert_with_log!(!ok, "different sbn should fail", false, ok);
    test_complete!("verify_rejects_different_sbn");
}

#[test]
fn verify_rejects_different_esi() {
    init_test_logging();
    test_phase!("verify_rejects_different_esi");
    let key = AuthKey::from_seed(42);
    let symbol = symbol_with(&[1, 2, 3, 4]);
    let different_esi = Symbol::new_for_test(1, 0, 1, &[1, 2, 3, 4]);

    let tag = AuthenticationTag::compute(&key, &symbol);
    let ok = tag.verify(&key, &different_esi);
    assert_with_log!(!ok, "different esi should fail", false, ok);
    test_complete!("verify_rejects_different_esi");
}

#[test]
fn verify_rejects_different_symbol_kind() {
    init_test_logging();
    test_phase!("verify_rejects_different_symbol_kind");
    let key = AuthKey::from_seed(42);
    let id = SymbolId::new_for_test(1, 0, 0);
    let source = Symbol::new(id, vec![1, 2, 3, 4], SymbolKind::Source);
    let repair = Symbol::new(id, vec![1, 2, 3, 4], SymbolKind::Repair);

    let source_tag = AuthenticationTag::compute(&key, &source);
    let repair_tag = AuthenticationTag::compute(&key, &repair);

    assert_with_log!(
        source_tag != repair_tag,
        "source and repair tags should differ",
        source_tag,
        repair_tag
    );
    assert_with_log!(
        !source_tag.verify(&key, &repair),
        "source tag should fail against repair symbol",
        false,
        source_tag.verify(&key, &repair)
    );
    assert_with_log!(
        !repair_tag.verify(&key, &source),
        "repair tag should fail against source symbol",
        false,
        repair_tag.verify(&key, &source)
    );
    test_complete!("verify_rejects_different_symbol_kind");
}

#[test]
fn verify_rejects_different_key() {
    init_test_logging();
    test_phase!("verify_rejects_different_key");
    let key1 = AuthKey::from_seed(42);
    let key2 = AuthKey::from_seed(43);
    let symbol = symbol_with(&[1, 2, 3, 4]);

    let tag = AuthenticationTag::compute(&key1, &symbol);
    let ok = tag.verify(&key2, &symbol);
    assert_with_log!(!ok, "different key should fail", false, ok);
    test_complete!("verify_rejects_different_key");
}

#[test]
fn verify_accepts_empty_data() {
    init_test_logging();
    test_phase!("verify_accepts_empty_data");
    let key = AuthKey::from_seed(42);
    let symbol = symbol_with(&[]);

    let tag = AuthenticationTag::compute(&key, &symbol);
    let ok = tag.verify(&key, &symbol);
    assert_with_log!(ok, "empty data should verify", true, ok);
    test_complete!("verify_accepts_empty_data");
}

#[test]
fn verify_accepts_large_data() {
    init_test_logging();
    test_phase!("verify_accepts_large_data");
    let key = AuthKey::from_seed(42);
    let data: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();
    let symbol = symbol_with(&data);

    let tag = AuthenticationTag::compute(&key, &symbol);
    let ok = tag.verify(&key, &symbol);
    assert_with_log!(ok, "large data should verify", true, ok);
    test_complete!("verify_accepts_large_data");
}

#[test]
fn zero_tag_fails_verification() {
    init_test_logging();
    test_phase!("zero_tag_fails_verification");
    let key = AuthKey::from_seed(42);
    let symbol = symbol_with(&[1, 2, 3]);
    let zero = AuthenticationTag::zero();

    let ok = zero.verify(&key, &symbol);
    assert_with_log!(!ok, "zero tag should fail", false, ok);
    test_complete!("zero_tag_fails_verification");
}

#[test]
fn from_bytes_roundtrip() {
    init_test_logging();
    test_phase!("from_bytes_roundtrip");
    let key = AuthKey::from_seed(42);
    let symbol = symbol_with(&[1, 2, 3]);

    let original = AuthenticationTag::compute(&key, &symbol);
    let bytes = *original.as_bytes();
    let restored = AuthenticationTag::from_bytes(bytes);

    assert_with_log!(
        original == restored,
        "roundtrip should preserve tag",
        original,
        restored
    );
    let ok = restored.verify(&key, &symbol);
    assert_with_log!(ok, "restored tag should verify", true, ok);
    test_complete!("from_bytes_roundtrip");
}
