//! Receipt-only negotiation and ownership; native executable journeys live in tests/.
use super::*;
use super::super::super::{Hello, initial, offer};
use crate::net::atp::sdk::native_auth::live::{Admission, advance, encode_epoch};
use std::sync::atomic::{AtomicUsize, Ordering};

fn hello() -> Hello { Hello { nonce: [7; 32], epoch_bytes: 8, max_bytes: 64 } }

fn receipt() -> LiveStreamReceipt {
    let prefix = initial(&hello());
    let payload = encode_epoch(&prefix, b"verified");
    LiveStreamReceipt {
        prefix: advance(&prefix, &payload, 8, 64).unwrap(),
        source_sha256: Sha256::digest(b"verified").into(),
    }
}

fn receiver(receipt: LiveStreamReceipt) -> ReceiptReceiver {
    let admission = Arc::new(Admission { active: AtomicUsize::new(0), capacity: 1 });
    let capacity = Arc::new(Capacity { _permits: vec![admission.reserve().unwrap()] });
    let config = LiveStreamConfig { epoch_bytes: 8, max_bytes: 64, ..LiveStreamConfig::default() };
    ReceiptReceiver {
        receipt, config, offered: None, state: Vec::new(),
        budget: Budget { used: 0, maximum: 2, _credit: Credit::Shared { _capacity: capacity } },
    }
}

#[test]
fn restored_state_is_the_exact_saved_prefix_digest_and_completion_flag() {
    let saved = receipt();
    let mut receiver = receiver(saved.clone());
    let offered = offer(&hello());
    let state = receiver.response(&offered).unwrap();
    assert_eq!(state.len(), 141);
    assert_eq!(&state[..60], offered);
    assert_eq!(&state[60..108], encode_prefix(&saved.prefix));
    assert_eq!(&state[108..140], saved.source_sha256);
    assert_eq!(state[140], 1);
    assert_eq!(receiver.response(&offered).unwrap(), state);
    assert_eq!(receiver.receipt, saved);
}

#[test]
fn malformed_history_and_current_size_limits_refuse_before_negotiation() {
    let saved = receipt();
    assert!(validate_receipt([8; 32], &saved, 8, 64).is_err());
    assert!(validate_receipt([7; 32], &saved, 8, 7).is_err());
    for (bytes, epochs) in [(0, 1), (8, 0), (8, 9), (64, 1)] {
        let mut invalid = saved.clone();
        invalid.prefix.bytes = bytes;
        invalid.prefix.epochs = epochs;
        assert!(validate_receipt([7; 32], &invalid, 8, 64).is_err());
    }
}

#[test]
fn wrong_nonce_and_narrow_offer_do_not_bind_the_restored_owner() {
    let mut receiver = receiver(receipt());
    let mut changed = hello(); changed.nonce[0] ^= 1;
    assert!(receiver.response(&offer(&changed)).is_err());
    assert!(receiver.offered.is_none());
    changed = hello(); changed.max_bytes = 7;
    assert!(receiver.response(&offer(&changed)).is_err());
    assert!(receiver.offered.is_none());
    let original = receiver.response(&offer(&hello())).unwrap();
    changed = hello(); changed.max_bytes = 63;
    assert!(receiver.response(&offer(&changed)).is_err());
    assert_eq!(receiver.response(&offer(&hello())).unwrap(), original);
}

#[test]
fn empty_receipt_requires_the_empty_hash_and_original_hello_commitment() {
    let saved = LiveStreamReceipt { prefix: initial(&hello()), source_sha256: Sha256::digest(b"").into() };
    assert!(validate_receipt([7; 32], &saved, 8, 64).is_ok());
    let mut invalid = saved.clone(); invalid.source_sha256[0] ^= 1;
    assert!(validate_receipt([7; 32], &invalid, 8, 64).is_err());
    let mut receiver = receiver(saved);
    let mut changed = hello(); changed.max_bytes = 63;
    assert!(receiver.response(&offer(&changed)).is_err());
    assert!(receiver.offered.is_none());
    assert!(receiver.response(&offer(&hello())).is_ok());
}

#[test]
fn recovered_history_holds_credit_and_a_finite_attempt_budget() {
    let admission = Arc::new(Admission { active: AtomicUsize::new(0), capacity: 1 });
    let credit = admission.reserve().unwrap();
    let mut receiver = receiver(receipt());
    receiver.budget._credit = Credit::Direct { _permit: credit };
    assert_eq!(admission.active.load(Ordering::Relaxed), 1);
    receiver.budget.take().unwrap(); receiver.budget.take().unwrap();
    assert!(matches!(receiver.budget.take(), Err(ResumeError::AttemptsExhausted)));
    assert_eq!(receiver.budget.used, 2);
    assert!(admission.reserve().is_err());
    drop(receiver);
    assert_eq!(admission.active.load(Ordering::Relaxed), 0);
}
