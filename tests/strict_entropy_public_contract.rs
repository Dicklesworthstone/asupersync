//! Public entropy-isolation contract, kept in its own integration-test process.
//!
//! The gate is process-wide. Changing it inside a library unit test would race
//! unrelated OS-entropy tests, even if this test used a private test mutex.

use asupersync::util::entropy::CryptoSalt;
use asupersync::util::{
    BrowserEntropy, DetEntropy, DetRng, EntropySource, OsEntropy, StrictEntropyGuard,
    disable_strict_entropy, enable_strict_entropy, strict_entropy_enabled,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

fn assert_ambient_refused(source: &str, operation: impl FnOnce()) {
    let payload = catch_unwind(AssertUnwindSafe(operation)).expect_err("ambient entropy was admitted");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .expect("entropy refusal must carry a diagnostic");
    let expected = format!(
        "ambient entropy source \"{source}\" used in strict mode; use Cx::random_* instead"
    );
    assert_eq!(message, expected.as_str(), "unexpected panic is not a refusal");
}

fn assert_all_ambient_sources_refused() {
    assert_ambient_refused("det-rng", || {
        let _ = DetRng::from_entropy();
    });
    assert_ambient_refused("os", || {
        let _ = OsEntropy.next_u64();
    });
    assert_ambient_refused("browser", || {
        let _ = BrowserEntropy.next_u64();
    });
    assert_ambient_refused("crypto-salt", || {
        let _ = CryptoSalt::generate("strict-entropy-contract");
    });
}

#[test]
fn strict_entropy_guards_protect_public_sources_without_changing_seeded_replay() {
    assert!(!strict_entropy_enabled());
    let first = StrictEntropyGuard::new();
    let second = StrictEntropyGuard::new();
    assert_all_ambient_sources_refused();

    // Seeded lab entropy remains usable and retains its existing replay vector.
    assert_eq!(DetRng::new(42).next_u64(), 0x0000_000A_9551_4AAA);
    assert_eq!(DetEntropy::new(42).next_u64(), 0x0000_000A_9551_4AAA);

    // Drop the earlier scope while a later scope still owns protection.
    drop(first);
    assert!(strict_entropy_enabled());
    assert_all_ambient_sources_refused();
    disable_strict_entropy();
    assert!(strict_entropy_enabled(), "a live guard cannot be disabled");
    drop(second);
    assert!(!strict_entropy_enabled());

    // Explicit policy updates survive the cleanup of pre-existing guards.
    let guard = StrictEntropyGuard::new();
    enable_strict_entropy();
    drop(guard);
    assert!(strict_entropy_enabled());
    assert_all_ambient_sources_refused();
    disable_strict_entropy();
    assert!(!strict_entropy_enabled());

    // Unwinding an inner scope must release only its own isolation claim.
    let outer = StrictEntropyGuard::new();
    assert!(catch_unwind(|| {
        let _inner = StrictEntropyGuard::new();
        panic!("exercise guard unwind");
    })
    .is_err());
    assert!(strict_entropy_enabled());
    assert_all_ambient_sources_refused();
    drop(outer);
    assert!(!strict_entropy_enabled());

    // The production constructor is still usable once all protection ends.
    let mut production_rng = DetRng::from_entropy();
    assert_ne!(production_rng.next_u64(), 0);
}
