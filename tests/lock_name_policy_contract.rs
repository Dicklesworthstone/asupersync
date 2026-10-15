//! Contract test for the production lock-name policy
//! (br-asupersync-lock-order-deadlock-proof-dw03gl.2).
//!
//! A focused integration test (links only the asupersync lib, not the
//! conformance dev-dependency) so the L2 fail-closed policy has a reliable remote
//! proof lane independent of the full lib-test harness.

#![allow(missing_docs)]

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
use asupersync::sync::Mutex;
use asupersync::sync::lock_ordering::{
    LockNamePolicy, LockRank, classify_lock_name, enforce_lock_name_policy, rank_for_lock_name,
    require_ranked_lock_name,
};
#[cfg(any(debug_assertions, feature = "lock-metrics"))]
use asupersync::sync::lock_ordering::{clear_held_locks, current_held_locks, current_held_ranks};

#[test]
fn classify_ranks_known_hierarchy_locks() {
    assert!(matches!(
        classify_lock_name("config_main"),
        LockNamePolicy::Ranked {
            rank: LockRank::Config,
            ..
        }
    ));
    assert!(matches!(
        classify_lock_name("trace_buffer"),
        LockNamePolicy::Ranked {
            rank: LockRank::Instrumentation,
            ..
        }
    ));
    assert!(matches!(
        classify_lock_name("region_table"),
        LockNamePolicy::Ranked {
            rank: LockRank::Regions,
            ..
        }
    ));
    assert!(matches!(
        classify_lock_name("task_table"),
        LockNamePolicy::Ranked {
            rank: LockRank::Tasks,
            ..
        }
    ));
    assert!(matches!(
        classify_lock_name("obligation_ledger"),
        LockNamePolicy::Ranked {
            rank: LockRank::Obligations,
            ..
        }
    ));
}

#[test]
fn classify_allows_documented_unranked_locks() {
    for name in [
        "unknown",
        "runtime_state",
        "atp_transfer_registry",
        "service_adapter",
    ] {
        let policy = classify_lock_name(name);
        assert!(
            matches!(policy, LockNamePolicy::AllowedUnranked { .. }),
            "{name} should be allowed-unranked"
        );
        assert!(!policy.is_denied());
        assert_eq!(policy.rank(), None);
        assert!(
            !policy.reason().is_empty(),
            "allowance needs a stable reason"
        );
    }
}

#[test]
fn classify_denies_undocumented_unknown_locks() {
    let policy = classify_lock_name("totally_made_up_widget_lock");
    assert!(policy.is_denied());
    assert!(matches!(policy, LockNamePolicy::DeniedUnknown { .. }));
    assert!(
        !policy.reason().is_empty(),
        "denial needs a stable machine-readable reason"
    );
}

#[test]
fn rank_for_known_lock_names_is_stable() {
    assert_eq!(rank_for_lock_name("config_main"), Some(LockRank::Config));
    assert_eq!(rank_for_lock_name("task_table"), Some(LockRank::Tasks));
    assert_eq!(
        rank_for_lock_name("obligation_ledger"),
        Some(LockRank::Obligations)
    );
}

#[test]
fn require_ranked_returns_rank_for_known_locks() {
    let (rank, _module) = require_ranked_lock_name("obligation_ledger");
    assert_eq!(rank, LockRank::Obligations);
    assert_eq!(
        enforce_lock_name_policy("config_main").rank(),
        Some(LockRank::Config)
    );
}

#[cfg(any(debug_assertions, feature = "lock-metrics"))]
#[test]
fn uppercase_module_names_cannot_bypass_cancel_before_obligation_rule() {
    clear_held_locks();
    let cancel = Mutex::with_name("TASKS_CANCEL_STATE", ());
    let obligation = Mutex::with_name("OBLIGATION_LEDGER", ());
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _cancel_guard = cancel.try_lock().expect("acquire cancel-ranked lock");
        let _obligation_guard = obligation
            .try_lock()
            .expect("uppercase obligation acquisition must fail lock ordering");
    }))
    .expect_err("uppercase cancel-before-obligation acquisition must panic");

    let held_locks = current_held_locks();
    let held_ranks = current_held_ranks();
    clear_held_locks();

    let message = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&'static str>().copied())
        .unwrap_or("<non-string panic payload>");
    assert!(
        message.starts_with("[ASUP-E205]"),
        "cross-module panic must start with ASUP-E205: {message}"
    );
    assert!(
        message.contains("CROSS-MODULE DEADLOCK PREVENTION"),
        "ascending ranks must reach the inferred cross-module rule: {message}"
    );
    assert!(
        held_locks.is_empty(),
        "unwinding must release uppercase lock tracking: {held_locks:?}"
    );
    assert!(
        held_ranks.is_empty(),
        "unwinding must release uppercase rank tracking: {held_ranks:?}"
    );
}

#[test]
#[should_panic(expected = "ASUP-E205")]
fn enforce_fails_closed_on_undocumented_unknown() {
    let _ = enforce_lock_name_policy("totally_made_up_widget_lock");
}

#[test]
#[should_panic(expected = "ASUP-E205")]
fn require_ranked_fails_closed_on_unranked_lock() {
    // `runtime_state` is allowed-unranked, not ranked: require_ranked rejects it.
    let _ = require_ranked_lock_name("runtime_state");
}

#[cfg(feature = "lock-metrics")]
#[test]
#[should_panic(expected = "ASUP-E205")]
fn rank_for_lock_name_fails_closed_under_lock_metrics() {
    // Under the production `lock-metrics` feature the constructor rank path
    // applies the documented allow/deny policy and fails closed on unknowns.
    let _ = rank_for_lock_name("totally_made_up_widget_lock");
}
