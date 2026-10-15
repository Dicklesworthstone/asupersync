//! Deterministic registry admission and ownership invariants.
use super::super::super::super::Admission;
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn config() -> ResumeServiceConfig {
    ResumeServiceConfig {
        max_connections: 2,
        max_sessions: 4,
        max_sessions_per_client: 2,
        max_session_keys: 8,
        max_attempts_per_session: 4,
    }
}

#[test]
fn resource_limits_are_independently_checked_before_reservation() {
    assert!(config().validate(4).is_ok());
    assert!(config().validate(3).is_err());
    let base = config();
    for invalid in [
        ResumeServiceConfig {
            max_connections: 0,
            ..base
        },
        ResumeServiceConfig {
            max_connections: 5,
            ..base
        },
        ResumeServiceConfig {
            max_sessions: 0,
            ..base
        },
        ResumeServiceConfig {
            max_sessions: usize::MAX,
            ..base
        },
        ResumeServiceConfig {
            max_sessions_per_client: 0,
            ..base
        },
        ResumeServiceConfig {
            max_sessions_per_client: 5,
            ..base
        },
        ResumeServiceConfig {
            max_session_keys: 3,
            ..base
        },
        ResumeServiceConfig {
            max_session_keys: 65_537,
            ..base
        },
        ResumeServiceConfig {
            max_attempts_per_session: 0,
            ..base
        },
        ResumeServiceConfig {
            max_attempts_per_session: 1025,
            ..base
        },
    ] {
        assert!(invalid.validate(usize::MAX).is_err());
    }
}

#[test]
fn admission_is_owned_by_retained_results_not_only_the_service_handle() {
    let admission = Arc::new(Admission {
        active: AtomicUsize::new(0),
        capacity: 2,
    });
    let service = Arc::new(Capacity {
        _permits: vec![admission.reserve().unwrap(), admission.reserve().unwrap()],
    });
    let uncollected = Credit::Shared {
        _capacity: Arc::clone(&service),
    };
    let retained = Credit::Shared {
        _capacity: Arc::clone(&service),
    };
    drop(service);
    drop(uncollected);
    assert_eq!(admission.active.load(Ordering::Relaxed), 2);
    assert!(matches!(
        admission.reserve(),
        Err(LiveStreamError::Capacity)
    ));
    drop(retained);
    assert_eq!(admission.active.load(Ordering::Relaxed), 0);
    assert!(admission.reserve().is_ok());
}

#[test]
fn a_nonce_never_substitutes_for_the_authenticated_client_identity() {
    let a = ResumeSessionKey {
        client: NativeClientCertificateId::from_sha256([1; 32]),
        nonce: [7; 32],
    };
    let b = ResumeSessionKey {
        client: NativeClientCertificateId::from_sha256([2; 32]),
        nonce: a.nonce,
    };
    let c = ResumeSessionKey {
        nonce: [8; 32],
        ..a
    };
    let mut entries = BTreeMap::new();
    entries.insert(a, ResumeSessionStatus::Retired);
    entries.insert(b, ResumeSessionStatus::Idle);
    entries.insert(c, ResumeSessionStatus::Active);
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[&a], ResumeSessionStatus::Retired);
    assert_eq!(entries[&b], ResumeSessionStatus::Idle);
    assert_eq!(entries[&c], ResumeSessionStatus::Active);
}
