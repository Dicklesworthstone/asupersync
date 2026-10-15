#[cfg(not(feature = "metrics-profile"))]
compile_error!("metrics_consumer must be checked with the metrics-profile fixture feature");

#[cfg(feature = "metrics-profile")]
fn main() {
    use asupersync::observability::otel::PrivacyConfig;
    use std::sync::{Arc, Condvar, Mutex};

    assert_eq!(
        asupersync_downstream_consumer_proof::public_surface_smoke_value(),
        2
    );

    let privacy = PrivacyConfig::new()
        .try_with_pii_pattern(r"token-[0-9]+")
        .expect("public fallible regex builder accepts a valid pattern");
    assert!(
        privacy
            .clone()
            .try_with_pii_pattern("(")
            .is_err(),
        "public fallible builder still reports invalid patterns"
    );
    for _ in 0..16 {
        assert_eq!(privacy.redact_pii("auth", "token-123"), "[REDACTED]");
    }

    let mut direct = PrivacyConfig::new();
    direct.pii_patterns.push(r"secret-[0-9]+".to_owned());
    assert_eq!(direct.redact_pii("auth", "secret-42"), "[REDACTED]");

    let shared = Arc::new(privacy);
    let start = Arc::new((Mutex::new(false), Condvar::new()));
    std::thread::scope(|scope| {
        let mut joins = Vec::new();
        for _ in 0..8 {
            let shared = Arc::clone(&shared);
            let worker_start = Arc::clone(&start);
            let worker = std::thread::Builder::new().spawn_scoped(scope, move || {
                let (lock, ready) = &*worker_start;
                let started = lock.lock().expect("downstream start gate");
                drop(
                    ready
                        .wait_while(started, |started| !*started)
                        .expect("downstream start gate wait"),
                );
                for _ in 0..16 {
                    assert_eq!(shared.redact_pii("auth", "token-456"), "[REDACTED]");
                }
            });
            match worker {
                Ok(join) => joins.push(join),
                Err(error) => {
                    let (lock, ready) = &*start;
                    *lock.lock().expect("release gate after spawn failure") = true;
                    ready.notify_all();
                    panic!("failed to spawn downstream privacy worker: {error}");
                }
            }
        }
        let (lock, ready) = &*start;
        *lock.lock().expect("release downstream start gate") = true;
        ready.notify_all();
        for join in joins {
            join.join().expect("downstream privacy worker");
        }
    });
}
