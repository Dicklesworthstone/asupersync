//! Enforcement tests for the previously-phantom `SecurityConfig` controls
//! (br-asupersync-x7ad3b).
//!
//! Before this fix the `[security]` config surface (`auth_mode`,
//! `auth_key_seed`, `reject_unauthenticated`) was parsed from env+TOML,
//! syntax-validated and serialized but consumed by ZERO production code, so
//! setting any of these knobs had no runtime effect — a "phantom control" that
//! gave operators a false sense of enforcement in BOTH directions.
//!
//! These tests pin the now-wired behavior at the config layer:
//!   * an internally-inconsistent security config (one the runtime physically
//!     cannot honor) is rejected FAIL-CLOSED at validation time, on the same
//!     `RaptorQConfig::validate()` path that `ConfigLoader::load()` and
//!     `RaptorQReceiverBuilder::build()` already call;
//!   * `build_context()` materializes a real `SecurityContext` exactly when a
//!     deterministic key seed is configured.
//!
//! The receiver-side crypto gate (config `auth_key_seed` actually
//! authenticating real signed symbols, and `reject_unauthenticated` failing
//! closed against unsigned ones) is proven by the unit tests in
//! `src/raptorq/pipeline.rs`.
//!
//! Lives as a standalone integration test (one small crate linking the lib) so
//! it is immune to unrelated `#[cfg(test)]` breakage in the lib unit-test
//! target.

use asupersync::config::{ConfigError, RaptorQConfig};
use asupersync::security::AuthMode;

#[test]
fn default_security_config_validates_fail_closed() {
    // The default posture is fail-closed (Strict + reject_unauthenticated) and
    // must validate cleanly — this is NOT a fail-open default, it was a
    // phantom-control gap.
    let config = RaptorQConfig::default();
    assert_eq!(config.security.auth_mode, AuthMode::Strict);
    assert!(config.security.reject_unauthenticated);
    config
        .security
        .validate()
        .expect("default security config must be valid");
    config
        .validate()
        .expect("default RaptorQConfig must be valid");
}

#[test]
fn reject_unauthenticated_with_disabled_mode_is_rejected() {
    // reject_unauthenticated=true + auth_mode=disabled is impossible to honor:
    // disabled mode skips verification entirely, so unauthenticated symbols
    // cannot be rejected. The runtime now fails closed at validation time
    // instead of silently accepting the contradiction.
    let mut config = RaptorQConfig::default();
    config.security.auth_mode = AuthMode::Disabled;
    config.security.reject_unauthenticated = true;

    let err = config
        .security
        .validate()
        .expect_err("contradictory security config must be rejected");
    assert!(
        matches!(err, ConfigError::InconsistentSecurity(_)),
        "expected InconsistentSecurity, got {err:?}"
    );

    // And the same failure must surface through the top-level validate() that
    // ConfigLoader::load() / the receiver builder run.
    let top = config
        .validate()
        .expect_err("RaptorQConfig::validate must reject the inconsistent security config");
    assert!(
        matches!(top, ConfigError::InconsistentSecurity(_)),
        "expected InconsistentSecurity from RaptorQConfig::validate, got {top:?}"
    );
}

#[test]
fn disabled_mode_without_reject_is_allowed() {
    // disabled + reject_unauthenticated=false is a coherent (if insecure)
    // explicit opt-out and must NOT be rejected — the validator only rejects
    // the impossible-to-honor combination, not every relaxed posture.
    let mut config = RaptorQConfig::default();
    config.security.auth_mode = AuthMode::Disabled;
    config.security.reject_unauthenticated = false;
    config
        .validate()
        .expect("disabled mode with reject_unauthenticated=false must validate");
}

#[test]
fn permissive_mode_round_trip_combo_is_allowed() {
    // Mirrors the canonical TOML/snapshot example (permissive + reject=false):
    // a previously-advertised knob combination that must remain valid now that
    // the config is actually read.
    let mut config = RaptorQConfig::default();
    config.security.auth_mode = AuthMode::Permissive;
    config.security.reject_unauthenticated = false;
    config.security.auth_key_seed = Some(12345);
    config
        .validate()
        .expect("permissive + reject=false must validate");
}

#[test]
fn build_context_is_present_iff_seed_configured() {
    // No seed -> no config-derived context (authentication, if any, must come
    // from a SecurityContext supplied at receiver construction time).
    let mut config = RaptorQConfig::default();
    config.security.auth_key_seed = None;
    assert!(
        config.security.build_context().is_none(),
        "no seed must yield no config-derived context"
    );

    // A configured seed materializes a real context that the receive path
    // consumes — the knob is wired, not phantom.
    config.security.auth_key_seed = Some(0xABCD_1234);
    assert!(
        config.security.build_context().is_some(),
        "configured seed must materialize a SecurityContext"
    );
}
