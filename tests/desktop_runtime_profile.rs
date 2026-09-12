#![cfg(feature = "desktop-runtime-profile")]

use asupersync::desktop_profile::{
    DESKTOP_RUNTIME_PROFILE_NAME, DesktopRuntimeProfile, DesktopRuntimeProfileError,
};

#[test]
fn public_desktop_profile_is_inert_until_the_host_builds_it() {
    let config = DesktopRuntimeProfile::default()
        .runtime_config()
        .expect("default desktop profile is valid");

    assert_eq!(DESKTOP_RUNTIME_PROFILE_NAME, "desktop-bounded-v1");
    assert!(config.global_queue_limit > 0);
    assert!(config.root_region_limits.is_some());
    assert_eq!(config.blocking.max_threads, 2);
}

#[test]
fn public_profile_rejects_unbounded_and_inverted_inputs() {
    let unbounded = DesktopRuntimeProfile::with_limits(1, 0, 1, 1, 0, 0, 1, 1, 1, 1);
    assert_eq!(
        unbounded
            .runtime_config()
            .err()
            .expect("unbounded profile must be rejected"),
        DesktopRuntimeProfileError::UnboundedGlobalQueue
    );

    let inverted = DesktopRuntimeProfile::with_limits(1, 1, 1, 1, 3, 2, 1, 1, 1, 1);
    assert_eq!(
        inverted
            .runtime_config()
            .err()
            .expect("inverted profile must be rejected"),
        DesktopRuntimeProfileError::BlockingRangeInverted { min: 3, max: 2 }
    );
}
