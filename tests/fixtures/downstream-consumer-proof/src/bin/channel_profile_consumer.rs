#[cfg(not(feature = "channel-mpsc-select-e2e-profile"))]
compile_error!(
    "channel_profile_consumer must be checked with the channel-mpsc-select-e2e-profile fixture feature"
);

#[cfg(feature = "channel-mpsc-select-e2e-profile")]
fn main() {
    let _public_runner: fn() =
        asupersync::real_channel_mpsc_combinator_select_integration_e2e_tests::run_all;
    assert_eq!(
        asupersync_downstream_consumer_proof::public_surface_smoke_value(),
        2
    );
}
