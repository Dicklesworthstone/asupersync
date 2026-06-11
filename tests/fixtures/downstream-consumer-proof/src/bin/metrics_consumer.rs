#[cfg(not(feature = "metrics-profile"))]
compile_error!("metrics_consumer must be checked with the metrics-profile fixture feature");

#[cfg(feature = "metrics-profile")]
fn main() {
    assert_eq!(
        asupersync_downstream_consumer_proof::public_surface_smoke_value(),
        2
    );
}
