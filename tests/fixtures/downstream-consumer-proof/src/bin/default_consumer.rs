fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread().build()?;
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);

    assert_eq!(cx.budget(), asupersync::Budget::INFINITE);
    assert_eq!(
        asupersync_downstream_consumer_proof::public_surface_smoke_value(),
        2
    );

    Ok(())
}
