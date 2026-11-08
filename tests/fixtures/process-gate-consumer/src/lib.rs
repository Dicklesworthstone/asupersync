//! The core half of the `process` gate check: a downstream crate that uses core API only.
//!
//! It must compile in all three dependency graphs the fixture builds: the bare legacy selection, the explicit slim
//! runtime profile, and the slim profile with `process` restored. It never names `asupersync::process`; its sibling,
//! `src/bin/process_consumer.rs`, is the half that needs the module.

/// A budget from the core API; no host module is involved.
#[must_use]
pub fn core_budget() -> asupersync::Budget {
    asupersync::Budget::INFINITE
}

/// A runtime builder; still core, still no `process`.
#[must_use]
pub fn core_runtime_builder() -> asupersync::runtime::RuntimeBuilder {
    asupersync::runtime::RuntimeBuilder::new()
}
