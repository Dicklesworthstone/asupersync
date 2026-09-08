//! Compile unchanged entry annotations against the published compatibility floor.
//!
//! The published runtime accepts newer 0.4.x macros through its dependency
//! requirement. Checking all targets covers both entry attributes without
//! replacing the runtime with the current workspace source.

/// An unconfigured entry point must remain compatible with runtime 0.4.3.
#[asupersync::main]
pub async fn main() {}

#[asupersync::test]
async fn unconfigured_test() {}

/// Explicit draining must fail to compile when the runtime lacks that API.
#[cfg(feature = "explicit-drain")]
pub mod explicit_drain {
    /// This request must not silently use the legacy teardown fallback.
    #[asupersync::main(drain_ms = 1)]
    pub async fn main() {}

    #[asupersync::test(drain_ms = 1)]
    async fn explicit_test() {}
}
