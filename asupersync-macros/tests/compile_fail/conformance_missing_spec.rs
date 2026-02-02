use asupersync_macros::conformance;

// conformance attribute requires both spec and requirement
#[conformance(requirement = "test")]
fn test_missing_spec() {}

fn main() {}
