import os

file_path = "tests/conformance/mod.rs"

with open(file_path, "r") as f:
    content = f.read()

content = content.replace("pub mod hpack_table_size;", "pub mod hpack_table_size;\npub mod h2_settings_flow_continuation;")

content = content.replace(
    "pub use h2_rst_stream_ping_rfc9113::H2ConformanceHarness;",
    "pub use h2_rst_stream_ping_rfc9113::H2ConformanceHarness;\npub use h2_settings_flow_continuation::H2SettingsFlowContinuationHarness;"
)

# Also we need to add the result types to the massive run_all_conformance_tests but honestly since we already assert success inside the tests module of h2_settings_flow_continuation we can just let `cargo test` run the #[test] functions. Wait, the `#[test]` is inside `h2_settings_flow_continuation::tests`. It will be discovered by cargo test.
# Let's just make sure the `mod h2_settings_flow_continuation;` is active.

with open(file_path, "w") as f:
    f.write(content)

print("Updated tests/conformance/mod.rs")
