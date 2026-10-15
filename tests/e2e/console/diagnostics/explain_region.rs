//! Region explanation E2E tests.

use crate::console_e2e::common::create_test_runtime_state;
use crate::console_e2e::util::init_console_test;
use asupersync::observability::{Diagnostics, Reason};
use asupersync::types::RegionId;

#[test]
fn e2e_diagnostics_explain_region_not_found() {
    init_console_test("e2e_diagnostics_explain_region_not_found");

    let state = create_test_runtime_state();
    let diagnostics = Diagnostics::new(state);

    // Query a non-existent region
    let fake_id = RegionId::new_for_test(99999, 0);
    let explanation = diagnostics.explain_region_open(fake_id);

    crate::assert_with_log!(
        explanation.region_state.is_none(),
        "no region state",
        true,
        explanation.region_state.is_none()
    );

    let has_not_found = explanation
        .reasons
        .iter()
        .any(|r| matches!(r, Reason::RegionNotFound));
    crate::assert_with_log!(has_not_found, "reason is not found", true, has_not_found);

    crate::test_complete!("e2e_diagnostics_explain_region_not_found");
}

#[test]
fn e2e_diagnostics_explain_region_display() {
    init_console_test("e2e_diagnostics_explain_region_display");

    let state = create_test_runtime_state();
    let diagnostics = Diagnostics::new(state);

    // Get an explanation and verify it can be displayed
    let fake_id = RegionId::new_for_test(12345, 0);
    let explanation = diagnostics.explain_region_open(fake_id);

    // The Display impl should produce readable output
    let rendered = format!("{explanation}");

    crate::assert_with_log!(
        rendered.contains("Region"),
        "display has region",
        true,
        rendered.contains("Region")
    );
    crate::assert_with_log!(
        rendered.contains("12345") || rendered.contains("RegionId"),
        "display has id",
        true,
        rendered.contains("12345") || rendered.contains("RegionId")
    );

    crate::test_complete!("e2e_diagnostics_explain_region_display");
}

#[test]
fn e2e_diagnostics_reason_display() {
    init_console_test("e2e_diagnostics_reason_display");

    // Test that each Reason variant has a meaningful Display
    let not_found = Reason::RegionNotFound;
    let rendered = format!("{not_found}");
    crate::assert_with_log!(
        rendered.contains("not found"),
        "not found display",
        true,
        rendered.contains("not found")
    );

    crate::test_complete!("e2e_diagnostics_reason_display");
}
