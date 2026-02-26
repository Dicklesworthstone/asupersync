#![doc = "Compile-fail tests for structured-concurrency proc macros."]

#[test]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
