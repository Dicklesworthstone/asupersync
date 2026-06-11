//! Compile-fail contract for the v2 spawn surface: a `Cx` whose
//! capability set lacks `HasSpawn` must not expose `spawn`
//! (br-asupersync-69ftra; pinned stderr asserts the capability bound).

#[test]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/*.rs");
}
