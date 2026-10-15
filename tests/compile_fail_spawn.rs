//! Compile-fail contracts for typestate and capability-gated APIs.
//!
//! The v2 spawn surface requires `HasSpawn` (br-asupersync-69ftra), and
//! database transactions consume their handle on commit/rollback
//! (br-asupersync-server-stack-hardening-eeexl1.5).

#[test]
#[ignore = "cold trybuild compile-fail lane; run explicitly with `cargo test --test compile_fail_spawn -- --ignored`"]
fn compile_fail() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compile_fail/spawn_without_capability.rs");
    t.compile_fail("tests/compile_fail/handler_arity_9.rs");

    if cfg!(feature = "postgres") {
        t.compile_fail("tests/compile_fail/database_transaction_consumes_self.rs");
    }

    if cfg!(feature = "mysql") {
        t.compile_fail("tests/compile_fail/mysql_transaction_consumes_self.rs");
    }

    if cfg!(feature = "sqlite") {
        t.compile_fail("tests/compile_fail/sqlite_transaction_consumes_self.rs");
    }
}
