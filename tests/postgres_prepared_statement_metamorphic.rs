//! Metamorphic test for prepared-statement re-execution isolation.
//!
//! Source: `src/database/postgres.rs`. The asupersync Postgres client
//! re-executes a prepared statement by re-using the cached statement
//! name on the server side and re-sending only `Bind → Describe →
//! Execute → Sync`. The metamorphic invariant is that **the parameter
//! payload of one Bind must NOT bleed into the next**: parameter
//! buffers are constructed from scratch per call, and there is no
//! hidden cross-call state in the wire-message builders that could
//! leak the prior execution's parameter bytes.
//!
//! The asupersync wire-builder surface is sync and pure — `build_bind_msg`,
//! `build_execute_msg`, `build_sync_msg` take params and return bytes.
//! Without a real Postgres server we drive these builders directly and
//! lock the leakage-isolation contract at the wire-byte layer; the
//! authoritative `psql 18.0` byte oracle is already pinned by the
//! in-tree test `build_bind_execute_msg_matches_psql_prepared_statement_wire_bytes`,
//! so this file focuses on the metamorphic relationships that the
//! single-fixture wire test cannot express.
//!
//! Runs in `tests/` so it compiles into its own integration-test
//! binary, independent of the in-tree `cfg(test)` modules in `src/`
//! that occasionally break the lib test binary.

#![cfg(feature = "postgres")]

use asupersync::database::postgres::{
    Format, ToSql, build_bind_msg, build_execute_msg, build_sync_msg,
};

/// Helper: list of `&dyn ToSql` references where each entry borrows
/// from a Boxed value owned for the duration of the call.
type Params<'a> = Vec<&'a dyn ToSql>;

fn bind(stmt: &str, params: &Params<'_>) -> Vec<u8> {
    build_bind_msg("", stmt, params, Format::Text).expect("build_bind_msg should succeed")
}

#[test]
fn mr_determinism_same_bind_inputs_produce_byte_identical_output() {
    let p1: Params = vec![&42i32, &true];
    let bind_a = bind("s", &p1);
    let bind_b = bind("s", &p1);
    assert_eq!(
        bind_a, bind_b,
        "MR-Determinism: same (stmt, params) must produce byte-identical Bind",
    );
}

#[test]
fn mr_parameter_independence_distinct_values_produce_distinct_bind() {
    let p1: Params = vec![&42i32];
    let p2: Params = vec![&100i32];
    let bind_a = bind("s", &p1);
    let bind_b = bind("s", &p2);
    assert_ne!(
        bind_a, bind_b,
        "MR-ParamIndependence: distinct parameter values must produce distinct Bind bytes",
    );
    // Header (B + 4-byte length + portal-name-NUL + stmt-name + NUL +
    // ... format-codes) is the same up through the first byte of the
    // parameter region. We don't lock the exact split here — that's
    // the job of the byte-fixture test in the lib unit tests; what we
    // pin is that the difference EXISTS, i.e. parameter bytes can't
    // collapse to identical output for distinct input values.
    assert_eq!(
        bind_a.len(),
        bind_b.len(),
        "two i32 params encoded in text form should occupy the same number of bytes \
         (both '42' and '100' fit in two and three ASCII digits respectively, \
         which differ — but the length-prefix bytes equalize)",
    );
    // Stronger: the bind is well-formed (starts with 'B' and the
    // 4-byte big-endian length matches the body).
    for buf in [&bind_a, &bind_b] {
        assert_eq!(buf[0], b'B', "Bind type byte");
        let declared = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        assert_eq!(
            declared,
            buf.len() - 1,
            "declared Bind length must match actual body size (excludes type byte)",
        );
    }
}

#[test]
fn mr_param_position_swap_produces_distinct_bind() {
    // The metamorphic relation: positional swap MUST produce different
    // bytes. If the wire builder accidentally sorted/dedup'd parameters,
    // [42, 100] and [100, 42] would collide and prior-execution state
    // could leak across a re-bind.
    let p_a: Params = vec![&42i32, &100i32];
    let p_b: Params = vec![&100i32, &42i32];
    let bind_a = bind("s", &p_a);
    let bind_b = bind("s", &p_b);
    assert_ne!(
        bind_a, bind_b,
        "MR-ParamPosition: positional parameter swap must produce distinct Bind bytes \
         (no implicit sorting / dedup / coalescing in the builder)",
    );
}

#[test]
fn mr_no_cross_call_state_between_consecutive_binds() {
    // Build a Bind with one parameter set, then a Bind with a
    // completely different parameter set, then re-build the FIRST
    // again. The third call must produce byte-identical output to the
    // first — i.e. the second call's parameters cannot leak into a
    // hidden builder buffer that the third call re-uses.
    let p1: Params = vec![&42i32, &true];
    let p2: Params = vec![&999_999i64, &false, &"sentinel"];

    let bind_first = bind("s1", &p1);
    let _bind_intermediate = bind("s2", &p2);
    let bind_third = bind("s1", &p1);

    assert_eq!(
        bind_first, bind_third,
        "MR-NoCrossCallState: re-binding the same (stmt, params) after an \
         intervening Bind with different parameters must produce byte-identical \
         output. A divergence here means the wire builder has hidden cross-call \
         state, which is precisely the prepared-statement leakage class this \
         test exists to prevent.",
    );
}

#[test]
fn mr_null_param_does_not_bleed_into_subsequent_non_null_bind() {
    // Sanity: a NULL parameter's `0xFF 0xFF 0xFF 0xFF` length marker
    // must appear in the NULL bind, and must NOT appear in a
    // subsequent non-NULL bind that re-uses the same statement.
    let null_val: Option<i32> = None;
    let p_null: Params = vec![&null_val];
    let p_nonnull: Params = vec![&42i32];

    let bind_null = bind("s", &p_null);
    let bind_after_null = bind("s", &p_nonnull);

    fn contains_null_marker(buf: &[u8]) -> bool {
        buf.windows(4).any(|w| w == [0xFF, 0xFF, 0xFF, 0xFF])
    }
    assert!(
        contains_null_marker(&bind_null),
        "NULL bind must contain -1 length marker",
    );
    assert!(
        !contains_null_marker(&bind_after_null),
        "MR-NullNoBleedthrough: a Bind built immediately after a NULL Bind \
         must NOT inherit the NULL marker bytes — that would mean the \
         parameter buffer was re-used without being zeroed/freshly built",
    );
}

#[test]
fn mr_execute_sync_are_stateless_across_re_execution() {
    // Execute and Sync take no parameters and are pure functions of
    // their (portal, max_rows) arguments. A correct implementation
    // produces the same bytes on every call, regardless of how many
    // Bind/Execute/Sync sequences preceded.
    let exec_a = build_execute_msg("", 0).expect("build_execute_msg");
    let sync_a = build_sync_msg().expect("build_sync_msg");

    // Drive a few Bind+Execute+Sync sequences with arbitrary params
    // to maximise the chance that any hidden state (a global thread-
    // local buffer, a static counter, etc.) would observably mutate.
    for params in [
        vec![&1i32 as &dyn ToSql],
        vec![&"a" as &dyn ToSql, &2i32],
        vec![&true as &dyn ToSql, &"b", &42i64],
    ] {
        let _ = bind("warmup", &params);
        let _ = build_execute_msg("warmup", 100).expect("build_execute_msg");
        let _ = build_sync_msg().expect("build_sync_msg");
    }

    let exec_b = build_execute_msg("", 0).expect("build_execute_msg");
    let sync_b = build_sync_msg().expect("build_sync_msg");

    assert_eq!(
        exec_a, exec_b,
        "MR-ExecuteStateless: build_execute_msg must be a pure function; \
         a divergence after intervening Bind/Execute/Sync calls indicates \
         leaked execution-context state in the builder",
    );
    assert_eq!(
        sync_a, sync_b,
        "MR-SyncStateless: build_sync_msg must be a pure function; \
         a divergence after intervening Bind/Execute/Sync calls indicates \
         leaked execution-context state in the builder",
    );
}
