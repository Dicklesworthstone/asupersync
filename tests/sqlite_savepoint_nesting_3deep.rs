//! Three-deep SQLite savepoint nesting with partial and cascade rollback.
//!
//! Bead: br-asupersync-server-stack-hardening-eeexl1.5 (AC2 — "Savepoint
//! matrix verified-or-added: nested 3-deep, partial rollback_to,
//! commit-with-pending-savepoints per-DB").
//!
//! The AC0 verdict on eeexl1.5 found the existing inline savepoint tests
//! (`src/database/transaction.rs`) only exercise a SINGLE savepoint level —
//! 3-deep nesting and the cascade semantics of `ROLLBACK TO` a middle
//! savepoint were untested on every backend. This integration test fills
//! that gap for SQLite (hermetic `:memory:`, no real-DB infra), and being a
//! `tests/*.rs` crate it links the library in normal (non-`cfg(test)`) mode,
//! so it is immune to in-crate `#[cfg(test)]` churn from concurrent work.
//!
//! Two scenarios, both driven through the real async transaction +
//! `SqliteSavepoint` API:
//!   1. `..._innermost_rollback_keeps_outer_levels`: build sp1>sp2>sp3, roll
//!      back ONLY the innermost (sp3) — its row vanishes while every outer
//!      level's rows survive the final commit.
//!   2. `..._cascade_rollback_to_middle_discards_inner`: release the innermost
//!      into its parent's scope, then `ROLLBACK TO` the MIDDLE savepoint —
//!      both the middle and the (folded-in) inner rows are discarded together,
//!      while the outermost level survives.
//!
//! Run with:
//!     rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_lib \
//!         cargo test --features sqlite --test sqlite_savepoint_nesting_3deep

#![cfg(all(test, feature = "sqlite"))]
#![allow(clippy::pedantic, clippy::nursery)]

use asupersync::cx::Cx;
use asupersync::database::sqlite::{SqliteConnection, SqliteValue};
use asupersync::database::transaction::{SqliteSavepoint, with_sqlite_transaction};
use asupersync::test_utils::run_test_with_cx;
use asupersync::types::Outcome;

/// Insert one named marker row into `nesting_items`.
async fn insert(tx: &asupersync::database::sqlite::SqliteTransaction<'_>, cx: &Cx, name: &str) {
    match tx
        .execute(
            cx,
            "INSERT INTO nesting_items(name) VALUES (?1)",
            &[SqliteValue::Text(name.to_string())],
        )
        .await
    {
        Outcome::Ok(_) => {}
        other => panic!("insert {name:?} failed: {other:?}"),
    }
}

/// Open an in-memory db with the shared schema and return the connection.
async fn setup(cx: &Cx) -> SqliteConnection {
    let conn = match SqliteConnection::open_in_memory(cx).await {
        Outcome::Ok(conn) => conn,
        other => panic!("open_in_memory failed: {other:?}"),
    };
    match conn
        .execute(
            cx,
            "CREATE TABLE nesting_items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
            &[],
        )
        .await
    {
        Outcome::Ok(_) => {}
        other => panic!("schema setup failed: {other:?}"),
    }
    conn
}

/// Return the surviving marker names in insertion order.
async fn names(conn: &SqliteConnection, cx: &Cx) -> Vec<String> {
    let rows = match conn
        .query(cx, "SELECT name FROM nesting_items ORDER BY id", &[])
        .await
    {
        Outcome::Ok(rows) => rows,
        other => panic!("final query failed: {other:?}"),
    };
    rows.iter()
        .map(|row| row.get_str("name").expect("name column").to_string())
        .collect()
}

#[test]
fn sqlite_savepoint_3deep_innermost_rollback_keeps_outer_levels() {
    run_test_with_cx(|cx| async move {
        let conn = setup(&cx).await;

        let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
            Box::pin(async move {
                insert(tx, cx, "base").await;

                // sp1 > sp2 > sp3 — three live, strictly-nested savepoints.
                let sp1 = match SqliteSavepoint::new(tx, cx, "sp1").await {
                    Outcome::Ok(sp) => sp,
                    other => panic!("sp1 create failed: {other:?}"),
                };
                insert(tx, cx, "lvl1").await;

                let sp2 = match SqliteSavepoint::new(tx, cx, "sp2").await {
                    Outcome::Ok(sp) => sp,
                    other => panic!("sp2 create failed: {other:?}"),
                };
                insert(tx, cx, "lvl2").await;

                let sp3 = match SqliteSavepoint::new(tx, cx, "sp3").await {
                    Outcome::Ok(sp) => sp,
                    other => panic!("sp3 create failed: {other:?}"),
                };
                insert(tx, cx, "lvl3").await;

                // Roll back ONLY the innermost level: lvl3 is discarded, the
                // sp3 marker is released, sp1/sp2 stay active.
                match sp3.rollback(cx).await {
                    Outcome::Ok(()) => {}
                    other => panic!("sp3 rollback failed: {other:?}"),
                }
                // Commit the two remaining levels back into the transaction
                // (commit-with-pending-savepoints, resolved LIFO).
                match sp2.release(cx).await {
                    Outcome::Ok(()) => {}
                    other => panic!("sp2 release failed: {other:?}"),
                }
                match sp1.release(cx).await {
                    Outcome::Ok(()) => {}
                    other => panic!("sp1 release failed: {other:?}"),
                }

                Outcome::Ok(())
            })
        })
        .await;
        match tx_outcome {
            Outcome::Ok(()) => {}
            other => panic!("outer transaction must commit, got {other:?}"),
        }

        assert_eq!(
            names(&conn, &cx).await,
            vec!["base".to_string(), "lvl1".to_string(), "lvl2".to_string()],
            "innermost rollback must discard only lvl3 and keep all outer levels"
        );
    });
}

#[test]
fn sqlite_savepoint_3deep_cascade_rollback_to_middle_discards_inner() {
    run_test_with_cx(|cx| async move {
        let conn = setup(&cx).await;

        let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
            Box::pin(async move {
                insert(tx, cx, "base").await;

                let sp1 = match SqliteSavepoint::new(tx, cx, "sp1").await {
                    Outcome::Ok(sp) => sp,
                    other => panic!("sp1 create failed: {other:?}"),
                };
                insert(tx, cx, "lvl1").await;

                let sp2 = match SqliteSavepoint::new(tx, cx, "sp2").await {
                    Outcome::Ok(sp) => sp,
                    other => panic!("sp2 create failed: {other:?}"),
                };
                insert(tx, cx, "lvl2").await;

                let sp3 = match SqliteSavepoint::new(tx, cx, "sp3").await {
                    Outcome::Ok(sp) => sp,
                    other => panic!("sp3 create failed: {other:?}"),
                };
                insert(tx, cx, "lvl3").await;

                // Release the innermost: lvl3 folds into sp2's scope.
                match sp3.release(cx).await {
                    Outcome::Ok(()) => {}
                    other => panic!("sp3 release failed: {other:?}"),
                }
                // Roll back to the MIDDLE savepoint: this cascades — lvl2 AND
                // the folded-in lvl3 are both discarded in one rollback.
                match sp2.rollback(cx).await {
                    Outcome::Ok(()) => {}
                    other => panic!("sp2 rollback failed: {other:?}"),
                }
                // Outermost level survives the commit.
                match sp1.release(cx).await {
                    Outcome::Ok(()) => {}
                    other => panic!("sp1 release failed: {other:?}"),
                }

                Outcome::Ok(())
            })
        })
        .await;
        match tx_outcome {
            Outcome::Ok(()) => {}
            other => panic!("outer transaction must commit, got {other:?}"),
        }

        assert_eq!(
            names(&conn, &cx).await,
            vec!["base".to_string(), "lvl1".to_string()],
            "rollback to the middle savepoint must cascade-discard lvl2 and lvl3"
        );
    });
}
