//! Real-disk SQLite roundtrip: cancel a transaction mid-body and prove
//! the on-disk WAL stays consistent — no partial writes leak to other
//! connections.
//!
//! Bead: br-asupersync-qlwsxf
//!
//! Run with:
//!     cargo test --features sqlite --test sqlite_real_disk_cancel_rollback
//!
//! Existing inline tests in `src/database/sqlite.rs` use `:memory:` and
//! exercise the rollback contract against a private VFS that never
//! touches the disk. This test pins the SAME contract against a real
//! filesystem-backed DB so the WAL fsync path and the cross-connection
//! visibility boundary are also covered:
//!
//! 1. Open a SQLite file in a tempdir, create the schema, set
//!    journal_mode=WAL.
//! 2. Run `with_sqlite_transaction` with a body that INSERTs a row
//!    then awaits a sleep. A sidecar `std::thread` cancels the same
//!    `Cx` after ~150 ms via `cx.cancel_with(CancelKind::User, …)`.
//! 3. Assert the outcome is `Outcome::Cancelled` with `CancelKind::User`
//!    attribution — the cancel signal flowed through the transaction
//!    helper and `with_sqlite_transaction` (src/database/transaction.rs:442)
//!    took the Cancelled arm which calls `tx.rollback`.
//! 4. Open a *fresh* `SqliteConnection` to the same file and verify the
//!    INSERTed row is NOT visible (rollback hit disk before any other
//!    reader could observe it).
//! 5. Run `PRAGMA integrity_check` on the fresh connection and assert
//!    the result is `"ok"` — no torn pages, no orphaned WAL frames.
//!
//! When the cancel-rollback contract regresses, this test fails with
//! whichever assertion broke first: an unexpected `Outcome::Ok` (the
//! commit slipped past the cancel), a row count > 0 (rollback didn't
//! flush), or an `integrity_check` other than `ok` (the WAL is in an
//! inconsistent state).

#![cfg(all(test, feature = "sqlite"))]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::cx::Cx;
use asupersync::database::sqlite::{SqliteConnection, SqliteValue};
use asupersync::database::transaction::with_sqlite_transaction;
use asupersync::test_utils::run_test_with_cx;
use asupersync::time::sleep;
use asupersync::types::{CancelKind, Outcome};

use std::pin::Pin;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

/// Cancel-during-transaction-body durability roundtrip (asupersync-qlwsxf).
#[test]
fn sqlite_real_disk_cancel_during_tx_body_rolls_back_and_leaves_file_consistent() {
    // Tempdir auto-cleans on drop. The path is unique per test run so
    // parallel test execution doesn't see each other's files.
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("asupersync_qlwsxf.db");
    let db_path_str = db_path.to_string_lossy().to_string();

    run_test_with_cx(|cx| async move {
        // ── setup: create the table, set WAL mode, baseline empty count ──
        let conn = match SqliteConnection::open(&cx, &db_path_str).await {
            Outcome::Ok(c) => c,
            other => panic!("open failed: {other:?}"),
        };

        // WAL mode is the production default for SQLite under asupersync;
        // set it explicitly here so the test exercises the WAL path even if
        // the runtime default ever changes.
        match conn
            .execute_unchecked(&cx, "PRAGMA journal_mode = WAL", &[])
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("set WAL failed: {other:?}"),
        }

        match conn
            .execute_unchecked(
                &cx,
                "CREATE TABLE qlwsxf_rows (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)",
                &[],
            )
            .await
        {
            Outcome::Ok(_) => {}
            other => panic!("create failed: {other:?}"),
        }

        let baseline = match conn
            .query_unchecked(&cx, "SELECT count(*) AS n FROM qlwsxf_rows", &[])
            .await
        {
            Outcome::Ok(rows) => rows[0].get_i64("n").expect("n"),
            other => panic!("baseline count failed: {other:?}"),
        };
        assert_eq!(baseline, 0, "fresh table must start empty");

        // ── act: cancel the Cx mid-transaction body ──
        // Clone Cx for the sidecar canceller. Cx is internally Arc, so
        // clones share cancel state; setting it from any thread is
        // observable by the awaiting transaction body via cx.checkpoint.
        let canceller_cx: Cx = cx.clone();
        let canceller = thread::Builder::new()
            .name("sqlite-qlwsxf-cancel".into())
            .spawn(move || {
                thread::sleep(Duration::from_millis(150));
                canceller_cx.cancel_with(
                    CancelKind::User,
                    Some("sqlite_real_disk_cancel_during_tx_body trigger"),
                );
            })
            .expect("spawn canceller");

        let started = Instant::now();
        let outcome =
            with_sqlite_transaction(&conn, &cx, |tx, tx_cx| {
                Box::pin(async move {
                    // INSERT a row that MUST not be visible on rollback.
                    match tx
                        .execute(
                            tx_cx,
                            "INSERT INTO qlwsxf_rows (id, payload) VALUES (?1, ?2)",
                            &[
                                SqliteValue::Integer(1),
                                SqliteValue::Text("must-not-persist".into()),
                            ],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => return other.map(|_| ()),
                    }

                    // Park on a long sleep so the cancel arrives mid-body.
                    // 5 s ceiling — the cancel should land in ~150 ms; a
                    // regression that misses the cancel makes this branch
                    // run to completion and the test catches an unexpected
                    // Outcome::Ok at the assertion below.
                    let now = tx_cx.now();
                    let mut sleeper = sleep(now, Duration::from_secs(5));
                    std::future::poll_fn(|task_cx| {
                        if tx_cx.checkpoint().is_err() {
                            return std::task::Poll::Ready(());
                        }
                        Pin::new(&mut sleeper).poll(task_cx)
                    })
                    .await;

                    // Re-check the cancel after the sleep so the body
                    // surfaces Outcome::Cancelled rather than Ok if the
                    // checkpoint hadn't fired before this point.
                    if tx_cx.checkpoint().is_err() {
                        return Outcome::Cancelled(tx_cx.cancel_reason().unwrap_or_else(|| {
                            asupersync::types::CancelReason::user("cancelled")
                        }));
                    }

                    Outcome::Ok(())
                })
            })
            .await;
        let elapsed = started.elapsed();
        canceller.join().expect("canceller thread");

        match outcome {
            Outcome::Cancelled(reason) => {
                assert_eq!(
                    reason.kind,
                    CancelKind::User,
                    "cancel attribution must be User; got {:?}",
                    reason.kind
                );
            }
            Outcome::Ok(_) => panic!(
                "transaction body completed normally in {elapsed:?} — cancel was not observed by \
                 the with_sqlite_transaction helper or the body's checkpoint"
            ),
            Outcome::Err(e) => panic!(
                "transaction body returned PgError instead of Outcome::Cancelled: {e:?} (elapsed {elapsed:?})"
            ),
            Outcome::Panicked(p) => panic!("transaction body panicked: {p:?}"),
        }

        // The 5 s sleep would still be active without the cancel. Hard
        // ceiling at 3 s catches a regression that closes the body
        // without firing the cancel checkpoint.
        assert!(
            elapsed < Duration::from_secs(3),
            "cancel must short-circuit the 5 s sleep well under 3 s, took {elapsed:?}"
        );

        // ── assert: rollback hit disk, no other reader sees the INSERT ──
        // Open a fresh connection to the same file. SqliteConnection on
        // the same path opens its own rusqlite handle, which sees the
        // server-side committed state — what asupersync's internal Mutex
        // cannot fake.
        let cx_recover = Cx::for_testing();
        let recover = match SqliteConnection::open(&cx_recover, &db_path_str).await {
            Outcome::Ok(c) => c,
            other => panic!("recover open failed: {other:?}"),
        };
        let after = match recover
            .query_unchecked(&cx_recover, "SELECT count(*) AS n FROM qlwsxf_rows", &[])
            .await
        {
            Outcome::Ok(rows) => rows[0].get_i64("n").expect("n"),
            other => panic!("post-cancel count failed: {other:?}"),
        };
        assert_eq!(
            after, 0,
            "transaction rolled back must hide INSERTed row from a fresh connection; got {after} \
             rows. If this fails the cancel arm of with_sqlite_transaction did NOT call rollback \
             before disposing the SqliteTransaction."
        );

        // PRAGMA integrity_check is server-side proof — only SQLite can
        // determine whether the WAL/main DB pages are torn or
        // orphaned. The single-row 'ok' result is the canonical
        // healthy DB signal.
        let integrity = match recover
            .query_unchecked(&cx_recover, "PRAGMA integrity_check", &[])
            .await
        {
            Outcome::Ok(rows) => rows[0]
                .get_str("integrity_check")
                .map(str::to_string)
                .unwrap_or_else(|_| "<missing>".to_string()),
            other => panic!("integrity_check failed: {other:?}"),
        };
        assert_eq!(
            integrity, "ok",
            "PRAGMA integrity_check must be 'ok' after a cancel-rollback; got {integrity:?}. \
             A non-ok result indicates torn writes or orphaned WAL frames — review the rollback \
             path in src/database/transaction.rs:442 and src/database/sqlite.rs:1801."
        );
    });
}
