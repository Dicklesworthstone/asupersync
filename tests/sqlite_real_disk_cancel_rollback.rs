//! Real-disk SQLite roundtrip: cancel a transaction mid-body and prove
//! the on-disk WAL stays consistent — no partial writes leak to other
//! connections.
//!
//! Bead: br-asupersync-qlwsxf
//!
//! Run with:
//!     rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_sqlite_real_disk_cancel_rollback cargo test --features sqlite --test sqlite_real_disk_cancel_rollback
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
//!    then awaits a cancel-aware oneshot receive. A sidecar `std::thread`
//!    cancels the same
//!    `Cx` after ~150 ms via `cx.cancel_with(CancelKind::User, …)`.
//! 3. Assert the outcome is `Outcome::Cancelled` with `CancelKind::User`
//!    attribution — the cancel signal flowed through the transaction
//!    helper and its Cancelled arm completed `tx.rollback`.
//! 4. Open a direct *reference* `rusqlite::Connection` to the same file and
//!    acquire `BEGIN IMMEDIATE` with a zero busy timeout before any wrapper
//!    query or close. This proves the helper released SQLite's physical write
//!    transaction before returning, rather than merely scheduling cleanup.
//! 5. Verify the INSERTed row is NOT visible, then run `PRAGMA integrity_check`
//!    on the reference connection and assert
//!    the result is `"ok"` — no torn pages, no orphaned WAL frames.
//! 6. Close the cancelled Asupersync connection, re-check through the
//!    reference connection that deferred rollback cleanup left zero rows,
//!    then commit a reference row, reopen through Asupersync, and verify that
//!    row is visible. This proves both directions of the wrapper boundary
//!    without relying on two simultaneous writers.
//!
//! When the cancel-rollback contract regresses, this test fails with
//! whichever assertion broke first: an unexpected `Outcome::Ok` (the
//! commit slipped past the cancel), a row count > 0 (rollback didn't
//! flush), or an `integrity_check` other than `ok` (the WAL is in an
//! inconsistent state).

#![cfg(all(test, feature = "sqlite"))]
#![allow(clippy::pedantic, clippy::nursery, clippy::print_stderr)]

use asupersync::channel::oneshot;
use asupersync::cx::Cx;
use asupersync::database::sqlite::{
    SqliteConnection, SqliteError, SqliteTransaction, SqliteValue,
};
use asupersync::database::transaction::{
    with_sqlite_transaction, with_sqlite_transaction_immediate,
};
use asupersync::observability::{LogCollector, LogLevel};
use asupersync::test_utils::run_test_with_cx;
use asupersync::types::{CancelKind, Outcome};

use std::future::Future;
use std::pin::Pin;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

type CancelledTransactionBody<'a> =
    Pin<Box<dyn Future<Output = Outcome<(), SqliteError>> + Send + 'a>>;

fn cancelled_transaction_body<'a>(
    tx: &'a SqliteTransaction<'_>,
    tx_cx: &'a Cx,
) -> CancelledTransactionBody<'a> {
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

        // Park on a cancel-aware receive with its sender retained. Unlike a
        // raw timer, the receive owns a cancellation-Waker registration and
        // must resume promptly when the sidecar cancels this Cx.
        let (pending_tx, mut pending_rx) = oneshot::channel::<()>();
        let wait_result = pending_rx.recv(tx_cx).await;
        assert!(
            matches!(wait_result, Err(oneshot::RecvError::Cancelled)),
            "pending receive must wake through Cx cancellation: {wait_result:?}"
        );
        drop(pending_tx);

        if tx_cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                tx_cx
                    .cancel_reason()
                    .unwrap_or_else(|| asupersync::types::CancelReason::user("cancelled")),
            );
        }

        Outcome::Ok(())
    })
}

fn run_real_disk_cancel_rollback_case(immediate: bool) {
    // Tempdir auto-cleans on drop. The path is unique per test run so
    // parallel test execution doesn't see each other's files.
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("asupersync_qlwsxf.db");
    let db_path_str = db_path.to_string_lossy().to_string();

    run_test_with_cx(|cx| async move {
        let logs = LogCollector::new(256).with_min_level(LogLevel::Trace);
        cx.set_log_collector(logs.clone());

        // ── setup: create the table, set WAL mode, baseline empty count ──
        let conn = match SqliteConnection::open(&cx, &db_path_str).await {
            Outcome::Ok(c) => c,
            other => panic!("open failed: {other:?}"),
        };

        // WAL mode is the production default for SQLite under asupersync;
        // set it explicitly here so the test exercises the WAL path even if
        // the runtime default ever changes.
        let journal_mode = match conn
            .query_unchecked(&cx, "PRAGMA journal_mode = WAL", &[])
            .await
        {
            Outcome::Ok(rows) => rows[0]
                .get_str("journal_mode")
                .expect("journal_mode")
                .to_ascii_lowercase(),
            other => panic!("set WAL failed: {other:?}"),
        };
        assert_eq!(
            journal_mode, "wal",
            "real-disk fixture must enter WAL mode before cancellation"
        );

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
        let outcome = if immediate {
            with_sqlite_transaction_immediate(&conn, &cx, cancelled_transaction_body).await
        } else {
            with_sqlite_transaction(&conn, &cx, cancelled_transaction_body).await
        };
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

        let rollback_completed = logs.peek().iter().any(|entry| {
            entry.message() == "database.transaction.lifecycle"
                && entry.get_field("backend") == Some("sqlite")
                && entry.get_field("operation") == Some("rollback")
                && entry.get_field("outcome") == Some("ok")
        });
        assert!(
            rollback_completed,
            "with_sqlite_transaction must await a successful physical rollback before returning the body's cancellation"
        );

        // Hard ceiling at 3 s catches a cancellation-Waker regression.
        assert!(
            elapsed < Duration::from_secs(3),
            "cancel must short-circuit the 5 s sleep well under 3 s, took {elapsed:?}"
        );

        // ── assert: rollback hit disk, no other reader sees the INSERT ──
        // Open an independent direct rusqlite connection to the same file.
        // This bypasses asupersync's internal Mutex and wrapper query path.
        let cx_recover = Cx::for_testing();
        let reference =
            rusqlite::Connection::open(&db_path_str).expect("open direct reference connection");
        reference
            .busy_timeout(Duration::ZERO)
            .expect("set zero busy timeout on reference connection");
        reference
            .execute_batch("BEGIN IMMEDIATE")
            .expect("helper return must release the write transaction immediately");
        reference
            .execute_batch("ROLLBACK")
            .expect("release reference write-lock probe");
        let after: i64 = reference
            .query_row("SELECT count(*) FROM qlwsxf_rows", [], |row| row.get(0))
            .expect("reference post-cancel count");
        assert_eq!(
            after, 0,
            "transaction rolled back must hide INSERTed row from the reference connection; got {after} \
             rows. If this fails the cancel arm of with_sqlite_transaction did NOT call rollback \
             before disposing the SqliteTransaction."
        );

        // PRAGMA integrity_check is server-side proof — only SQLite can
        // determine whether the WAL/main DB pages are torn or
        // orphaned. The single-row 'ok' result is the canonical
        // healthy DB signal.
        let integrity: String = reference
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))
            .expect("reference integrity_check");
        assert_eq!(
            integrity, "ok",
            "PRAGMA integrity_check must be 'ok' after a cancel-rollback; got {integrity:?}. \
             A non-ok result indicates torn writes or orphaned WAL frames — review the rollback \
             path in with_sqlite_transaction and SqliteTransaction::rollback."
        );

        // End the cancelled connection's lifecycle before handing write
        // ownership to the reference connection. SQLite permits the
        // read-only checks above while the wrapper retains its WAL handle,
        // but a second writer must not depend on overlapping connection
        // teardown. `close` also drains any rollback marked for deferred
        // cleanup by the cancelled transaction path.
        conn.close()
            .expect("close cancelled asupersync connection before reference write");
        assert!(
            !conn.is_open(),
            "explicit fixture teardown must release the original connection"
        );
        let after_close: i64 = reference
            .query_row("SELECT count(*) FROM qlwsxf_rows", [], |row| row.get(0))
            .expect("reference count after rollback-draining close");
        assert_eq!(
            after_close, 0,
            "explicit close must drain the cancelled transaction rollback before reference writes"
        );

        reference
            .execute(
                "INSERT INTO qlwsxf_rows (id, payload) VALUES (?1, ?2)",
                rusqlite::params![2_i64, "reference-persists"],
            )
            .expect("reference write");
        drop(reference);

        let recover = match SqliteConnection::open(&cx_recover, &db_path_str).await {
            Outcome::Ok(c) => c,
            other => panic!("recover open failed: {other:?}"),
        };
        let payload = match recover
            .query_unchecked(
                &cx_recover,
                "SELECT payload FROM qlwsxf_rows WHERE id = ?1",
                &[SqliteValue::Integer(2)],
            )
            .await
        {
            Outcome::Ok(rows) => rows[0]
                .get_str("payload")
                .map(str::to_string)
                .expect("reference payload"),
            other => panic!("asupersync read of reference write failed: {other:?}"),
        };
        assert_eq!(
            payload, "reference-persists",
            "asupersync must read a committed row written by the reference connection"
        );
    });
}

/// Deferred transaction cancel/rollback durability roundtrip (asupersync-qlwsxf).
#[test]
fn sqlite_real_disk_cancel_during_tx_body_rolls_back_and_leaves_file_consistent() {
    run_real_disk_cancel_rollback_case(false);
}

/// Immediate transaction cancel/rollback durability roundtrip (asupersync-ym2wtv.2.4).
#[test]
fn sqlite_real_disk_cancel_during_immediate_tx_rolls_back_before_return() {
    run_real_disk_cancel_rollback_case(true);
}
