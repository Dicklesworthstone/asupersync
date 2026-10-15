//! Executable lifecycle contract for `CAP-TEMP-ARTIFACTS`.
//!
//! Bead: asupersync-d24mms.5
//! Scenario: temp_artifacts

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::future::Future;
use std::io::{self, Write};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::task::{Context, Poll, Waker};

const PREFIX: &str = "asupersync-cap-temp-artifacts-";

fn new_tempdir() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    builder.prefix(PREFIX);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    let dir = builder.tempdir().expect("create capability tempdir");
    assert_owner_only(dir.path(), "capability tempdir");
    dir
}

#[cfg(unix)]
fn assert_owner_only(path: &std::path::Path, artifact: &str) {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("read {artifact} metadata: {error}"))
        .permissions()
        .mode();
    assert_eq!(
        mode & 0o077,
        0,
        "{artifact} exposed group/other permissions"
    );
}

#[cfg(not(unix))]
fn assert_owner_only(_path: &std::path::Path, _artifact: &str) {
    // Windows access checks are covered by platform-specific ACL evidence.
}

fn fail_after_create(path: &Mutex<Option<PathBuf>>) -> io::Result<()> {
    let dir = new_tempdir();
    let dir_path = dir.path().to_owned();
    std::fs::write(dir_path.join("partial"), b"injected failure residue")?;
    *path.lock().expect("error path lock") = Some(dir_path);
    Err(io::Error::other("injected post-create failure"))
}

struct PendingTempArtifact {
    path: Arc<Mutex<Option<PathBuf>>>,
    dir: Option<tempfile::TempDir>,
}

impl Future for PendingTempArtifact {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.dir.is_none() {
            let dir = new_tempdir();
            *this.path.lock().expect("cancellation path lock") = Some(dir.path().to_owned());
            this.dir = Some(dir);
        }
        Poll::Pending
    }
}

#[test]
fn temp_artifact_success_error_panic_and_cancellation_cleanup() {
    let success_path = {
        let dir = new_tempdir();
        let path = dir.path().to_owned();
        std::fs::write(path.join("complete"), b"complete").expect("write success artifact");
        assert!(path.join("complete").is_file());
        path
    };
    assert!(!success_path.exists(), "success cleanup left residue");

    let error_path = Mutex::new(None);
    let error = fail_after_create(&error_path).expect_err("failure must be injected");
    assert_eq!(error.kind(), io::ErrorKind::Other);
    let error_path = error_path
        .into_inner()
        .expect("error path mutex")
        .expect("error path recorded");
    assert!(!error_path.exists(), "error cleanup left residue");

    let panic_path = Arc::new(Mutex::new(None));
    let panic_path_for_body = Arc::clone(&panic_path);
    let unwind = std::panic::catch_unwind(move || {
        let dir = new_tempdir();
        *panic_path_for_body.lock().expect("panic path lock") = Some(dir.path().to_owned());
        std::fs::write(dir.path().join("panic"), b"panic").expect("write panic artifact");
        panic!("injected lifecycle panic");
    });
    assert!(unwind.is_err(), "panic fixture must unwind");
    let panic_path = panic_path
        .lock()
        .expect("panic path mutex")
        .clone()
        .expect("panic path recorded");
    assert!(!panic_path.exists(), "panic cleanup left residue");

    let cancellation_path = Arc::new(Mutex::new(None));
    let mut future = Box::pin(PendingTempArtifact {
        path: Arc::clone(&cancellation_path),
        dir: None,
    });
    let mut cx = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    let cancellation_path = cancellation_path
        .lock()
        .expect("cancellation path mutex")
        .clone()
        .expect("cancellation path recorded");
    assert!(cancellation_path.is_dir());
    drop(future);
    assert!(
        !cancellation_path.exists(),
        "cancelled future cleanup left residue"
    );
}

#[test]
fn temp_artifact_permissions_and_owned_retention_are_bounded() {
    let owner = new_tempdir();
    let owner_path = owner.path().to_owned();
    let mut staged_builder = tempfile::Builder::new();
    staged_builder.prefix("retained-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        staged_builder.permissions(std::fs::Permissions::from_mode(0o600));
    }
    let mut staged = staged_builder
        .tempfile_in(&owner_path)
        .expect("create staged artifact");
    staged
        .write_all(b"retained evidence")
        .expect("write staged artifact");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let dir_mode = std::fs::metadata(&owner_path)
            .expect("tempdir metadata")
            .permissions()
            .mode();
        let file_mode = staged
            .as_file()
            .metadata()
            .expect("tempfile metadata")
            .permissions()
            .mode();
        assert_eq!(
            dir_mode & 0o077,
            0,
            "tempdir exposed group/other permissions"
        );
        assert_eq!(
            file_mode & 0o077,
            0,
            "tempfile exposed group/other permissions"
        );
    }

    let staged_path = staged.path().to_owned();
    let (retained_file, retained_path) = staged.keep().expect("retain staged artifact");
    drop(retained_file);
    assert_eq!(retained_path, staged_path);
    assert_eq!(
        std::fs::read(&retained_path).expect("read retained artifact"),
        b"retained evidence"
    );

    drop(owner);
    assert!(!owner_path.exists(), "outer owner cleanup left residue");
    assert!(
        !retained_path.exists(),
        "retained artifact escaped its explicit owner"
    );
}

#[test]
fn parallel_temp_artifact_runs_are_isolated_and_clean() {
    const WORKERS: usize = 8;

    let release = Arc::new(Barrier::new(WORKERS + 1));
    let (paths_tx, paths_rx) = mpsc::channel();
    let mut workers = Vec::with_capacity(WORKERS);
    for worker_id in 0..WORKERS {
        let release = Arc::clone(&release);
        let paths_tx = paths_tx.clone();
        workers.push(std::thread::spawn(move || {
            let dir = new_tempdir();
            let path = dir.path().to_owned();
            std::fs::write(path.join("worker"), worker_id.to_string())
                .expect("write isolated worker artifact");
            paths_tx.send(path.clone()).expect("publish worker path");
            release.wait();
            drop(dir);
            path
        }));
    }
    drop(paths_tx);

    let paths = paths_rx.iter().take(WORKERS).collect::<Vec<_>>();
    assert_eq!(paths.len(), WORKERS);
    assert_eq!(paths.iter().collect::<BTreeSet<_>>().len(), WORKERS);
    assert!(paths.iter().all(|path| path.is_dir()));

    release.wait();
    for worker in workers {
        let path = worker.join().expect("parallel worker joined");
        assert!(!path.exists(), "parallel worker cleanup left residue");
    }
}

#[cfg(feature = "test-internals")]
#[test]
fn test_logging_temp_dir_fixture_cleans_on_stop() {
    use asupersync::test_logging::{FixtureService, TempDirFixture};

    let mut fixture = TempDirFixture::new("cap-temp-artifacts");
    fixture.start().expect("start test-logging temp fixture");
    let path = fixture.path().expect("fixture path").to_owned();
    assert_owner_only(&path, "test-logging tempdir");
    std::fs::write(path.join("fixture-evidence"), b"fixture evidence")
        .expect("write fixture evidence");
    assert!(fixture.is_healthy());

    fixture.stop().expect("stop test-logging temp fixture");
    assert!(!fixture.is_healthy());
    assert!(!path.exists(), "test-logging fixture cleanup left residue");
}

#[cfg(feature = "benchmark-adapters")]
#[test]
fn benchmark_suite_work_dir_lifetime_matches_suite_lifetime() {
    use asupersync::atp::benchmark::{BenchmarkConfig, BenchmarkSuite};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("build benchmark test runtime");
    let mut suite = BenchmarkSuite::new("temp-artifact-lifecycle");
    runtime
        .block_on(suite.run_benchmark(&BenchmarkConfig::smoke_test()))
        .expect("empty benchmark suite initializes its work directory");
    let path = suite
        .work_dir_path()
        .expect("benchmark work directory")
        .to_owned();
    assert!(path.is_dir());
    assert_owner_only(&path, "benchmark tempdir");

    drop(suite);
    assert!(!path.exists(), "benchmark suite cleanup left residue");
}
