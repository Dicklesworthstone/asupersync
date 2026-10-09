//! `io::{stdin, stdout, stderr}`: the test binary runs itself as a child
//! process whose standard streams are pipes. The child pipes 300 KB through
//! asupersync's handles (several chunks each way, write-behind output), and
//! shows that a read cancelled by a timeout loses no input when the `Stdin`
//! handle is kept.
#![cfg(unix)]

use asupersync::io::{AsyncReadExt, AsyncWriteExt, stderr, stdin, stdout};
use asupersync::runtime::RuntimeBuilder;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

const HELPER: &str = "ASUPERSYNC_STDIO_TEST_HELPER";
const BEGIN: &str = "<<begin>>";
const END: &str = "<<end>>";

/// Runs this test binary's `stdio_helper` with `role`.
fn helper(role: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test binary"));
    command
        .args(["--exact", "stdio_helper", "--nocapture", "--test-threads=1"])
        .env(HELPER, role)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// The bytes the helper wrote between its markers.
fn between_markers(output: &[u8]) -> &[u8] {
    let text = output;
    let start = find(text, BEGIN.as_bytes()).expect("begin marker") + BEGIN.len();
    let end = find(&text[start..], END.as_bytes()).expect("end marker") + start;
    &text[start..end]
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Not a test of its own: the body of the child process.
#[test]
fn stdio_helper() {
    let Ok(role) = std::env::var(HELPER) else {
        return;
    };
    let runtime = RuntimeBuilder::new()
        .worker_threads(2)
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let mut input = stdin();
        let mut output = stdout();
        match role.as_str() {
            "uppercase" => {
                let mut received = Vec::new();
                input.read_to_end(&mut received).await.expect("read stdin");
                output.write_all(BEGIN.as_bytes()).await.expect("write");
                for chunk in received.chunks(7_000) {
                    output
                        .write_all(&chunk.to_ascii_uppercase())
                        .await
                        .expect("write stdout");
                }
                output.write_all(END.as_bytes()).await.expect("write");
                output.flush().await.expect("flush stdout");
                let mut errors = stderr();
                errors
                    .write_all(format!("read {} bytes\n", received.len()).as_bytes())
                    .await
                    .expect("write stderr");
                errors.flush().await.expect("flush stderr");
            }
            "cancelled-read" => {
                output.write_all(b"waiting\n").await.expect("write");
                output.flush().await.expect("flush");
                let mut buf = [0_u8; 64];
                let attempt = asupersync::time::timeout(
                    asupersync::time::wall_now(),
                    Duration::from_millis(200),
                    input.read(&mut buf),
                )
                .await;
                assert!(attempt.is_err(), "no input yet: the read times out");
                output.write_all(b"timed out\n").await.expect("write");
                output.flush().await.expect("flush");
                // The parent writes now. The read the timeout abandoned is
                // still the handle's, so its bytes arrive here.
                let mut received = Vec::new();
                input.read_to_end(&mut received).await.expect("read");
                output.write_all(BEGIN.as_bytes()).await.expect("write");
                output.write_all(&received).await.expect("write");
                output.write_all(END.as_bytes()).await.expect("write");
                output.flush().await.expect("flush");
            }
            "unflushed-then-read" => {
                // No flush and no further write: the line must still leave
                // while the helper waits for input.
                output.write_all(b"ready\n").await.expect("write");
                let mut received = Vec::new();
                input.read_to_end(&mut received).await.expect("read");
            }
            "dropped-handle" => {
                output.write_all(BEGIN.as_bytes()).await.expect("write");
                output
                    .write_all(b"written after the drop")
                    .await
                    .expect("write");
                output.write_all(END.as_bytes()).await.expect("write");
                // The last write is still in flight. Dropping the handle must
                // not lose it; nothing touches the stream again.
                drop(output);
                asupersync::time::sleep(asupersync::time::wall_now(), Duration::from_millis(500))
                    .await;
            }
            other => panic!("unknown helper role {other}"),
        }
    });
}

#[test]
fn bytes_flow_through_stdin_stdout_and_stderr() {
    let input: Vec<u8> = (0..300_000_u32)
        .map(|i| b"abcdefghijklmnopqrstuvwxyz\n"[(i % 27) as usize])
        .collect();
    let mut child = helper("uppercase").spawn().expect("spawn helper");
    let mut child_stdin = child.stdin.take().expect("stdin pipe");
    let feed = {
        let input = input.clone();
        std::thread::spawn(move || {
            child_stdin.write_all(&input).expect("feed stdin");
        })
    };
    let output = child.wait_with_output().expect("helper output");
    feed.join().expect("feeder");
    assert!(output.status.success(), "{output:?}");
    assert!(
        between_markers(&output.stdout) == input.to_ascii_uppercase().as_slice(),
        "stdout carries every byte, uppercased, in order"
    );
    let errors = String::from_utf8_lossy(&output.stderr);
    assert!(errors.contains("read 300000 bytes"), "{errors}");
}

#[test]
fn a_read_cancelled_by_a_timeout_loses_no_input() {
    let mut child = helper("cancelled-read").spawn().expect("spawn helper");
    let mut child_stdin = child.stdin.take().expect("stdin pipe");
    let mut child_stdout = BufReader::new(child.stdout.take().expect("stdout pipe"));
    let mut line = String::new();
    loop {
        line.clear();
        assert!(
            child_stdout.read_line(&mut line).expect("read line") > 0,
            "the helper exited early"
        );
        if line == "timed out\n" {
            break;
        }
    }
    child_stdin.write_all(b"after the timeout").expect("write");
    drop(child_stdin);
    let mut rest = Vec::new();
    child_stdout.read_to_end(&mut rest).expect("read rest");
    let status = child.wait().expect("wait");
    assert!(status.success());
    assert_eq!(between_markers(&rest), b"after the timeout");
}

/// A write starts when `write` accepts it. It used to wait for the handle's
/// next operation, so a helper that wrote a line without flushing and then
/// waited for input never sent the line its parent was waiting for
/// (br-asupersync-68jvck).
#[test]
fn a_write_leaves_before_the_next_operation_on_the_handle() {
    let mut child = helper("unflushed-then-read").spawn().expect("spawn helper");
    let child_stdin = child.stdin.take().expect("stdin pipe");
    let child_stdout = child.stdout.take().expect("stdout pipe");
    let (seen_tx, seen_rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut lines = BufReader::new(child_stdout);
        let mut line = String::new();
        loop {
            line.clear();
            if lines.read_line(&mut line).expect("read line") == 0 {
                let _ = seen_tx.send(false);
                return;
            }
            // libtest prints "test stdio_helper ... " without a newline
            // before the helper runs, so the helper's line ends this one.
            if line.ends_with("ready\n") {
                let _ = seen_tx.send(true);
                let mut rest = Vec::new();
                let _ = lines.read_to_end(&mut rest);
                return;
            }
        }
    });
    let seen = seen_rx.recv_timeout(Duration::from_secs(10));
    // Release the helper either way.
    drop(child_stdin);
    let status = child.wait().expect("wait");
    reader.join().expect("reader");
    assert!(status.success());
    assert_eq!(
        seen,
        Ok(true),
        "the unflushed line reached the parent while the helper waited for input"
    );
}

/// Bytes accepted by `write` are written even when the handle is dropped
/// right after, as the module documents (br-asupersync-68jvck).
#[test]
fn a_dropped_handle_still_writes_what_it_accepted() {
    let output = helper("dropped-handle").output().expect("run helper");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(END),
        "the last write before the drop reached stdout: {stdout:?}"
    );
    assert_eq!(between_markers(&output.stdout), b"written after the drop");
}

/// The standard-stream handles are I/O entry points that take no `Cx`: a task
/// whose context lacks the IO capability is refused with `[ASUP-E009]`, as by
/// `fs::File::open` and the net entry points (br-asupersync-68jvck).
#[test]
fn a_task_without_io_is_refused_the_standard_streams() {
    use asupersync::Cx;
    use asupersync::cx::IoCapabilityDenied;
    use asupersync::cx::cap::{CapSet, CapSetRuntimeMask};
    type NoIo = CapSet<true, true, true, false, true>;

    fn refused(result: std::io::Result<usize>, operation: &str) {
        let error = result.expect_err("refused");
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied,
            "{error}"
        );
        let denied = error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<IoCapabilityDenied>())
            .unwrap_or_else(|| panic!("not an IoCapabilityDenied: {error}"));
        assert_eq!(denied.operation(), operation);
    }

    let runtime = RuntimeBuilder::current_thread().build().expect("runtime");
    runtime.block_on(async {
        let cx = Cx::current().expect("root cx");
        let mut task = {
            let _no_io = Cx::push_restriction(<NoIo as CapSetRuntimeMask>::MASK);
            Cx::current()
                .expect("narrowed cx")
                .spawn(move |_cx| async move {
                    assert!(Cx::current().expect("task cx").io().is_none());
                    refused(stdout().write(b"x").await, "io::stdout");
                    refused(stderr().write(b"x").await, "io::stderr");
                    let mut buf = [0_u8; 8];
                    refused(stdin().read(&mut buf).await, "io::stdin");
                })
                .expect("spawn")
        };
        task.join(&cx).await.expect("the restricted task completes");
    });
}
