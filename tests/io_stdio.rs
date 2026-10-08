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
