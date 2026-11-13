//! Windows child stdio through the async traits: `ChildStdin: AsyncWrite`,
//! `ChildStdout`/`ChildStderr: AsyncRead` over std's overlapped parent pipe
//! ends (`src/process/windows_pipe.rs`).
//!
//! `harness = false`: this binary is also the child (selected by
//! `ASUPERSYNC_CHILD_STDIO_ROLE`), and a test harness would print its banner
//! into the child's stdout. Futures run on a parking executor whose only
//! wake source is the pipe's: a lost wake fails at the deadline instead of
//! hanging.

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    windows::main();
}

#[cfg(windows)]
mod windows {
    use asupersync::io::{AsyncRead, AsyncWrite, ReadBuf};
    use asupersync::process::{Child, Command, Stdio};
    use std::future::{Future, poll_fn};
    use std::io::Write;
    use std::pin::{Pin, pin};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Wake, Waker};
    use std::thread::{self, Thread};
    use std::time::{Duration, Instant};

    const ROLE: &str = "ASUPERSYNC_CHILD_STDIO_ROLE";
    const LATE_DELAY: Duration = Duration::from_millis(300);
    /// Output can only arrive this long after the spawn (the delay, less
    /// timer slack).
    const LATE_FLOOR: Duration = Duration::from_millis(250);
    const LATE_STDOUT: usize = 200 * 1024;
    const LATE_STDERR: usize = 1000;
    const ROUND_TRIP: usize = 1024 * 1024;

    fn pattern(length: usize, seed: u8) -> Vec<u8> {
        (0..length)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    pub fn main() {
        if let Ok(role) = std::env::var(ROLE) {
            child(&role);
            return;
        }
        let tests: [(&str, fn()); 4] = [
            ("echo_round_trip_larger_than_the_pipe", echo_round_trip),
            ("late_output_wakes_a_parked_reader", late_output_wakes),
            (
                "dropping_a_pending_read_returns_promptly",
                dropping_pending_read,
            ),
            (
                "writing_to_an_exited_child_reports_an_error",
                write_after_exit,
            ),
        ];
        let filter: Vec<String> = std::env::args()
            .skip(1)
            .filter(|a| !a.starts_with('-'))
            .collect();
        let mut ran = 0;
        for (name, test) in tests {
            if !filter.is_empty() && !filter.iter().any(|f| name.contains(f.as_str())) {
                continue;
            }
            let started = Instant::now();
            test();
            ran += 1;
            println!("test {name} ... ok ({:?})", started.elapsed());
        }
        assert!(ran > 0, "no test matched {filter:?}");
        println!("{ran} passed");
    }

    fn child(role: &str) {
        match role {
            "echo" => {
                let mut input = std::io::stdin().lock();
                let mut output = std::io::stdout().lock();
                std::io::copy(&mut input, &mut output).expect("echo");
                output.flush().expect("flush");
            }
            "late" => {
                thread::sleep(LATE_DELAY);
                std::io::stderr()
                    .write_all(&pattern(LATE_STDERR, 7))
                    .expect("stderr");
                let mut output = std::io::stdout().lock();
                output.write_all(&pattern(LATE_STDOUT, 3)).expect("stdout");
                output.flush().expect("flush");
            }
            "silent" => thread::sleep(Duration::from_secs(10)),
            "exit" => {}
            other => panic!("unknown role {other}"),
        }
    }

    fn spawn(role: &str, stdin: bool, stderr: bool) -> Child {
        let mut command = Command::new(std::env::current_exe().expect("current exe"));
        command
            .env(ROLE, role)
            .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(if stderr {
                Stdio::piped()
            } else {
                Stdio::null()
            });
        command.spawn().expect("spawn")
    }

    struct Parker {
        thread: Thread,
        wakes: AtomicUsize,
    }
    impl Wake for Parker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.wakes.fetch_add(1, Ordering::SeqCst);
            self.thread.unpark();
        }
    }

    /// Polls `future` to completion, parking between polls. Returns the
    /// output and how many times it was woken.
    fn block_on<F: Future>(future: F) -> (F::Output, usize) {
        let parker = Arc::new(Parker {
            thread: thread::current(),
            wakes: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&parker));
        let mut cx = Context::from_waker(&waker);
        let mut future = pin!(future);
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return (output, parker.wakes.load(Ordering::SeqCst));
            }
            let now = Instant::now();
            assert!(now < deadline, "not woken within 20 s");
            thread::park_timeout(deadline - now);
        }
    }

    fn read_some<R: AsyncRead + Unpin>(
        reader: &mut R,
        cx: &mut Context<'_>,
        out: &mut Vec<u8>,
    ) -> Poll<std::io::Result<usize>> {
        let mut chunk = [0_u8; 7000];
        let mut buf = ReadBuf::new(&mut chunk);
        match Pin::new(reader).poll_read(cx, &mut buf) {
            Poll::Ready(Ok(())) => {
                out.extend_from_slice(buf.filled());
                Poll::Ready(Ok(buf.filled().len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    async fn read_to_end<R: AsyncRead + Unpin>(mut reader: R) -> Vec<u8> {
        let mut out = Vec::new();
        poll_fn(|cx| {
            loop {
                match read_some(&mut reader, cx, &mut out) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(()),
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(e)) => panic!("read: {e}"),
                    Poll::Pending => return Poll::Pending,
                }
            }
        })
        .await;
        out
    }

    /// 1 MiB through a child that copies stdin to stdout: sixteen times
    /// the pipe's capacity each way, so writes wait for the child to read
    /// and reads wait for it to write. Writing and reading advance in the
    /// same future.
    fn echo_round_trip() {
        let mut child = spawn("echo", true, false);
        let mut stdin = Some(child.stdin().expect("stdin"));
        let mut stdout = child.stdout().expect("stdout");
        let input = pattern(ROUND_TRIP, 1);
        let mut written = 0;
        let mut output = Vec::new();
        let (eof, wakes) = block_on(poll_fn(|cx| {
            while let Some(writer) = stdin.as_mut() {
                if written < input.len() {
                    match Pin::new(&mut *writer).poll_write(cx, &input[written..]) {
                        Poll::Ready(Ok(n)) => {
                            assert!(n > 0);
                            written += n;
                            continue;
                        }
                        Poll::Ready(Err(e)) => panic!("write: {e}"),
                        Poll::Pending => break,
                    }
                }
                match Pin::new(&mut *writer).poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => stdin = None,
                    Poll::Ready(Err(e)) => panic!("shutdown: {e}"),
                    Poll::Pending => break,
                }
            }
            loop {
                match read_some(&mut stdout, cx, &mut output) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(true),
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(e)) => panic!("read: {e}"),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }));
        assert!(eof);
        assert_eq!(written, input.len());
        assert!(output == input, "echo differs: {} bytes back", output.len());
        assert!(
            wakes > 0,
            "a 1 MiB exchange through a 64 KiB pipe must wait"
        );
        assert!(child.wait().expect("wait").success());
    }

    /// The first read finds nothing and returns at once; the child's output
    /// 300 ms later wakes the parked task. Stdout and stderr both arrive.
    fn late_output_wakes() {
        let mut child = spawn("late", false, true);
        let mut stdout = child.stdout().expect("stdout");
        let stderr = child.stderr().expect("stderr");
        let started = Instant::now();
        let waker = Waker::from(Arc::new(Parker {
            thread: thread::current(),
            wakes: AtomicUsize::new(0),
        }));
        let mut cx = Context::from_waker(&waker);
        let mut first = Vec::new();
        let poll = read_some(&mut stdout, &mut cx, &mut first);
        let returned = started.elapsed();
        assert!(poll.is_pending(), "nothing written yet: {poll:?}");
        assert!(
            returned < Duration::from_millis(100),
            "a read with no data must not block ({returned:?})"
        );
        let ((out, err), wakes) = block_on(async {
            let out = read_to_end(&mut stdout).await;
            let err = read_to_end(stderr).await;
            (out, err)
        });
        assert!(
            started.elapsed() >= LATE_FLOOR,
            "output came before the child wrote it"
        );
        assert!(wakes > 0, "the reader must have parked and been woken");
        assert!(out == pattern(LATE_STDOUT, 3), "stdout {} bytes", out.len());
        assert!(err == pattern(LATE_STDERR, 7), "stderr {} bytes", err.len());
        assert!(child.wait().expect("wait").success());
    }

    /// A read the child never answers is cancelled, not waited out, when
    /// its stream is dropped.
    fn dropping_pending_read() {
        let mut child = spawn("silent", false, false);
        let mut stdout = child.stdout().expect("stdout");
        let waker = Waker::from(Arc::new(Parker {
            thread: thread::current(),
            wakes: AtomicUsize::new(0),
        }));
        let mut cx = Context::from_waker(&waker);
        let mut out = Vec::new();
        assert!(read_some(&mut stdout, &mut cx, &mut out).is_pending());
        let started = Instant::now();
        drop(stdout);
        let dropped = started.elapsed();
        assert!(
            dropped < Duration::from_secs(1),
            "drop waited for the child ({dropped:?})"
        );
        child.kill().expect("kill");
        let _ = child.wait();
    }

    /// Bytes written to a child that has exited (and so closed its stdin)
    /// end in an error from the write or the flush, not a hang.
    fn write_after_exit() {
        let mut child = spawn("exit", true, false);
        let mut stdin = child.stdin().expect("stdin");
        assert!(child.wait().expect("wait").success());
        let input = pattern(4096, 9);
        let (result, _) = block_on(poll_fn(|cx| {
            for _ in 0..4 {
                match Pin::new(&mut stdin).poll_write(cx, &input) {
                    Poll::Ready(Ok(_)) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            Pin::new(&mut stdin).poll_flush(cx)
        }));
        let error = result.expect_err("the child's stdin is closed");
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe, "{error}");
    }
}
