//! Regression tests for shared `File` cursor semantics.

use crate::fs::File;
use crate::io::{AsyncRead, ReadBuf};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use tempfile::tempdir;

fn init_test(name: &str) {
    crate::test_utils::init_test_logging();
    crate::test_phase!(name);
}

fn poll_read_once(file: &mut File, output: &mut [u8]) -> io::Result<usize> {
    let mut read_buf = ReadBuf::new(output);
    let waker = Waker::noop().clone();
    let mut context = Context::from_waker(&waker);

    match Pin::new(file).poll_read(&mut context, &mut read_buf) {
        Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
        Poll::Ready(Err(error)) => Err(error),
        Poll::Pending => panic!("filesystem poll_read should not park in phase-0 sync mode"),
    }
}

#[test]
fn cloned_file_wrappers_share_cursor_state() {
    init_test("cloned_file_wrappers_share_cursor_state");
    let temp_dir = tempdir().unwrap();
    let file_path = temp_dir.path().join("concurrent_test");
    std::fs::write(&file_path, b"hello world test data").unwrap();

    let std_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .unwrap();
    let std_file_clone = std_file.try_clone().unwrap();
    let mut first = File::from_std(std_file);
    let mut second = File::from_std(std_file_clone);

    let mut first_chunk = [0u8; 5];
    let first_len = poll_read_once(&mut first, &mut first_chunk).unwrap();
    crate::assert_with_log!(first_len == 5, "first_len", 5, first_len);
    crate::assert_with_log!(
        first_chunk == *b"hello",
        "first_chunk",
        b"hello",
        first_chunk
    );

    let mut second_chunk = [0u8; 5];
    let second_len = poll_read_once(&mut second, &mut second_chunk).unwrap();
    crate::assert_with_log!(second_len == 5, "second_len", 5, second_len);
    crate::assert_with_log!(
        second_chunk == *b" worl",
        "second_chunk",
        b" worl",
        second_chunk
    );

    crate::test_complete!("cloned_file_wrappers_share_cursor_state");
}
