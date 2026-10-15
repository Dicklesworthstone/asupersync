//! Fuzz shared filesystem cursor behavior through the public `File` API.
//!
//! `std::fs::File::try_clone` handles share the underlying OS cursor. This
//! target creates several asupersync `File` wrappers from cloned standard
//! handles, interleaves read/write/seek polls across them, and checks those
//! polls against a single shared-cursor model. It keeps the original Arc/File
//! race seam covered without depending on private `File::inner` access.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::fs::File;
use asupersync::io::{AsyncRead, AsyncSeek, AsyncWrite, ReadBuf};
use libfuzzer_sys::fuzz_target;
use std::io::{self, SeekFrom};
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use tempfile::{TempDir, tempdir};

const MAX_HANDLES: usize = 8;
const MAX_INITIAL_LEN: usize = 4096;
const MAX_OPERATIONS: usize = 64;
const MAX_IO_LEN: usize = 1024;
const MAX_SEEK_ABS: u64 = 16_384;
const MAX_FILE_LEN: u64 = 32_768;

#[derive(Debug, Arbitrary)]
struct SharedFileCase {
    initial_len: u16,
    handle_count: u8,
    operations: Vec<FileOperation>,
}

#[derive(Debug, Clone, Arbitrary)]
struct FileOperation {
    handle: u8,
    action: FileAction,
}

#[derive(Debug, Clone, Arbitrary)]
enum FileAction {
    Read { len: u16 },
    Write { len: u16, byte: u8 },
    Seek { position: SeekPosition },
    Flush,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum SeekPosition {
    Start(u16),
    End(i16),
    Current(i16),
}

struct SharedFileHarness {
    _temp_dir: TempDir,
    files: Vec<File>,
}

#[derive(Debug, Clone)]
struct SharedCursorModel {
    len: u64,
    cursor: u64,
}

impl SharedCursorModel {
    fn new(len: u64) -> Self {
        Self { len, cursor: 0 }
    }

    fn observe_read(&mut self, requested: usize, actual: usize) {
        let available = self.len.saturating_sub(self.cursor) as usize;
        let expected = requested.min(available);
        assert_eq!(
            actual, expected,
            "shared file cursor read length diverged from model"
        );
        self.cursor = self.cursor.saturating_add(actual as u64);
    }

    fn observe_write(&mut self, requested: usize, actual: usize) {
        assert!(
            actual <= requested,
            "file poll_write returned more bytes than requested"
        );
        self.cursor = self.cursor.saturating_add(actual as u64);
        self.len = self.len.max(self.cursor);
        assert!(
            self.len <= MAX_FILE_LEN + MAX_IO_LEN as u64,
            "fuzz file grew past bounded model length"
        );
    }

    fn expected_seek(&self, position: SeekPosition) -> Result<u64, ()> {
        let next = match position {
            SeekPosition::Start(pos) => i128::from(u64::from(pos).min(MAX_SEEK_ABS)),
            SeekPosition::End(offset) => i128::from(self.len) + i128::from(offset),
            SeekPosition::Current(offset) => i128::from(self.cursor) + i128::from(offset),
        };

        if next < 0 {
            Err(())
        } else {
            Ok(u64::try_from(next).expect("non-negative seek target should fit u64"))
        }
    }

    fn observe_seek(&mut self, position: SeekPosition, result: io::Result<u64>) {
        match (self.expected_seek(position), result) {
            (Ok(expected), Ok(actual)) => {
                assert_eq!(actual, expected, "shared file seek position diverged");
                self.cursor = actual;
            }
            (Err(()), Err(_)) => {}
            (Err(()), Ok(actual)) => {
                panic!("negative seek unexpectedly succeeded at position {actual}");
            }
            (Ok(expected), Err(error)) => {
                panic!("valid seek to {expected} unexpectedly failed: {error}");
            }
        }
    }
}

fuzz_target!(|case: SharedFileCase| {
    let initial_len = usize::from(case.initial_len).min(MAX_INITIAL_LEN);
    let handle_count = usize::from(case.handle_count.clamp(1, MAX_HANDLES as u8));
    let mut harness = match create_shared_files(initial_len, handle_count) {
        Ok(harness) => harness,
        Err(_) => return,
    };
    let files = &mut harness.files;
    let mut model = SharedCursorModel::new(initial_len as u64);

    if case.operations.is_empty() {
        let actual = poll_read_once(&mut files[0], 1).expect("empty-case read should succeed");
        model.observe_read(1, actual);
    }

    for operation in case.operations.iter().take(MAX_OPERATIONS) {
        let handle = usize::from(operation.handle) % files.len();
        match operation.action {
            FileAction::Read { len } => {
                let requested = usize::from(len).min(MAX_IO_LEN);
                let actual = poll_read_once(&mut files[handle], requested)
                    .expect("poll_read on fuzz file should succeed");
                model.observe_read(requested, actual);
            }
            FileAction::Write { len, byte } => {
                let requested = usize::from(len).min(MAX_IO_LEN);
                let actual = poll_write_once(&mut files[handle], requested, byte)
                    .expect("poll_write on fuzz file should succeed");
                model.observe_write(requested, actual);
            }
            FileAction::Seek { position } => {
                let result = poll_seek_once(&mut files[handle], position);
                model.observe_seek(position, result);
            }
            FileAction::Flush => {
                poll_flush_once(&mut files[handle]).expect("poll_flush should succeed");
            }
        }
    }

    for file in files {
        poll_flush_once(file).expect("final poll_flush should succeed");
    }
});

fn create_shared_files(initial_len: usize, handle_count: usize) -> io::Result<SharedFileHarness> {
    let temp_dir = tempdir()?;
    let file_path = temp_dir.path().join("shared_cursor_fuzz.bin");
    let initial_content: Vec<u8> = (0..initial_len)
        .map(|index| u8::try_from(index % 251).expect("bounded byte"))
        .collect();
    std::fs::write(&file_path, initial_content)?;

    let base = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)?;
    let mut files = Vec::with_capacity(handle_count);
    for _ in 0..handle_count {
        files.push(File::from_std(base.try_clone()?));
    }

    Ok(SharedFileHarness {
        _temp_dir: temp_dir,
        files,
    })
}

fn poll_read_once(file: &mut File, requested: usize) -> io::Result<usize> {
    let mut buffer = vec![0u8; requested];
    let mut read_buf = ReadBuf::new(&mut buffer);
    let waker = Waker::noop().clone();
    let mut context = Context::from_waker(&waker);

    match Pin::new(file).poll_read(&mut context, &mut read_buf) {
        Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
        Poll::Ready(Err(error)) => Err(error),
        Poll::Pending => panic!("phase-0 file poll_read should not park"),
    }
}

fn poll_write_once(file: &mut File, requested: usize, byte: u8) -> io::Result<usize> {
    let data = vec![byte; requested];
    let waker = Waker::noop().clone();
    let mut context = Context::from_waker(&waker);

    match Pin::new(file).poll_write(&mut context, &data) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("phase-0 file poll_write should not park"),
    }
}

fn poll_seek_once(file: &mut File, position: SeekPosition) -> io::Result<u64> {
    let seek_from = match position {
        SeekPosition::Start(pos) => SeekFrom::Start(u64::from(pos).min(MAX_SEEK_ABS)),
        SeekPosition::End(offset) => SeekFrom::End(i64::from(offset)),
        SeekPosition::Current(offset) => SeekFrom::Current(i64::from(offset)),
    };
    let waker = Waker::noop().clone();
    let mut context = Context::from_waker(&waker);

    match Pin::new(file).poll_seek(&mut context, seek_from) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("phase-0 file poll_seek should not park"),
    }
}

fn poll_flush_once(file: &mut File) -> io::Result<()> {
    let waker = Waker::noop().clone();
    let mut context = Context::from_waker(&waker);

    match Pin::new(file).poll_flush(&mut context) {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("phase-0 file poll_flush should not park"),
    }
}
