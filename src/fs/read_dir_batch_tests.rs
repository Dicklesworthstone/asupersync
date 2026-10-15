//! Regression tests for bounded directory prefetch and cancel-safe iteration.

use super::*;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Waker;

fn make_files(root: &Path, count: usize) -> Vec<OsString> {
    (0..count)
        .map(|index| {
            let name = OsString::from(format!("{index:04}.txt"));
            std::fs::write(root.join(&name), b"payload").unwrap();
            name
        })
        .collect()
}

fn delayed_reader(root: &Path) -> (ReadDir, Arc<AtomicUsize>) {
    let inner = std::fs::read_dir(root).unwrap();
    let mut result = Some(read_dir_batch(
        inner,
        VecDeque::with_capacity(READ_DIR_BATCH_SIZE),
    ));
    let polls = Arc::new(AtomicUsize::new(0));
    let future_polls = Arc::clone(&polls);
    let future = std::future::poll_fn(move |cx| {
        if future_polls.fetch_add(1, Ordering::SeqCst) == 0 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(Ok(result.take().expect("completed batch polled twice")))
        }
    });
    (
        ReadDir {
            state: ReadDirState::Pending(Box::pin(future)),
            buffered: VecDeque::new(),
        },
        polls,
    )
}

async fn collect_names(entries: &mut ReadDir) -> Vec<OsString> {
    let mut names = Vec::new();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        names.push(entry.file_name());
    }
    names.sort();
    names
}

#[test]
fn batch_stops_at_limit_without_consuming_the_next_item() {
    let mut source = (0..3 * READ_DIR_BATCH_SIZE).map(Ok::<usize, io::Error>);
    let (batch, exhausted) = read_batch(&mut source, VecDeque::new());
    assert!(!exhausted);
    assert_eq!(batch.len(), READ_DIR_BATCH_SIZE);
    assert_eq!(
        batch.into_iter().collect::<io::Result<Vec<_>>>().unwrap(),
        (0..READ_DIR_BATCH_SIZE).collect::<Vec<_>>()
    );
    assert_eq!(source.next().unwrap().unwrap(), READ_DIR_BATCH_SIZE);
}

#[test]
fn batch_preserves_error_position_and_allows_later_entries() {
    let mut source = vec![
        Ok(10),
        Ok(20),
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "entry error")),
        Ok(30),
    ]
    .into_iter();
    let (mut batch, exhausted) = read_batch(&mut source, VecDeque::new());
    assert!(!exhausted, "an entry error is not EOF");
    assert_eq!(batch.pop_front().unwrap().unwrap(), 10);
    assert_eq!(batch.pop_front().unwrap().unwrap(), 20);
    assert_eq!(
        batch.pop_front().unwrap().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(batch.is_empty());
    let (mut batch, exhausted) = read_batch(&mut source, batch);
    assert!(exhausted);
    assert_eq!(batch.pop_front().unwrap().unwrap(), 30);
    assert!(batch.is_empty());
}

#[test]
fn exact_full_batch_requires_a_real_eof_observation() {
    let mut source = (0..READ_DIR_BATCH_SIZE).map(Ok::<usize, io::Error>);
    let (mut batch, exhausted) = read_batch(&mut source, VecDeque::new());
    assert!(!exhausted);
    assert_eq!(batch.len(), READ_DIR_BATCH_SIZE);
    let capacity = batch.capacity();
    batch.clear();
    let (batch, exhausted) = read_batch(&mut source, batch);
    assert!(exhausted);
    assert!(batch.is_empty());
    assert_eq!(batch.capacity(), capacity);
}

#[test]
fn real_directory_boundaries_preserve_every_entry_and_cached_readiness() {
    for count in [0, 1, 31, 32, 33, 65, 103] {
        let root = tempfile::tempdir().unwrap();
        let expected = make_files(root.path(), count);
        let mut entries = futures_lite::future::block_on(read_dir(root.path())).unwrap();
        assert_eq!(entries.buffered.len(), count.min(READ_DIR_BATCH_SIZE));
        let mut names = Vec::new();
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..count.min(READ_DIR_BATCH_SIZE) {
            match Pin::new(&mut entries).poll_next(&mut cx) {
                Poll::Ready(Some(Ok(entry))) => names.push(entry.file_name()),
                other => panic!("cached entry should be immediately ready: {other:?}"),
            }
        }
        assert!(entries.buffered.is_empty());
        names.extend(futures_lite::future::block_on(collect_names(&mut entries)));
        names.sort();
        assert_eq!(names, expected, "count={count}");
        assert!(matches!(Pin::new(&mut entries).poll_next(&mut cx), Poll::Ready(None)));
        assert!(matches!(Pin::new(&mut entries).poll_next(&mut cx), Poll::Ready(None)));
    }
}

#[test]
fn dropped_pending_next_entry_retains_batch_and_remaining_directory() {
    let root = tempfile::tempdir().unwrap();
    let expected = make_files(root.path(), READ_DIR_BATCH_SIZE + 3);
    let (mut entries, polls) = delayed_reader(root.path());
    let mut cx = Context::from_waker(Waker::noop());
    {
        let mut next = Box::pin(entries.next_entry());
        assert!(next.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert!(matches!(&entries.state, ReadDirState::Pending(_)));
    let names = futures_lite::future::block_on(collect_names(&mut entries));
    assert_eq!(names, expected);
    assert_eq!(polls.load(Ordering::SeqCst), 2);
}

#[test]
fn restricted_caller_cannot_consume_or_discard_prefetched_entries() {
    let root = tempfile::tempdir().unwrap();
    let expected = make_files(root.path(), 3);
    let mut entries = futures_lite::future::block_on(read_dir(root.path())).unwrap();
    let cx = crate::cx::Cx::for_testing().restrict::<crate::cx::cap::None>();
    let error = futures_lite::future::block_on(cx.with_ambient(entries.next_entry()))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(
        error
            .get_ref()
            .and_then(|error| error.downcast_ref::<crate::cx::IoCapabilityDenied>())
            .is_some()
    );
    assert_eq!(entries.buffered.len(), 3);
    assert_eq!(
        futures_lite::future::block_on(collect_names(&mut entries)),
        expected
    );
    assert!(
        futures_lite::future::block_on(cx.with_ambient(entries.next_entry()))
            .unwrap()
            .is_none(),
        "completed iterators remain at EOF without doing I/O"
    );
}

#[test]
fn restriction_does_not_poll_or_drop_an_owned_pending_batch() {
    let root = tempfile::tempdir().unwrap();
    let expected = make_files(root.path(), 3);
    let (mut entries, polls) = delayed_reader(root.path());
    let cx = crate::cx::Cx::for_testing().restrict::<crate::cx::cap::None>();
    let error = futures_lite::future::block_on(cx.with_ambient(entries.next_entry()))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert!(matches!(&entries.state, ReadDirState::Pending(_)));
    assert_eq!(
        futures_lite::future::block_on(collect_names(&mut entries)),
        expected
    );
    assert_eq!(polls.load(Ordering::SeqCst), 2);
}

#[test]
fn blocking_job_failure_is_reported_once_then_iteration_finishes() {
    let mut entries = ReadDir {
        state: ReadDirState::Pending(Box::pin(async {
            Err(io::Error::other("injected blocking job failure"))
        })),
        buffered: VecDeque::new(),
    };
    let error = futures_lite::future::block_on(entries.next_entry()).unwrap_err();
    assert!(error.to_string().contains("injected blocking job failure"));
    assert!(futures_lite::future::block_on(entries.next_entry()).unwrap().is_none());
    assert!(futures_lite::future::block_on(entries.next_entry()).unwrap().is_none());
}

#[test]
fn invalid_directory_open_still_fails_before_returning_an_iterator() {
    let root = tempfile::tempdir().unwrap();
    let error = futures_lite::future::block_on(read_dir(root.path().join("missing")))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    let file = root.path().join("file");
    std::fs::write(&file, b"not a directory").unwrap();
    assert!(futures_lite::future::block_on(read_dir(&file)).is_err());
}
