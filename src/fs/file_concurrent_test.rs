//! Validation test for Arc<File> concurrent access vulnerability
#[cfg(test)]
mod concurrent_access_validation {
    use crate::fs::File;
    use crate::io::{AsyncRead, ReadBuf};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};
    use tempfile::tempdir;

    // Mock waker for testing poll operations
    fn mock_waker() -> Waker {
        use std::task::{RawWaker, RawWakerVTable};

        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }

        const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let raw_waker = RawWaker::new(std::ptr::null(), &VTABLE);
        unsafe { Waker::from_raw(raw_waker) }
    }

    #[test]
    fn test_arc_file_concurrent_approach() {
        // Create a test file
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("concurrent_test");
        std::fs::write(&file_path, b"hello world test data").unwrap();

        // Create Arc<File> for sharing
        let std_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file_path)
            .unwrap();
        let file = File::from_std(std_file);
        let arc_file = Arc::new(file);

        // Simulate concurrent access (sequentially for testing)
        let file1 = Arc::clone(&arc_file);
        let file2 = Arc::clone(&arc_file);

        // Task 1: Read
        let mut buffer1 = vec![0u8; 10];
        let mut read_buf1 = ReadBuf::new(&mut buffer1);
        let waker1 = mock_waker();
        let mut context1 = Context::from_waker(&waker1);
        let mut file1_pin = Pin::new(file1.as_ref());

        let result1 = file1_pin.as_mut().poll_read(&mut context1, &mut read_buf1);
        assert!(matches!(result1, Poll::Ready(Ok(()))));

        // Task 2: Another read (would race in real concurrent scenario)
        let mut buffer2 = vec![0u8; 10];
        let mut read_buf2 = ReadBuf::new(&mut buffer2);
        let waker2 = mock_waker();
        let mut context2 = Context::from_waker(&waker2);
        let mut file2_pin = Pin::new(file2.as_ref());

        let result2 = file2_pin.as_mut().poll_read(&mut context2, &mut read_buf2);
        assert!(matches!(result2, Poll::Ready(Ok(()))));

        // Both succeeded - this demonstrates the shared Arc access pattern
        // In a real concurrent scenario with multiple threads, this would race
        println!("Arc<File> sharing works: {} bytes, {} bytes",
                 read_buf1.filled().len(), read_buf2.filled().len());
    }
}