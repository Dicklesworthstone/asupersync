    use super::*;

    #[test]
    fn upload_names_cannot_escape_the_spool_or_alias_windows_devices() {
        for name in [
            "", ".", "..", "../file", "a/b", "a\\b", "C:foo", "NUL", "x.", "x ",
        ] {
            assert!(
                NativeUploadOptions::new("spool", name).validate().is_err(),
                "{name:?}"
            );
        }
        assert!(
            NativeUploadOptions::new("spool", "payload.bin")
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn bounded_reads_probe_only_one_byte_past_the_limit_without_overflow() {
        assert_eq!(read_window(65536, 0, 0), 1);
        assert_eq!(read_window(65536, 100, 99), 2);
        assert_eq!(read_window(65536, 100, 100), 1);
        assert_eq!(read_window(65536, u64::MAX, 0), 65536);
        assert_eq!(read_window(65536, u64::MAX, u64::MAX), 1);
        for limit in 0..128 {
            for written in 0..=limit {
                let window = read_window(17, limit, written);
                assert!((1..=17).contains(&window));
                assert!(window as u64 <= limit - written + 1);
            }
        }
    }

    #[test]
    fn buffer_reader_delivers_exact_prefixes_and_only_then_eof() {
        let mut reader = BufferReader(b"abcdefg");
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut output = Vec::new();
        loop {
            let mut bytes = [0u8; 3];
            let mut buf = ReadBuf::new(&mut bytes);
            assert!(matches!(
                Pin::new(&mut reader).poll_read(&mut cx, &mut buf),
                Poll::Ready(Ok(()))
            ));
            if buf.filled().is_empty() {
                break;
            }
            output.extend_from_slice(buf.filled());
        }
        assert_eq!(output, b"abcdefg");
    }
