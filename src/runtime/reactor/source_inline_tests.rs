    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::test_utils::init_test_logging;

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn source_id_generates_unique_ids() {
        init_test("source_id_generates_unique_ids");
        let id1 = next_source_id();
        let id2 = next_source_id();
        let id3 = next_source_id();

        crate::assert_with_log!(id1 != id2, "id1 != id2", true, id1 != id2);
        crate::assert_with_log!(id2 != id3, "id2 != id3", true, id2 != id3);
        crate::assert_with_log!(id1 != id3, "id1 != id3", true, id1 != id3);

        // IDs should be monotonically increasing
        crate::assert_with_log!(id1 < id2, "id1 < id2", true, id1 < id2);
        crate::assert_with_log!(id2 < id3, "id2 < id3", true, id2 < id3);
        crate::test_complete!("source_id_generates_unique_ids");
    }

    #[test]
    #[should_panic(expected = "source ID counter overflow")]
    fn source_id_overflow_panics() {
        init_test("source_id_overflow_panics");
        let counter = AtomicU64::new(u64::MAX);
        let _ = next_source_id_from(&counter);
    }

    #[cfg(unix)]
    mod unix_tests {
        use super::*;
        use std::os::unix::io::AsRawFd;
        use std::os::unix::net::UnixStream;

        fn accepts_source<T: Source>(_: &T) {}

        #[test]
        fn source_wrapper_with_pipe() {
            super::init_test("source_wrapper_with_pipe");
            // Use a real unix stream which is Send + Sync
            let (sock1, _sock2) = UnixStream::pair().expect("failed to create unix stream pair");
            let fd = sock1.as_raw_fd();
            let wrapper = SourceWrapper::new(sock1);

            crate::assert_with_log!(
                wrapper.as_raw_fd() == fd,
                "wrapper raw fd",
                fd,
                wrapper.as_raw_fd()
            );
            crate::assert_with_log!(
                wrapper.source_id() > 0,
                "source id nonzero",
                true,
                wrapper.source_id() > 0
            );
            crate::test_complete!("source_wrapper_with_pipe");
        }

        #[test]
        fn source_wrapper_has_unique_ids() {
            super::init_test("source_wrapper_has_unique_ids");
            let (sock1, sock2) = UnixStream::pair().expect("failed to create unix stream pair");
            let wrapper1 = SourceWrapper::new(sock1);
            let wrapper2 = SourceWrapper::new(sock2);

            crate::assert_with_log!(
                wrapper1.source_id() != wrapper2.source_id(),
                "unique ids",
                true,
                wrapper1.source_id() != wrapper2.source_id()
            );
            crate::test_complete!("source_wrapper_has_unique_ids");
        }

        #[test]
        fn source_wrapper_with_custom_id() {
            super::init_test("source_wrapper_with_custom_id");
            let (sock, _) = UnixStream::pair().expect("failed to create unix stream pair");
            let wrapper = SourceWrapper::with_id(sock, 12345);

            crate::assert_with_log!(
                wrapper.source_id() == 12345,
                "custom id",
                12345u64,
                wrapper.source_id()
            );
            crate::test_complete!("source_wrapper_with_custom_id");
        }

        #[test]
        fn source_wrapper_into_inner() {
            super::init_test("source_wrapper_into_inner");
            let (sock, _) = UnixStream::pair().expect("failed to create unix stream pair");
            let expected_fd = sock.as_raw_fd();
            let wrapper = SourceWrapper::new(sock);
            let recovered = wrapper.into_inner();

            crate::assert_with_log!(
                recovered.as_raw_fd() == expected_fd,
                "into_inner returns socket",
                expected_fd,
                recovered.as_raw_fd()
            );
            crate::test_complete!("source_wrapper_into_inner");
        }

        #[test]
        fn source_wrapper_get_ref() {
            super::init_test("source_wrapper_get_ref");
            let (sock, _) = UnixStream::pair().expect("failed to create unix stream pair");
            let expected_fd = sock.as_raw_fd();
            let wrapper = SourceWrapper::new(sock);

            crate::assert_with_log!(
                wrapper.get_ref().as_raw_fd() == expected_fd,
                "get_ref returns inner",
                expected_fd,
                wrapper.get_ref().as_raw_fd()
            );
            crate::test_complete!("source_wrapper_get_ref");
        }

        #[test]
        fn unix_stream_implements_source() {
            super::init_test("unix_stream_implements_source");
            let (sock, _) = UnixStream::pair().expect("failed to create unix stream pair");

            // UnixStream should implement Source automatically
            accepts_source(&sock);

            let fd = sock.as_raw_fd();
            crate::assert_with_log!(fd >= 0, "raw fd valid", true, fd >= 0);
            crate::test_complete!("unix_stream_implements_source");
        }

        #[test]
        fn source_wrapper_implements_source() {
            super::init_test("source_wrapper_implements_source");
            let (sock, _) = UnixStream::pair().expect("failed to create unix stream pair");
            let wrapper = SourceWrapper::new(sock);

            // SourceWrapper should implement Source
            accepts_source(&wrapper);

            let fd = wrapper.as_raw_fd();
            crate::assert_with_log!(fd >= 0, "wrapper raw fd valid", true, fd >= 0);
            crate::test_complete!("source_wrapper_implements_source");
        }

        #[test]
        fn source_as_trait_object() {
            super::init_test("source_as_trait_object");
            let (sock, _) = UnixStream::pair().expect("failed to create unix stream pair");
            let expected_fd = sock.as_raw_fd();
            let source: &dyn Source = &sock;

            crate::assert_with_log!(
                source.as_raw_fd() == expected_fd,
                "trait object raw fd",
                expected_fd,
                source.as_raw_fd()
            );
            crate::test_complete!("source_as_trait_object");
        }
    }

    #[cfg(windows)]
    mod windows_tests {
        use super::*;
        use std::net::TcpListener;
        use std::os::windows::io::AsRawSocket;

        #[test]
        fn source_wrapper_with_tcp_listener() {
            super::init_test("source_wrapper_with_tcp_listener");
            let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
            let socket = listener.as_raw_socket();
            let wrapper = SourceWrapper::new(listener);

            crate::assert_with_log!(
                wrapper.as_raw_socket() == socket,
                "wrapper raw socket",
                socket,
                wrapper.as_raw_socket()
            );
            crate::assert_with_log!(
                wrapper.source_id() > 0,
                "source id nonzero",
                true,
                wrapper.source_id() > 0
            );
            crate::test_complete!("source_wrapper_with_tcp_listener");
        }

        #[test]
        fn source_wrapper_has_unique_ids() {
            super::init_test("source_wrapper_has_unique_ids");
            let listener1 = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
            let listener2 = TcpListener::bind("127.0.0.1:0").expect("failed to bind");

            let wrapper1 = SourceWrapper::new(listener1);
            let wrapper2 = SourceWrapper::new(listener2);

            crate::assert_with_log!(
                wrapper1.source_id() != wrapper2.source_id(),
                "unique ids",
                true,
                wrapper1.source_id() != wrapper2.source_id()
            );
            crate::test_complete!("source_wrapper_has_unique_ids");
        }

        #[test]
        fn source_wrapper_with_custom_id() {
            super::init_test("source_wrapper_with_custom_id");
            let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");
            let wrapper = SourceWrapper::with_id(listener, 12345);

            crate::assert_with_log!(
                wrapper.source_id() == 12345,
                "custom id",
                12345u64,
                wrapper.source_id()
            );
            crate::test_complete!("source_wrapper_with_custom_id");
        }

        #[test]
        fn tcp_listener_implements_source() {
            super::init_test("tcp_listener_implements_source");
            let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind");

            fn accepts_source<T: Source>(_: &T) {}
            accepts_source(&listener);

            let socket = listener.as_raw_socket();
            crate::assert_with_log!(socket != 0, "raw socket valid", true, socket != 0);
            crate::test_complete!("tcp_listener_implements_source");
        }
    }
