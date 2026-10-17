    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_shutdown_write_golden() {
        init_test("test_shutdown_write_golden");
        let tester = HalfCloseGoldenTester::new();

        let result = tester
            .test_shutdown_write_sends_fin("shutdown_write")
            .expect("shutdown write test should succeed");

        // Golden: shutdown(Write) should prevent local writes, allow reads, trigger peer EOF
        tester.assert_half_close_golden(
            &result,
            "shutdown_write",
            "op:shutdown_write,eof:true,read:true,write:false,err:none",
        );

        crate::test_complete!("test_shutdown_write_golden");
    }

    #[test]
    fn test_shutdown_read_golden() {
        init_test("test_shutdown_read_golden");
        let tester = HalfCloseGoldenTester::new();

        let result = tester
            .test_shutdown_read_discards_data("shutdown_read")
            .expect("shutdown read test should succeed");

        // Golden: shutdown(Read) on Linux marks the socket so empty-buffer
        // reads return EOF, but data the peer has already buffered (or
        // writes after our shutdown) is still delivered — POSIX leaves
        // this implementation-defined and Linux's tcp_recvmsg() only
        // honors RCV_SHUTDOWN when the receive queue is empty. Pin the
        // observed behavior so a kernel/runtime change in either
        // direction (stricter discard or peer write rejection) trips
        // the golden and forces explicit reviewer acknowledgment.
        #[cfg(target_os = "linux")]
        let expected = "op:shutdown_read,eof:false,read:true,write:true,err:shutdown(Read) still allowed local reads";
        // Darwin: shutdown(SHUT_RD) also fails the local write in this
        // probe (observed on macOS 26.2 arm64, br-asupersync-bi2462.21);
        // recorded as its own golden so a change in either direction trips it.
        #[cfg(target_os = "macos")]
        let expected = "op:shutdown_read,eof:false,read:false,write:false,err:none";
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let expected = "op:shutdown_read,eof:false,read:false,write:true,err:none";
        tester.assert_half_close_golden(&result, "shutdown_read", expected);

        crate::test_complete!("test_shutdown_read_golden");
    }

    #[test]
    fn test_shutdown_both_golden() {
        init_test("test_shutdown_both_golden");
        let tester = HalfCloseGoldenTester::new();

        let result = tester
            .test_shutdown_both_equals_close("shutdown_both")
            .expect("shutdown both test should succeed");

        // Golden: shutdown(Both) should behave identically to close()
        tester.assert_half_close_golden(
            &result,
            "shutdown_both",
            "op:shutdown_both,eof:true,read:false,write:false,err:none",
        );

        crate::test_complete!("test_shutdown_both_golden");
    }

    #[test]
    fn test_peer_half_close_eof_golden() {
        init_test("test_peer_half_close_eof_golden");
        let tester = HalfCloseGoldenTester::new();

        let result = tester
            .test_peer_initiated_half_close_eof("peer_half_close")
            .expect("peer half close test should succeed");

        // Golden: peer shutdown(Write) should be observable as EOF on local read
        tester.assert_half_close_golden(
            &result,
            "peer_half_close",
            "op:peer_half_close,eof:true,read:true,write:true,err:none",
        );

        crate::test_complete!("test_peer_half_close_eof_golden");
    }
