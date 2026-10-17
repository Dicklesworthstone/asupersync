    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn builder_creates_with_defaults() {
        let builder = TcpListenerBuilder::new("127.0.0.1:0");
        assert_eq!(builder.backlog, None);
        assert!(!builder.reuse_addr);
        assert!(!builder.reuse_port);
    }

    #[test]
    fn builder_chain_works() {
        let builder = TcpListenerBuilder::new("127.0.0.1:0")
            .backlog(256)
            .reuse_addr(true)
            .reuse_port(true);

        assert_eq!(builder.backlog, Some(256));
        assert!(builder.reuse_addr);
        assert!(builder.reuse_port);
    }

    /// asupersync-7tg3di finding 6: `only_v6(false)` reaches the socket, like
    /// `only_v6(true)`. It used to be dropped, so the OS default stayed. On
    /// Linux that default is already dual-stack, so the old code passes here;
    /// the bug showed where the default is IPv6-only (Windows, FreeBSD). The
    /// wildcard address is the one where the option matters: binding a
    /// specific IPv6 address such as `[::1]` makes Linux set it. Only a host
    /// without IPv6 skips; where a plain `[::]` bind works, both requests must
    /// bind, so an option the builder fails to apply cannot pass as a skip.
    /// OpenBSD has no dual-stack sockets and refuses `false`.
    #[cfg(all(unix, not(target_os = "openbsd")))]
    #[test]
    fn only_v6_reaches_the_socket_in_both_directions() {
        futures_lite::future::block_on(async {
            if TcpListenerBuilder::new("[::]:0").bind().await.is_err() {
                // No IPv6 on this host.
                return;
            }
            for only_v6 in [true, false] {
                let listener = TcpListenerBuilder::new("[::]:0")
                    .only_v6(only_v6)
                    .bind()
                    .await
                    .unwrap_or_else(|error| panic!("bind [::]:0 with only_v6({only_v6}): {error}"));
                let socket = socket2::SockRef::from(&listener);
                assert_eq!(socket.only_v6().expect("IPV6_V6ONLY"), only_v6);
            }
        });
    }
