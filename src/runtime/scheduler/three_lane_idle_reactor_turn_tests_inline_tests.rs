    use super::*;
    use crate::io::{AsyncReadExt, AsyncWriteExt};
    use crate::net::{TcpListener, TcpStream};
    use crate::runtime::RuntimeBuilder;

    /// br-asupersync-issue65-criticisms-kpmoy5.1.11: on a one-worker runtime
    /// every socket wake is raised while that worker, with nothing else to
    /// run, drives the reactor. Those wakes are kept for it (no parker unpark,
    /// no reactor re-arm), and every round trip of the echo exchange is still
    /// answered, so no kept wake was lost.
    #[test]
    fn idle_reactor_leader_keeps_its_own_socket_wakes() {
        let before = IDLE_TURN_KEPT_WAKES.load(Ordering::Relaxed);
        let rt = RuntimeBuilder::new()
            .worker_threads(1)
            .build()
            .expect("one-worker runtime");
        let answered = rt.block_on(rt.handle().spawn(async move {
            let cx = crate::Cx::current().expect("a spawned task has a Cx");
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("listener address");
            let mut server = cx
                .spawn(move |_| async move {
                    let (mut stream, _) = listener.accept().await.expect("accept");
                    let mut buf = [0u8; 8];
                    while stream.read_exact(&mut buf).await.is_ok() {
                        if stream.write_all(&buf).await.is_err() {
                            break;
                        }
                    }
                })
                .expect("spawn the echo server");
            let mut client = TcpStream::connect(addr).await.expect("connect");
            let mut buf = [7u8; 8];
            let mut answered = 0usize;
            for _ in 0..50 {
                client.write_all(&buf).await.expect("request");
                client.read_exact(&mut buf).await.expect("response");
                answered += 1;
            }
            drop(client);
            let _ = server.join(&cx).await;
            answered
        }));
        assert_eq!(answered, 50, "every round trip is answered");
        let kept = IDLE_TURN_KEPT_WAKES.load(Ordering::Relaxed) - before;
        assert!(
            kept > 0,
            "the idle reactor leader kept none of its socket wakes"
        );
    }
