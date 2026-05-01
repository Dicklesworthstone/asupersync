//! Regression tests for explicit TCP stream socket-option configuration.

use asupersync::net::tcp::traits::TcpStreamApi;
use asupersync::net::{TcpListener, TcpStream, TcpStreamBuilder};
use futures_lite::future::block_on;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

async fn connect_with_accept<F, Fut>(connect: F) -> TcpStream
where
    F: FnOnce(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<TcpStream>>,
{
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("get listener addr");
    let accept = thread::spawn(move || {
        block_on(listener.accept()).expect("accept connection");
    });

    let stream = connect(addr).await.expect("connect stream");
    accept.join().expect("accept thread should finish");
    stream
}

#[test]
fn direct_connect_and_empty_builder_use_the_same_nodelay_policy() {
    block_on(async {
        let direct = connect_with_accept(TcpStream::connect).await;
        let builder_default =
            connect_with_accept(|addr| TcpStreamBuilder::new(addr).connect()).await;

        assert_eq!(
            builder_default.nodelay().expect("get builder nodelay"),
            direct.nodelay().expect("get direct nodelay"),
            "empty TcpStreamBuilder must preserve TcpStream::connect socket-option policy"
        );
    });
}

#[test]
fn builder_nodelay_explicitly_overrides_default_policy() {
    block_on(async {
        let enabled =
            connect_with_accept(|addr| TcpStreamBuilder::new(addr).nodelay(true).connect()).await;
        assert!(
            enabled.nodelay().expect("get enabled nodelay"),
            "builder nodelay(true) should set TCP_NODELAY"
        );

        let disabled =
            connect_with_accept(|addr| TcpStreamBuilder::new(addr).nodelay(false).connect()).await;

        assert!(
            !disabled.nodelay().expect("get disabled nodelay"),
            "builder nodelay(false) should clear TCP_NODELAY"
        );
    });
}

#[test]
fn keepalive_configuration_is_explicit_and_non_sticky() {
    block_on(async {
        let stream = connect_with_accept(TcpStream::connect).await;
        stream
            .set_keepalive(Some(Duration::from_secs(30)))
            .expect("enable keepalive");
        stream.set_keepalive(None).expect("disable keepalive");

        let enabled = connect_with_accept(|addr| {
            TcpStreamBuilder::new(addr)
                .keepalive(Some(Duration::from_secs(60)))
                .connect()
        })
        .await;
        assert!(enabled.peer_addr().is_ok(), "enabled stream is connected");

        let disabled =
            connect_with_accept(|addr| TcpStreamBuilder::new(addr).keepalive(None).connect()).await;
        assert!(disabled.peer_addr().is_ok(), "disabled stream is connected");
    });
}
