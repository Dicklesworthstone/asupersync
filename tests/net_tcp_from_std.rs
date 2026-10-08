//! `TcpListener::from_std` and `TcpStream::try_from` adopt standard-library
//! sockets (a listener inherited through systemd socket activation, or one
//! configured with `socket2` before `listen`), and both types expose their raw
//! socket so options this API does not cover can be set through `socket2`.

use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::RuntimeBuilder;

#[test]
fn adopted_std_sockets_carry_traffic_and_expose_their_raw_socket() {
    // A blocking std listener, as an inherited or pre-configured socket is.
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind std listener");
    let address = std_listener.local_addr().expect("listener address");
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("build runtime");
    runtime.block_on(async move {
        let listener = TcpListener::from_std(std_listener).expect("adopt listener");
        assert_eq!(listener.local_addr().expect("local address"), address);

        let std_client = std::net::TcpStream::connect(address).expect("connect std client");
        let mut client = TcpStream::try_from(std_client).expect("adopt stream");
        let (mut server, peer) = listener.accept().await.expect("accept");
        assert_eq!(peer, client.local_addr().expect("client address"));

        client.write_all(b"ping").await.expect("client write");
        let mut buf = [0_u8; 4];
        server.read_exact(&mut buf).await.expect("server read");
        assert_eq!(&buf, b"ping");
        server.write_all(b"pong").await.expect("server write");
        client.read_exact(&mut buf).await.expect("client read");
        assert_eq!(&buf, b"pong");

        // Options outside this API go through the raw socket.
        let client_socket = socket2::SockRef::from(&client);
        client_socket
            .set_recv_buffer_size(64 * 1024)
            .expect("set SO_RCVBUF");
        assert!(client_socket.recv_buffer_size().expect("SO_RCVBUF") >= 64 * 1024);
        let listener_socket = socket2::SockRef::from(&listener);
        assert_eq!(
            listener_socket
                .local_addr()
                .expect("listener sockaddr")
                .as_socket(),
            Some(address)
        );
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            assert_ne!(client.as_raw_fd(), listener.as_raw_fd());
        }
    });
}
