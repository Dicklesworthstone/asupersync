//! Loopback smoke proof for the SWIM membership UDP adapter (bead
//! `asupersync-dist-otp-completeness-8y37kz.4.4`, AC2).
//!
//! Binds two `UdpMembershipTransport`s on loopback, sends a membership packet
//! (a probe plus piggybacked gossip) from one to the other, and asserts it
//! arrives byte-for-byte equal after the wire round-trip. Support-class scoped:
//! a best-effort loopback datagram, no production WAN claim.
//!
//! Run with: `cargo test --test swim_udp_loopback_proof --features test-internals`.

#![allow(missing_docs)]

use asupersync::cx::Cx;
use asupersync::distributed::membership::{Packet, Payload, Rumor, UdpMembershipTransport};
use asupersync::net::UdpSocket;
use asupersync::remote::NodeId;
use asupersync::runtime::RuntimeBuilder;

#[test]
fn membership_packet_round_trips_over_loopback_udp() {
    let runtime = RuntimeBuilder::multi_thread().build().expect("runtime");
    let outcome: Result<(), String> = runtime.block_on(runtime.handle().spawn(async {
        let _cx = Cx::current().expect("cx");

        let sender_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("bind sender: {e}"))?;
        let receiver_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("bind receiver: {e}"))?;

        let mut sender = UdpMembershipTransport::new(sender_socket);
        let mut receiver = UdpMembershipTransport::new(receiver_socket);

        let sender_addr = sender
            .local_addr()
            .map_err(|e| format!("sender addr: {e}"))?;
        let receiver_addr = receiver
            .local_addr()
            .map_err(|e| format!("receiver addr: {e}"))?;

        let packet = Packet {
            payload: Payload::PingReq {
                seq: 42,
                target: NodeId::new("target-node"),
            },
            gossip: vec![
                Rumor::alive(NodeId::new("a"), 1),
                Rumor::suspect(NodeId::new("b"), 3, NodeId::new("c")),
                Rumor::confirm(NodeId::new("d"), 5, NodeId::new("e")),
            ],
        };

        let encoded = sender
            .send(receiver_addr, &packet)
            .await
            .map_err(|e| format!("send: {e}"))?;
        if encoded.gossip_dropped != 0 {
            return Err(format!(
                "gossip unexpectedly dropped: {}",
                encoded.gossip_dropped
            ));
        }

        let (from, received) = receiver.recv().await.map_err(|e| format!("recv: {e}"))?;
        if received != packet {
            return Err("received packet differs from sent packet".to_string());
        }
        if from != sender_addr {
            return Err(format!("source addr {from} != sender {sender_addr}"));
        }
        Ok(())
    }));

    outcome.expect("loopback round-trip succeeds");
}
