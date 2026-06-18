//! Loopback UDP send-batch benchmark for the send_to loop versus native sendmmsg/GSO.

use asupersync::net::{UdpOutboundDatagram, UdpSocket};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures_lite::future;

const PACKETS_PER_BATCH: usize = 64;
const PAYLOAD_BYTES: usize = 1200;

fn payloads() -> Vec<Vec<u8>> {
    (0..PACKETS_PER_BATCH)
        .map(|packet| vec![packet as u8; PAYLOAD_BYTES])
        .collect()
}

fn send_and_drain(payloads: &[Vec<u8>], connected_sender: bool) {
    future::block_on(async {
        let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if connected_sender {
            sender.connect(receiver_addr).await.unwrap();
        }

        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: receiver_addr,
                payload,
            })
            .collect::<Vec<_>>();
        let report = sender.send_batch_to(&packets).await.unwrap();
        assert_eq!(report.packets_processed, PACKETS_PER_BATCH);

        let mut received = 0usize;
        while received < PACKETS_PER_BATCH {
            let batch = receiver
                .recv_batch_from(PACKETS_PER_BATCH - received, PAYLOAD_BYTES)
                .await
                .unwrap();
            received += batch.report.packets_processed;
        }
    });
}

fn bench_udp_send_batch(c: &mut Criterion) {
    let payloads = payloads();
    let mut group = c.benchmark_group("udp_send_batch_loopback");
    group.throughput(Throughput::Bytes(
        (PACKETS_PER_BATCH * PAYLOAD_BYTES) as u64,
    ));

    group.bench_with_input(
        BenchmarkId::new("portable_send_to_loop", PACKETS_PER_BATCH),
        &false,
        |b, connected_sender| b.iter(|| send_and_drain(&payloads, *connected_sender)),
    );
    group.bench_with_input(
        BenchmarkId::new("native_sendmmsg_gso", PACKETS_PER_BATCH),
        &true,
        |b, connected_sender| b.iter(|| send_and_drain(&payloads, *connected_sender)),
    );

    group.finish();
}

criterion_group!(benches, bench_udp_send_batch);
criterion_main!(benches);
