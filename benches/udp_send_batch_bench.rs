//! Loopback UDP send-batch benchmark for the send_to loop, sendmmsg, and GSO.

use asupersync::net::{UdpOutboundDatagram, UdpSendBatchStrategy, UdpSocket};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures_lite::future;

const PACKETS_PER_BATCH: usize = 64;
const PAYLOAD_BYTES: usize = 1424;

#[derive(Debug, Clone, Copy)]
enum SendBatchBenchCase {
    PortableLoop,
    NativeSendmmsgOnly,
    NativeGsoSendmmsg,
}

impl SendBatchBenchCase {
    fn name(self) -> &'static str {
        match self {
            Self::PortableLoop => "portable_send_to_loop",
            Self::NativeSendmmsgOnly => "native_sendmmsg_only",
            Self::NativeGsoSendmmsg => "native_gso_sendmmsg",
        }
    }

    fn connected_sender(self) -> bool {
        !matches!(self, Self::PortableLoop)
    }

    fn strategy(self) -> UdpSendBatchStrategy {
        match self {
            Self::PortableLoop | Self::NativeGsoSendmmsg => UdpSendBatchStrategy::default(),
            Self::NativeSendmmsgOnly => UdpSendBatchStrategy {
                prefer_gso: false,
                ..UdpSendBatchStrategy::default()
            },
        }
    }
}

fn payloads() -> Vec<Vec<u8>> {
    (0..PACKETS_PER_BATCH)
        .map(|packet| vec![packet as u8; PAYLOAD_BYTES])
        .collect()
}

fn send_and_drain(payloads: &[Vec<u8>], bench_case: SendBatchBenchCase) {
    future::block_on(async {
        let mut receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let mut sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        if bench_case.connected_sender() {
            sender.connect(receiver_addr).await.unwrap();
        }

        let packets = payloads
            .iter()
            .map(|payload| UdpOutboundDatagram {
                dst_addr: receiver_addr,
                payload,
            })
            .collect::<Vec<_>>();
        let report = sender
            .send_batch_to_with_strategy(&packets, bench_case.strategy())
            .await
            .unwrap();
        assert_eq!(report.packets_processed, PACKETS_PER_BATCH);
        assert_eq!(report.bytes_processed, PACKETS_PER_BATCH * PAYLOAD_BYTES);

        match bench_case {
            SendBatchBenchCase::PortableLoop => {
                assert!(report.fallback_used);
                assert!(!report.native_send_batch_used);
                assert!(!report.gso_send_used);
            }
            SendBatchBenchCase::NativeSendmmsgOnly => {
                if cfg!(target_os = "linux") {
                    assert!(report.native_send_batch_used);
                    assert!(!report.gso_send_used);
                }
            }
            SendBatchBenchCase::NativeGsoSendmmsg => {
                if cfg!(target_os = "linux") {
                    assert!(
                        report.native_send_batch_used,
                        "expected native GSO send path, got {report:?}"
                    );
                    assert!(
                        report.gso_send_used,
                        "GSO-eligible benchmark fell back before using UDP_SEGMENT: {report:?}"
                    );
                }
            }
        }

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

    for bench_case in [
        SendBatchBenchCase::PortableLoop,
        SendBatchBenchCase::NativeSendmmsgOnly,
        SendBatchBenchCase::NativeGsoSendmmsg,
    ] {
        group.bench_with_input(
            BenchmarkId::new(bench_case.name(), PACKETS_PER_BATCH),
            &bench_case,
            |b, bench_case| b.iter(|| send_and_drain(&payloads, *bench_case)),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_udp_send_batch);
criterion_main!(benches);
