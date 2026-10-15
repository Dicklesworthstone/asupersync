//! Generic typed erasure channel (`asupersync-raptorq-leverage-3bb2pl.1`): the
//! bead's `channel::<T: Serialize>` headline shape.
//!
//! Drives `EcSender::send_value` / `EcReceiver::recv_value` over the public
//! erasure channel: a `Serialize` value is serialized, erasure-coded, and
//! delivered, then deserialized back to an equal value on the receiver. Proves
//! typed round-trip, FIFO order across typed messages, and fail-closed behavior
//! on a deserialization type mismatch. Reactor-free (`futures_lite::block_on`).
#![allow(missing_docs)]

use asupersync::channel::erasure::{EcConfig, channel};
use asupersync::cx::Cx;
use futures_lite::future::block_on;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Job {
    id: u64,
    name: String,
    payload: Vec<u8>,
    retries: u32,
}

fn config() -> EcConfig {
    EcConfig {
        symbol_size: 64,
        repair_overhead: 6,
        max_message_size: 1 << 20,
    }
}

#[test]
fn typed_value_roundtrips() {
    let (mut tx, mut rx) = channel(config());
    let cx = Cx::for_testing();
    let job = Job {
        id: 7,
        name: "rebuild-index".to_string(),
        payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        retries: 2,
    };

    tx.send_value(&cx, &job).expect("send_value");
    let got: Job = block_on(rx.recv_value(&cx)).expect("recv_value");
    assert_eq!(got, job, "a typed value must round-trip to an equal value");
}

#[test]
fn typed_values_preserve_fifo_order() {
    let (mut tx, mut rx) = channel(config());
    let cx = Cx::for_testing();
    let jobs: Vec<Job> = (0..4u64)
        .map(|i| Job {
            id: i,
            name: format!("job-{i}"),
            payload: vec![i as u8; (i as usize) * 10],
            retries: i as u32,
        })
        .collect();

    for job in &jobs {
        tx.send_value(&cx, job).expect("send");
    }
    for expected in &jobs {
        let got: Job = block_on(rx.recv_value(&cx)).expect("recv");
        assert_eq!(&got, expected, "typed messages must arrive in FIFO order");
    }
}

#[test]
fn deserialize_type_mismatch_fails_closed() {
    let (mut tx, mut rx) = channel(config());
    let cx = Cx::for_testing();
    let job = Job {
        id: 1,
        name: "x".to_string(),
        payload: vec![],
        retries: 0,
    };

    tx.send_value(&cx, &job).expect("send");
    // The bytes describe a Job object; deserializing them into a bare u64 must
    // fail closed rather than yield a bogus value.
    let got: Result<u64, _> = block_on(rx.recv_value::<u64>(&cx));
    assert!(
        got.is_err(),
        "a type mismatch must fail closed, got {got:?}"
    );
}
