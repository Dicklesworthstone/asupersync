#![no_main]
#![allow(warnings)]

use libfuzzer_sys::fuzz_target;
use asupersync::bytes::BytesMut;
use arbitrary::Arbitrary;
use asupersync::grpc::codec::{GrpcCodec, GrpcMessage, MESSAGE_HEADER_SIZE};
use asupersync::codec::{Decoder, Encoder};
use asupersync::grpc::status::GrpcError;

#[derive(Arbitrary, Debug)]
enum Action {
    FeedBytes(Vec<u8>),
    FeedFrame {
        compressed_flag: u8,
        length: u32,
        payload: Vec<u8>,
        truncate: Option<usize>, // To simulate partial frames
    },
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    actions: Vec<Action>,
    max_decode_size: u32,
}

fuzz_target!(|input: FuzzInput| {
    // Cap max decode size to prevent OOM in fuzzer, but allow it to be large enough to trigger overflow logic
    let max_decode_size = (input.max_decode_size % 1_000_000) as usize; 
    let mut codec = GrpcCodec::with_message_size_limits(max_decode_size, max_decode_size);
    let mut buf = BytesMut::new();
    
    for action in input.actions {
        match action {
            Action::FeedBytes(bytes) => {
                if bytes.len() > 100_000 { continue; }
                buf.extend_from_slice(&bytes);
            }
            Action::FeedFrame { compressed_flag, length, payload, truncate } => {
                if payload.len() > 100_000 { continue; }
                
                let mut frame = Vec::new();
                frame.push(compressed_flag);
                frame.extend_from_slice(&length.to_be_bytes());
                frame.extend_from_slice(&payload);
                
                if let Some(t) = truncate {
                    let t = t % (frame.len() + 1);
                    frame.truncate(t);
                }
                
                buf.extend_from_slice(&frame);
            }
        }
        
        // Try decoding
        loop {
            // Take a snapshot of the buffer length to ensure decode makes progress or returns Ok(None)/Err
            let prev_len = buf.len();
            match codec.decode(&mut buf) {
                Ok(Some(msg)) => {
                    // Valid message
                    assert!(prev_len > buf.len()); // MUST consume bytes
                    let mut out = BytesMut::new();
                    let _ = codec.encode(msg, &mut out);
                }
                Ok(None) => {
                    assert_eq!(prev_len, buf.len()); // MUST NOT consume bytes if incomplete
                    break;
                }
                Err(e) => {
                    // Invariants:
                    match e {
                        GrpcError::MessageTooLarge | GrpcError::Protocol(_) => {
                            // Expected errors, valid
                        }
                        _ => {
                            panic!("Unexpected error from decoder: {:?}", e);
                        }
                    }
                    buf.clear(); // Recover from error state by clearing buffer (simplification)
                    break;
                }
            }
        }
    }
});