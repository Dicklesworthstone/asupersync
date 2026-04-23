#![no_main]

use arbitrary::Arbitrary;
use asupersync::{
    codec::{FramedRead, length_delimited::LengthDelimitedCodecBuilder},
    io::{AsyncRead, ReadBuf},
    cx::Cx,
};
use std::{
    io as std_io,
    pin::Pin,
    task::{Context, Poll},
};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    chunks: Vec<Vec<u8>>,
    max_frame_len: u16, // Use u16 to avoid excessive large allocations
    length_field_len: u8,
    num_skip: u8,
    length_adjustment: i8,
}

struct MockTransport {
    chunks: std::vec::IntoIter<Vec<u8>>,
    current_chunk: Vec<u8>,
    pos: usize,
}

impl MockTransport {
    fn new(chunks: Vec<Vec<u8>>) -> Self {
        Self {
            chunks: chunks.into_iter(),
            current_chunk: Vec::new(),
            pos: 0,
        }
    }
}

impl AsyncRead for MockTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std_io::Result<()>> {
        if self.pos >= self.current_chunk.len() {
            if let Some(next) = self.chunks.next() {
                self.current_chunk = next;
                self.pos = 0;
            } else {
                return Poll::Ready(Ok(())); // EOF
            }
        }
        
        let rem = &self.current_chunk[self.pos..];
        let take = std::cmp::min(rem.len(), buf.remaining());
        
        if take > 0 {
            buf.put_slice(&rem[..take]);
            self.pos += take;
            Poll::Ready(Ok(()))
        } else {
            // Either the current chunk is empty, or the caller's buf is empty
            if buf.remaining() == 0 {
                Poll::Ready(Ok(()))
            } else {
                // Empty chunk, skip to next on next poll (but we'll just yield empty now)
                Poll::Ready(Ok(()))
            }
        }
    }
}

fuzz_target!(|data: FuzzInput| {
    let length_field_len = match data.length_field_len % 4 {
        0 => 1,
        1 => 2,
        2 => 3,
        _ => 4,
    };
    
    let mut builder = LengthDelimitedCodecBuilder::new();
    builder.max_frame_length((data.max_frame_len as usize).max(1));
    builder.length_field_length(length_field_len);
    builder.num_skip(data.num_skip as usize);
    builder.length_adjustment(data.length_adjustment as isize);
    
    let codec = builder.new_codec();
    let transport = MockTransport::new(data.chunks);
    let mut framed = FramedRead::new(transport, codec);
    
    let cx = Cx::for_testing();
    let waker = futures_util::task::noop_waker();
    let mut ctx = Context::from_waker(&waker);
    
    loop {
        // Run under a panic catch block just to be defensive, though libfuzzer catches panics anyway.
        // We want to ensure NO panic happens on partial frames or underflow.
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut pin_framed = Pin::new(&mut framed);
            pin_framed.poll_next(&mut ctx)
        }));
        
        match res {
            Ok(Poll::Ready(Some(Ok(_frame)))) => {
                // Successfully parsed a frame
            }
            Ok(Poll::Ready(Some(Err(_e)))) => {
                // Parsing failed (e.g. frame too large, underflow). 
                // This is expected and valid; it must fail closed.
                break;
            }
            Ok(Poll::Ready(None)) => {
                // Clean EOF
                break;
            }
            Ok(Poll::Pending) => {
                // We don't return Pending in MockTransport, so if we get here, 
                // something's weird but not a bug necessarily if Buf is empty.
                break;
            }
            Err(e) => {
                std::panic::resume_unwind(e); // Panic is a bug
            }
        }
    }
});