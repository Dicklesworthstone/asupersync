#![allow(clippy::all)]
use asupersync::http::h1::codec::{Http1Codec, HttpError};
use asupersync::bytes::BytesMut;
use asupersync::codec::Decoder;

fn main() {
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::new();
    // Valid request line
    buf.extend_from_slice(b"GET / HTTP/1.1\r\n");
    // Valid header name, invalid UTF-8 (obs-text 0xFF) in value
    buf.extend_from_slice(b"Test-Header: \xff\r\n");
    buf.extend_from_slice(b"\r\n");
    
    let res = codec.decode(&mut buf);
    println!("{:?}", res);
}
