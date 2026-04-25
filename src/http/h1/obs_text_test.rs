use crate::bytes::BytesMut;
use crate::codec::Decoder;
use crate::http::h1::codec::Http1Codec;

#[test]
fn obs_text_header_value_decodes_with_latin1_fallback() {
    let mut codec = Http1Codec::new();
    let mut buf = BytesMut::new();

    buf.extend_from_slice(b"GET / HTTP/1.1\r\n");
    buf.extend_from_slice(b"Test-Header: \xff\r\n");
    buf.extend_from_slice(b"\r\n");

    let request = codec
        .decode(&mut buf)
        .expect("obs-text header value should be syntactically valid")
        .expect("complete request should decode");

    assert_eq!(request.headers, vec![("Test-Header".into(), "ÿ".into())]);
}
