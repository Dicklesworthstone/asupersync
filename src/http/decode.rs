//! Explicit, bounded content decoding for buffered HTTP client responses.

use super::compress::{ContentEncoding, DecompressionLimit, Decompressor};
use super::{Method, Response};
use std::borrow::Cow;
use std::io;

// Bound nesting independently of output size: identity and tiny encoded bodies
// must not let an attacker request unbounded codec construction or CPU work.
const MAX_CONTENT_CODINGS: usize = 8;

impl Response {
    /// Decode this buffered response's Content-Encoding in reverse application order.
    ///
    /// Decoding is explicit: a response is decoded by this call, which an
    /// `HttpClient` also makes only when its opt-in
    /// `HttpClientBuilder::response_decompression` is enabled (that option also
    /// sends Accept-Encoding). Supply the original request method so HEAD
    /// and successful CONNECT responses retain their representation metadata.
    /// Informational, 204, 205, and 304 responses are also left unchanged.
    /// Encoded partial representations are rejected rather than guessing which
    /// bytes the Content-Range describes. A body declared empty by
    /// `Content-Length: 0` is the empty representation whatever its codings;
    /// an empty body without that declaration fails like any truncated stream.
    ///
    /// The mandatory limit applies to every intermediate decoded representation
    /// and the final body, including identity bodies. At most eight content
    /// codings are accepted, including codings in repeated header fields.
    /// This bounds decoding, not the memory already used to receive the wire body;
    /// configure the client's receive-body limit separately.
    ///
    /// On success, compressed content is replaced atomically and Content-Encoding,
    /// Content-Length, and payload digest fields are removed from headers and
    /// trailers. Other metadata, including origin cache validators, is preserved.
    /// On any error the entire response remains unchanged. A second successful
    /// call is a no-op apart from checking the supplied limit.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown or unavailable codec, malformed coding
    /// list, excessive nesting, encoded partial response, invalid/truncated stream,
    /// or output exceeding the limit. Gzip, deflate, and Brotli require the
    /// `compression` feature; identity bodies work without it.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use asupersync::http::{Client, Method};
    /// use asupersync::http::compress::DecompressionLimit;
    ///
    /// # async fn example(cx: &asupersync::Cx) -> Result<(), Box<dyn std::error::Error>> {
    /// let mut response = Client::new().get("https://example.invalid/data").send(cx).await?;
    /// response.decode_content(&Method::Get, DecompressionLimit::new(1024 * 1024))?;
    /// let value: serde_json::Value = response.json()?;
    /// # let _ = value;
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode_content(
        &mut self,
        request_method: &Method,
        limit: DecompressionLimit,
    ) -> io::Result<()> {
        if request_method.as_str() == "HEAD"
            || (request_method.as_str() == "CONNECT" && (200..300).contains(&self.status))
            || (100..200).contains(&self.status)
            || matches!(self.status, 204 | 205 | 304)
        {
            return Ok(());
        }

        let codings = content_codings(&self.headers)?;
        if codings.iter().all(|coding| *coding == ContentEncoding::Identity) {
            return check_size(self.body.len(), limit);
        }
        if self.status == 206
            || self
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-range"))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot decode an encoded partial representation",
            ));
        }
        // A body declared empty (Content-Length: 0) with a content coding holds
        // no encoded data: it is the empty representation, which other clients
        // accept. Decoding it would fail as a truncated stream and fail the
        // whole response (br-asupersync-ecnp0m). Without that declaration an
        // empty body may be content cut off before its first byte, so it still
        // fails like any other truncated stream.
        if self.body.is_empty() && declared_empty(&self.headers) {
            self.headers.retain(|(name, _)| !invalidated_field(name));
            self.trailers.retain(|(name, _)| !invalidated_field(name));
            return Ok(());
        }

        // Keep the original response intact until every layer has completed,
        // including each codec's trailer/checksum validation in finish().
        let mut decoded = Cow::Borrowed(self.body.as_slice());
        for coding in codings.into_iter().rev() {
            if coding == ContentEncoding::Identity {
                check_size(decoded.len(), limit)?;
                continue;
            }
            let mut decoder = decoder_for(coding, limit)?;
            let mut output = Vec::new();
            decoder.decompress(decoded.as_ref(), &mut output)?;
            decoder.finish(&mut output)?;
            check_size(output.len(), limit)?;
            decoded = Cow::Owned(output);
        }
        self.body = decoded.into_owned();
        self.headers.retain(|(name, _)| !invalidated_field(name));
        self.trailers.retain(|(name, _)| !invalidated_field(name));
        Ok(())
    }
}

// Whether the message framing declared the body empty: at least one
// Content-Length field, and every one of them 0.
fn declared_empty(headers: &[(String, String)]) -> bool {
    let mut lengths = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .peekable();
    lengths.peek().is_some() && lengths.all(|(_, value)| value.trim() == "0")
}

fn check_size(size: usize, limit: DecompressionLimit) -> io::Result<()> {
    if size > limit.get() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decoded response exceeds output limit",
        ))
    } else {
        Ok(())
    }
}

fn content_codings(headers: &[(String, String)]) -> io::Result<Vec<ContentEncoding>> {
    let mut codings = Vec::new();
    let mut present = false;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("content-encoding") {
            continue;
        }
        present = true;
        for token in value.split(',') {
            let token = token.trim_matches([' ', '\t']);
            // RFC 9110 list parsing tolerates empty list members. A field set
            // containing no actual coding at all is still invalid here.
            if token.is_empty() {
                continue;
            }
            if codings.len() == MAX_CONTENT_CODINGS {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "too many response content codings",
                ));
            }
            let coding = if token.eq_ignore_ascii_case("identity") {
                ContentEncoding::Identity
            } else if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
                ContentEncoding::Gzip
            } else if token.eq_ignore_ascii_case("deflate") {
                ContentEncoding::Deflate
            } else if token.eq_ignore_ascii_case("br") {
                ContentEncoding::Brotli
            } else {
                // Do not echo an untrusted, potentially enormous header value.
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported response content coding",
                ));
            };
            codings.push(coding);
        }
    }
    if present && codings.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty response content coding list",
        ));
    }
    Ok(codings)
}

fn decoder_for(
    coding: ContentEncoding,
    limit: DecompressionLimit,
) -> io::Result<Box<dyn Decompressor>> {
    match coding {
        ContentEncoding::Identity => Ok(Box::new(super::compress::IdentityDecompressor::new(
            Some(limit.get()),
        ))),
        #[cfg(feature = "compression")]
        ContentEncoding::Gzip => Ok(Box::new(super::compress::GzipDecompressor::new(limit))),
        #[cfg(feature = "compression")]
        ContentEncoding::Deflate => Ok(Box::new(super::compress::DeflateDecompressor::new(Some(
            limit.get(),
        )))),
        #[cfg(feature = "compression")]
        ContentEncoding::Brotli => Ok(Box::new(super::compress::BrotliDecompressor::new(Some(
            limit.get(),
        )))),
        #[cfg(not(feature = "compression"))]
        ContentEncoding::Gzip | ContentEncoding::Deflate | ContentEncoding::Brotli => Err(
            io::Error::new(io::ErrorKind::Unsupported, "response codec requires compression feature"),
        ),
    }
}

fn invalidated_field(name: &str) -> bool {
    [
        "content-encoding",
        "content-length",
        "content-md5",
        "digest",
        "content-digest",
        "repr-digest",
    ]
    .iter()
    .any(|field| name.eq_ignore_ascii_case(field))
}
