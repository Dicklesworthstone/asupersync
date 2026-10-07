# HTTP deflate compatibility correction

Related bead: `asupersync-zodgeb`.

`DeflateCompressor` now emits RFC 1950 zlib framing, including the Adler-32
trailer, rather than raw RFC 1951 DEFLATE. This corrects the wire representation
of `Content-Encoding: deflate` required by RFC 9110 section 8.4.1.2 and already
promised by `ContentEncoding::Deflate`. The compressor factory and HTTP response
compression middleware inherit the correction without configuration changes.

Direct callers that intentionally consume raw DEFLATE should use a raw codec
such as `flate2::write::DeflateEncoder`, not this HTTP content-coding helper.
Compressed output limits include the zlib header and trailer.

`DeflateDecompressor` accepts zlib streams and legacy raw streams. It buffers at
most two bytes to choose framing, including when a header spans input chunks.
A valid zlib header commits to zlib interpretation: checksum errors and
unsupported preset dictionaries are not retried as raw streams. A legacy raw
stream whose first two bytes happen to satisfy the zlib header check is
ambiguous and is interpreted as zlib; there is no error-triggered fallback.

Call `finish()` to validate completion. Missing headers, incomplete compressed
data or trailers, and trailing bytes after the single stream are errors.
Errors are terminal; a failing decode call does not append its staged output.
Bytes returned by earlier successful calls remain provisional until `finish()`
succeeds. Output limits remain cumulative across calls. Repeated successful
`finish()` calls do not append bytes; input after finishing is rejected.

Regression coverage is in `tests/http_deflate_interoperability.rs` and the
existing `http::compress` unit tests. The new tests include independent zlib
and raw reference encoders, every two-chunk split, byte-at-a-time delivery,
large expansions, truncated prefixes, checksum and dictionary rejection,
trailing data, and output limits. Rust compilation and execution were not
available in the editing environment; these are added tests, not a passing
validation receipt.
