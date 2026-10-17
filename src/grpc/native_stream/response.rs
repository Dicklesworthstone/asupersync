//! Response-envelope validation shared by the demand-driven native client.

use super::{Bytes, Code, GrpcError, Header, Metadata, Status};
use base64::Engine as _;

pub(super) struct ResponseHead {
    pub initial: Option<Metadata>,
    pub trailers: Option<Metadata>,
    pub encoding: Option<String>,
    pub terminal: Option<Status>,
    pub ended: bool,
    limit: usize,
    informational: u8,
    accept_gzip: bool,
}

impl ResponseHead {
    pub fn new(limit: usize, accept_gzip: bool) -> Self {
        Self {
            initial: None,
            trailers: None,
            encoding: None,
            terminal: None,
            ended: false,
            limit,
            informational: 0,
            accept_gzip,
        }
    }

    pub fn headers(&mut self, headers: Vec<Header>, end_stream: bool) -> Result<(), Status> {
        if self.ended {
            return Err(Status::internal("HEADERS after gRPC stream termination"));
        }
        let mut used = 0usize;
        for header in &headers {
            used = used.checked_add(header.name.len())
                .and_then(|n| n.checked_add(header.value.len()))
                .and_then(|n| n.checked_add(32))
                .ok_or_else(|| Status::resource_exhausted("gRPC metadata size overflow"))?;
            if used > self.limit {
                return Err(Status::resource_exhausted("gRPC metadata exceeds its byte limit"));
            }
        }
        let first = self.initial.is_none();
        let mut http_status = None;
        let mut content_type = None;
        let mut encoding = None;
        let mut code = None;
        let mut message = None;
        let mut details = None;
        let mut metadata = Metadata::new();
        for Header { name, value } in headers {
            match name.as_str() {
                ":status" if first => {
                    if http_status.is_some() || value.len() != 3
                        || !value.bytes().all(|byte| byte.is_ascii_digit())
                    {
                        return Err(Status::internal("invalid or duplicate HTTP response status"));
                    }
                    http_status = Some(value.parse::<u16>()
                        .map_err(|_| Status::internal("invalid HTTP response status"))?);
                }
                "content-type" if first => {
                    if content_type.replace(value).is_some() {
                        return Err(Status::internal("duplicate gRPC content-type"));
                    }
                }
                "grpc-encoding" if first => {
                    if encoding.replace(value).is_some() {
                        return Err(Status::internal("duplicate gRPC message encoding"));
                    }
                }
                "grpc-status" => {
                    if code.is_some() || value.is_empty()
                        || !value.bytes().all(|byte| byte.is_ascii_digit())
                    {
                        return Err(Status::internal("invalid or duplicate grpc-status"));
                    }
                    let raw = value.parse::<i32>()
                        .map_err(|_| Status::internal("invalid grpc-status"))?;
                    if !(0..=16).contains(&raw) {
                        return Err(Status::internal("unknown grpc-status"));
                    }
                    code = Some(Code::from_i32(raw));
                }
                "grpc-message" => {
                    if message.is_some() {
                        return Err(Status::internal("duplicate grpc-message"));
                    }
                    message = Some(crate::grpc::status::percent_decode_grpc_message(&value)
                        .map_err(GrpcError::into_status)?);
                }
                "grpc-status-details-bin" => {
                    if details.replace(decode_binary(&value)?).is_some() {
                        return Err(Status::internal("duplicate grpc-status-details-bin"));
                    }
                }
                "grpc-accept-encoding" if first => {}
                "content-type" | "grpc-encoding" | "grpc-accept-encoding" => {
                    return Err(Status::internal("response framing field in gRPC trailers"));
                }
                name if name.starts_with(':') => {
                    return Err(Status::internal("unexpected response pseudo-header"));
                }
                "connection" | "transfer-encoding" | "keep-alive" | "upgrade"
                | "proxy-connection" | "te" => {
                    return Err(Status::internal("connection-specific response metadata"));
                }
                _ => {
                    if name.ends_with("-bin") {
                        // Intermediaries may comma-join binary metadata. Preserve
                        // every value, including an explicitly empty value.
                        for value in value.split(',') {
                            if !metadata.insert_bin(name.clone(), decode_binary(value.trim())?) {
                                return Err(Status::internal("invalid binary response metadata"));
                            }
                        }
                    } else if !metadata.insert(name, value) {
                        return Err(Status::internal("invalid response metadata"));
                    }
                }
            }
        }
        if first {
            let http_status = http_status
                .ok_or_else(|| Status::internal("response is missing HTTP status"))?;
            if (100..200).contains(&http_status) {
                if end_stream || code.is_some() || message.is_some() || details.is_some()
                    || http_status == 101 || self.informational == 16
                {
                    return Err(Status::internal("invalid informational gRPC response"));
                }
                self.informational += 1;
                return Ok(());
            }
            if http_status != 200 {
                // A trailers-only gRPC status takes precedence over HTTP mapping.
                if !end_stream || code.is_none() {
                    return Err(http_fallback(http_status));
                }
            } else if !content_type.as_deref().is_some_and(valid_content_type) {
                return Err(Status::internal("response is not application/grpc"));
            }
            // A trailers-only response carries no message, so an encoding this
            // client cannot decode is moot: its grpc-status is the result.
            if let Some(value) = encoding.as_ref().filter(|_| !end_stream) {
                if value != "identity" && !(value == "gzip" && self.accept_gzip) {
                    return Err(Status::internal("unsupported gRPC response compression"));
                }
            }
        } else if !end_stream {
            return Err(Status::internal("gRPC trailers must end the stream"));
        }
        if !end_stream && (code.is_some() || message.is_some() || details.is_some()) {
            return Err(Status::internal("gRPC status appeared before terminal trailers"));
        }
        if end_stream {
            let code = code.ok_or_else(|| http_fallback(200))?;
            let message = message.unwrap_or_default();
            self.terminal = Some(match details {
                Some(details) => Status::with_details(code, message, details),
                None => Status::new(code, message),
            });
            self.trailers = Some(metadata);
            self.ended = true;
            if first {
                // Trailers-only custom metadata is trailing, not initial. It
                // carries no message, so its (unchecked) encoding is not kept.
                self.initial = Some(Metadata::new());
                self.encoding = None;
            }
        } else {
            self.initial = Some(metadata);
            self.encoding = encoding;
        }
        Ok(())
    }

    pub fn data(&mut self, end_stream: bool) -> Result<(), Status> {
        if self.initial.is_none() || self.ended {
            return Err(Status::internal("gRPC DATA outside an open response body"));
        }
        if end_stream {
            self.ended = true;
            self.terminal = Some(http_fallback(200));
        }
        Ok(())
    }
}

fn valid_content_type(value: &str) -> bool {
    let value = value.split(';').next().unwrap_or_default().trim();
    value.eq_ignore_ascii_case("application/grpc")
        || value.get(..17).is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/grpc+"))
            && value.len() > 17
}

fn decode_binary(value: &str) -> Result<Bytes, Status> {
    base64::engine::general_purpose::STANDARD.decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(value))
        .map(Bytes::from)
        .map_err(|_| Status::internal("invalid base64 in gRPC response metadata"))
}

pub fn http_fallback(status: u16) -> Status {
    let code = match status {
        400 => Code::Internal,
        401 => Code::Unauthenticated,
        403 => Code::PermissionDenied,
        404 => Code::Unimplemented,
        429 | 502 | 503 | 504 => Code::Unavailable,
        _ => Code::Unknown,
    };
    Status::new(code, format!("HTTP {status} response without grpc-status"))
}

#[cfg(test)]
#[path = "response_inline_tests.rs"]
mod tests;
