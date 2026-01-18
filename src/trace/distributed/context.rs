//! Trace context that propagates with symbols.

use super::id::{SymbolSpanId, TraceId};
use crate::types::Time;
use crate::util::DetRng;
use core::fmt;

/// Trace flags controlling sampling and debug behavior.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct TraceFlags(u8);

impl TraceFlags {
    /// No flags set.
    pub const NONE: Self = Self(0);
    /// Trace is sampled (should be recorded).
    pub const SAMPLED: Self = Self(0x01);
    /// Debug flag (record everything).
    pub const DEBUG: Self = Self(0x02);

    /// Creates new flags from a byte.
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        Self(b)
    }

    /// Returns the flags as a byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// Returns true if the sampled flag is set.
    #[must_use]
    pub const fn is_sampled(self) -> bool {
        self.0 & 0x01 != 0
    }

    /// Returns true if the debug flag is set.
    #[must_use]
    pub const fn is_debug(self) -> bool {
        self.0 & 0x02 != 0
    }

    /// Sets the sampled flag.
    #[must_use]
    pub const fn with_sampled(self) -> Self {
        Self(self.0 | 0x01)
    }

    /// Sets the debug flag.
    #[must_use]
    pub const fn with_debug(self) -> Self {
        Self(self.0 | 0x02)
    }
}

/// A tag identifying a region/data center.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RegionTag(String);

impl RegionTag {
    /// Creates a new region tag.
    #[must_use]
    pub fn new(tag: impl Into<String>) -> Self {
        Self(tag.into())
    }

    /// Returns the tag as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unknown region tag value.
    pub const UNKNOWN: &'static str = "unknown";
}

impl fmt::Display for RegionTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Trace context embedded in symbol metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolTraceContext {
    trace_id: TraceId,
    parent_span_id: SymbolSpanId,
    span_id: SymbolSpanId,
    flags: TraceFlags,
    origin_region: RegionTag,
    created_at: Time,
    baggage: Vec<(String, String)>,
}

impl SymbolTraceContext {
    /// Creates a new trace context for an object encoding operation.
    #[must_use]
    pub fn new_for_encoding(
        trace_id: TraceId,
        parent_span_id: SymbolSpanId,
        origin_region: RegionTag,
        rng: &mut DetRng,
    ) -> Self {
        Self {
            trace_id,
            parent_span_id,
            span_id: SymbolSpanId::new_random(rng),
            flags: TraceFlags::SAMPLED,
            origin_region,
            created_at: Time::ZERO,
            baggage: Vec::new(),
        }
    }

    /// Creates a child context for a derived operation.
    #[must_use]
    pub fn child(&self, rng: &mut DetRng) -> Self {
        Self {
            trace_id: self.trace_id,
            parent_span_id: self.span_id,
            span_id: SymbolSpanId::new_random(rng),
            flags: self.flags,
            origin_region: self.origin_region.clone(),
            created_at: Time::ZERO,
            baggage: self.baggage.clone(),
        }
    }

    /// Sets the creation timestamp.
    #[must_use]
    pub fn with_created_at(mut self, time: Time) -> Self {
        self.created_at = time;
        self
    }

    /// Adds a baggage item.
    #[must_use]
    pub fn with_baggage(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.baggage.push((key.into(), value.into()));
        self
    }

    /// Returns the trace ID.
    #[must_use]
    pub const fn trace_id(&self) -> TraceId {
        self.trace_id
    }

    /// Returns the parent span ID.
    #[must_use]
    pub const fn parent_span_id(&self) -> SymbolSpanId {
        self.parent_span_id
    }

    /// Returns this span's ID.
    #[must_use]
    pub const fn span_id(&self) -> SymbolSpanId {
        self.span_id
    }

    /// Returns the trace flags.
    #[must_use]
    pub const fn flags(&self) -> TraceFlags {
        self.flags
    }

    /// Returns the origin region.
    #[must_use]
    pub fn origin_region(&self) -> &RegionTag {
        &self.origin_region
    }

    /// Returns the creation timestamp.
    #[must_use]
    pub const fn created_at(&self) -> Time {
        self.created_at
    }

    /// Returns the baggage items.
    #[must_use]
    pub fn baggage(&self) -> &[(String, String)] {
        &self.baggage
    }

    /// Looks up a baggage item by key.
    #[must_use]
    pub fn get_baggage(&self, key: &str) -> Option<&str> {
        self.baggage
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Serializes to bytes for transmission.
    ///
    /// Returns an empty buffer if any component exceeds serialization limits.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let region_bytes = self.origin_region.0.as_bytes();
        let Ok(region_len) = u16::try_from(region_bytes.len()) else {
            return Vec::new();
        };
        let Ok(baggage_len) = u16::try_from(self.baggage.len()) else {
            return Vec::new();
        };

        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&self.trace_id.high().to_be_bytes());
        buf.extend_from_slice(&self.trace_id.low().to_be_bytes());
        buf.extend_from_slice(&self.parent_span_id.as_u64().to_be_bytes());
        buf.extend_from_slice(&self.span_id.as_u64().to_be_bytes());
        buf.push(self.flags.as_byte());
        buf.extend_from_slice(&self.created_at.as_nanos().to_be_bytes());
        buf.extend_from_slice(&region_len.to_be_bytes());
        buf.extend_from_slice(region_bytes);
        buf.extend_from_slice(&baggage_len.to_be_bytes());

        for (k, v) in &self.baggage {
            let k_bytes = k.as_bytes();
            let v_bytes = v.as_bytes();
            let Ok(k_len) = u16::try_from(k_bytes.len()) else {
                return Vec::new();
            };
            let Ok(v_len) = u16::try_from(v_bytes.len()) else {
                return Vec::new();
            };
            buf.extend_from_slice(&k_len.to_be_bytes());
            buf.extend_from_slice(k_bytes);
            buf.extend_from_slice(&v_len.to_be_bytes());
            buf.extend_from_slice(v_bytes);
        }

        buf
    }

    /// Deserializes from bytes.
    #[must_use]
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 49 {
            return None;
        }

        let trace_id = TraceId::new(
            u64::from_be_bytes(data[0..8].try_into().ok()?),
            u64::from_be_bytes(data[8..16].try_into().ok()?),
        );
        let parent_span_id = SymbolSpanId::new(u64::from_be_bytes(data[16..24].try_into().ok()?));
        let span_id = SymbolSpanId::new(u64::from_be_bytes(data[24..32].try_into().ok()?));
        let flags = TraceFlags::from_byte(data[32]);
        let created_at = Time::from_nanos(u64::from_be_bytes(data[33..41].try_into().ok()?));

        let region_len = u16::from_be_bytes(data[41..43].try_into().ok()?) as usize;
        if data.len() < 43 + region_len + 2 {
            return None;
        }
        let origin_region =
            RegionTag(String::from_utf8(data[43..43 + region_len].to_vec()).ok()?);

        let baggage_offset = 43 + region_len;
        let baggage_count =
            u16::from_be_bytes(data[baggage_offset..baggage_offset + 2].try_into().ok()?) as usize;

        let mut baggage = Vec::with_capacity(baggage_count);
        let mut offset = baggage_offset + 2;

        for _ in 0..baggage_count {
            if data.len() < offset + 2 {
                return None;
            }
            let k_len = u16::from_be_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
            offset += 2;
            if data.len() < offset + k_len + 2 {
                return None;
            }
            let k = String::from_utf8(data[offset..offset + k_len].to_vec()).ok()?;
            offset += k_len;
            let v_len = u16::from_be_bytes(data[offset..offset + 2].try_into().ok()?) as usize;
            offset += 2;
            if data.len() < offset + v_len {
                return None;
            }
            let v = String::from_utf8(data[offset..offset + v_len].to_vec()).ok()?;
            offset += v_len;
            baggage.push((k, v));
        }

        Some(Self {
            trace_id,
            parent_span_id,
            span_id,
            flags,
            origin_region,
            created_at,
            baggage,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_context_serialization_roundtrip() {
        let mut rng = DetRng::new(42);
        let ctx = SymbolTraceContext::new_for_encoding(
            TraceId::new_for_test(1),
            SymbolSpanId::new_for_test(0),
            RegionTag::new("us-east-1"),
            &mut rng,
        )
        .with_created_at(Time::from_millis(1000))
        .with_baggage("request_id", "req-123");

        let bytes = ctx.to_bytes();
        let parsed = SymbolTraceContext::from_bytes(&bytes).expect("roundtrip should work");

        assert_eq!(ctx.trace_id(), parsed.trace_id());
        assert_eq!(ctx.span_id(), parsed.span_id());
        assert_eq!(ctx.get_baggage("request_id"), Some("req-123"));
    }

    #[test]
    fn trace_flags_bits() {
        let flags = TraceFlags::NONE.with_sampled().with_debug();
        assert!(flags.is_sampled());
        assert!(flags.is_debug());
    }
}
