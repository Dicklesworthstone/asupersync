//! Datagram wire codec for SWIM membership packets (UDP transport adapter).
//!
//! The pure, transport-free framing half of the UDP adapter (bead
//! `asupersync-dist-otp-completeness-8y37kz.4.4`): a deterministic,
//! length-delimited, versioned byte encoding of a [`Packet`] (its protocol
//! [`Payload`] plus piggybacked gossip [`Rumor`]s), with an MTU budget that
//! truncates the gossip tail so a single datagram never exceeds the configured
//! size. Dropping gossip under MTU pressure is safe: the [`super::gossip`]
//! buffer retransmits anything that did not ride out this round, so
//! dissemination still converges.
//!
//! The actual socket binding (bind/recv/send through the runtime UDP surface +
//! `Cx`) is support-class and layered on top of this codec; production WAN
//! hardening (path MTU discovery, congestion response, auth) is explicitly out
//! of scope and recorded as an adapter-lane follow-up — there is no blanket
//! production claim here.

use super::swim::{Packet, Payload, Rumor};
use crate::remote::NodeId;

/// Wire format version. Bump on any incompatible framing change.
pub const WIRE_VERSION: u8 = 1;

/// A conservative default UDP payload budget.
///
/// Below the common 1500-byte Ethernet MTU minus IPv4/IPv6 + UDP headers,
/// leaving margin to avoid IP fragmentation on typical LAN paths. Not a
/// path-MTU-discovery result.
pub const DEFAULT_MTU: usize = 1400;

/// Minimum encoded size of a single gossip [`Rumor`], in bytes: a 1-byte tag, a
/// 2-byte zero-length node name length prefix, and an 8-byte incarnation
/// (`Rumor::Alive`/`Leave`; the `Suspect`/`Confirm` variants carry an extra
/// node and are larger). Used to bound the gossip-vector pre-allocation against
/// the actual datagram size so an attacker-controlled `u16` count cannot force a
/// large eager allocation from a tiny datagram (see [`decode_packet`]).
const MIN_RUMOR_BYTES: usize = 11;

/// Errors produced while decoding (or over-budget encoding) a datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended mid-field.
    UnexpectedEof,
    /// The version byte did not match [`WIRE_VERSION`].
    UnknownVersion(u8),
    /// The payload discriminant byte was not recognized.
    UnknownPayloadTag(u8),
    /// A gossip rumor discriminant byte was not recognized.
    UnknownRumorTag(u8),
    /// A length-delimited string was not valid UTF-8.
    InvalidUtf8,
    /// The payload alone does not fit within the MTU budget.
    PayloadExceedsMtu,
    /// A string is longer than the `u16` length prefix can describe
    /// (`> u16::MAX`); encoding it would silently truncate the length field and
    /// corrupt the datagram. Carries the offending byte length.
    StringTooLong(usize),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "datagram ended mid-field"),
            Self::UnknownVersion(v) => write!(f, "unknown wire version {v}"),
            Self::UnknownPayloadTag(t) => write!(f, "unknown payload tag {t}"),
            Self::UnknownRumorTag(t) => write!(f, "unknown rumor tag {t}"),
            Self::InvalidUtf8 => write!(f, "invalid utf-8 in node id"),
            Self::PayloadExceedsMtu => write!(f, "payload alone exceeds the MTU budget"),
            Self::StringTooLong(len) => {
                write!(f, "string length {len} exceeds u16 length-prefix capacity")
            }
        }
    }
}

impl std::error::Error for WireError {}

/// The result of encoding a packet to a datagram under an MTU budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedDatagram {
    /// The encoded bytes (`<= mtu`).
    pub bytes: Vec<u8>,
    /// How many gossip rumors were included.
    pub gossip_included: usize,
    /// How many gossip rumors were dropped for lack of room (they will be
    /// retransmitted by the gossip buffer next round).
    pub gossip_dropped: usize,
}

/// Encodes `packet` into a single datagram no larger than `mtu`.
///
/// The protocol payload is always included; gossip rumors are appended in order
/// until the next one would exceed the budget, after which the remainder is
/// dropped. Returns [`WireError::PayloadExceedsMtu`] only if the payload itself
/// (plus the fixed header) does not fit.
pub fn encode_packet(packet: &Packet, mtu: usize) -> Result<EncodedDatagram, WireError> {
    let mut buf = Vec::new();
    buf.push(WIRE_VERSION);
    encode_payload(&packet.payload, &mut buf)?;

    // Reserve space for the gossip count, written once the tail is packed.
    let count_pos = buf.len();
    buf.extend_from_slice(&0u16.to_le_bytes());

    if buf.len() > mtu {
        return Err(WireError::PayloadExceedsMtu);
    }

    let mut included: usize = 0;
    for rumor in &packet.gossip {
        if included >= u16::MAX as usize {
            break;
        }
        let mut encoded = Vec::new();
        encode_rumor(rumor, &mut encoded)?;
        if buf.len() + encoded.len() > mtu {
            break;
        }
        buf.extend_from_slice(&encoded);
        included += 1;
    }
    let dropped = packet.gossip.len() - included;

    let count = included as u16;
    buf[count_pos..count_pos + 2].copy_from_slice(&count.to_le_bytes());

    Ok(EncodedDatagram {
        bytes: buf,
        gossip_included: included,
        gossip_dropped: dropped,
    })
}

/// Decodes a datagram produced by [`encode_packet`] back into a [`Packet`].
pub fn decode_packet(bytes: &[u8]) -> Result<Packet, WireError> {
    let mut reader = Reader::new(bytes);
    let version = reader.read_u8()?;
    if version != WIRE_VERSION {
        return Err(WireError::UnknownVersion(version));
    }
    let payload = decode_payload(&mut reader)?;
    let count = reader.read_u16()?;
    // Bound the pre-allocation to what the remaining bytes could actually hold.
    // `count` is an untrusted u16 read straight off the (unauthenticated) UDP
    // datagram; reserving `count` elements directly let a ~12-byte packet with
    // count=0xFFFF force a ~4 MiB eager allocation (a ~350,000x amplification
    // DoS) before the loop fails at EOF. Each rumor needs >= MIN_RUMOR_BYTES, so
    // `remaining / MIN_RUMOR_BYTES` is the exact capacity for a well-formed
    // packet and a hard bound (= datagram size) for a malformed one.
    let capacity = (count as usize).min(reader.remaining() / MIN_RUMOR_BYTES);
    let mut gossip = Vec::with_capacity(capacity);
    for _ in 0..count {
        gossip.push(decode_rumor(&mut reader)?);
    }
    Ok(Packet { payload, gossip })
}

fn encode_payload(payload: &Payload, buf: &mut Vec<u8>) -> Result<(), WireError> {
    match payload {
        Payload::Ping { seq } => {
            buf.push(0);
            buf.extend_from_slice(&seq.to_le_bytes());
        }
        Payload::Ack { seq } => {
            buf.push(1);
            buf.extend_from_slice(&seq.to_le_bytes());
        }
        Payload::PingReq { seq, target } => {
            buf.push(2);
            buf.extend_from_slice(&seq.to_le_bytes());
            encode_str(target.as_str(), buf)?;
        }
        Payload::Nack { seq } => {
            buf.push(3);
            buf.extend_from_slice(&seq.to_le_bytes());
        }
    }
    Ok(())
}

fn decode_payload(reader: &mut Reader<'_>) -> Result<Payload, WireError> {
    let tag = reader.read_u8()?;
    match tag {
        0 => Ok(Payload::Ping {
            seq: reader.read_u64()?,
        }),
        1 => Ok(Payload::Ack {
            seq: reader.read_u64()?,
        }),
        2 => {
            let seq = reader.read_u64()?;
            let target = reader.read_node()?;
            Ok(Payload::PingReq { seq, target })
        }
        3 => Ok(Payload::Nack {
            seq: reader.read_u64()?,
        }),
        other => Err(WireError::UnknownPayloadTag(other)),
    }
}

fn encode_rumor(rumor: &Rumor, buf: &mut Vec<u8>) -> Result<(), WireError> {
    match rumor {
        Rumor::Alive { node, incarnation } => {
            buf.push(0);
            encode_str(node.as_str(), buf)?;
            buf.extend_from_slice(&incarnation.to_le_bytes());
        }
        Rumor::Suspect {
            node,
            incarnation,
            from,
        } => {
            buf.push(1);
            encode_str(node.as_str(), buf)?;
            buf.extend_from_slice(&incarnation.to_le_bytes());
            encode_str(from.as_str(), buf)?;
        }
        Rumor::Confirm {
            node,
            incarnation,
            from,
        } => {
            buf.push(2);
            encode_str(node.as_str(), buf)?;
            buf.extend_from_slice(&incarnation.to_le_bytes());
            encode_str(from.as_str(), buf)?;
        }
        Rumor::Leave { node, incarnation } => {
            buf.push(3);
            encode_str(node.as_str(), buf)?;
            buf.extend_from_slice(&incarnation.to_le_bytes());
        }
    }
    Ok(())
}

fn decode_rumor(reader: &mut Reader<'_>) -> Result<Rumor, WireError> {
    let tag = reader.read_u8()?;
    match tag {
        0 => {
            let node = reader.read_node()?;
            let incarnation = reader.read_u64()?;
            Ok(Rumor::Alive { node, incarnation })
        }
        1 => {
            let node = reader.read_node()?;
            let incarnation = reader.read_u64()?;
            let from = reader.read_node()?;
            Ok(Rumor::Suspect {
                node,
                incarnation,
                from,
            })
        }
        2 => {
            let node = reader.read_node()?;
            let incarnation = reader.read_u64()?;
            let from = reader.read_node()?;
            Ok(Rumor::Confirm {
                node,
                incarnation,
                from,
            })
        }
        3 => {
            let node = reader.read_node()?;
            let incarnation = reader.read_u64()?;
            Ok(Rumor::Leave { node, incarnation })
        }
        other => Err(WireError::UnknownRumorTag(other)),
    }
}

fn encode_str(value: &str, buf: &mut Vec<u8>) -> Result<(), WireError> {
    let len = value.len();
    // The wire format prefixes each string with a little-endian `u16` length.
    // Casting `value.len() as u16` silently truncated any string longer than
    // 65535 bytes, writing a length prefix that no longer matched the appended
    // bytes and corrupting the rest of the datagram. Reject over-long strings
    // instead of emitting a malformed frame.
    if len > u16::MAX as usize {
        return Err(WireError::StringTooLong(len));
    }
    buf.extend_from_slice(&(len as u16).to_le_bytes());
    buf.extend_from_slice(value.as_bytes());
    Ok(())
}

/// A bounds-checked cursor over a datagram.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let remaining = self.remaining();
        if n > remaining {
            return Err(WireError::UnexpectedEof);
        }
        let slice = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    /// Number of bytes left to read. Used to bound trusted-of-nothing
    /// length/count fields decoded from the wire against the actual datagram
    /// size before any allocation.
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(b);
        Ok(u64::from_le_bytes(array))
    }

    fn read_str(&mut self) -> Result<String, WireError> {
        let len = self.read_u16()? as usize;
        let bytes = self.take(len)?;
        std::str::from_utf8(bytes)
            .map(|s| s.to_string())
            .map_err(|_| WireError::InvalidUtf8)
    }

    fn read_node(&mut self) -> Result<NodeId, WireError> {
        Ok(NodeId::new(self.read_str()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(s: &str) -> NodeId {
        NodeId::new(s)
    }

    fn roundtrip(packet: &Packet) {
        let encoded = encode_packet(packet, DEFAULT_MTU).expect("encode");
        assert_eq!(encoded.gossip_dropped, 0);
        let decoded = decode_packet(&encoded.bytes).expect("decode");
        assert_eq!(&decoded, packet);
    }

    #[test]
    fn payload_roundtrips() {
        roundtrip(&Packet::new(Payload::Ping { seq: 7 }));
        roundtrip(&Packet::new(Payload::Ack { seq: 9 }));
        roundtrip(&Packet::new(Payload::PingReq {
            seq: 11,
            target: node("node-b"),
        }));
        roundtrip(&Packet::new(Payload::Nack { seq: 13 }));
    }

    #[test]
    fn gossip_roundtrips() {
        let packet = Packet {
            payload: Payload::Ping { seq: 1 },
            gossip: vec![
                Rumor::alive(node("a"), 3),
                Rumor::suspect(node("b"), 5, node("c")),
                Rumor::confirm(node("d"), 7, node("e")),
                Rumor::leave(node("f"), 9),
            ],
        };
        roundtrip(&packet);
    }

    #[test]
    fn mtu_budget_truncates_gossip_tail() {
        let mut gossip = Vec::new();
        for i in 0..50 {
            gossip.push(Rumor::alive(node(&format!("node-{i}")), i));
        }
        let packet = Packet {
            payload: Payload::Ping { seq: 1 },
            gossip,
        };
        // A tiny MTU admits the payload + only a few rumors.
        let encoded = encode_packet(&packet, 64).expect("encode");
        assert!(encoded.bytes.len() <= 64);
        assert!(encoded.gossip_included < 50);
        assert_eq!(
            encoded.gossip_included + encoded.gossip_dropped,
            packet.gossip.len()
        );
        // What survived decodes cleanly (a prefix of the gossip).
        let decoded = decode_packet(&encoded.bytes).expect("decode");
        assert_eq!(decoded.gossip.len(), encoded.gossip_included);
        assert_eq!(decoded.payload, Payload::Ping { seq: 1 });
    }

    #[test]
    fn payload_exceeding_mtu_errors() {
        let packet = Packet::new(Payload::PingReq {
            seq: 1,
            target: node("a-very-long-node-identifier-that-will-not-fit"),
        });
        assert_eq!(encode_packet(&packet, 8), Err(WireError::PayloadExceedsMtu));
    }

    #[test]
    fn decode_rejects_bad_input() {
        assert_eq!(decode_packet(&[]), Err(WireError::UnexpectedEof));
        assert_eq!(decode_packet(&[9, 0]), Err(WireError::UnknownVersion(9)));
        // Version ok, unknown payload tag.
        assert_eq!(
            decode_packet(&[WIRE_VERSION, 99]),
            Err(WireError::UnknownPayloadTag(99))
        );
        // Truncated mid-payload (ping tag but no u64 seq).
        assert_eq!(
            decode_packet(&[WIRE_VERSION, 0, 1, 2]),
            Err(WireError::UnexpectedEof)
        );
    }

    #[test]
    fn decode_caps_gossip_capacity_to_remaining_bytes() {
        // Off-wire allocation-amplification guard: a tiny datagram claiming the
        // maximum gossip count (u16::MAX) must NOT eagerly reserve ~65535 rumor
        // slots. The pre-allocation is bounded by remaining bytes / MIN_RUMOR_BYTES
        // (here 0), so the decode fails cleanly at EOF with no giant allocation
        // and no panic — pre-fix this forced a ~4 MiB reservation per 12-byte
        // packet.
        let mut dgram = vec![WIRE_VERSION, 0]; // version + Ping tag
        dgram.extend_from_slice(&0u64.to_le_bytes()); // seq
        dgram.extend_from_slice(&u16::MAX.to_le_bytes()); // gossip count = 65535
        assert_eq!(dgram.len(), 12);
        assert_eq!(decode_packet(&dgram), Err(WireError::UnexpectedEof));
    }

    #[test]
    fn determinism() {
        let packet = Packet {
            payload: Payload::Ack { seq: 42 },
            gossip: vec![Rumor::suspect(node("x"), 2, node("y"))],
        };
        let a = encode_packet(&packet, DEFAULT_MTU).expect("a");
        let b = encode_packet(&packet, DEFAULT_MTU).expect("b");
        assert_eq!(a, b);
    }
}
