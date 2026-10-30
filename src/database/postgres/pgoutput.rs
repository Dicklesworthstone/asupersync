//! Borrowing decoder for PostgreSQL's `pgoutput` protocol version 1.
//!
//! Decode the `data` portion of a replication `XLogData` event, after its WAL
//! envelope has been removed. Names and tuple payloads borrow that buffer;
//! only column and tuple descriptors are allocated. Counts and lengths are
//! checked against available input before allocation. Tuple text remains raw
//! bytes, keeping NULL, an unchanged TOAST value, and empty text distinct.
//!
//! This module decodes messages, not transaction application or durability.
//! The consumer owns relation metadata, transaction assembly, and the decision
//! to acknowledge a committed LSN. Versions 2 through 4, including streamed
//! transactions and two-phase commit, are deliberately rejected.
//!
//! Wire reference: <https://www.postgresql.org/docs/current/protocol-logicalrep-message-formats.html>.

use super::replication::PgLsn;
use std::fmt;
use std::iter::FusedIterator;

/// A malformed or unsupported `pgoutput` payload.
///
/// Diagnostics expose offsets and format expectations, never row contents.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PgOutputError {
    /// A fixed-width field, string terminator, or payload is incomplete.
    Truncated {
        /// Byte offset of the incomplete field.
        offset: usize,
        /// Minimum bytes required at that offset.
        needed: usize,
        /// Bytes actually available at that offset.
        remaining: usize,
    },
    /// A field violates the negotiated version-1 representation.
    Invalid {
        /// Byte offset of the invalid field.
        offset: usize,
        /// Static format expectation without server-supplied data.
        reason: &'static str,
    },
    /// This tag is not supported by the version-1 decoder.
    UnsupportedMessage {
        /// Byte offset of the message tag.
        offset: usize,
        /// The unrecognized or newer-protocol tag.
        tag: u8,
    },
    /// Strict single-message decoding found additional bytes.
    TrailingBytes {
        /// Offset immediately after the complete message.
        offset: usize,
        /// Number of unconsumed bytes.
        remaining: usize,
    },
}

impl PgOutputError {
    /// Byte offset relative to the decoded buffer, or the iterator's input.
    #[must_use]
    pub const fn offset(&self) -> usize {
        match self {
            Self::Truncated { offset, .. }
            | Self::Invalid { offset, .. }
            | Self::UnsupportedMessage { offset, .. }
            | Self::TrailingBytes { offset, .. } => *offset,
        }
    }

    fn shifted(mut self, base: usize) -> Self {
        let offset = match &mut self {
            Self::Truncated { offset, .. }
            | Self::Invalid { offset, .. }
            | Self::UnsupportedMessage { offset, .. }
            | Self::TrailingBytes { offset, .. } => offset,
        };
        *offset = offset.saturating_add(base);
        self
    }
}

impl fmt::Display for PgOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { offset, needed, remaining } => write!(
                f,
                "incomplete pgoutput field at byte {offset}: need {needed} bytes, have {remaining}"
            ),
            Self::Invalid { offset, reason } => {
                write!(f, "invalid pgoutput field at byte {offset}: {reason}")
            }
            Self::UnsupportedMessage { offset, tag } => write!(
                f,
                "unsupported pgoutput version-1 message tag 0x{tag:02x} at byte {offset}"
            ),
            Self::TrailingBytes { offset, remaining } => write!(
                f,
                "{remaining} trailing pgoutput bytes after message ending at byte {offset}"
            ),
        }
    }
}

impl std::error::Error for PgOutputError {}

/// A published column's value, borrowing its wire payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PgTupleValue<'a> {
    /// SQL NULL, not an empty byte string.
    Null,
    /// The old TOAST value must be retained; no replacement bytes were sent.
    UnchangedToast,
    /// PostgreSQL text-format bytes in the session's encoding.
    Text(&'a [u8]),
    /// PostgreSQL binary-format bytes, interpreted using the column type OID.
    Binary(&'a [u8]),
}

/// Published column values in the corresponding Relation message's order.
pub type PgTuple<'a> = Vec<PgTupleValue<'a>>;

/// An old key or full row supplied by an UPDATE or DELETE.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PgOldTuple<'a> {
    /// Old key values selected by the relation's replica identity.
    Key(PgTuple<'a>),
    /// Old row values for a relation with FULL replica identity.
    Full(PgTuple<'a>),
}

/// Replica identity advertised by a Relation message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PgReplicaIdentity {
    /// Use the relation's primary key.
    Default,
    /// No old-row identity is published.
    Nothing,
    /// Publish the full old row.
    Full,
    /// Use a selected replica identity index.
    Index,
}

/// One published column in a relation description.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PgRelationColumn<'a> {
    /// Whether this column participates in the replica identity key.
    pub key: bool,
    /// Column name in UTF-8.
    pub name: &'a str,
    /// PostgreSQL type OID.
    pub type_oid: u32,
    /// PostgreSQL type modifier, including negative sentinel values.
    pub type_modifier: i32,
}

/// Relation metadata, replaced when the publisher announces a schema change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PgRelation<'a> {
    /// Publisher-local relation OID used by subsequent changes.
    pub id: u32,
    /// Namespace; an empty value denotes `pg_catalog` on the wire.
    pub namespace: &'a str,
    /// Relation name.
    pub name: &'a str,
    /// Old-row identity policy.
    pub replica_identity: PgReplicaIdentity,
    /// Columns included in this publication, in tuple order.
    pub columns: Vec<PgRelationColumn<'a>>,
}

/// A decoded version-1 message. Timestamps retain PostgreSQL's signed
/// microseconds since 2000-01-01; they are not Unix timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PgOutputMessage<'a> {
    /// Start of a committed transaction's change sequence.
    Begin {
        /// Final LSN advertised for this transaction.
        final_lsn: PgLsn,
        /// Commit timestamp in PostgreSQL microseconds.
        commit_time_micros: i64,
        /// Publisher transaction ID.
        xid: u32,
    },
    /// End of the transaction. Acknowledgment remains the consumer's decision.
    Commit {
        /// Commit record LSN.
        commit_lsn: PgLsn,
        /// End of the transaction's WAL record.
        end_lsn: PgLsn,
        /// Commit timestamp in PostgreSQL microseconds.
        commit_time_micros: i64,
    },
    /// Origin information for a transaction replicated from another node.
    Origin {
        /// Commit LSN at the origin.
        origin_lsn: PgLsn,
        /// Origin name.
        name: &'a str,
    },
    /// Published relation metadata.
    Relation(PgRelation<'a>),
    /// Name of a non-built-in PostgreSQL type.
    Type {
        /// Publisher-local type OID.
        id: u32,
        /// Type namespace.
        namespace: &'a str,
        /// Type name.
        name: &'a str,
    },
    /// A new row.
    Insert {
        /// OID from the relation description.
        relation_id: u32,
        /// New published column values.
        new_tuple: PgTuple<'a>,
    },
    /// Changed row values, optionally accompanied by the old key or full row.
    Update {
        /// OID from the relation description.
        relation_id: u32,
        /// Previous identity, when present on the wire.
        old_tuple: Option<PgOldTuple<'a>>,
        /// New published column values.
        new_tuple: PgTuple<'a>,
    },
    /// Deletion identified by an old key or full row.
    Delete {
        /// OID from the relation description.
        relation_id: u32,
        /// The row identity supplied by the publisher.
        old_tuple: PgOldTuple<'a>,
    },
    /// Truncation of one or more relations.
    Truncate {
        /// Publisher-local relation OIDs.
        relation_ids: Vec<u32>,
        /// Whether CASCADE was requested.
        cascade: bool,
        /// Whether RESTART IDENTITY was requested.
        restart_identity: bool,
    },
    /// An application message emitted through `pg_logical_emit_message`.
    Message {
        /// Whether the application message is transactional.
        transactional: bool,
        /// LSN associated with the application message.
        lsn: PgLsn,
        /// Application prefix in UTF-8.
        prefix: &'a str,
        /// Opaque application payload; no UTF-8 assumption is made.
        content: &'a [u8],
    },
}

/// Decode exactly one `pgoutput` version-1 message.
///
/// Extra bytes are rejected. Use [`decode_pgoutput_prefix`] or
/// [`PgOutputMessages`] when an application buffer contains several messages.
pub fn decode_pgoutput(data: &[u8]) -> Result<PgOutputMessage<'_>, PgOutputError> {
    let (message, consumed) = decode_pgoutput_prefix(data)?;
    if consumed != data.len() {
        return Err(PgOutputError::TrailingBytes {
            offset: consumed,
            remaining: data.len() - consumed,
        });
    }
    Ok(message)
}

/// Decode the first message and return its byte length.
///
/// An incomplete message returns an error without a partial value. The input
/// is never changed, so a caller can retain and extend its buffer if needed.
pub fn decode_pgoutput_prefix(data: &[u8]) -> Result<(PgOutputMessage<'_>, usize), PgOutputError> {
    let mut input = Input { data, offset: 0 };
    let tag = input.byte()?;
    let message = match tag {
        b'B' => PgOutputMessage::Begin {
            final_lsn: input.lsn()?,
            commit_time_micros: input.i64()?,
            xid: input.u32()?,
        },
        b'C' => {
            input.flags(0)?;
            PgOutputMessage::Commit {
                commit_lsn: input.lsn()?,
                end_lsn: input.lsn()?,
                commit_time_micros: input.i64()?,
            }
        }
        b'O' => PgOutputMessage::Origin {
            origin_lsn: input.lsn()?,
            name: input.string()?,
        },
        b'R' => PgOutputMessage::Relation(input.relation()?),
        b'Y' => PgOutputMessage::Type {
            id: input.u32()?,
            namespace: input.string()?,
            name: input.string()?,
        },
        b'I' => {
            let relation_id = input.u32()?;
            input.expect(b'N')?;
            PgOutputMessage::Insert { relation_id, new_tuple: input.tuple()? }
        }
        b'U' => {
            let relation_id = input.u32()?;
            let tuple_tag = input.byte()?;
            let old_tuple = if tuple_tag == b'N' {
                None
            } else {
                let old = input.old_tuple(tuple_tag)?;
                input.expect(b'N')?;
                Some(old)
            };
            PgOutputMessage::Update { relation_id, old_tuple, new_tuple: input.tuple()? }
        }
        b'D' => {
            let relation_id = input.u32()?;
            let tuple_tag = input.byte()?;
            PgOutputMessage::Delete { relation_id, old_tuple: input.old_tuple(tuple_tag)? }
        }
        b'T' => {
            let count_offset = input.offset;
            let count = usize::try_from(input.u32()?).map_err(|_| PgOutputError::Invalid {
                offset: count_offset,
                reason: "relation count exceeds address space",
            })?;
            let flags = input.flags(3)?;
            let bytes = count.checked_mul(4).ok_or(PgOutputError::Invalid {
                offset: count_offset,
                reason: "relation count overflows its wire size",
            })?;
            input.ensure(bytes)?;
            let mut relation_ids = Vec::with_capacity(count);
            for _ in 0..count {
                relation_ids.push(input.u32()?);
            }
            PgOutputMessage::Truncate {
                relation_ids,
                cascade: flags & 1 != 0,
                restart_identity: flags & 2 != 0,
            }
        }
        b'M' => {
            let transactional = input.flags(1)? != 0;
            let lsn = input.lsn()?;
            let prefix = input.string()?;
            let content = input.sized_bytes()?;
            PgOutputMessage::Message { transactional, lsn, prefix, content }
        }
        tag => return Err(PgOutputError::UnsupportedMessage { offset: 0, tag }),
    };
    Ok((message, input.offset))
}

/// Decode consecutive messages from one application buffer without copying
/// their payloads.
///
/// An error is yielded once, then iteration stops; malformed bytes are never
/// skipped in an attempt to resynchronize the change stream.
#[derive(Debug, Clone)]
pub struct PgOutputMessages<'a> {
    remaining: &'a [u8],
    offset: usize,
}

impl<'a> PgOutputMessages<'a> {
    /// Borrow a buffer containing zero or more complete messages.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { remaining: data, offset: 0 }
    }
}

impl<'a> Iterator for PgOutputMessages<'a> {
    type Item = Result<PgOutputMessage<'a>, PgOutputError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        match decode_pgoutput_prefix(self.remaining) {
            Ok((message, consumed)) => {
                self.remaining = &self.remaining[consumed..];
                self.offset += consumed;
                Some(Ok(message))
            }
            Err(error) => {
                self.remaining = &[];
                Some(Err(error.shifted(self.offset)))
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining.len()))
    }
}

impl FusedIterator for PgOutputMessages<'_> {}

struct Input<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Input<'a> {
    fn ensure(&self, needed: usize) -> Result<(), PgOutputError> {
        let remaining = self.data.len() - self.offset;
        if needed > remaining {
            return Err(PgOutputError::Truncated { offset: self.offset, needed, remaining });
        }
        Ok(())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], PgOutputError> {
        self.ensure(length)?;
        let data = &self.data[self.offset..self.offset + length];
        self.offset += length;
        Ok(data)
    }

    fn byte(&mut self) -> Result<u8, PgOutputError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PgOutputError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, PgOutputError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i32(&mut self) -> Result<i32, PgOutputError> {
        let bytes = self.take(4)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i64(&mut self) -> Result<i64, PgOutputError> {
        let bytes = self.take(8)?;
        Ok(i64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn lsn(&mut self) -> Result<PgLsn, PgOutputError> {
        let bytes = self.take(8)?;
        Ok(PgLsn::new(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ])))
    }

    fn string(&mut self) -> Result<&'a str, PgOutputError> {
        let offset = self.offset;
        let remaining = &self.data[offset..];
        let length = remaining.iter().position(|byte| *byte == 0).ok_or(
            PgOutputError::Truncated {
                offset,
                needed: remaining.len().saturating_add(1),
                remaining: remaining.len(),
            },
        )?;
        let bytes = self.take(length + 1)?;
        std::str::from_utf8(&bytes[..length]).map_err(|_| PgOutputError::Invalid {
            offset,
            reason: "name or prefix is not UTF-8",
        })
    }

    fn expect(&mut self, expected: u8) -> Result<(), PgOutputError> {
        let offset = self.offset;
        if self.byte()? != expected {
            return Err(PgOutputError::Invalid { offset, reason: "expected a new-tuple marker" });
        }
        Ok(())
    }

    fn flags(&mut self, allowed: u8) -> Result<u8, PgOutputError> {
        let offset = self.offset;
        let flags = self.byte()?;
        if flags & !allowed != 0 {
            return Err(PgOutputError::Invalid { offset, reason: "unknown flag bits" });
        }
        Ok(flags)
    }

    fn sized_bytes(&mut self) -> Result<&'a [u8], PgOutputError> {
        let offset = self.offset;
        let length = self.i32()?;
        let length = usize::try_from(length).map_err(|_| PgOutputError::Invalid {
            offset,
            reason: "negative or unrepresentable payload length",
        })?;
        self.take(length)
    }

    fn tuple(&mut self) -> Result<PgTuple<'a>, PgOutputError> {
        let count = usize::from(self.u16()?);
        // Every value needs at least its one-byte tag. A malicious count must
        // not reserve memory when even those tags cannot fit in the payload.
        self.ensure(count)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            let offset = self.offset;
            values.push(match self.byte()? {
                b'n' => PgTupleValue::Null,
                b'u' => PgTupleValue::UnchangedToast,
                b't' => PgTupleValue::Text(self.sized_bytes()?),
                b'b' => PgTupleValue::Binary(self.sized_bytes()?),
                _ => return Err(PgOutputError::Invalid { offset, reason: "unknown tuple value tag" }),
            });
        }
        Ok(values)
    }

    fn old_tuple(&mut self, tag: u8) -> Result<PgOldTuple<'a>, PgOutputError> {
        match tag {
            b'K' => Ok(PgOldTuple::Key(self.tuple()?)),
            b'O' => Ok(PgOldTuple::Full(self.tuple()?)),
            _ => Err(PgOutputError::Invalid {
                offset: self.offset - 1,
                reason: "expected an old-key or old-row tuple marker",
            }),
        }
    }

    fn relation(&mut self) -> Result<PgRelation<'a>, PgOutputError> {
        let id = self.u32()?;
        let namespace = self.string()?;
        let name = self.string()?;
        let offset = self.offset;
        let replica_identity = match self.byte()? {
            b'd' => PgReplicaIdentity::Default,
            b'n' => PgReplicaIdentity::Nothing,
            b'f' => PgReplicaIdentity::Full,
            b'i' => PgReplicaIdentity::Index,
            _ => return Err(PgOutputError::Invalid { offset, reason: "unknown replica identity" }),
        };
        let count = usize::from(self.u16()?);
        // Minimum column representation: flags, NUL, type OID and modifier.
        self.ensure(count * 10)?;
        let mut columns = Vec::with_capacity(count);
        for _ in 0..count {
            columns.push(PgRelationColumn {
                key: self.flags(1)? != 0,
                name: self.string()?,
                type_oid: self.u32()?,
                type_modifier: self.i32()?,
            });
        }
        Ok(PgRelation { id, namespace, name, replica_identity, columns })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent wire fixtures follow the published v1 format; no production
    // encoder generates the bytes that the decoder is expected to accept.
    const BEGIN: &[u8] = &[
        b'B', 0x80, 0, 0, 0, 0, 0, 0, 1, // unsigned LSN above i64::MAX
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // timestamp -1
        0, 0, 0, 42,
    ];
    const COMMIT: &[u8] = &[
        b'C', 0, 0, 0, 0, 0, 0, 0, 0, 10, // commit LSN
        0, 0, 0, 0, 0, 0, 0, 11, // transaction end LSN
        0, 0, 0, 0, 0, 0, 0, 12, // timestamp
    ];
    const RELATION: &[u8] = b"R\0\0\0\x2apublic\0widgets\0f\0\x02\x01id\0\0\0\0\x17\xff\xff\xff\xff\0payload\0\0\0\0\x19\0\0\0\x64";
    const TYPE: &[u8] = b"Y\0\0\xc3\x50custom\0widget_type\0";
    const ORIGIN: &[u8] = b"O\0\0\0\0\0\0\0\x0anode-a\0";
    const INSERT: &[u8] = &[
        b'I', 0, 0, 0, 42, b'N', 0, 5,
        b'n', b'u', b't', 0, 0, 0, 0,
        b't', 0, 0, 0, 2, 0xff, 0,
        b'b', 0, 0, 0, 3, 0, 1, 0xff,
    ];
    const UPDATE: &[u8] = b"U\0\0\0\x2aK\0\x01t\0\0\0\x03oldN\0\x01t\0\0\0\x03new";
    const DELETE: &[u8] = b"D\0\0\0\x2aO\0\x01n";
    const TRUNCATE: &[u8] = b"T\0\0\0\x02\x03\0\0\0\x2a\xff\xff\xff\xff";
    const MESSAGE: &[u8] = b"M\x01\0\0\0\0\0\0\0\x0atopic\0\0\0\0\x03\xff\0\x01";

    #[test]
    fn pgoutput_transaction_boundaries_preserve_lsn_and_signed_timestamp() {
        assert_eq!(
            decode_pgoutput(BEGIN).unwrap(),
            PgOutputMessage::Begin {
                final_lsn: PgLsn::new(0x8000_0000_0000_0001),
                commit_time_micros: -1,
                xid: 42,
            },
        );
        assert_eq!(
            decode_pgoutput(COMMIT).unwrap(),
            PgOutputMessage::Commit {
                commit_lsn: PgLsn::new(10),
                end_lsn: PgLsn::new(11),
                commit_time_micros: 12,
            },
        );
    }

    #[test]
    fn pgoutput_relation_type_and_origin_decode_publisher_metadata() {
        let PgOutputMessage::Relation(relation) = decode_pgoutput(RELATION).unwrap() else {
            panic!("expected a relation");
        };
        assert_eq!(relation.id, 42);
        assert_eq!(relation.namespace, "public");
        assert_eq!(relation.name, "widgets");
        assert_eq!(relation.replica_identity, PgReplicaIdentity::Full);
        assert_eq!(relation.columns, vec![
            PgRelationColumn { key: true, name: "id", type_oid: 23, type_modifier: -1 },
            PgRelationColumn { key: false, name: "payload", type_oid: 25, type_modifier: 100 },
        ]);
        assert_eq!(relation.namespace.as_ptr(), RELATION[5..].as_ptr());
        assert_eq!(
            decode_pgoutput(TYPE).unwrap(),
            PgOutputMessage::Type { id: 50_000, namespace: "custom", name: "widget_type" },
        );
        assert_eq!(
            decode_pgoutput(ORIGIN).unwrap(),
            PgOutputMessage::Origin { origin_lsn: PgLsn::new(10), name: "node-a" },
        );
    }

    #[test]
    fn pgoutput_tuple_values_distinguish_null_toast_empty_text_and_binary_without_copies() {
        let PgOutputMessage::Insert { relation_id, new_tuple } = decode_pgoutput(INSERT).unwrap() else {
            panic!("expected an insert");
        };
        assert_eq!(relation_id, 42);
        assert_eq!(new_tuple, vec![
            PgTupleValue::Null,
            PgTupleValue::UnchangedToast,
            PgTupleValue::Text(b""),
            PgTupleValue::Text(&[0xff, 0]),
            PgTupleValue::Binary(&[0, 1, 0xff]),
        ]);
        let PgTupleValue::Text(text) = new_tuple[3] else { panic!("expected raw text bytes") };
        let PgTupleValue::Binary(binary) = new_tuple[4] else { panic!("expected binary bytes") };
        assert_eq!(text.as_ptr(), INSERT[20..].as_ptr());
        assert_eq!(binary.as_ptr(), INSERT[27..].as_ptr());
    }

    #[test]
    fn pgoutput_update_and_delete_preserve_old_key_or_full_row() {
        assert_eq!(
            decode_pgoutput(UPDATE).unwrap(),
            PgOutputMessage::Update {
                relation_id: 42,
                old_tuple: Some(PgOldTuple::Key(vec![PgTupleValue::Text(b"old")])),
                new_tuple: vec![PgTupleValue::Text(b"new")],
            },
        );
        assert_eq!(
            decode_pgoutput(b"U\0\0\0\x2aN\0\x01u").unwrap(),
            PgOutputMessage::Update {
                relation_id: 42,
                old_tuple: None,
                new_tuple: vec![PgTupleValue::UnchangedToast],
            },
        );
        assert_eq!(
            decode_pgoutput(b"U\0\0\0\x2aO\0\x01nN\0\x01t\0\0\0\0").unwrap(),
            PgOutputMessage::Update {
                relation_id: 42,
                old_tuple: Some(PgOldTuple::Full(vec![PgTupleValue::Null])),
                new_tuple: vec![PgTupleValue::Text(b"")],
            },
        );
        assert_eq!(
            decode_pgoutput(DELETE).unwrap(),
            PgOutputMessage::Delete {
                relation_id: 42,
                old_tuple: PgOldTuple::Full(vec![PgTupleValue::Null]),
            },
        );
        assert_eq!(
            decode_pgoutput(b"D\0\0\0\x2aK\0\x01b\0\0\0\x01\x07").unwrap(),
            PgOutputMessage::Delete {
                relation_id: 42,
                old_tuple: PgOldTuple::Key(vec![PgTupleValue::Binary(&[7])]),
            },
        );
    }

    #[test]
    fn pgoutput_truncate_and_application_messages_preserve_flags_and_bytes() {
        assert_eq!(
            decode_pgoutput(TRUNCATE).unwrap(),
            PgOutputMessage::Truncate {
                relation_ids: vec![42, u32::MAX],
                cascade: true,
                restart_identity: true,
            },
        );
        assert_eq!(
            decode_pgoutput(MESSAGE).unwrap(),
            PgOutputMessage::Message {
                transactional: true,
                lsn: PgLsn::new(10),
                prefix: "topic",
                content: &[0xff, 0, 1],
            },
        );
        let mut message = MESSAGE.to_vec();
        message[1] = 0;
        assert!(matches!(decode_pgoutput(&message), Ok(PgOutputMessage::Message {
            transactional: false, ..
        })));
    }

    #[test]
    fn pgoutput_rejects_every_truncated_prefix_of_all_supported_message_families() {
        for wire in [BEGIN, COMMIT, RELATION, TYPE, ORIGIN, INSERT, UPDATE, DELETE, TRUNCATE, MESSAGE] {
            assert!(decode_pgoutput(wire).is_ok(), "fixture tag {}", wire[0]);
            for length in 0..wire.len() {
                assert!(
                    decode_pgoutput(&wire[..length]).is_err(),
                    "accepted incomplete tag {} at {length}/{}", wire[0], wire.len(),
                );
            }
        }
    }

    #[test]
    fn pgoutput_rejects_untrusted_counts_and_lengths_before_allocating_payloads() {
        for wire in [
            b"I\0\0\0\x01N\xff\xff".as_slice(),
            b"R\0\0\0\x01\0\0d\xff\xff".as_slice(),
            b"T\xff\xff\xff\xff\0".as_slice(),
            b"I\0\0\0\x01N\0\x01t\xff\xff\xff\xff".as_slice(),
            b"I\0\0\0\x01N\0\x01b\x7f\xff\xff\xff".as_slice(),
            b"M\0\0\0\0\0\0\0\0\x01\0\xff\xff\xff\xff".as_slice(),
        ] {
            assert!(decode_pgoutput(wire).is_err());
        }
    }

    #[test]
    fn pgoutput_rejects_reserved_flags_and_newer_protocol_tags() {
        for (wire, offset, flags) in [
            (COMMIT, 1, 1),
            (TRUNCATE, 5, 4),
            (MESSAGE, 1, 2),
            (RELATION, 23, 2),
        ] {
            let mut invalid = wire.to_vec();
            invalid[offset] = flags;
            assert!(matches!(decode_pgoutput(&invalid), Err(PgOutputError::Invalid { .. })));
        }
        for tag in [b'S', b'E', b'c', b'A', b'b', b'P', b'K', b'r', b'p', b'?', 0] {
            assert_eq!(
                decode_pgoutput(&[tag]),
                Err(PgOutputError::UnsupportedMessage { offset: 0, tag }),
            );
        }
    }

    #[test]
    fn pgoutput_rejects_bad_names_tuple_markers_and_conflicting_old_rows() {
        for wire in [
            b"Y\0\0\0\x01\xff\0name\0".as_slice(),
            b"Y\0\0\0\x01public\0unterminated".as_slice(),
            b"R\0\0\0\x01public\0name\0z\0\0".as_slice(),
            b"I\0\0\0\x01O\0\0".as_slice(),
            b"D\0\0\0\x01N\0\0".as_slice(),
            b"I\0\0\0\x01N\0\x01x".as_slice(),
            b"U\0\0\0\x01K\0\0O\0\0N\0\0".as_slice(),
        ] {
            assert!(decode_pgoutput(wire).is_err());
        }
        let error = decode_pgoutput(b"Y\0\0\0\x01private-name\0unterminated-secret").unwrap_err();
        assert!(!error.to_string().contains("secret"));
        assert!(!error.to_string().contains("private"));
    }

    #[test]
    fn pgoutput_strict_prefix_and_batch_decoding_have_explicit_boundaries() {
        let mut batch = BEGIN.to_vec();
        batch.extend_from_slice(COMMIT);
        assert_eq!(
            decode_pgoutput(&batch),
            Err(PgOutputError::TrailingBytes { offset: BEGIN.len(), remaining: COMMIT.len() }),
        );
        let (first, consumed) = decode_pgoutput_prefix(&batch).unwrap();
        assert_eq!(first, decode_pgoutput(BEGIN).unwrap());
        assert_eq!(consumed, BEGIN.len());
        let messages = PgOutputMessages::new(&batch).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(messages, vec![decode_pgoutput(BEGIN).unwrap(), decode_pgoutput(COMMIT).unwrap()]);

        batch.insert(BEGIN.len(), b'?');
        let mut messages = PgOutputMessages::new(&batch);
        assert!(messages.next().unwrap().is_ok());
        assert_eq!(messages.next(), Some(Err(PgOutputError::UnsupportedMessage {
            offset: BEGIN.len(), tag: b'?',
        })));
        assert!(messages.next().is_none(), "do not skip a bad record and expose a later commit");
        assert!(messages.next().is_none());
        assert!(PgOutputMessages::new(&[]).next().is_none());
    }
}
