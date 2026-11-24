//! Explicit logical-slot setup and a borrowed exported-snapshot lifetime.

use super::super::{IsolationLevel, PgTransaction};
use super::{
    Cx, FrontendMessage, MessageBuffer, MessageReader, Outcome, PendingWrite, PgConnection,
    PgError, PgLsn, PgReplicationConfig, PgReplicationConnection, ReplicationControl, WriteKind,
    outcome_from_error, poll_pending_write, protocol, quote_postgres_identifier,
    unexpected_backend_message,
};
use std::future::poll_fn;

// Control responses contain four small scalar fields, never WAL or query data.
const MAX_SLOT_CONTROL_MESSAGE_BYTES: usize = 16 * 1024;

/// Publisher identity and WAL position returned by `IDENTIFY_SYSTEM`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgReplicationIdentity {
    /// Cluster identifier. Persist it with checkpoints to detect a different
    /// cluster after reconnecting.
    pub system_id: u64,
    /// Current WAL timeline. Promotion can change it without changing the cluster.
    pub timeline: u32,
    /// Current WAL flush position, not an application durability acknowledgement.
    pub wal_position: PgLsn,
    /// Database selected by this connection, if supplied by the server.
    pub database: Option<String>,
}

/// Options for explicitly creating a logical slot using `pgoutput`.
///
/// The default is a persistent slot with an exported consistent snapshot.
/// Persistent slots retain WAL until the application acknowledges progress or
/// explicitly drops the slot; this API never automatically deletes one.
#[derive(Debug, Clone)]
pub struct PgReplicationSlotOptions {
    name: String,
    temporary: bool,
    export_snapshot: bool,
    two_phase: bool,
}

impl PgReplicationSlotOptions {
    /// Validate a slot name before any network or server-side effect.
    pub fn new(name: impl Into<String>) -> Result<Self, PgError> {
        let name = name.into();
        validate_slot_name(&name)?;
        Ok(Self {
            name,
            temporary: false,
            export_snapshot: true,
            two_phase: false,
        })
    }

    /// Bind the slot to this server session. PostgreSQL drops temporary slots
    /// on a session error or disconnect; they cannot be resumed after reconnecting.
    #[must_use]
    pub fn temporary(mut self, enabled: bool) -> Self {
        self.temporary = enabled;
        self
    }

    /// Export a snapshot for the initial table copy (enabled by default).
    /// Disabling this returns only the consistent WAL position.
    #[must_use]
    pub fn export_snapshot(mut self, enabled: bool) -> Self {
        self.export_snapshot = enabled;
        self
    }

    /// Enable decoding of prepared transactions. This option requires
    /// PostgreSQL 15 or later and composes with snapshot export.
    #[must_use]
    pub fn two_phase(mut self, enabled: bool) -> Self {
        self.two_phase = enabled;
        self
    }

    fn command(&self) -> String {
        let temporary = if self.temporary { " TEMPORARY" } else { "" };
        let prefix = format!(
            "CREATE_REPLICATION_SLOT {}{temporary} LOGICAL pgoutput",
            quote_postgres_identifier(&self.name)
        );
        // Keep the ordinary path compatible with pre-15 servers. The
        // parenthesized options introduced in 15 allow TWO_PHASE and SNAPSHOT
        // together, which the legacy single-option grammar cannot express.
        if self.two_phase {
            let snapshot = if self.export_snapshot {
                "export"
            } else {
                "nothing"
            };
            format!("{prefix} (TWO_PHASE true, SNAPSHOT '{snapshot}')")
        } else {
            let snapshot = if self.export_snapshot {
                "EXPORT_SNAPSHOT"
            } else {
                "NOEXPORT_SNAPSHOT"
            };
            format!("{prefix} {snapshot}")
        }
    }
}

/// A newly created slot and its optional exported snapshot.
///
/// This value borrows the replication connection, preventing another command
/// from invalidating the snapshot while it is being imported. Open a separate
/// ordinary connection to the same publisher and database, then use
/// [`Self::import_snapshot`] in a `REPEATABLE READ` transaction before reading
/// any table. After import, the transaction retains
/// its snapshot independently. Build a stream config with
/// [`Self::replication_config`], release this value, and start streaming from
/// the consistent position. Multiple readers may import the same snapshot.
///
/// Dropping this value does not issue a command or drop the slot. A copied
/// snapshot name is valid only until the next command on the replication
/// connection or its disconnect. Losing the creation response is ambiguous:
/// a persistent slot may already exist and must not be recreated blindly.
#[derive(Debug)]
pub struct PgReplicationSlot<'connection> {
    connection: &'connection mut PgReplicationConnection,
    options: PgReplicationSlotOptions,
    consistent_point: PgLsn,
    snapshot_name: Option<String>,
}

impl PgReplicationSlot<'_> {
    /// Name of the slot that PostgreSQL acknowledged creating.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.options.name
    }

    /// First WAL position consistent with the exported table snapshot.
    #[must_use]
    pub const fn consistent_point(&self) -> PgLsn {
        self.consistent_point
    }

    /// Exported snapshot identifier, absent when export was disabled.
    #[must_use]
    pub fn snapshot_name(&self) -> Option<&str> {
        self.snapshot_name.as_deref()
    }

    /// Whether PostgreSQL will discard this slot when its session ends.
    #[must_use]
    pub const fn is_temporary(&self) -> bool {
        self.options.temporary
    }

    /// Build a stream configuration at the slot's consistent point, retaining
    /// its two-phase setting. Publications must already exist on the publisher.
    pub fn replication_config<I, S>(&self, publications: I) -> Result<PgReplicationConfig, PgError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        PgReplicationConfig::new(self.name(), publications, self.consistent_point)
            .map(|config| config.two_phase(self.options.two_phase))
    }
    /// Import this snapshot into a separate ordinary connection's transaction.
    ///
    /// The receiving connection must target the same publisher and database.
    /// Begin with `begin_with_isolation(RepeatableRead, true)` and call this
    /// before its first table query. PostgreSQL checks snapshot validity and
    /// transaction state. Multiple transactions may import this snapshot.
    ///
    /// The replication connection stays borrowed through the await. The
    /// original owner's and caller's cancellation/deadline bounds both apply.
    /// An interrupted import poisons the receiving transaction for rollback
    /// and closes any incomplete wire exchange; it cannot be reused with an
    /// uncertain snapshot. No command is sent on the replication connection.
    pub async fn import_snapshot(
        &self,
        cx: &Cx,
        transaction: &mut PgTransaction<'_>,
    ) -> Outcome<(), PgError> {
        let Some(snapshot) = self.snapshot_name() else {
            return Outcome::Err(protocol("this replication slot did not export a snapshot"));
        };
        if transaction.isolation_level() != Some(IsolationLevel::RepeatableRead) {
            return Outcome::Err(protocol(
                "replication snapshots require an explicitly REPEATABLE READ transaction",
            ));
        }
        // Validate on receipt and quote independently of the server's spelling.
        let sql = format!("SET TRANSACTION SNAPSHOT '{}'", snapshot.replace('\'', "''"));
        let mut control = ReplicationControl::new(&self.connection.owner);
        let mut guard = SnapshotImportGuard {
            transaction,
            owner: cx.clone(),
            complete: false,
        };
        let result = control
            .drive(cx, async {
                Ok(guard.transaction.execute_unchecked(cx, &sql).await)
            })
            .await;
        match result {
            Ok(Outcome::Ok(_)) => {
                guard.complete = true;
                Outcome::Ok(())
            }
            Err(error) => {
                // The outer owner can cancel independently of the receiving
                // query's Cx. Its partially sent operation still needs cleanup.
                if matches!(&error, PgError::Cancelled(_))
                    && guard.transaction.conn.inner.closed
                {
                    cx.with_ambient(guard.transaction.conn.wire_cancel_in_drain(cx))
                        .await;
                }
                outcome_from_error(error)
            }
            Ok(Outcome::Err(error)) => outcome_from_error(error),
            Ok(Outcome::Cancelled(reason)) => Outcome::Cancelled(reason),
            Ok(Outcome::Panicked(payload)) => Outcome::Panicked(payload),
        }
    }

}

impl Drop for PgReplicationSlot<'_> {
    fn drop(&mut self) {
        // Retain the exclusive borrow through destruction. Releasing this
        // handle has no wire effect and leaves persistent slots intact.
        let _ = &self.connection;
    }
}

impl PgReplicationConnection {
    /// Identify the publisher before accepting an existing checkpoint.
    /// Like any command, this invalidates a previously exported snapshot.
    pub async fn identify_system(&mut self, cx: &Cx) -> Outcome<PgReplicationIdentity, PgError> {
        match self
            .slot_command(cx, "IDENTIFY_SYSTEM", ControlKind::Identify, parse_identity)
            .await
        {
            Ok(identity) => Outcome::Ok(identity),
            Err(error) => outcome_from_error(error),
        }
    }

    /// Explicitly create a logical `pgoutput` slot and retain its exported
    /// snapshot until the application has imported it.
    ///
    /// No retry or reconnect is performed. Dropping an in-flight future closes
    /// its socket; if a persistent slot was created before that disconnect,
    /// it remains on the server. An existing slot is an error, never adopted
    /// implicitly. Cancellation attempts a bounded wire CancelRequest.
    pub async fn create_slot(
        &mut self,
        cx: &Cx,
        options: PgReplicationSlotOptions,
    ) -> Outcome<PgReplicationSlot<'_>, PgError> {
        let command = options.command();
        let result = self
            .slot_command(cx, &command, ControlKind::Create, |row| {
                parse_created(row, &options)
            })
            .await;
        match result {
            Ok((consistent_point, snapshot_name)) => Outcome::Ok(PgReplicationSlot {
                connection: self,
                options,
                consistent_point,
                snapshot_name,
            }),
            Err(error) => outcome_from_error(error),
        }
    }

    /// Explicitly release a replication slot's server-side resources.
    ///
    /// `wait` asks PostgreSQL to wait for an active slot to become inactive.
    /// The caller's and original owner's deadlines still bound that wait.
    /// A lost acknowledgement has an ambiguous outcome and is never retried.
    pub async fn drop_slot(&mut self, cx: &Cx, name: &str, wait: bool) -> Outcome<(), PgError> {
        if let Err(error) = validate_slot_name(name) {
            return Outcome::Err(error);
        }
        let command = format!(
            "DROP_REPLICATION_SLOT {}{}",
            quote_postgres_identifier(name),
            if wait { " WAIT" } else { "" },
        );
        match self
            .slot_command(cx, &command, ControlKind::Drop, |_| Ok(()))
            .await
        {
            Ok(()) => Outcome::Ok(()),
            Err(error) => outcome_from_error(error),
        }
    }

    async fn slot_command<T>(
        &mut self,
        cx: &Cx,
        command: &str,
        kind: ControlKind,
        decode: impl FnOnce(ControlRow) -> Result<T, PgError>,
    ) -> Result<T, PgError> {
        let owner = self.owner.clone();
        let mut control = ReplicationControl::new(&owner);
        // Pre-admission cancellation/authority denial must not consume a
        // healthy connection or emit a mutation to the server.
        control.drive(cx, async { Ok(()) }).await?;
        let connection = self.connection.as_mut().ok_or(PgError::ConnectionClosed)?;
        if connection.inner.closed {
            return Err(PgError::ConnectionClosed);
        }
        let mut message = MessageBuffer::new();
        message.write_cstring(command);
        let message = message.build_message(FrontendMessage::Query as u8)?;
        let mut pending = PendingWrite::new(message, WriteKind::Start);
        connection.inner.closed = true;
        let mut guard = SlotCommandGuard {
            connection,
            owner: owner.clone(),
            complete: false,
        };
        let result = control
            .drive(cx, async {
                poll_fn(|task| {
                    poll_pending_write(&mut pending, &mut guard.connection.inner.stream, task)
                })
                .await?;
                let mut response = ControlResponse::new(kind);
                loop {
                    let (tag, data) = guard
                        .connection
                        .read_message_buffered(
                            &owner,
                            MAX_SLOT_CONTROL_MESSAGE_BYTES,
                            "replication slot control",
                        )
                        .await?;
                    if tag == b'E' {
                        return Err(guard
                            .connection
                            .parse_error_response(&data)
                            .unwrap_or_else(|error| error));
                    }
                    if guard.connection.handle_async_backend_message(tag, &data)? {
                        crate::runtime::yield_now().await;
                        continue;
                    }
                    if response.accept(tag, &data)? {
                        guard.connection.handle_ready_for_query(&data)?;
                        return decode(response.row);
                    }
                    crate::runtime::yield_now().await;
                }
            })
            .await;
        match result {
            Ok(value) => {
                guard.connection.inner.closed = false;
                guard.complete = true;
                Ok(value)
            }
            Err(error) => {
                if matches!(&error, PgError::Cancelled(_)) {
                    owner
                        .with_ambient(guard.connection.wire_cancel_in_drain(&owner))
                        .await;
                }
                Err(error)
            }
        }
    }
}

struct SnapshotImportGuard<'transaction, 'connection> {
    transaction: &'transaction mut PgTransaction<'connection>,
    owner: Cx,
    complete: bool,
}

impl Drop for SnapshotImportGuard<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.transaction.poison_for_rollback();
            if self.transaction.conn.inner.closed {
                let _ambient = self.owner.clone().set_current_restricted();
                self.transaction.conn.abort_in_flight_exchange();
            }
        }
    }
}

struct SlotCommandGuard<'a> {
    connection: &'a mut PgConnection,
    owner: Cx,
    complete: bool,
}

impl Drop for SlotCommandGuard<'_> {
    fn drop(&mut self) {
        if !self.complete {
            let _ambient = self.owner.clone().set_current_restricted();
            self.connection.abort_in_flight_exchange();
        }
    }
}

pub(super) fn validate_slot_name(name: &str) -> Result<(), PgError> {
    if name.is_empty()
        || name.len() > 63
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(protocol(
            "slot name must be 1..=63 lowercase ASCII letters, digits, or underscores",
        ));
    }
    Ok(())
}

type ControlRow = Option<[Option<String>; 4]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlKind {
    Identify,
    Create,
    Drop,
}

impl ControlKind {
    const fn tag(self) -> &'static str {
        match self {
            Self::Identify => "IDENTIFY_SYSTEM",
            Self::Create => "CREATE_REPLICATION_SLOT",
            Self::Drop => "DROP_REPLICATION_SLOT",
        }
    }

    const fn columns(self) -> Option<[&'static str; 4]> {
        match self {
            Self::Identify => Some(["systemid", "timeline", "xlogpos", "dbname"]),
            Self::Create => Some([
                "slot_name",
                "consistent_point",
                "snapshot_name",
                "output_plugin",
            ]),
            Self::Drop => None,
        }
    }
}

struct ControlResponse {
    kind: ControlKind,
    described: bool,
    row: ControlRow,
    completed: bool,
}

impl ControlResponse {
    const fn new(kind: ControlKind) -> Self {
        Self {
            kind,
            described: false,
            row: None,
            completed: false,
        }
    }

    fn accept(&mut self, tag: u8, data: &[u8]) -> Result<bool, PgError> {
        let mut reader = MessageReader::new(data);
        match tag {
            b'T' if !self.described && !self.completed => {
                let names = self
                    .kind
                    .columns()
                    .ok_or_else(|| protocol("slot drop returned a row description"))?;
                if reader.read_i16()? != 4 {
                    return Err(protocol("replication control must describe exactly four columns"));
                }
                for (index, expected) in names.iter().enumerate() {
                    if reader.read_cstring()? != *expected {
                        return Err(protocol("unexpected replication control column name"));
                    }
                    let _table_oid = reader.read_i32()?;
                    let _column_id = reader.read_i16()?;
                    let oid = reader.read_i32()?;
                    let _type_size = reader.read_i16()?;
                    let _type_modifier = reader.read_i32()?;
                    let format = reader.read_i16()?;
                    // PostgreSQL changed the timeline from int4 to int8.
                    // Both carry the same unsigned 32-bit timeline identifier.
                    let valid_oid = if self.kind == ControlKind::Identify && index == 1 {
                        oid == 23 || oid == 20
                    } else {
                        oid == 25
                    };
                    if !valid_oid || format != 0 {
                        return Err(protocol("unexpected replication control column type or format"));
                    }
                }
                reader.ensure_consumed("replication control RowDescription")?;
                self.described = true;
            }
            b'D' if self.described && self.row.is_none() && !self.completed => {
                if reader.read_i16()? != 4 {
                    return Err(protocol("replication control must return exactly four values"));
                }
                let mut values = [None, None, None, None];
                for value in &mut values {
                    match reader.read_i32()? {
                        -1 => {}
                        length if length >= 0 => {
                            let bytes = reader.read_bytes(length as usize)?;
                            let text = std::str::from_utf8(bytes)
                                .map_err(|_| protocol("invalid UTF-8 in replication control result"))?;
                            if text.as_bytes().contains(&0) {
                                return Err(protocol("NUL in replication control result"));
                            }
                            *value = Some(text.to_owned());
                        }
                        _ => return Err(protocol("invalid replication control value length")),
                    }
                }
                reader.ensure_consumed("replication control DataRow")?;
                self.row = Some(values);
            }
            b'C' if !self.completed => {
                if self.kind.columns().is_some() && self.row.is_none() {
                    return Err(protocol("replication control completed without its result row"));
                }
                if reader.read_cstring()? != self.kind.tag() {
                    return Err(protocol("unexpected replication control command tag"));
                }
                reader.ensure_consumed("replication control CommandComplete")?;
                self.completed = true;
            }
            b'Z' if self.completed && data == b"I" => return Ok(true),
            _ => return Err(unexpected_backend_message("replication slot control", tag)),
        }
        Ok(false)
    }
}

fn required(value: Option<String>) -> Result<String, PgError> {
    value
        .filter(|text| !text.is_empty())
        .ok_or_else(|| protocol("missing replication control value"))
}

fn unsigned<T: std::str::FromStr>(value: Option<String>) -> Result<T, PgError> {
    let text = required(value)?;
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(protocol("invalid unsigned replication control value"));
    }
    text.parse()
        .map_err(|_| protocol("replication control integer out of range"))
}

fn parse_identity(row: ControlRow) -> Result<PgReplicationIdentity, PgError> {
    let [system_id, timeline, wal_position, database] =
        row.ok_or_else(|| protocol("missing publisher identity"))?;
    let system_id = unsigned(system_id)?;
    let timeline = unsigned(timeline)?;
    if system_id == 0 || timeline == 0 {
        return Err(protocol("publisher identifiers must be nonzero"));
    }
    if database
        .as_ref()
        .is_some_and(|name| name.is_empty() || name.len() > 63)
    {
        return Err(protocol("invalid publisher database name"));
    }
    Ok(PgReplicationIdentity {
        system_id,
        timeline,
        wal_position: required(wal_position)?.parse()?,
        database,
    })
}

fn parse_created(
    row: ControlRow,
    options: &PgReplicationSlotOptions,
) -> Result<(PgLsn, Option<String>), PgError> {
    let [name, point, snapshot, plugin] =
        row.ok_or_else(|| protocol("missing created replication slot"))?;
    if required(name)? != options.name || required(plugin)? != "pgoutput" {
        return Err(protocol("server created an unexpected slot or output plugin"));
    }
    if snapshot.is_some() != options.export_snapshot {
        return Err(protocol("server did not honor replication snapshot export policy"));
    }
    if let Some(snapshot) = &snapshot
        && (snapshot.is_empty()
            || snapshot.len() > 128
            || !snapshot
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    {
        return Err(protocol("invalid exported snapshot identifier"));
    }
    Ok((required(point)?.parse()?, snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn description(kind: ControlKind, timeline_oid: i32) -> Vec<u8> {
        let mut data = 4i16.to_be_bytes().to_vec();
        for (index, name) in kind.columns().unwrap().iter().enumerate() {
            data.extend_from_slice(name.as_bytes());
            data.push(0);
            data.extend_from_slice(&0i32.to_be_bytes());
            data.extend_from_slice(&0i16.to_be_bytes());
            let oid: i32 = if kind == ControlKind::Identify && index == 1 {
                timeline_oid
            } else {
                25
            };
            data.extend_from_slice(&oid.to_be_bytes());
            data.extend_from_slice(&(-1i16).to_be_bytes());
            data.extend_from_slice(&(-1i32).to_be_bytes());
            data.extend_from_slice(&0i16.to_be_bytes());
        }
        data
    }

    fn row(values: [Option<&str>; 4]) -> ControlRow {
        Some(values.map(|value| value.map(str::to_owned)))
    }

    fn data_row(values: [Option<&str>; 4]) -> Vec<u8> {
        let mut bytes = 4i16.to_be_bytes().to_vec();
        for value in values {
            if let Some(value) = value {
                bytes.extend_from_slice(&i32::try_from(value.len()).unwrap().to_be_bytes());
                bytes.extend_from_slice(value.as_bytes());
            } else {
                bytes.extend_from_slice(&(-1i32).to_be_bytes());
            }
        }
        bytes
    }

    #[test]
    fn slot_options_quote_valid_names_and_compose_snapshot_with_two_phase() {
        for invalid in ["", "UPPER", "slot;DROP", "slot\0suffix", "quote\"", "not-ascii-λ"] {
            assert!(PgReplicationSlotOptions::new(invalid).is_err(), "{invalid:?}");
        }
        assert!(PgReplicationSlotOptions::new("a".repeat(64)).is_err());
        let options = PgReplicationSlotOptions::new("slot_1").unwrap();
        assert_eq!(options.command(), "CREATE_REPLICATION_SLOT \"slot_1\" LOGICAL pgoutput EXPORT_SNAPSHOT");
        assert_eq!(options.clone().temporary(true).export_snapshot(false).command(), "CREATE_REPLICATION_SLOT \"slot_1\" TEMPORARY LOGICAL pgoutput NOEXPORT_SNAPSHOT");
        assert_eq!(options.clone().two_phase(true).command(), "CREATE_REPLICATION_SLOT \"slot_1\" LOGICAL pgoutput (TWO_PHASE true, SNAPSHOT 'export')");
        assert_eq!(options.two_phase(true).export_snapshot(false).command(), "CREATE_REPLICATION_SLOT \"slot_1\" LOGICAL pgoutput (TWO_PHASE true, SNAPSHOT 'nothing')");
    }

    #[test]
    fn identify_accepts_both_server_timeline_widths_without_truncation() {
        for oid in [23, 20] {
            let mut response = ControlResponse::new(ControlKind::Identify);
            assert!(!response.accept(b'T', &description(ControlKind::Identify, oid)).unwrap());
            assert!(!response.accept(b'D', &data_row([
                Some("18446744073709551615"), Some("4294967295"),
                Some("ABCDEF01/00000042"), None,
            ])).unwrap());
            assert!(!response.accept(b'C', b"IDENTIFY_SYSTEM\0").unwrap());
            assert!(response.accept(b'Z', b"I").unwrap());
            let identity = parse_identity(response.row).unwrap();
            assert_eq!(identity.system_id, u64::MAX);
            assert_eq!(identity.timeline, u32::MAX);
            assert_eq!(identity.wal_position.as_u64(), 0xABCD_EF01_0000_0042);
            assert!(identity.database.is_none());
        }
    }

    #[test]
    fn control_requires_one_row_matching_completion_and_idle_boundary() {
        let mut response = ControlResponse::new(ControlKind::Create);
        assert!(response.accept(b'Z', b"I").is_err());
        assert!(response.accept(b'C', b"CREATE_REPLICATION_SLOT\0").is_err());
        let values = [Some("slot_1"), Some("0/42"), Some("00000003-0000001B-1"), Some("pgoutput")];
        assert!(response.accept(b'D', &data_row(values)).is_err());
        assert!(!response.accept(b'T', &description(ControlKind::Create, 23)).unwrap());
        assert!(response.accept(b'T', &description(ControlKind::Create, 23)).is_err());
        assert!(!response.accept(b'D', &data_row(values)).unwrap());
        assert!(response.accept(b'D', &data_row(values)).is_err());
        assert!(response.accept(b'C', b"SELECT 1\0").is_err());
        assert!(!response.accept(b'C', b"CREATE_REPLICATION_SLOT\0").unwrap());
        assert!(response.accept(b'Z', b"T").is_err());
        assert!(response.accept(b'Z', b"I\0").is_err());
        assert!(response.accept(b'Z', b"I").unwrap());
        let options = PgReplicationSlotOptions::new("slot_1").unwrap();
        let (position, snapshot) = parse_created(response.row, &options).unwrap();
        assert_eq!(position, PgLsn::new(0x42));
        assert_eq!(snapshot.as_deref(), Some("00000003-0000001B-1"));
    }

    #[test]
    fn malformed_or_binary_control_results_fail_closed() {
        let description = description(ControlKind::Identify, 23);
        for len in 0..description.len() {
            assert!(ControlResponse::new(ControlKind::Identify).accept(b'T', &description[..len]).is_err(), "truncation {len}");
        }
        let mut trailing = description.clone();
        trailing.push(0);
        assert!(ControlResponse::new(ControlKind::Identify).accept(b'T', &trailing).is_err());
        let mut binary = description;
        *binary.last_mut().unwrap() = 1;
        assert!(ControlResponse::new(ControlKind::Identify).accept(b'T', &binary).is_err());
        for malformed in [
            vec![0, 4, 0x7f, 0xff, 0xff, 0xff],
            vec![0, 4, 0xff, 0xff, 0xff, 0xfe],
            data_row([Some("1\0"), Some("1"), Some("0/1"), None]),
        ] {
            let mut response = ControlResponse::new(ControlKind::Identify);
            response.accept(b'T', &self::description(ControlKind::Identify, 23)).unwrap();
            assert!(response.accept(b'D', &malformed).is_err());
        }
    }

    #[test]
    fn slot_result_must_match_requested_name_plugin_and_snapshot_policy() {
        let options = PgReplicationSlotOptions::new("slot_1").unwrap();
        for values in [
            [Some("another_slot"), Some("0/1"), Some("00000001-1"), Some("pgoutput")],
            [Some("slot_1"), Some("0/1"), Some("00000001-1"), Some("test_decoding")],
            [Some("slot_1"), Some("0/1"), None, Some("pgoutput")],
            [Some("slot_1"), Some("0/1"), Some("x'; SELECT 1; --"), Some("pgoutput")],
            [Some("slot_1"), Some("bad-lsn"), Some("00000001-1"), Some("pgoutput")],
        ] {
            assert!(parse_created(row(values), &options).is_err());
        }
        let no_snapshot = options.export_snapshot(false);
        assert_eq!(parse_created(row([Some("slot_1"), Some("0/1"), None, Some("pgoutput")]), &no_snapshot).unwrap(), (PgLsn::new(1), None));
        assert!(parse_created(row([Some("slot_1"), Some("0/1"), Some("00000001-1"), Some("pgoutput")]), &no_snapshot).is_err());
    }

    #[test]
    fn publisher_identity_rejects_invalid_and_overflowed_identifiers() {
        for system in ["0", "-1", "+1", "18446744073709551616", "1 "] {
            assert!(parse_identity(row([Some(system), Some("1"), Some("0/1"), None])).is_err());
        }
        for timeline in ["0", "-1", "+1", "4294967296"] {
            assert!(parse_identity(row([Some("1"), Some(timeline), Some("0/1"), None])).is_err());
        }
        assert!(parse_identity(row([Some("1"), Some("1"), None, None])).is_err());
    }

    #[test]
    fn drop_slot_requires_acknowledgement_before_connection_reuse() {
        let mut response = ControlResponse::new(ControlKind::Drop);
        assert!(response.accept(b'Z', b"I").is_err());
        assert!(response.accept(b'T', &description(ControlKind::Create, 23)).is_err());
        assert!(!response.accept(b'C', b"DROP_REPLICATION_SLOT\0").unwrap());
        assert!(response.accept(b'C', b"DROP_REPLICATION_SLOT\0").is_err());
        assert!(response.accept(b'Z', b"I").unwrap());
        assert!(response.row.is_none());
    }
}
