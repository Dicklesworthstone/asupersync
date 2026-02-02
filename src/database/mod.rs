//! Database clients with async wrappers and Cx integration.
//!
//! This module provides async wrappers for database clients, integrating with
//! asupersync's cancel-correct semantics and blocking pool.
//!
//! # Available Clients
//!
//! - [`sqlite`]: SQLite async wrapper using blocking pool (requires `sqlite` feature)
//! - [`postgres`]: PostgreSQL async client with wire protocol (requires `postgres` feature)
//! - [`mysql`]: MySQL async client with wire protocol (requires `mysql` feature)
//!
//! # Design Philosophy
//!
//! Database clients integrate with [`Cx`] for checkpointing and cancellation.
//! SQLite uses the blocking pool for synchronous operations, while PostgreSQL
//! and MySQL implement their respective wire protocols over async TCP.
//!
//! [`Cx`]: crate::cx::Cx

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "mysql")]
pub mod mysql;

#[cfg(feature = "sqlite")]
pub use sqlite::{SqliteConnection, SqliteError, SqliteRow, SqliteTransaction, SqliteValue};

#[cfg(feature = "postgres")]
pub use postgres::{
    oid as pg_oid, PgColumn, PgConnectOptions, PgConnection, PgError, PgRow, PgTransaction,
    PgValue, SslMode,
};

#[cfg(feature = "mysql")]
pub use mysql::{
    column_type as mysql_column_type, MySqlColumn, MySqlConnectOptions, MySqlConnection,
    MySqlError, MySqlRow, MySqlTransaction, MySqlValue, SslMode as MySqlSslMode,
};
