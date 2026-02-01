//! Database clients with async wrappers and Cx integration.
//!
//! This module provides async wrappers for database clients, integrating with
//! asupersync's cancel-correct semantics and blocking pool.
//!
//! # Available Clients
//!
//! - [`sqlite`]: SQLite async wrapper using blocking pool
//!
//! # Design Philosophy
//!
//! Database clients use the blocking pool to execute synchronous operations
//! without blocking the async runtime. All operations integrate with [`Cx`]
//! for checkpointing and cancellation.
//!
//! [`Cx`]: crate::cx::Cx

pub mod sqlite;

pub use sqlite::{
    SqliteConnection, SqliteError, SqliteRow, SqliteTransaction, SqliteValue,
};
