//! E2E Database Pool Reconnection Tests — MOVED
//!
//! This file is no longer the canonical pool-reconnection test surface.
//!
//! The live tests live at:
//!
//!   tests/database_e2e.rs
//!
//! That file exercises real `PgConnection` / `MySqlConnection` through
//! `AsyncDbPool`, drives faults via `sudo iptables`, and asserts circuit-
//! breaker activation, exponential backoff, pool recovery, and absence of
//! connection leaks against actual PostgreSQL and MySQL Docker containers.
//!
//! The previous in-tree copy contained two panic-only connection paths in
//! `PgTestManager::connect` / `MySqlTestManager::connect`; those `connect`
//! impls could not be written outside an async context, so they could not be
//! wired into a real `AsyncDbPool`. It also carried a test-only connection
//! manager that contradicted the file's own docstring. As of commit `795c8b2b8`
//! the work was fully superseded by `tests/database_e2e.rs`.
//!
//! Per RULE 1 (no file deletion), this file is retained as a redirect marker
//! by `br-asupersync-rqhu0s`, mirroring the resolution applied to
//! `docs/asupersync_v4_formal_semantics.md` in `br-asupersync-4nw2lb`.
//! The redirect marker keeps the path alive and removes the misleading
//! panic-only paths and test doubles so future readers (and any tooling
//! that scans for incomplete test code) do not trip on dead test scaffolding.
//!
//! All future pool-reconnection coverage should be added to
//! `tests/database_e2e.rs`.
