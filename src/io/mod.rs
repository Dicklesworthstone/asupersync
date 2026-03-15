//! Async I/O traits, adapters, and capability infrastructure.
//!
//! This module provides minimal `AsyncRead` and `AsyncWrite` traits, a safe
//! `ReadBuf` type, and common adapters and extension futures. The design
//! mirrors `std::io` and `futures::io` but is intentionally small and cancel-aware.
//!
//! # I/O Capability Model
//!
//! Asupersync uses explicit capability-based I/O access. The [`IoCap`] trait
//! defines the I/O capability boundary - tasks can only perform I/O when they
//! have access to an implementation:
//!
//! - Production: Real I/O via reactor (epoll/kqueue/IOCP)
//! - Lab: Virtual I/O for deterministic testing (see [`LabIoCap`])
//!
//! # Cancel Safety
//!
//! ## Read operations
//! - `poll_read` is cancel-safe (partial data is discarded by the caller).
//! - `read_exact` is **not** cancel-safe (partial state is retained).
//! - `read_to_end` is cancel-safe (collected bytes remain in the buffer).
//! - `read_to_string` is **not** fully cancel-safe (bytes are preserved, but a partial UTF-8 sequence at the end may be lost if cancelled).
//! - `read_line` is cancel-safe for bytes already appended to the `String`; a
//!   trailing partial UTF-8 code point buffered internally is only preserved
//!   across polls, not across drop.
//!
//! ## Write operations
//! - `poll_write` is cancel-safe (partial writes are OK).
//! - `write_all` is **not** cancel-safe (partial writes may occur).
//! - `WritePermit` is cancel-safe (uncommitted data is discarded on drop).
//! - `flush` and `shutdown` are cancel-safe (can retry).
//!
//! ## Copy operations
//! - `copy` is cancel-safe (bytes already written remain committed).
//! - `copy_buf` is cancel-safe (bytes already written remain committed).
//! - `copy_with_progress` is cancel-safe (progress callback is accurate).
//! - `copy_bidirectional` is cancel-safe (both directions can be partially complete).

pub mod browser_storage;
pub mod browser_stream;
mod buf_reader;
mod buf_writer;
pub mod cap;
mod copy;
pub mod ext;
mod lines;
mod read;
mod read_buf;
mod read_line;
mod seek;
mod split;
mod stream_adapters;
mod write;
mod write_permit;

pub use copy::{
    AsyncBufRead, Copy, CopyBidirectional, CopyBuf, CopyWithProgress, copy, copy_bidirectional,
    copy_buf, copy_with_progress,
};
pub use ext::{
    AsyncReadExt, AsyncReadVectoredExt, Read, ReadExact, ReadI8, ReadToEnd, ReadToString, ReadU8,
    ReadVectored,
};
pub use ext::{AsyncSeekExt, Seek};
pub use ext::{
    AsyncWriteExt, Buf, Flush, Shutdown, Write, WriteAll, WriteAllBuf, WriteI8, WriteU8,
    WriteVectored,
};
pub use read::{AsyncRead, AsyncReadVectored, Chain, Take};
pub use read_buf::ReadBuf;
pub use seek::AsyncSeek;
pub use split::{ReadHalf, SplitStream, WriteHalf, split};
pub use stream_adapters::{ReaderStream, StreamReader};
pub use write::{AsyncWrite, AsyncWriteVectored};
pub use write_permit::WritePermit;

pub use browser_storage::{
    BrowserStorageAdapter, BrowserStorageError, StorageEvent, StorageEventOutcome,
};
pub use browser_stream::{
    BackpressureStrategy, BrowserBroadcastChannel, BrowserMessageChannel,
    BrowserMessageChannelPair, BrowserMessageError, BrowserMessagePayload, BrowserMessagePort,
    BrowserMessageState, BrowserReadableStream, BrowserStreamConfig, BrowserStreamError,
    BrowserStreamIoCap, BrowserStreamState, BrowserWritableStream, StreamStats,
};
#[cfg(target_arch = "wasm32")]
pub use browser_stream::{WasmReadableStreamSource, WasmWritableStreamSink};
pub use buf_reader::BufReader;
pub use buf_writer::BufWriter;
pub use cap::{
    BrowserEntropyIoCap, BrowserFetchIoCap, BrowserHostApiIoCap, BrowserStorageIoCap,
    BrowserTimeIoCap, BrowserTransportAuthority, BrowserTransportCancellationPolicy,
    BrowserTransportIoCap, BrowserTransportKind, BrowserTransportPolicyError,
    BrowserTransportReconnectPolicy, BrowserTransportRequest, BrowserTransportSupport,
    EntropyAuthority, EntropyIoCap, EntropyOperation, EntropyPolicyError, EntropyRequest,
    EntropySourceKind, FetchAuthority, FetchCancellationPolicy, FetchIoCap, FetchMethod,
    FetchPolicyError, FetchRequest, FetchStreamPolicy, FetchTimeoutPolicy, HostApiAuthority,
    HostApiIoCap, HostApiPolicyError, HostApiRequest, HostApiSurface, IoCap, IoNotAvailable,
    LabIoCap, StorageAuthority, StorageBackend, StorageConsistencyPolicy, StorageIoCap,
    StorageOperation, StoragePolicyError, StorageQuotaPolicy, StorageRedactionPolicy,
    StorageRequest, TimeAuthority, TimeIoCap, TimeOperation, TimePolicyError, TimeRequest,
    TimeSourceKind, TransportIoCap,
};
pub use lines::Lines;
pub use read_line::{ReadLine, read_line};
pub use std::io::SeekFrom;
