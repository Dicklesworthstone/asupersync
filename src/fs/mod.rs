//! Async filesystem operations.
//!
//! This module provides async file I/O operations that mirror the `std::fs` API
//! but with async/await support. In Phase 0 (single-threaded runtime), operations
//! are synchronous internally but exposed through async interfaces.
//!
//! # Cancel Safety
//!
//! - `File::open`, `File::create`: Cancel-safe (no partial state)
//! - Read operations: Cancel-safe (partial data discarded by caller)
//! - Write operations: Use `WritePermit` for cancel-safe writes, or accept
//!   potential partial writes on cancellation
//! - `sync_all`, `sync_data`: Cancel-safe (atomic completion)
//! - Seek: Cancel-safe (atomic completion)
//!
//! # Example
//!
//! ```ignore
//! use asupersync::fs::File;
//!
//! async fn example() -> std::io::Result<()> {
//!     // Create and write
//!     let mut file = File::create("test.txt").await?;
//!     file.write_all(b"hello").await?;
//!     file.sync_all().await?;
//!     drop(file);
//!
//!     // Read back
//!     let mut file = File::open("test.txt").await?;
//!     let mut contents = String::new();
//!     file.read_to_string(&mut contents).await?;
//!     Ok(())
//! }
//! ```
//!
//! # Platform Strategy
//!
//! - **Phase 0**: Synchronous I/O wrapped in async interface
//! - **Phase 1+**: Use `spawn_blocking` for thread pool offload
//! - **Future**: io_uring on Linux for true async I/O

mod buf_reader;
mod buf_writer;
mod dir;
mod file;
mod lines;
mod metadata;
mod open_options;
mod path_ops;
mod read_dir;
pub mod vfs;

#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub mod uring;

pub use buf_reader::BufReader;
pub use buf_writer::BufWriter;
pub use dir::{create_dir, create_dir_all, remove_dir, remove_dir_all};
pub use file::File;
pub use lines::Lines;
pub use metadata::{FileType, Metadata, Permissions};
pub use open_options::OpenOptions;
pub use path_ops::{
    canonicalize, copy, hard_link, metadata, read, read_link, read_to_string, remove_file, rename,
    set_permissions, symlink_metadata, write,
};
pub use read_dir::{read_dir, DirEntry, ReadDir};

#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub use uring::IoUringFile;

#[cfg(unix)]
pub use path_ops::symlink;

#[cfg(windows)]
pub use path_ops::{symlink_dir, symlink_file};

pub use std::io::SeekFrom;

pub use vfs::{UnixVfs, UnixVfsFile, Vfs, VfsFile};
