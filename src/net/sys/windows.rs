//! Windows-specific networking primitives.
//!
//! This module currently provides a named-pipe client surface that mirrors the
//! core migration shape from `tokio::net::windows::named_pipe::ClientOptions`
//! and `NamedPipeClient`.

#![cfg(target_os = "windows")]

use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const PIPE_PREFIX: &str = r"\\.\pipe\";

fn validate_named_pipe_path(path: &Path) -> io::Result<()> {
    let raw = path.to_string_lossy();
    if !raw.starts_with(PIPE_PREFIX) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "named pipe path must start with \\\\.\\pipe\\",
        ));
    }
    if raw.len() <= PIPE_PREFIX.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "named pipe path must include a pipe name",
        ));
    }
    Ok(())
}

/// Builder for opening a Windows named-pipe client.
#[derive(Debug, Clone, Copy)]
pub struct NamedPipeClientOptions {
    read: bool,
    write: bool,
}

impl Default for NamedPipeClientOptions {
    fn default() -> Self {
        Self {
            read: true,
            write: true,
        }
    }
}

impl NamedPipeClientOptions {
    /// Construct default options (`read = true`, `write = true`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable/disable read access.
    #[must_use]
    pub fn read(mut self, enabled: bool) -> Self {
        self.read = enabled;
        self
    }

    /// Enable/disable write access.
    #[must_use]
    pub fn write(mut self, enabled: bool) -> Self {
        self.write = enabled;
        self
    }

    /// Connect to a named pipe with the configured access mode.
    ///
    /// The path must use the canonical Windows named-pipe namespace prefix:
    /// `\\.\pipe\...`.
    pub fn open(self, path: impl AsRef<Path>) -> io::Result<NamedPipeClient> {
        if !self.read && !self.write {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "named pipe client requires read or write access",
            ));
        }

        let path = path.as_ref();
        validate_named_pipe_path(path)?;

        let mut options = OpenOptions::new();
        options.read(self.read).write(self.write);

        let file = options.open(path)?;
        Ok(NamedPipeClient {
            inner: file,
            path: path.to_path_buf(),
        })
    }
}

/// Connected Windows named-pipe client.
#[derive(Debug)]
pub struct NamedPipeClient {
    inner: File,
    path: PathBuf,
}

impl NamedPipeClient {
    /// Connect to a named pipe with default read/write options.
    pub fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        NamedPipeClientOptions::new().open(path)
    }

    /// Return the pipe path used for this client.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Clone the underlying handle.
    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            inner: self.inner.try_clone()?,
            path: self.path.clone(),
        })
    }

    /// Consume the wrapper and return the underlying file handle.
    #[must_use]
    pub fn into_inner(self) -> File {
        self.inner
    }
}

impl Read for NamedPipeClient {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for NamedPipeClient {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_named_pipe_path_rejects_non_pipe_namespace() {
        let err = validate_named_pipe_path(Path::new(r"C:\tmp\not-a-pipe")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn validate_named_pipe_path_rejects_empty_pipe_name() {
        let err = validate_named_pipe_path(Path::new(r"\\.\pipe\")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn validate_named_pipe_path_accepts_valid_prefix_and_name() {
        let valid = validate_named_pipe_path(Path::new(r"\\.\pipe\asupersync-test"));
        assert!(valid.is_ok());
    }

    #[test]
    fn options_reject_read_and_write_both_disabled() {
        let err = NamedPipeClientOptions::new()
            .read(false)
            .write(false)
            .open(Path::new(r"\\.\pipe\asupersync-test"))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
