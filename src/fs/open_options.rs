//! Options and flags for configuring how a file is opened.
//!
//! This module provides [`OpenOptions`], a builder for controlling file
//! open behavior. The API mirrors `std::fs::OpenOptions`.

use super::File;
use crate::cx::io_gate::spawn_blocking_io;
use std::io;
use std::path::Path;

/// Options for opening a file.
///
/// This is a builder that allows configuring various options before
/// opening a file. The API mirrors `std::fs::OpenOptions`.
///
/// # Example
///
/// ```ignore
/// use asupersync::fs::OpenOptions;
///
/// let file = OpenOptions::new()
///     .read(true)
///     .write(true)
///     .create(true)
///     .open("example.txt")
///     .await?;
/// ```
#[derive(Debug, Clone, Default)]
#[allow(clippy::struct_excessive_bools)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    #[cfg(unix)]
    mode: Option<u32>,
    #[cfg(unix)]
    custom_flags: Option<i32>,
}

impl OpenOptions {
    /// Creates a new set of options with default settings.
    ///
    /// All options are initially set to `false`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the option for read access.
    ///
    /// This option, when true, means the file will be readable after opening.
    #[must_use]
    pub fn read(mut self, read: bool) -> Self {
        self.read = read;
        self
    }

    /// Sets the option for write access.
    ///
    /// This option, when true, means the file will be writable after opening.
    #[must_use]
    pub fn write(mut self, write: bool) -> Self {
        self.write = write;
        self
    }

    /// Sets the option for append mode.
    ///
    /// This option, when true, means writes will append to a file instead
    /// of overwriting previous contents.
    #[must_use]
    pub fn append(mut self, append: bool) -> Self {
        self.append = append;
        self
    }

    /// Sets the option to truncate a previous file.
    ///
    /// This option, when true, will truncate the file to 0 bytes after opening.
    /// The file must be opened with write access for truncation to work.
    #[must_use]
    pub fn truncate(mut self, truncate: bool) -> Self {
        self.truncate = truncate;
        self
    }

    /// Sets the option to create a new file.
    ///
    /// This option indicates whether a new file will be created if the file
    /// does not already exist. The file must be opened with write or append
    /// access in order to create a new file.
    #[must_use]
    pub fn create(mut self, create: bool) -> Self {
        self.create = create;
        self
    }

    /// Sets the option to create a new file, failing if it already exists.
    ///
    /// No file is allowed to exist at the target location. The file must be
    /// opened with write or append access for this option to work.
    ///
    /// This is useful for atomic file creation.
    #[must_use]
    pub fn create_new(mut self, create_new: bool) -> Self {
        self.create_new = create_new;
        self
    }

    /// Sets the mode bits that a new file will be created with (Unix only).
    ///
    /// If no mode is specified, the default is 0o666 (modified by umask).
    #[cfg(unix)]
    #[must_use]
    pub fn mode(mut self, mode: u32) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Sets custom flags for the underlying `open(2)` call (Unix only).
    ///
    /// Mirrors Tokio's `OpenOptionsExt::custom_flags`.
    #[cfg(unix)]
    #[must_use]
    pub fn custom_flags(mut self, flags: i32) -> Self {
        self.custom_flags = Some(flags);
        self
    }

    /// Opens a file at `path` with the options specified by `self`.
    ///
    /// This uses soft cancellation. If creation or truncation is enabled, a
    /// started open may mutate the filesystem after the returned future is
    /// dropped. A successfully opened but unobserved handle is closed when the
    /// discarded result is dropped.
    pub async fn open<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
        let path = path.as_ref().to_owned();
        let opts = self.clone();

        let std_file = spawn_blocking_io(move || opts.to_std_options().open(&path)).await?;
        Ok(File::from_std(std_file))
    }

    /// Converts these options to `std::fs::OpenOptions`.
    fn to_std_options(&self) -> std::fs::OpenOptions {
        let mut opts = std::fs::OpenOptions::new();
        opts.read(self.read);
        opts.write(self.write);
        opts.append(self.append);
        opts.truncate(self.truncate);
        opts.create(self.create);
        opts.create_new(self.create_new);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if let Some(mode) = self.mode {
                opts.mode(mode);
            }
            if let Some(flags) = self.custom_flags {
                opts.custom_flags(flags);
            }
        }

        opts
    }
}

#[cfg(test)]
#[path = "open_options_inline_tests.rs"]
mod tests;
