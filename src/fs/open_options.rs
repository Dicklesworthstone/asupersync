//! Options and flags for configuring how a file is opened.
//!
//! This module provides [`OpenOptions`], a builder for controlling file
//! open behavior. The API mirrors `std::fs::OpenOptions`.

use super::File;
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
#[derive(Debug, Clone)]
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
}

impl OpenOptions {
    /// Creates a new set of options with default settings.
    ///
    /// All options are initially set to `false`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            #[cfg(unix)]
            mode: None,
        }
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

    /// Opens a file at `path` with the options specified by `self`.
    #[allow(clippy::unused_async)]
    pub async fn open<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
        let path = path.as_ref().to_owned();
        let opts = self.clone();

        // Phase 0: Synchronous open (will use spawn_blocking in Phase 1+)
        let std_file = opts.to_std_options().open(&path)?;
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
        if let Some(mode) = self.mode {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }

        opts
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn open_options_builder() {
        let opts = OpenOptions::new().read(true).write(true).create(true);

        assert!(opts.read);
        assert!(opts.write);
        assert!(opts.create);
        assert!(!opts.append);
        assert!(!opts.truncate);
        assert!(!opts.create_new);
    }

    #[test]
    fn open_options_default() {
        let opts = OpenOptions::default();
        assert!(!opts.read);
        assert!(!opts.write);
        assert!(!opts.append);
        assert!(!opts.truncate);
        assert!(!opts.create);
        assert!(!opts.create_new);
    }

    #[test]
    fn to_std_options_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.txt");

        // Create a file using our options
        let opts = OpenOptions::new().write(true).create(true);
        let std_opts = opts.to_std_options();

        // Should succeed
        let file = std_opts.open(&path);
        assert!(file.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn mode_option_unix() {
        let opts = OpenOptions::new().write(true).create(true).mode(0o600);

        assert_eq!(opts.mode, Some(0o600));
    }
}
