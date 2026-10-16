    #![allow(clippy::pedantic, clippy::nursery)]

    use super::*;

    #[test]
    fn new_preserves_bytes() {
        let s = SecretString::new("hunter2");
        assert_eq!(s.as_str(), "hunter2");
        assert_eq!(s.as_bytes(), b"hunter2");
        assert_eq!(s.len(), 7);
        assert!(!s.is_empty());
    }

    #[test]
    fn from_string_preserves_bytes() {
        let owned = String::from("correct horse battery staple");
        let s = SecretString::from_string(owned);
        assert_eq!(s.as_str(), "correct horse battery staple");
    }

    #[test]
    fn from_str_via_into() {
        let s: SecretString = "p@ssw0rd".into();
        assert_eq!(s.as_str(), "p@ssw0rd");
    }

    #[test]
    fn from_string_via_into() {
        let s: SecretString = String::from("alpha").into();
        assert_eq!(s.as_str(), "alpha");
    }

    #[test]
    fn empty_secret() {
        let s = SecretString::new("");
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
        assert_eq!(s.as_str(), "");
    }

    #[test]
    fn debug_always_redacts() {
        let s = SecretString::new("topsecret");
        let dbg = format!("{s:?}");
        assert_eq!(dbg, "SecretString(<redacted>)");
        assert!(!dbg.contains("topsecret"));
    }

    #[test]
    fn debug_redacts_even_for_empty() {
        let s = SecretString::new("");
        assert_eq!(format!("{s:?}"), "SecretString(<redacted>)");
    }

    #[test]
    fn clone_is_independent() {
        let a = SecretString::new("shared");
        let b = a.clone();
        assert_eq!(a, b);
        // Drop one — the other must remain valid (separate
        // allocations).
        drop(a);
        assert_eq!(b.as_str(), "shared");
    }

    #[test]
    fn eq_constant_time_correctness() {
        assert_eq!(SecretString::new("abc"), SecretString::new("abc"));
        assert_ne!(SecretString::new("abc"), SecretString::new("abd"));
        assert_ne!(SecretString::new("abc"), SecretString::new("abcd"));
        assert_ne!(SecretString::new("abc"), SecretString::new(""));
        assert_eq!(SecretString::new(""), SecretString::new(""));
    }

    /// br-asupersync-r2l1ze: `Drop` MUST overwrite every byte of the
    /// secret before the allocation is released. The destructor is
    /// `fn drop(&mut self) { self.zeroize_bytes(); }`, so we verify by
    /// invoking that exact routine on a still-live buffer and reading the
    /// bytes back in place — no reads of freed memory.
    #[test]
    fn drop_zeroizes_secret_bytes() {
        // br-asupersync-r2l1ze: the `Drop` impl is exactly
        // `fn drop(&mut self) { self.zeroize_bytes(); }`, so we verify the
        // destructor's zeroization by invoking that *same* routine while the
        // backing allocation is still live and reading the bytes back in
        // place. This avoids the use-after-free that results from reading a
        // pointer into a buffer the `Vec` destructor has already freed (the
        // previous version snapshotted `as_ptr()` then read it back after the
        // allocation was released — undefined behaviour that could observe
        // reused/garbage memory rather than the zeroized bytes).
        let mut s = SecretString::new("plaintext");

        // Sanity: pre-zeroize the bytes are the plaintext we put in.
        assert_eq!(s.as_bytes(), b"plaintext");

        // Run the destructor's side-effect directly. `zeroize_bytes` is the
        // single source of truth shared by `Drop` and `explicit_zeroize`.
        s.zeroize_bytes();

        // Every byte must now be zero. The buffer is still allocated and
        // owned by `s`, so this read is fully defined.
        assert!(
            s.bytes.iter().all(|&b| b == 0),
            "Drop's zeroize must clear every byte; observed: {:02x?}",
            s.bytes
        );
        assert_eq!(s.bytes.len(), b"plaintext".len());
    }

    /// br-asupersync-r2l1ze: `from_string` consumes the source `String`
    /// and re-uses its allocation; verify by checking that the bytes
    /// stored in the SecretString are byte-for-byte identical to what
    /// the source held. (We cannot directly assert "same allocation"
    /// without exposing internals, but we can assert content fidelity
    /// and zeroization on drop, which together imply the safety property.)
    #[test]
    fn from_string_zeroizes_on_drop() {
        // br-asupersync-r2l1ze: `from_string` re-uses the source `String`'s
        // allocation; verify the destructor's zeroization clears exactly
        // those bytes. As in `drop_zeroizes_secret_bytes`, we exercise the
        // shared `zeroize_bytes` routine (which `Drop` calls verbatim) on the
        // still-live buffer rather than reading a freed allocation.
        let mut s = SecretString::from_string(String::from("from_string"));
        assert_eq!(s.as_bytes(), b"from_string");

        s.zeroize_bytes();

        assert!(
            s.bytes.iter().all(|&b| b == 0),
            "Drop's zeroize must clear every byte; observed: {:02x?}",
            s.bytes
        );
        assert_eq!(s.bytes.len(), b"from_string".len());
    }

    /// br-asupersync-s45073 L7: the wipe spans the spare capacity, where a
    /// truncated `String` handed to `from_string` still holds the tail of its
    /// earlier value. Before, only the first `len` bytes were wiped.
    #[test]
    fn zeroize_spans_the_spare_capacity() {
        let mut source = String::from("short, then a longer secret tail");
        source.truncate(5);
        let mut s = SecretString::from_string(source);
        assert_eq!(s.as_bytes(), b"short");
        let capacity = s.bytes.capacity();
        assert!(capacity > 5, "from_string keeps the source allocation");

        s.zeroize_bytes();

        assert_eq!(
            s.bytes.len(),
            capacity,
            "the wipe must cover the whole allocation"
        );
        assert!(s.bytes.iter().all(|&b| b == 0));
    }

    /// `explicit_zeroize` must wipe the bytes IMMEDIATELY (before drop)
    /// and leave the value usable as an empty string. Callers use this
    /// to minimise the in-memory residency of the secret beyond the
    /// scope-bounded Drop guarantee.
    #[test]
    fn explicit_zeroize_clears_bytes_in_place() {
        let mut s = SecretString::new("ephemeral");
        assert_eq!(s.as_str(), "ephemeral");
        s.explicit_zeroize();
        assert!(s.is_empty());
        assert_eq!(s.as_str(), "");
        assert_eq!(s.as_bytes(), b"");
    }

    /// `explicit_zeroize` is idempotent — calling it twice is a no-op
    /// after the first invocation.
    #[test]
    fn explicit_zeroize_is_idempotent() {
        let mut s = SecretString::new("twice");
        s.explicit_zeroize();
        s.explicit_zeroize();
        assert!(s.is_empty());
    }

    #[test]
    fn utf8_multibyte_preserved() {
        // SCRAM SASLprep allows non-ASCII; ensure round-trip works.
        let s = SecretString::new("пароль🔒");
        assert_eq!(s.as_str(), "пароль🔒");
        assert_eq!(s.as_bytes(), "пароль🔒".as_bytes());
    }
