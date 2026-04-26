# Duplication Map

- `src/net/unix/split.rs`
  - repeated `Poll::Ready(Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled")))`
  - sites: borrowed read/write halves and owned read/write halves
