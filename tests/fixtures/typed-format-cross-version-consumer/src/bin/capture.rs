//! Materialize a fresh build-provenanced corpus and the Cargo-generated lockfile.
//!
//! The v0.3.9 typed-symbol identity fields depend on Rust `TypeId`, so a fresh
//! build is a comparison artifact rather than a byte-for-byte replacement for
//! the committed historical capture.

use std::path::Path;

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create output directory");
    }
    std::fs::write(path, bytes).expect("write generated fixture");
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let corpus_path = args.next().expect("usage: capture CORPUS_PATH LOCK_PATH");
    let lock_path = args.next().expect("usage: capture CORPUS_PATH LOCK_PATH");
    assert!(
        args.next().is_none(),
        "usage: capture CORPUS_PATH LOCK_PATH"
    );

    let manifest = typed_format_cross_version_consumer::historical_corpus();
    let corpus_bytes = serde_json::to_vec_pretty(&manifest).expect("encode historical corpus");
    write_file(Path::new(&corpus_path), &corpus_bytes);
    write_file(Path::new(&lock_path), include_bytes!("../../Cargo.lock"));
}
