//! GH#85: new readiness owners must be classified when they are introduced.
//!
//! This source census supplements the native socket regression. It does not
//! establish runtime progress, cancellation behavior, or old-red/new-green proof.

use std::collections::BTreeSet;
use std::path::Path;

const CLASSIFIED: &[(&str, &str)] = &[
    ("src/cx/cx.rs", "ambient dispatcher access"),
    (
        "src/io/async_fd.rs",
        "common arm path; shared readiness waiters",
    ),
    ("src/net/mod.rs", "internal re-exports"),
    ("src/net/tcp/listener.rs", "common arm path; accept waiters"),
    (
        "src/net/tcp/split.rs",
        "serialized split migration; survivor notification",
    ),
    (
        "src/net/tcp/stream.rs",
        "common arm path and pending connect migration",
    ),
    (
        "src/net/udp.rs",
        "common dispatcher selection; Unix shared waiters",
    ),
    ("src/net/unix/datagram.rs", "common arm path"),
    (
        "src/net/unix/listener.rs",
        "common arm path; accept waiters",
    ),
    (
        "src/net/unix/split.rs",
        "serialized split migration; survivor notification",
    ),
    (
        "src/net/unix/stream.rs",
        "common arm path; connect and ancillary waiters",
    ),
    (
        "src/process.rs",
        "child pipe readiness through the common arm path",
    ),
    (
        "src/runtime/io_driver.rs",
        "registration lifetime and dispatcher identity",
    ),
    (
        "src/runtime/io_driver/shared.rs",
        "shared dispatcher retirement",
    ),
    ("src/runtime/mod.rs", "public re-export"),
];

fn registration_paths(root: &Path, directory: &Path, found: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(directory).expect("read source directory") {
        let entry = entry.expect("read source entry");
        let path = entry.path();
        let kind = entry.file_type().expect("source file type");
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if kind.is_dir() {
            if name != "tests" && name != "snapshots" {
                registration_paths(root, &path, found);
            }
        } else if kind.is_file()
            && path.extension().is_some_and(|extension| extension == "rs")
            && name != "test.rs"
            && !name.ends_with("tests.rs")
            && !name.ends_with("_test.rs")
        {
            let source = std::fs::read_to_string(&path).expect("read Rust source");
            if source.contains("IoRegistration") || source.contains("ReactorRegistration") {
                found.insert(
                    path.strip_prefix(root)
                        .expect("source is beneath crate root")
                        .to_string_lossy()
                        .replace('\\', "/"),
                );
            }
        }
    }
}

#[test]
fn all_readiness_registration_paths_have_a_handoff_classification() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = BTreeSet::new();
    registration_paths(root, &root.join("src"), &mut found);
    let classified: BTreeSet<_> = CLASSIFIED
        .iter()
        .map(|(path, _role)| (*path).to_owned())
        .collect();
    assert_eq!(
        found, classified,
        "classify each new readiness owner and add its handoff/retirement witness; \
         this inventory alone never substitutes for the native regression",
    );
}
