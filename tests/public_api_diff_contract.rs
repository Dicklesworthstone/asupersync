//! Contract for `scripts/public_api_diff.py` (asupersync-bi2462.139), the public API surface
//! diff behind the v0.4.3 compatibility gate. The fixtures are rendered by the pinned
//! toolchain's rustdoc, so a change in the rustdoc JSON format fails here before it can
//! silently blind the lane.

use std::path::{Path, PathBuf};
use std::process::Command;

const BASE: &str = r#"
pub mod pool {
    #[derive(Debug, Clone)]
    pub struct Handle<T> {
        pub value: T,
        slot: u8,
    }

    impl<T: Clone> Handle<T> {
        pub fn new(value: T) -> Self {
            Self { value, slot: 0 }
        }
    }

    pub enum Event {
        Opened,
        Closed { code: u16 },
    }

    pub trait Source: Send {
        fn next(&mut self) -> Option<u32>;
    }

    pub struct Settings {
        pub limit: usize,
    }
}

pub use pool::Handle;
"#;

/// Only compatible growth: a new function, a provided trait method, and a public field on a
/// struct that already had a private one (so nobody outside could construct it).
const ADDITIVE: &str = r#"
pub mod pool {
    #[derive(Debug, Clone)]
    pub struct Handle<T> {
        pub value: T,
        pub label: &'static str,
        slot: u8,
    }

    impl<T: Clone> Handle<T> {
        pub fn new(value: T) -> Self {
            Self { value, label: "", slot: 0 }
        }
    }

    pub enum Event {
        Opened,
        Closed { code: u16 },
    }

    pub trait Source: Send {
        fn next(&mut self) -> Option<u32>;
        fn size_hint(&self) -> usize {
            0
        }
    }

    pub struct Settings {
        pub limit: usize,
    }
}

pub use pool::Handle;

pub fn helper() -> u8 {
    1
}
"#;

/// Five planted breaks: a lost `Debug`, a changed return type, a variant on an exhaustive enum,
/// a required trait method, and a field on a constructible struct.
const BROKEN: &str = r#"
pub mod pool {
    #[derive(Clone)]
    pub struct Handle<T> {
        pub value: T,
        slot: u8,
    }

    impl<T: Clone> Handle<T> {
        pub fn new(value: T) -> Option<Self> {
            Some(Self { value, slot: 0 })
        }
    }

    pub enum Event {
        Opened,
        Closed { code: u16 },
        Reset,
    }

    pub trait Source: Send {
        fn next(&mut self) -> Option<u32>;
        fn reset(&mut self);
    }

    pub struct Settings {
        pub limit: usize,
        pub burst: usize,
    }
}

pub use pool::Handle;
"#;

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("public_api_diff_contract_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// The toolchain's own rustdoc: `$RUSTDOC`, else the one beside the cargo that built this
/// test, else `rustdoc` on PATH (resolved by rustup through rust-toolchain.toml).
fn rustdoc() -> PathBuf {
    if let Some(explicit) = std::env::var_os("RUSTDOC") {
        return PathBuf::from(explicit);
    }
    let beside_cargo = Path::new(env!("CARGO")).with_file_name("rustdoc");
    if beside_cargo.is_file() {
        return beside_cargo;
    }
    PathBuf::from("rustdoc")
}

fn render(dir: &Path, name: &str, source: &str) -> PathBuf {
    let src = dir.join(format!("{name}.rs"));
    std::fs::write(&src, source).expect("write fixture");
    let out = dir.join(name);
    let status = Command::new(rustdoc())
        .args(["--edition", "2024", "--crate-name", "surface_fixture"])
        .args(["-Z", "unstable-options", "--output-format", "json", "-o"])
        .arg(&out)
        .arg(&src)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("rustdoc must run");
    assert!(status.success(), "rustdoc failed on the {name} fixture");
    out.join("surface_fixture.json")
}

fn diff(base: &Path, head: &Path) -> (i32, String) {
    let output = Command::new("python3")
        .arg("scripts/public_api_diff.py")
        .arg("diff")
        .arg(base)
        .arg(head)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("python3 must run the diff");
    let stdout = String::from_utf8(output.stdout).expect("utf-8 diff output");
    eprintln!(
        "public_api_diff exit={:?}\n{stdout}{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.code().expect("diff exited normally"), stdout)
}

#[test]
fn an_unchanged_surface_diffs_clean() {
    let dir = scratch();
    let base = render(&dir, "unchanged", BASE);
    assert_eq!(diff(&base, &base), (0, String::new()));
}

#[test]
fn compatible_growth_is_reported_but_passes() {
    let dir = scratch();
    let (code, out) = diff(&render(&dir, "base_a", BASE), &render(&dir, "additive", ADDITIVE));
    assert_eq!(code, 0, "only additions: the gate must pass");
    let lines: Vec<&str> = out.lines().collect();
    assert!(!lines.is_empty(), "the additions are still listed");
    assert!(lines.iter().all(|l| l.starts_with("+ ")), "nothing but additions: {lines:?}");
    for expected in [
        "+ fn surface_fixture::helper fn() -> u8",
        "+ trait_fn surface_fixture::pool::Source::size_hint provided fn(&Self) -> usize",
        "+ field surface_fixture::pool::Handle.label: &'static str",
    ] {
        assert!(lines.contains(&expected), "missing {expected:?}");
    }
}

#[test]
fn every_planted_break_is_flagged_in_its_class() {
    let dir = scratch();
    let (code, out) = diff(&render(&dir, "base_b", BASE), &render(&dir, "broken", BROKEN));
    assert_eq!(code, 1, "a broken surface must fail the gate");
    let lines: Vec<&str> = out.lines().collect();
    for expected in [
        // Removed: both public paths of the type lose the impl.
        "- impl surface_fixture::Handle: core::fmt::Debug [impl<T: core::fmt::Debug>]",
        "- impl surface_fixture::pool::Handle: core::fmt::Debug [impl<T: core::fmt::Debug>]",
        // Breaking additions.
        "! variant surface_fixture::pool::Event::Reset",
        "! trait_fn surface_fixture::pool::Source::reset required fn(&mut Self)",
        "! field surface_fixture::pool::Settings.burst: usize",
        // Changed signature: shown old and new.
        "~- method surface_fixture::pool::Handle::new [impl<T: core::clone::Clone>] fn(T) -> Self",
        "~+ method surface_fixture::pool::Handle::new [impl<T: core::clone::Clone>] fn(T) -> core::option::Option<Self>",
    ] {
        assert!(lines.contains(&expected), "missing {expected:?} in {lines:?}");
    }
    assert!(
        lines.iter().all(|l| !l.starts_with("+ ")),
        "nothing in BROKEN is a plain addition: {lines:?}"
    );
}
