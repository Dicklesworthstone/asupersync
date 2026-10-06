use std::env;
use std::ffi::OsString;
use std::io::Write;
use std::process::{Command, Stdio};

const EXPLICIT_REVISION_ENV: &str = "ASUPERSYNC_GIT_COMMIT";
const COMPILED_REVISION_ENV: &str = "ASUPERSYNC_BUILD_GIT_COMMIT";
const TRY_TRAIT_CFG: &str = "asupersync_try_trait";

/// The shape of the `Try`/`Residual`/`FromResidual` impls that
/// `nightly-outcome-try` enables in `src/types/outcome.rs`.
const TRY_TRAIT_PROBE: &str = r"
#![feature(try_trait_v2, try_trait_v2_residual)]
use core::convert::Infallible;
use core::ops::{ControlFlow, FromResidual, Residual, Try};
pub enum Probe<T, E> {
    Ok(T),
    Err(E),
}
impl<T, E> Try for Probe<T, E> {
    type Output = T;
    type Residual = Probe<Infallible, E>;
    fn from_output(output: T) -> Self {
        Self::Ok(output)
    }
    fn branch(self) -> ControlFlow<Self::Residual, T> {
        match self {
            Self::Ok(value) => ControlFlow::Continue(value),
            Self::Err(error) => ControlFlow::Break(Probe::Err(error)),
        }
    }
}
impl<T, E> Residual<T> for Probe<Infallible, E> {
    type TryType = Probe<T, E>;
}
impl<T, E> FromResidual<Probe<Infallible, E>> for Probe<T, E> {
    fn from_residual(residual: Probe<Infallible, E>) -> Self {
        match residual {
            Probe::Ok(never) => match never {},
            Probe::Err(error) => Self::Err(error),
        }
    }
}
";

fn main() {
    println!("cargo:rerun-if-env-changed={EXPLICIT_REVISION_ENV}");
    println!("cargo:rerun-if-env-changed=RUSTC_BOOTSTRAP");
    println!("cargo::rustc-check-cfg=cfg({TRY_TRAIT_CFG})");

    if let Some(revision) = selected_revision() {
        println!("cargo:rustc-env={COMPILED_REVISION_ENV}={revision}");
    }

    // `tls-core` compiles the TLS code without linking a crypto provider. That
    // code is gated on `feature = "tls"`, and the `tls` feature also selects
    // ring, so the cfg is set here instead of duplicating every gate. Code that
    // names the ring provider is gated on `feature = "tls-ring"`.
    if env::var_os("CARGO_FEATURE_TLS_CORE").is_some() {
        println!("cargo:rustc-cfg=feature=\"tls\"");
    }

    // `nightly-outcome-try` is a default feature, so a stable compiler must
    // still build the crate: the `Try` impls (and `?` on `Outcome`) are
    // compiled only when this compiler accepts them
    // (br-asupersync-issue65-criticisms-kpmoy5.3.5).
    if env::var_os("CARGO_FEATURE_NIGHTLY_OUTCOME_TRY").is_some() {
        match compile_probe(TRY_TRAIT_PROBE) {
            Ok(()) => println!("cargo:rustc-cfg={TRY_TRAIT_CFG}"),
            // E0554: a stable or beta compiler refuses `#![feature]`.
            Err(stderr) if stderr.contains("E0554") => println!(
                "cargo:warning=asupersync: this compiler does not accept unstable features, \
                 so `nightly-outcome-try` is inactive and `?` on `Outcome` is unavailable"
            ),
            // Any other failure (a nightly whose `Try` API changed, a broken
            // wrapper) fails the build as before, instead of silently dropping
            // `?` on `Outcome` from a compiler that is expected to provide it.
            Err(stderr) => panic!(
                "asupersync: `nightly-outcome-try` is enabled but its Try-trait probe failed:\n{stderr}"
            ),
        }
    }
}

/// Compiles `source` as a library with the compiler, wrappers, target and
/// flags Cargo uses for this crate, the way `autocfg` probes. Returns the
/// compiler's stderr on failure.
fn compile_probe(source: &str) -> Result<(), String> {
    let out_dir = env::var_os("OUT_DIR").ok_or("OUT_DIR is not set")?;
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    let mut program = [
        env::var_os("RUSTC_WRAPPER"),
        env::var_os("RUSTC_WORKSPACE_WRAPPER"),
    ]
    .into_iter()
    .flatten()
    .filter(|wrapper| !wrapper.is_empty())
    .chain(std::iter::once(rustc));
    let first = program.next().ok_or("no compiler to run")?;
    let mut command = Command::new(first);
    command
        .args(program)
        .args([
            "--crate-name=asupersync_try_trait_probe",
            "--crate-type=lib",
            "--emit=metadata",
            "--edition=2021",
            "--cap-lints=allow",
        ])
        .arg("--out-dir")
        .arg(out_dir);
    if let Some(target) = env::var_os("TARGET") {
        command.arg("--target").arg(target);
    }
    if let Ok(flags) = env::var("CARGO_ENCODED_RUSTFLAGS") {
        command.args(flags.split('\x1f').filter(|flag| !flag.is_empty()));
    }
    command
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not run the compiler: {error}"))?;
    let mut stdin = child.stdin.take().ok_or("no compiler stdin")?;
    stdin
        .write_all(source.as_bytes())
        .map_err(|error| format!("could not write the probe: {error}"))?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|error| format!("could not wait for the compiler: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).into_owned())
    }
}

fn selected_revision() -> Option<String> {
    match env::var(EXPLICIT_REVISION_ENV) {
        Ok(value) => normalize_revision(value.as_bytes()),
        Err(env::VarError::NotPresent) => clean_checkout_revision(),
        Err(env::VarError::NotUnicode(_)) => None,
    }
}

fn clean_checkout_revision() -> Option<String> {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")?;
    let prefix = Command::new("git")
        .args(["rev-parse", "--show-prefix"])
        .current_dir(&manifest_dir)
        .output()
        .ok()?;
    if !prefix.status.success() || !prefix.stdout.iter().all(u8::is_ascii_whitespace) {
        return None;
    }

    let status = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=normal"])
        .current_dir(&manifest_dir)
        .output()
        .ok()?;
    if !status.status.success() || !status.stdout.is_empty() {
        return None;
    }

    let revision = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(manifest_dir)
        .output()
        .ok()?;
    if !revision.status.success() {
        return None;
    }
    normalize_revision(&revision.stdout)
}

fn normalize_revision(bytes: &[u8]) -> Option<String> {
    let revision = std::str::from_utf8(bytes).ok()?.trim();
    let supported_width = matches!(revision.len(), 40 | 64);
    (supported_width && revision.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| revision.to_ascii_lowercase())
}
