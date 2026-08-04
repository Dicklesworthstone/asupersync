use std::env;
use std::process::Command;

const EXPLICIT_REVISION_ENV: &str = "ASUPERSYNC_GIT_COMMIT";
const COMPILED_REVISION_ENV: &str = "ASUPERSYNC_BUILD_GIT_COMMIT";

fn main() {
    println!("cargo:rerun-if-env-changed={EXPLICIT_REVISION_ENV}");

    if let Some(revision) = selected_revision() {
        println!("cargo:rustc-env={COMPILED_REVISION_ENV}={revision}");
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
