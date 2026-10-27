//! Plan a three-way directory reconciliation from saved JSON manifests.
//!
//! Run from a repository checkout:
//! `cargo run --example atp_reconcile -- baseline.json local.json remote.json`
//!
//! `--demo` supplies three small manifests in memory. The JSON result records
//! decisions and all three observed versions. Exit status 0 means the plan has
//! no conflicts, 2 means conflicts require resolution, and 1 means input or
//! output failed. This program does not apply the plan or save a new baseline.
//! A caller should advance its baseline only after verifying both destinations.

use asupersync::atp::sync::{
    DirectoryEntryKind, DirectoryEntryMetadata, DirectoryManifest, DirectoryManifestEntry,
    DirectoryPath, PathNormalizationRules, plan_bidirectional_sync,
};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::ExitCode;

/// Bound bytes read from each input, including files that grow during reading.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

fn main() -> ExitCode {
    match run() {
        Ok(false) => ExitCode::SUCCESS,
        Ok(true) => ExitCode::from(2),
        Err(error) => {
            eprintln!("atp_reconcile: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<bool, Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!(
            "Usage: atp_reconcile BASELINE.json LOCAL.json REMOTE.json\n\
             \x20      atp_reconcile --demo\n\n\
             Prints a three-way reconciliation plan as JSON.\n\
             Each input must be a complete DirectoryManifest, including parent\n\
             directory entries, and must fit within 8 MiB. The baseline must\n\
             describe the last state verified on both sides.\n\n\
             Exit codes: 0 = no conflicts, 2 = unresolved conflicts, 1 = error.\n\
             No transfers, filesystem changes, or baseline updates are performed."
        );
        return Ok(false);
    }

    let (baseline, local, remote) = if args.len() == 1 && args[0] == "--demo" {
        demo_manifests()?
    } else if args.len() == 3 {
        (
            read_manifest(Path::new(&args[0]))?,
            read_manifest(Path::new(&args[1]))?,
            read_manifest(Path::new(&args[2]))?,
        )
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected BASELINE.json LOCAL.json REMOTE.json, --demo, or --help",
        )
        .into());
    };

    let plan = plan_bidirectional_sync(&baseline, &local, &remote)?;
    let mut output = io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, &plan)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(plan.has_conflicts())
}

fn read_manifest(path: &Path) -> io::Result<DirectoryManifest> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_MANIFEST_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: manifest exceeds the 8 MiB input limit", path.display()),
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: invalid manifest JSON: {error}", path.display()),
        )
    })
}

fn demo_manifests()
-> Result<(DirectoryManifest, DirectoryManifest, DirectoryManifest), Box<dyn Error>> {
    let rules = PathNormalizationRules::default();
    let mut baseline = DirectoryManifest::new(rules);
    baseline.insert(demo_file("shared.txt", b"original\n", rules)?)?;

    let mut local = DirectoryManifest::new(rules);
    local.insert(demo_file("shared.txt", b"edited locally\n", rules)?)?;
    local.insert(demo_file("local.txt", b"created locally\n", rules)?)?;

    let mut remote = baseline.clone();
    remote.insert(demo_file("remote.txt", b"created remotely\n", rules)?)?;
    Ok((baseline, local, remote))
}

fn demo_file(
    path: &str,
    contents: &[u8],
    rules: PathNormalizationRules,
) -> Result<DirectoryManifestEntry, Box<dyn Error>> {
    Ok(DirectoryManifestEntry::new(
        DirectoryPath::normalize(path, rules)?,
        DirectoryEntryKind::File,
        Some(hex::encode(Sha256::digest(contents))),
        DirectoryEntryMetadata {
            size_bytes: Some(contents.len() as u64),
            ..DirectoryEntryMetadata::default()
        },
    ))
}
