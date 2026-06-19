use std::path::PathBuf;

const LEDGER_PATH: &str = "docs/atp_rq_beat_rsync_ledger.md";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn ledger() -> String {
    std::fs::read_to_string(repo_root().join(LEDGER_PATH))
        .expect("ATP/RQ beat-rsync ledger must be readable")
}

#[test]
fn land1_insert_shift_proven_win_is_documented_and_bounded() {
    let doc = ledger();

    for needle in [
        "F-POS-5 LAND.1 PROVEN WIN",
        "insert/shift re-sync",
        "11-14x fewer bytes-on-wire",
        "tuned rsync",
        "byte-identical",
        "sha_ok=true",
        "scripts/atp_bench/resync_bench.sh",
        "ATP-vs-rsync bytes-on-wire, not old-ATP improvement",
        "No-claim boundary",
        "append is beaten",
        "2% lossy-link convergence",
        "whole-file clean-link parity",
        "F4/Finding-2 per-block repair",
    ] {
        assert!(
            doc.contains(needle),
            "LAND.1 ledger entry must contain: {needle}"
        );
    }
}
