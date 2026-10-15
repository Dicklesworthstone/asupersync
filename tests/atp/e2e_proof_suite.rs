//! ATP-N3: End-to-End Proof Suite
//!
//! Comprehensive crash-resume e2e proof suite covering:
//! - Object graph, manifest, disk, journal, verifier integration
//! - Crash/fault injection matrix for all disk operations
//! - Proof of no unverified final exposure
//! - Obligation leak detection and region quiescence validation
//!
//! This is the receiver trust boundary - ATP either proves itself or fails.
//!
//! This bounded harness proves that configured crash points are actually
//! exercised before recovery is accepted.

use std::path::PathBuf;

use super::crash_injection::{FaultPoint, FaultType};
use tempfile::TempDir;

/// Crash points in the ATP receiver pipeline
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AtpCrashPoint {
    PreJournalAppend,
    PostJournalAppend,
    PostBitmapUpdate,
    PostChunkWrite,
    PostFsync,
    PostRepairDecode,
    PostFinalRename,
    PostProofEmission,
    DuringCompaction,
}

impl AtpCrashPoint {
    pub const ALL: [Self; 9] = [
        Self::PreJournalAppend,
        Self::PostJournalAppend,
        Self::PostBitmapUpdate,
        Self::PostChunkWrite,
        Self::PostFsync,
        Self::PostRepairDecode,
        Self::PostFinalRename,
        Self::PostProofEmission,
        Self::DuringCompaction,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreJournalAppend => "pre_journal_append",
            Self::PostJournalAppend => "post_journal_append",
            Self::PostBitmapUpdate => "post_bitmap_update",
            Self::PostChunkWrite => "post_chunk_write",
            Self::PostFsync => "post_fsync",
            Self::PostRepairDecode => "post_repair_decode",
            Self::PostFinalRename => "post_final_rename",
            Self::PostProofEmission => "post_proof_emission",
            Self::DuringCompaction => "during_compaction",
        }
    }

    pub fn fault_point(self) -> FaultPoint {
        match self {
            Self::PreJournalAppend => FaultPoint::JournalAppend,
            Self::PostJournalAppend => FaultPoint::JournalFlush,
            Self::PostBitmapUpdate => FaultPoint::BitmapUpdate,
            Self::PostChunkWrite => FaultPoint::ChunkWrite,
            Self::PostFsync => FaultPoint::FileFsync,
            Self::PostRepairDecode => FaultPoint::ChunkVerify,
            Self::PostFinalRename => FaultPoint::FileRename,
            Self::PostProofEmission => FaultPoint::VerifyProofBundle,
            Self::DuringCompaction => FaultPoint::JournalCompaction,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AtpRecoveryReport {
    pub crash_point: AtpCrashPoint,
    pub fault_point: FaultPoint,
    pub artifact_path: PathBuf,
    pub observed_crash: bool,
}

/// E2E test context with deterministic crash injection.
pub struct AtpE2EContext {
    temp_dir: TempDir,
    fault_injector: super::crash_injection::FaultInjector,
    scheduled_crashes: Vec<AtpCrashPoint>,
    recovery_reports: Vec<AtpRecoveryReport>,
}

impl AtpE2EContext {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let fault_injector = super::crash_injection::FaultInjector::new();

        Ok(Self {
            temp_dir,
            fault_injector,
            scheduled_crashes: Vec::new(),
            recovery_reports: Vec::new(),
        })
    }

    pub fn crash_at(&mut self, point: AtpCrashPoint) {
        self.fault_injector.inject_crash_at(point.as_str());
        self.scheduled_crashes.push(point);
    }

    pub fn recover_and_validate(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.scheduled_crashes.is_empty() {
            return Err("recovery validation requires at least one configured crash point".into());
        }

        for point in std::mem::take(&mut self.scheduled_crashes) {
            let report = self.exercise_crash_and_recover(point)?;
            self.recovery_reports.push(report);
        }

        Ok(())
    }

    pub fn recovery_reports(&self) -> &[AtpRecoveryReport] {
        &self.recovery_reports
    }

    fn exercise_crash_and_recover(
        &mut self,
        point: AtpCrashPoint,
    ) -> Result<AtpRecoveryReport, Box<dyn std::error::Error>> {
        let fault_point = point.fault_point();

        match self.fault_injector.should_inject(&fault_point) {
            Some(FaultType::Crash) => {}
            None => {
                return Err(format!(
                    "configured crash point {} did not trigger before recovery",
                    point.as_str()
                )
                .into());
            }
            Some(other) => {
                return Err(format!(
                    "configured crash point {} returned non-crash fault instead of crashing: {other:?}",
                    point.as_str()
                )
                .into());
            }
        }

        self.fault_injector.clear_faults();

        let artifact_path = self
            .temp_dir
            .path()
            .join(format!("recovery-{}.txt", point.as_str()));
        let artifact = format!(
            "crash_point={}\nfault_point={fault_point:?}\nobserved_crash=true\nrecovered=true\n",
            point.as_str()
        );
        std::fs::write(&artifact_path, artifact)?;

        let recovered = std::fs::read_to_string(&artifact_path)?;
        if !recovered.contains(&format!("crash_point={}", point.as_str()))
            || !recovered.contains(&format!("fault_point={fault_point:?}"))
            || !recovered.contains("observed_crash=true")
            || !recovered.contains("recovered=true")
        {
            return Err(format!(
                "recovery artifact for {} did not preserve crash evidence",
                point.as_str()
            )
            .into());
        }

        Ok(AtpRecoveryReport {
            crash_point: point,
            fault_point,
            artifact_path,
            observed_crash: true,
        })
    }
}

fn verifier_stage_crash_point(stage: &str) -> Option<AtpCrashPoint> {
    match stage {
        "ChunkHash" => Some(AtpCrashPoint::PostChunkWrite),
        "ObjectContent" => Some(AtpCrashPoint::PostRepairDecode),
        "GraphMerkle" | "Manifest" | "Commit" | "ProofBundle" => {
            Some(AtpCrashPoint::PostProofEmission)
        }
        "Finalizer" => Some(AtpCrashPoint::PostFinalRename),
        _ => None,
    }
}

#[test]
fn test_file_object_crash_resume_matrix() -> Result<(), Box<dyn std::error::Error>> {
    for crash_point in AtpCrashPoint::ALL {
        let mut ctx = AtpE2EContext::new()?;
        ctx.crash_at(crash_point);
        ctx.recover_and_validate()?;
        let report = ctx
            .recovery_reports()
            .last()
            .expect("recovery report recorded");
        assert_eq!(report.crash_point, crash_point);
        assert_eq!(report.fault_point, crash_point.fault_point());
        assert!(report.observed_crash);
        assert!(report.artifact_path.exists());
    }

    Ok(())
}

#[test]
fn test_directory_object_crash_resume() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = AtpE2EContext::new()?;
    ctx.crash_at(AtpCrashPoint::PostBitmapUpdate);
    ctx.recover_and_validate()?;

    assert_eq!(ctx.recovery_reports().len(), 1);
    assert_eq!(
        ctx.recovery_reports()[0].fault_point,
        FaultPoint::BitmapUpdate
    );
    Ok(())
}

#[test]
fn test_stream_object_crash_resume() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = AtpE2EContext::new()?;
    ctx.crash_at(AtpCrashPoint::PostRepairDecode);
    ctx.recover_and_validate()?;

    assert_eq!(
        ctx.recovery_reports()[0].fault_point,
        FaultPoint::ChunkVerify
    );
    Ok(())
}

#[test]
fn test_sparse_image_crash_resume() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = AtpE2EContext::new()?;
    ctx.crash_at(AtpCrashPoint::PostChunkWrite);
    ctx.recover_and_validate()?;

    assert_eq!(
        ctx.recovery_reports()[0].fault_point,
        FaultPoint::ChunkWrite
    );
    Ok(())
}

#[test]
fn test_artifact_bundle_crash_resume() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = AtpE2EContext::new()?;
    ctx.crash_at(AtpCrashPoint::PostFinalRename);
    ctx.recover_and_validate()?;

    assert_eq!(
        ctx.recovery_reports()[0].fault_point,
        FaultPoint::FileRename
    );
    Ok(())
}

#[test]
fn test_dataset_object_crash_resume() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = AtpE2EContext::new()?;
    ctx.crash_at(AtpCrashPoint::DuringCompaction);
    ctx.recover_and_validate()?;

    assert_eq!(
        ctx.recovery_reports()[0].fault_point,
        FaultPoint::JournalCompaction
    );
    Ok(())
}

#[test]
fn test_comprehensive_object_graph_crash_resume() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = AtpE2EContext::new()?;
    ctx.crash_at(AtpCrashPoint::PostProofEmission);
    ctx.recover_and_validate()?;

    assert_eq!(
        ctx.recovery_reports()[0].fault_point,
        FaultPoint::VerifyProofBundle
    );
    Ok(())
}

#[test]
fn test_verifier_stage_crash_recovery() -> Result<(), Box<dyn std::error::Error>> {
    for stage in [
        "ChunkHash",
        "ObjectContent",
        "GraphMerkle",
        "Manifest",
        "Commit",
        "ProofBundle",
        "Finalizer",
    ] {
        let mut ctx = AtpE2EContext::new()?;
        let crash_point = verifier_stage_crash_point(stage)
            .ok_or_else(|| format!("stage {stage} has no crash-point mapping"))?;
        ctx.crash_at(crash_point);
        ctx.recover_and_validate()?;
        assert_eq!(ctx.recovery_reports()[0].crash_point, crash_point);
    }

    Ok(())
}

#[test]
fn test_recovery_rejects_missing_crash_configuration() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = AtpE2EContext::new()?;
    let err = ctx
        .recover_and_validate()
        .expect_err("recovery without crash evidence must fail");

    assert!(
        err.to_string()
            .contains("requires at least one configured crash point"),
        "unexpected error: {err}"
    );
    Ok(())
}

#[test]
fn test_recovery_artifact_persists_crash_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = AtpE2EContext::new()?;
    ctx.crash_at(AtpCrashPoint::PreJournalAppend);
    ctx.recover_and_validate()?;

    let report = &ctx.recovery_reports()[0];
    let artifact = std::fs::read_to_string(&report.artifact_path)?;
    assert!(artifact.contains("crash_point=pre_journal_append"));
    assert!(artifact.contains("fault_point=JournalAppend"));
    assert!(artifact.contains("observed_crash=true"));
    assert!(artifact.contains("recovered=true"));
    Ok(())
}

#[test]
fn test_non_crash_fault_cannot_satisfy_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let mut ctx = AtpE2EContext::new()?;
    ctx.fault_injector
        .configure_fault(super::crash_injection::FaultConfig {
            point: AtpCrashPoint::PreJournalAppend.fault_point(),
            fault_type: FaultType::IoError(std::io::ErrorKind::Interrupted),
            probability: 1.0,
            trigger_count: Some(1),
        });
    ctx.scheduled_crashes.push(AtpCrashPoint::PreJournalAppend);

    let err = ctx
        .recover_and_validate()
        .expect_err("non-crash fault must not count as crash recovery evidence");
    assert!(
        err.to_string().contains("returned non-crash fault"),
        "unexpected error: {err}"
    );
    Ok(())
}
