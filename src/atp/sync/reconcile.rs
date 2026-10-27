//! Three-way reconciliation of complete directory inventories.
//!
//! This is a read-only comparison of a last-common inventory and two current
//! inventories. It neither contacts a peer nor applies filesystem changes.

use super::{
    DirectoryEntryKind, DirectoryManifest, DirectoryManifestEntry, DirectoryPath,
    PathNormalizationRules,
};
use std::collections::{BTreeMap, BTreeSet};

/// Why a three-way reconciliation must preserve both sides for resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum BidirectionalConflict {
    /// Both sides created different entries at a previously absent path.
    ConcurrentCreation,
    /// Both sides changed an existing entry differently.
    ConcurrentModification,
    /// One side deleted an entry the other side changed.
    DeleteVsEdit,
    /// A directory was removed/replaced while its peer gained or edited content.
    DirectoryVsDescendantChange,
    /// A conflicting ancestor prevents a safe descendant operation.
    AncestorConflict,
    /// Reconciliation would collapse differently spelled paths on this platform.
    CaseCollision,
    /// Both sides moved the same explicitly identified entry to different paths.
    DivergentRename,
    /// One side moved an explicitly identified entry that the other side edited.
    RenameVsEdit,
    /// One side moved an explicitly identified entry that the other side deleted.
    RenameVsDelete,
    /// An explicit identity has multiple candidate destinations after a move.
    AmbiguousRename,
}

/// A proposed operation; no variant grants authority to modify a filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum BidirectionalSyncAction {
    /// Current inventories agree; no transfer is necessary.
    Keep,
    /// Copy the local entry, including its recorded metadata, to the remote side.
    CopyLocalToRemote,
    /// Copy the remote entry, including its recorded metadata, to the local side.
    CopyRemoteToLocal,
    /// Remove the unchanged local entry after an observed remote deletion.
    DeleteLocal,
    /// Remove the unchanged remote entry after an observed local deletion.
    DeleteRemote,
    /// Preserve both sides; an automatic reconciliation is not available.
    Conflict {
        /// Specific cause requiring resolution.
        reason: BidirectionalConflict,
    },
}

/// One path's three observations and proposed operation.
///
/// Snapshots retain the exact observations needed for review and later
/// revalidation. They are not live filesystem handles or authenticated evidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct BidirectionalSyncDecision {
    /// Canonical manifest-relative path.
    pub path: DirectoryPath,
    /// Proposed operation or unresolved conflict.
    pub action: BidirectionalSyncAction,
    /// Last common observation, absent for a newly created path.
    pub baseline: Option<DirectoryManifestEntry>,
    /// Current local observation, absent after a local deletion.
    pub local: Option<DirectoryManifestEntry>,
    /// Current remote observation, absent after a remote deletion.
    pub remote: Option<DirectoryManifestEntry>,
}

impl BidirectionalSyncDecision {
    /// Whether application would overwrite or remove an existing entry.
    /// Such effects need separate operator authorization and revalidation.
    #[must_use]
    pub fn is_destructive(&self) -> bool {
        match self.action {
            BidirectionalSyncAction::CopyLocalToRemote => self.remote.is_some(),
            BidirectionalSyncAction::CopyRemoteToLocal => self.local.is_some(),
            BidirectionalSyncAction::DeleteLocal | BidirectionalSyncAction::DeleteRemote => true,
            BidirectionalSyncAction::Keep | BidirectionalSyncAction::Conflict { .. } => false,
        }
    }

    fn selected_entry(&self) -> Option<&DirectoryManifestEntry> {
        match self.action {
            BidirectionalSyncAction::Keep | BidirectionalSyncAction::CopyLocalToRemote => {
                self.local.as_ref()
            }
            BidirectionalSyncAction::CopyRemoteToLocal => self.remote.as_ref(),
            BidirectionalSyncAction::DeleteLocal
            | BidirectionalSyncAction::DeleteRemote
            | BidirectionalSyncAction::Conflict { .. } => None,
        }
    }
}

/// Deterministic, read-only three-way reconciliation result.
///
/// Operations are in path order, not filesystem execution order. In particular,
/// replacing a directory with a file requires separately authorized staging and
/// child retirement. A conflict blocks whole-plan automatic application; callers
/// must not execute a subset that crosses a conflicting ancestor or rename.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct BidirectionalSyncPlan {
    /// Common path interpretation validated across all three inputs.
    pub path_rules: PathNormalizationRules,
    /// One decision per path in the union of the three inputs.
    pub decisions: Vec<BidirectionalSyncDecision>,
}

impl BidirectionalSyncPlan {
    /// Whether at least one path requires explicit conflict resolution.
    #[must_use]
    pub fn has_conflicts(&self) -> bool {
        self.decisions
            .iter()
            .any(|decision| matches!(decision.action, BidirectionalSyncAction::Conflict { .. }))
    }

    /// Whether the current sides already agree and require no operations.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        self.decisions
            .iter()
            .all(|decision| decision.action == BidirectionalSyncAction::Keep)
    }

    /// Whether any proposed operation needs overwrite/deletion authorization.
    #[must_use]
    pub fn has_destructive_actions(&self) -> bool {
        self.decisions
            .iter()
            .any(BidirectionalSyncDecision::is_destructive)
    }

    /// Preview the common inventory after every proposed operation succeeds.
    ///
    /// Returns `None` for conflicts or an invalid projected inventory. It does
    /// not authenticate deserialized or caller-modified decisions. This is only
    /// a model preview: do not persist it as the next common baseline
    /// until both real endpoints have independently verified their resulting
    /// inventories. This function performs no filesystem or network effects.
    #[must_use]
    pub fn merged_manifest(&self) -> Option<DirectoryManifest> {
        if self.has_conflicts() {
            return None;
        }
        let mut merged = DirectoryManifest::new(self.path_rules);
        for decision in &self.decisions {
            if let Some(entry) = decision.selected_entry() {
                if decision.path != entry.path || merged.insert(entry.clone()).is_err() {
                    return None;
                }
            }
        }
        validate_manifest("merged", &merged).ok()?;
        Some(merged)
    }
}

/// Refusal to compare inventories whose identity or structure is incomplete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BidirectionalSyncError {
    /// A prior/current inventory used a different path interpretation.
    #[error("bidirectional sync requires identical path normalization rules")]
    IncompatiblePathRules,
    /// A public/deserialized inventory did not satisfy the complete-tree contract.
    #[error("invalid {side} manifest at {path}: {reason}")]
    InvalidManifest {
        /// `baseline`, `local`, `remote`, or a model `merged` inventory.
        side: &'static str,
        /// The offending manifest-relative path.
        path: DirectoryPath,
        /// Stable diagnostic explaining the refusal.
        reason: &'static str,
    },
}

/// Reconcile local and remote changes against their last common inventory.
///
/// A change on exactly one side propagates to the unchanged side. Equal current
/// entries converge even if both changed. Different concurrent creations, edits,
/// and delete/edit pairs remain conflicts. A directory deletion or type change
/// cannot erase a peer's new or edited descendant. Content identifiers and all
/// recorded metadata/caveats participate in equality; timestamps never decide a
/// winner. Explicit unique `stable_identity` values also protect rename/edit,
/// rename/delete, and divergent-rename cases. Content hashes alone do not prove
/// rename lineage: otherwise a move is represented conservatively as independent
/// creation and deletion proposals.
///
/// Inputs must be complete inventories with explicit directory ancestors, equal
/// path rules, canonical relative paths, and nonempty content identities for
/// file-like entries. The caller supplies trusted content observations and the
/// actual last common baseline; this function does not authenticate or hash files.
/// Empty inventories provide a first-sync baseline. Existing one-way planning
/// APIs retain their separate, more permissive manifest contract.
///
/// No transfer, overwrite, or deletion is executed or authorized here. Before
/// application, revalidate both endpoints against the retained observations and
/// obtain the required destructive-operation authorization. The returned preview
/// is not a completed transfer or a new durable baseline.
///
/// # Errors
/// Rejects incompatible path rules, missing content identities, ambiguous path
/// spellings, key/entry mismatches, and missing or non-directory ancestors.
pub fn plan_bidirectional_sync(
    baseline: &DirectoryManifest,
    local: &DirectoryManifest,
    remote: &DirectoryManifest,
) -> Result<BidirectionalSyncPlan, BidirectionalSyncError> {
    if baseline.path_rules != local.path_rules || baseline.path_rules != remote.path_rules {
        return Err(BidirectionalSyncError::IncompatiblePathRules);
    }
    validate_manifest("baseline", baseline)?;
    validate_manifest("local", local)?;
    validate_manifest("remote", remote)?;
    let paths: BTreeSet<_> = baseline
        .entries
        .keys()
        .chain(local.entries.keys())
        .chain(remote.entries.keys())
        .cloned()
        .collect();
    let mut decisions = BTreeMap::new();
    for path in paths {
        let before = baseline.entries.get(&path);
        let left = local.entries.get(&path);
        let right = remote.entries.get(&path);
        decisions.insert(
            path.clone(),
            BidirectionalSyncDecision {
                path,
                action: classify(before, left, right),
                baseline: before.cloned(),
                local: left.cloned(),
                remote: right.cloned(),
            },
        );
    }

    protect_changed_subtrees(baseline, local, remote, &mut decisions);
    protect_renames(baseline, local, remote, &mut decisions);
    protect_projected_case_collisions(baseline.path_rules, &mut decisions);
    protect_conflicting_ancestors(&mut decisions);
    Ok(BidirectionalSyncPlan {
        path_rules: baseline.path_rules,
        decisions: decisions.into_values().collect(),
    })
}

fn same(left: Option<&DirectoryManifestEntry>, right: Option<&DirectoryManifestEntry>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.semantically_matches(right),
        (None, None) => true,
        _ => false,
    }
}

fn classify(
    baseline: Option<&DirectoryManifestEntry>,
    local: Option<&DirectoryManifestEntry>,
    remote: Option<&DirectoryManifestEntry>,
) -> BidirectionalSyncAction {
    if same(local, remote) {
        return BidirectionalSyncAction::Keep;
    }
    if same(local, baseline) {
        return if remote.is_some() {
            BidirectionalSyncAction::CopyRemoteToLocal
        } else {
            BidirectionalSyncAction::DeleteLocal
        };
    }
    if same(remote, baseline) {
        return if local.is_some() {
            BidirectionalSyncAction::CopyLocalToRemote
        } else {
            BidirectionalSyncAction::DeleteRemote
        };
    }
    BidirectionalSyncAction::Conflict {
        reason: if baseline.is_none() {
            BidirectionalConflict::ConcurrentCreation
        } else if local.is_none() || remote.is_none() {
            BidirectionalConflict::DeleteVsEdit
        } else {
            BidirectionalConflict::ConcurrentModification
        },
    }
}

fn validate_manifest(
    side: &'static str,
    manifest: &DirectoryManifest,
) -> Result<(), BidirectionalSyncError> {
    let invalid = |path: &DirectoryPath, reason| BidirectionalSyncError::InvalidManifest {
        side,
        path: path.clone(),
        reason,
    };
    let strict_rules = PathNormalizationRules {
        reject_absolute_paths: true,
        ..manifest.path_rules
    };
    let mut case_keys = BTreeMap::new();
    for (path, entry) in &manifest.entries {
        if path != &entry.path {
            return Err(invalid(path, "map key differs from entry path"));
        }
        if !DirectoryPath::normalize(path.as_str(), strict_rules)
            .is_ok_and(|normalized| normalized == *path)
        {
            return Err(invalid(path, "path is not canonical and relative"));
        }
        if matches!(
            entry.kind,
            DirectoryEntryKind::File
                | DirectoryEntryKind::HardLink
                | DirectoryEntryKind::SparseFile
        ) && entry.content_id.as_ref().is_none_or(String::is_empty)
        {
            return Err(invalid(path, "file-like entry lacks a content identity"));
        }
        if entry.kind == DirectoryEntryKind::Symlink
            && entry
                .metadata
                .symlink_target
                .as_ref()
                .is_none_or(String::is_empty)
        {
            return Err(invalid(path, "symlink entry lacks its target"));
        }
        if !manifest.path_rules.case_sensitive
            && case_keys
                .insert(path.case_key(manifest.path_rules), path)
                .is_some()
        {
            return Err(invalid(path, "case-insensitive path collision"));
        }
    }
    for path in manifest.entries.keys() {
        for (index, _) in path.as_str().match_indices('/') {
            let ancestor = DirectoryPath(path.as_str()[..index].to_string());
            match manifest.entries.get(&ancestor) {
                Some(entry) if entry.kind == DirectoryEntryKind::Directory => {}
                Some(_) => return Err(invalid(path, "ancestor is not a directory")),
                None => {
                    return Err(invalid(
                        path,
                        "complete inventory requires explicit ancestors",
                    ));
                }
            }
        }
    }
    Ok(())
}

type Decisions = BTreeMap<DirectoryPath, BidirectionalSyncDecision>;

fn mark_subtree(decisions: &mut Decisions, root: &DirectoryPath, reason: BidirectionalConflict) {
    if let Some(decision) = decisions.get_mut(root) {
        decision.action = BidirectionalSyncAction::Conflict { reason };
    }
    let prefix = format!("{}/", root.as_str());
    for (path, decision) in decisions.range_mut(DirectoryPath(prefix.clone())..) {
        if !path.as_str().starts_with(&prefix) {
            break;
        }
        decision.action = BidirectionalSyncAction::Conflict { reason };
    }
}

fn changed_ancestors(
    baseline: &DirectoryManifest,
    current: &DirectoryManifest,
) -> BTreeSet<DirectoryPath> {
    let mut ancestors = BTreeSet::new();
    for (path, entry) in &current.entries {
        if !same(Some(entry), baseline.entries.get(path)) {
            for (index, _) in path.as_str().match_indices('/') {
                ancestors.insert(DirectoryPath(path.as_str()[..index].to_string()));
            }
        }
    }
    ancestors
}

fn changed_or_deleted_ancestors(
    baseline: &DirectoryManifest,
    current: &DirectoryManifest,
) -> BTreeSet<DirectoryPath> {
    let mut ancestors = changed_ancestors(baseline, current);
    // A rename cannot carry a peer's descendant deletion to the new path.
    // Plain subtree removal deliberately ignores these compatible deletions.
    for path in baseline.entries.keys() {
        if !current.entries.contains_key(path) {
            for (index, _) in path.as_str().match_indices('/') {
                ancestors.insert(DirectoryPath(path.as_str()[..index].to_string()));
            }
        }
    }
    ancestors
}

fn protect_changed_subtrees(
    baseline: &DirectoryManifest,
    local: &DirectoryManifest,
    remote: &DirectoryManifest,
    decisions: &mut Decisions,
) {
    let local_changes = changed_ancestors(baseline, local);
    let remote_changes = changed_ancestors(baseline, remote);
    for (path, entry) in &baseline.entries {
        if entry.kind != DirectoryEntryKind::Directory {
            continue;
        }
        let removed = |manifest: &DirectoryManifest| {
            manifest
                .entries
                .get(path)
                .is_none_or(|entry| entry.kind != DirectoryEntryKind::Directory)
        };
        if decisions.get(path).is_some_and(|decision| {
            matches!(
                decision.action,
                BidirectionalSyncAction::Conflict {
                    reason: BidirectionalConflict::DirectoryVsDescendantChange
                }
            )
        }) {
            continue;
        }
        if (removed(local) && remote_changes.contains(path))
            || (removed(remote) && local_changes.contains(path))
        {
            mark_subtree(
                decisions,
                path,
                BidirectionalConflict::DirectoryVsDescendantChange,
            );
        }
    }
}

fn explicit_identities(manifest: &DirectoryManifest) -> BTreeMap<&str, Vec<&DirectoryPath>> {
    let mut identities: BTreeMap<&str, Vec<&DirectoryPath>> = BTreeMap::new();
    for (path, entry) in &manifest.entries {
        if let Some(identity) = entry
            .metadata
            .stable_identity
            .as_deref()
            .filter(|id| !id.is_empty())
        {
            identities.entry(identity).or_default().push(path);
        }
    }
    identities
}

fn protect_renames(
    baseline: &DirectoryManifest,
    local: &DirectoryManifest,
    remote: &DirectoryManifest,
    decisions: &mut Decisions,
) {
    let left = explicit_identities(local);
    let right = explicit_identities(remote);
    let local_changes = changed_or_deleted_ancestors(baseline, local);
    let remote_changes = changed_or_deleted_ancestors(baseline, remote);
    for (identity, before) in explicit_identities(baseline) {
        let [old] = before.as_slice() else {
            // Hard-link groups or reused labels do not prove unique lineage.
            continue;
        };
        let local_paths = left.get(identity).map_or(&[][..], Vec::as_slice);
        let remote_paths = right.get(identity).map_or(&[][..], Vec::as_slice);
        let local_moved = !local_paths.is_empty() && !local_paths.contains(old);
        let remote_moved = !remote_paths.is_empty() && !remote_paths.contains(old);
        if !local_moved && !remote_moved {
            continue;
        }
        let reason = match (local_paths, remote_paths) {
            ([local_path], [remote_path])
                if local_path != remote_path && local_moved && remote_moved =>
            {
                Some(BidirectionalConflict::DivergentRename)
            }
            ([_], [remote_path]) if local_moved && !remote_moved => {
                (!same(remote.entries.get(*remote_path), baseline.entries.get(*old))
                    || remote_changes.contains(*old))
                .then_some(BidirectionalConflict::RenameVsEdit)
            }
            ([local_path], [_]) if remote_moved && !local_moved => {
                (!same(local.entries.get(*local_path), baseline.entries.get(*old))
                    || local_changes.contains(*old))
                .then_some(BidirectionalConflict::RenameVsEdit)
            }
            ([_], []) => Some(if remote.entries.contains_key(*old) {
                BidirectionalConflict::RenameVsEdit
            } else {
                BidirectionalConflict::RenameVsDelete
            }),
            ([], [_]) => Some(if local.entries.contains_key(*old) {
                BidirectionalConflict::RenameVsEdit
            } else {
                BidirectionalConflict::RenameVsDelete
            }),
            ([_], [_]) => None,
            _ => Some(BidirectionalConflict::AmbiguousRename),
        };
        if let Some(reason) = reason {
            mark_subtree(decisions, old, reason);
            for path in local_paths.iter().chain(remote_paths) {
                mark_subtree(decisions, path, reason);
            }
        }
    }
}

fn protect_projected_case_collisions(rules: PathNormalizationRules, decisions: &mut Decisions) {
    if rules.case_sensitive {
        return;
    }
    let mut groups: BTreeMap<String, Vec<DirectoryPath>> = BTreeMap::new();
    for (path, decision) in decisions.iter() {
        if decision.selected_entry().is_some() {
            groups
                .entry(path.case_key(rules))
                .or_default()
                .push(path.clone());
        }
    }
    for paths in groups.into_values().filter(|paths| paths.len() > 1) {
        for path in paths {
            mark_subtree(decisions, &path, BidirectionalConflict::CaseCollision);
        }
    }
}

fn protect_conflicting_ancestors(decisions: &mut Decisions) {
    let roots: Vec<_> = decisions
        .iter()
        .filter(|(_, decision)| matches!(decision.action, BidirectionalSyncAction::Conflict { .. }))
        .map(|(path, _)| path.clone())
        .collect();
    let mut covered = BTreeSet::new();
    for root in roots {
        if root
            .as_str()
            .match_indices('/')
            .any(|(index, _)| covered.contains(&DirectoryPath(root.as_str()[..index].to_string())))
        {
            continue;
        }
        covered.insert(root.clone());
        let prefix = format!("{}/", root.as_str());
        for (path, decision) in decisions.range_mut(DirectoryPath(prefix.clone())..) {
            if !path.as_str().starts_with(&prefix) {
                break;
            }
            if !matches!(decision.action, BidirectionalSyncAction::Conflict { .. }) {
                decision.action = BidirectionalSyncAction::Conflict {
                    reason: BidirectionalConflict::AncestorConflict,
                };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::sync::DirectoryEntryMetadata;

    fn path(raw: &str) -> DirectoryPath {
        DirectoryPath::normalize(raw, PathNormalizationRules::default()).unwrap()
    }

    fn file(raw: &str, content: &str) -> DirectoryManifestEntry {
        DirectoryManifestEntry::new(
            path(raw),
            DirectoryEntryKind::File,
            Some(content.to_string()),
            DirectoryEntryMetadata::default(),
        )
    }

    fn directory(raw: &str) -> DirectoryManifestEntry {
        DirectoryManifestEntry::new(
            path(raw),
            DirectoryEntryKind::Directory,
            None,
            DirectoryEntryMetadata::default(),
        )
    }

    fn identified(mut entry: DirectoryManifestEntry, identity: &str) -> DirectoryManifestEntry {
        entry.metadata.stable_identity = Some(identity.to_string());
        entry
    }

    fn inventory(entries: Vec<DirectoryManifestEntry>) -> DirectoryManifest {
        let mut manifest = DirectoryManifest::new(PathNormalizationRules::default());
        for entry in entries {
            manifest.insert(entry).unwrap();
        }
        manifest
    }

    fn singleton(content: Option<&str>) -> DirectoryManifest {
        inventory(
            content
                .map(|content| file("item", content))
                .into_iter()
                .collect(),
        )
    }

    fn action(plan: &BidirectionalSyncPlan, raw: &str) -> BidirectionalSyncAction {
        plan.decisions
            .iter()
            .find(|decision| decision.path == path(raw))
            .unwrap()
            .action
    }

    #[test]
    fn three_way_truth_table_preserves_conflicts_and_convergent_changes() {
        use BidirectionalSyncAction::{
            Conflict, CopyLocalToRemote, CopyRemoteToLocal, DeleteLocal, DeleteRemote, Keep,
        };
        let cases = [
            (None, None, Some("new"), CopyRemoteToLocal),
            (None, Some("new"), None, CopyLocalToRemote),
            (None, Some("new"), Some("new"), Keep),
            (
                None,
                Some("left"),
                Some("right"),
                Conflict {
                    reason: BidirectionalConflict::ConcurrentCreation,
                },
            ),
            (Some("old"), Some("old"), Some("old"), Keep),
            (Some("old"), Some("new"), Some("old"), CopyLocalToRemote),
            (Some("old"), Some("old"), Some("new"), CopyRemoteToLocal),
            (Some("old"), Some("new"), Some("new"), Keep),
            (
                Some("old"),
                Some("left"),
                Some("right"),
                Conflict {
                    reason: BidirectionalConflict::ConcurrentModification,
                },
            ),
            (Some("old"), None, Some("old"), DeleteRemote),
            (Some("old"), Some("old"), None, DeleteLocal),
            (Some("old"), None, None, Keep),
            (
                Some("old"),
                None,
                Some("new"),
                Conflict {
                    reason: BidirectionalConflict::DeleteVsEdit,
                },
            ),
            (
                Some("old"),
                Some("new"),
                None,
                Conflict {
                    reason: BidirectionalConflict::DeleteVsEdit,
                },
            ),
        ];
        for (before, left, right, expected) in cases {
            let plan =
                plan_bidirectional_sync(&singleton(before), &singleton(left), &singleton(right))
                    .unwrap();
            assert_eq!(plan.decisions.len(), 1, "{before:?}/{left:?}/{right:?}");
            assert_eq!(
                plan.decisions[0].action, expected,
                "{before:?}/{left:?}/{right:?}"
            );
            assert_eq!(plan.has_conflicts(), matches!(expected, Conflict { .. }));
            assert_eq!(plan.merged_manifest().is_some(), !plan.has_conflicts());
        }
        let empty = inventory(vec![]);
        let plan = plan_bidirectional_sync(&empty, &empty, &empty).unwrap();
        assert!(plan.is_noop());
        assert_eq!(plan.merged_manifest(), Some(empty));
    }

    #[test]
    fn independent_edits_and_additions_merge_in_both_directions() {
        let baseline = inventory(vec![file("a", "old-a"), file("b", "old-b")]);
        let local = inventory(vec![
            file("a", "new-a"),
            file("b", "old-b"),
            file("c", "new-c"),
        ]);
        let remote = inventory(vec![
            file("a", "old-a"),
            file("b", "new-b"),
            file("d", "new-d"),
        ]);
        let plan = plan_bidirectional_sync(&baseline, &local, &remote).unwrap();
        assert!(!plan.has_conflicts());
        assert!(plan.has_destructive_actions());
        assert_eq!(
            action(&plan, "a"),
            BidirectionalSyncAction::CopyLocalToRemote
        );
        assert_eq!(
            action(&plan, "b"),
            BidirectionalSyncAction::CopyRemoteToLocal
        );
        assert_eq!(
            plan.merged_manifest(),
            Some(inventory(vec![
                file("a", "new-a"),
                file("b", "new-b"),
                file("c", "new-c"),
                file("d", "new-d"),
            ]))
        );
        let reversed = plan_bidirectional_sync(&baseline, &remote, &local).unwrap();
        assert_eq!(plan.merged_manifest(), reversed.merged_manifest());
        assert_eq!(
            action(&reversed, "a"),
            BidirectionalSyncAction::CopyRemoteToLocal
        );
    }

    #[test]
    fn conflict_retains_both_original_observations_without_selecting_a_winner() {
        let baseline = singleton(Some("old"));
        let local = singleton(Some("left"));
        let remote = singleton(Some("right"));
        let plan = plan_bidirectional_sync(&baseline, &local, &remote).unwrap();
        let decision = &plan.decisions[0];
        assert_eq!(
            decision.baseline.as_ref(),
            baseline.entries.get(&path("item"))
        );
        assert_eq!(decision.local.as_ref(), local.entries.get(&path("item")));
        assert_eq!(decision.remote.as_ref(), remote.entries.get(&path("item")));
        assert!(plan.merged_manifest().is_none());
        assert!(!plan.has_destructive_actions());
    }

    #[test]
    fn metadata_and_type_changes_participate_in_three_way_equality() {
        let baseline = singleton(Some("same"));
        let mut local = baseline.clone();
        local
            .entries
            .get_mut(&path("item"))
            .unwrap()
            .metadata
            .unix_mode = Some(0o700);
        let mut remote = baseline.clone();
        remote
            .entries
            .get_mut(&path("item"))
            .unwrap()
            .metadata
            .unix_mode = Some(0o755);
        let conflict = plan_bidirectional_sync(&baseline, &local, &remote).unwrap();
        assert_eq!(
            action(&conflict, "item"),
            BidirectionalSyncAction::Conflict {
                reason: BidirectionalConflict::ConcurrentModification,
            }
        );
        let update = plan_bidirectional_sync(&baseline, &local, &baseline).unwrap();
        assert_eq!(update.merged_manifest(), Some(local));
        let changed_kind = inventory(vec![directory("item")]);
        let replace = plan_bidirectional_sync(&baseline, &changed_kind, &baseline).unwrap();
        assert_eq!(replace.merged_manifest(), Some(changed_kind));
    }

    #[test]
    fn directory_deletion_cannot_erase_an_edited_or_added_descendant() {
        let baseline = inventory(vec![directory("dir"), file("dir/a", "old")]);
        let deleted = inventory(vec![]);
        for other in [
            inventory(vec![directory("dir"), file("dir/a", "edited")]),
            inventory(vec![
                directory("dir"),
                file("dir/a", "old"),
                file("dir/new", "new"),
            ]),
        ] {
            for (local, remote) in [(&deleted, &other), (&other, &deleted)] {
                let plan = plan_bidirectional_sync(&baseline, local, remote).unwrap();
                assert!(plan.decisions.iter().all(|decision| decision.action
                    == BidirectionalSyncAction::Conflict {
                        reason: BidirectionalConflict::DirectoryVsDescendantChange,
                    }));
                assert!(plan.merged_manifest().is_none());
                assert!(!plan.has_destructive_actions());
            }
        }
    }

    #[test]
    fn replacing_a_directory_cannot_erase_an_edited_descendant() {
        let baseline = inventory(vec![directory("dir"), file("dir/a", "old")]);
        let local = inventory(vec![file("dir", "replacement")]);
        let remote = inventory(vec![directory("dir"), file("dir/a", "edited")]);
        let plan = plan_bidirectional_sync(&baseline, &local, &remote).unwrap();
        assert_eq!(
            action(&plan, "dir"),
            BidirectionalSyncAction::Conflict {
                reason: BidirectionalConflict::DirectoryVsDescendantChange,
            }
        );
        assert_eq!(action(&plan, "dir/a"), action(&plan, "dir"));
        assert!(plan.merged_manifest().is_none());
    }

    #[test]
    fn unchanged_subtrees_can_be_deleted_or_replaced_as_explicit_proposals() {
        let baseline = inventory(vec![
            directory("dir"),
            directory("dir/nested"),
            file("dir/nested/a", "old"),
        ]);
        let deleted = plan_bidirectional_sync(&baseline, &inventory(vec![]), &baseline).unwrap();
        assert!(
            deleted
                .decisions
                .iter()
                .all(|decision| decision.action == BidirectionalSyncAction::DeleteRemote)
        );
        assert!(deleted.has_destructive_actions());
        assert_eq!(deleted.merged_manifest(), Some(inventory(vec![])));
        let replacement = inventory(vec![file("dir", "new")]);
        let replaced = plan_bidirectional_sync(&baseline, &replacement, &baseline).unwrap();
        assert_eq!(
            action(&replaced, "dir"),
            BidirectionalSyncAction::CopyLocalToRemote
        );
        assert_eq!(
            action(&replaced, "dir/nested/a"),
            BidirectionalSyncAction::DeleteRemote
        );
        assert_eq!(replaced.merged_manifest(), Some(replacement));
    }

    #[test]
    fn incompatible_parent_creation_blocks_all_descendant_operations() {
        let baseline = inventory(vec![]);
        let local = inventory(vec![file("dir", "local")]);
        let remote = inventory(vec![directory("dir"), file("dir/a", "remote")]);
        let plan = plan_bidirectional_sync(&baseline, &local, &remote).unwrap();
        assert_eq!(
            action(&plan, "dir"),
            BidirectionalSyncAction::Conflict {
                reason: BidirectionalConflict::ConcurrentCreation,
            }
        );
        assert_eq!(
            action(&plan, "dir/a"),
            BidirectionalSyncAction::Conflict {
                reason: BidirectionalConflict::AncestorConflict,
            }
        );
    }

    #[test]
    fn cross_peer_case_collisions_cover_directories_and_descendants() {
        let mut baseline = inventory(vec![]);
        let mut local = inventory(vec![directory("Docs"), file("Docs/a", "a")]);
        let mut remote = inventory(vec![directory("docs"), file("docs/b", "b")]);
        baseline.path_rules.case_sensitive = false;
        local.path_rules.case_sensitive = false;
        remote.path_rules.case_sensitive = false;
        let plan = plan_bidirectional_sync(&baseline, &local, &remote).unwrap();
        assert!(plan.decisions.iter().all(|decision| decision.action
            == BidirectionalSyncAction::Conflict {
                reason: BidirectionalConflict::CaseCollision,
            }));
        assert!(plan.merged_manifest().is_none());
        baseline.path_rules.case_sensitive = true;
        local.path_rules.case_sensitive = true;
        remote.path_rules.case_sensitive = true;
        assert!(
            !plan_bidirectional_sync(&baseline, &local, &remote)
                .unwrap()
                .has_conflicts()
        );
    }

    #[test]
    fn case_only_rename_is_not_a_collision_with_the_retiring_old_path() {
        let original = identified(file("README", "same"), "identity");
        let renamed = identified(file("Readme", "same"), "identity");
        let mut baseline = inventory(vec![original]);
        let mut local = inventory(vec![renamed]);
        baseline.path_rules.case_sensitive = false;
        local.path_rules.case_sensitive = false;
        let plan = plan_bidirectional_sync(&baseline, &local, &baseline).unwrap();
        assert!(!plan.has_conflicts());
        assert_eq!(
            action(&plan, "README"),
            BidirectionalSyncAction::DeleteRemote
        );
        assert_eq!(
            action(&plan, "Readme"),
            BidirectionalSyncAction::CopyLocalToRemote
        );
        assert_eq!(plan.merged_manifest(), Some(local));
    }

    #[test]
    fn explicit_divergent_renames_preserve_all_three_paths() {
        let baseline = inventory(vec![identified(file("old", "same"), "identity")]);
        let local = inventory(vec![identified(file("left", "same"), "identity")]);
        let remote = inventory(vec![identified(file("right", "same"), "identity")]);
        let plan = plan_bidirectional_sync(&baseline, &local, &remote).unwrap();
        assert_eq!(plan.decisions.len(), 3);
        assert!(plan.decisions.iter().all(|decision| decision.action
            == BidirectionalSyncAction::Conflict {
                reason: BidirectionalConflict::DivergentRename,
            }));
    }

    #[test]
    fn rename_versus_edit_or_delete_is_one_unresolved_operation() {
        let baseline = inventory(vec![identified(file("old", "original"), "identity")]);
        let moved = inventory(vec![identified(file("new", "original"), "identity")]);
        for (other, reason) in [
            (
                inventory(vec![identified(file("old", "edited"), "identity")]),
                BidirectionalConflict::RenameVsEdit,
            ),
            (
                inventory(vec![file("old", "edited-without-identity")]),
                BidirectionalConflict::RenameVsEdit,
            ),
            (inventory(vec![]), BidirectionalConflict::RenameVsDelete),
        ] {
            for (local, remote) in [(&moved, &other), (&other, &moved)] {
                let plan = plan_bidirectional_sync(&baseline, local, remote).unwrap();
                assert!(plan.decisions.iter().all(
                    |decision| decision.action == BidirectionalSyncAction::Conflict { reason }
                ));
                assert!(plan.merged_manifest().is_none());
            }
        }
    }

    #[test]
    fn directory_rename_protects_new_and_old_subtrees_against_remote_edits() {
        let baseline = inventory(vec![
            identified(directory("old"), "directory-id"),
            file("old/a", "original"),
        ]);
        let local = inventory(vec![
            identified(directory("new"), "directory-id"),
            file("new/a", "original"),
        ]);
        let remote = inventory(vec![
            identified(directory("old"), "directory-id"),
            file("old/a", "edited"),
        ]);
        let plan = plan_bidirectional_sync(&baseline, &local, &remote).unwrap();
        assert!(plan.decisions.iter().all(|decision| decision.action
            == BidirectionalSyncAction::Conflict {
                reason: BidirectionalConflict::RenameVsEdit,
            }));
    }

    #[test]
    fn directory_rename_does_not_restore_a_peer_deleted_descendant() {
        let baseline = inventory(vec![
            identified(directory("old"), "directory-id"),
            directory("old/nested"),
            file("old/nested/a", "original"),
        ]);
        let moved = inventory(vec![
            identified(directory("new"), "directory-id"),
            directory("new/nested"),
            file("new/nested/a", "original"),
        ]);
        for other in [
            inventory(vec![
                identified(directory("old"), "directory-id"),
                directory("old/nested"),
            ]),
            inventory(vec![identified(directory("old"), "directory-id")]),
        ] {
            for (local, remote) in [(&moved, &other), (&other, &moved)] {
                let plan = plan_bidirectional_sync(&baseline, local, remote).unwrap();
                assert!(plan.decisions.iter().all(|decision| decision.action
                    == BidirectionalSyncAction::Conflict {
                        reason: BidirectionalConflict::RenameVsEdit,
                    }));
                assert!(plan.merged_manifest().is_none());
            }
            // Deleting a directory and a descendant independently is still
            // compatible when neither peer relocates the directory.
            let deleted = inventory(vec![]);
            let plan = plan_bidirectional_sync(&baseline, &deleted, &other).unwrap();
            assert!(!plan.has_conflicts());
            assert_eq!(plan.merged_manifest(), Some(deleted));
        }
    }

    #[test]
    fn ambiguous_explicit_rename_candidates_are_never_chosen_arbitrarily() {
        let baseline = inventory(vec![identified(file("old", "same"), "identity")]);
        let local = inventory(vec![
            identified(file("a", "same"), "identity"),
            identified(file("b", "same"), "identity"),
        ]);
        let plan = plan_bidirectional_sync(&baseline, &local, &baseline).unwrap();
        assert!(plan.decisions.iter().all(|decision| decision.action
            == BidirectionalSyncAction::Conflict {
                reason: BidirectionalConflict::AmbiguousRename,
            }));
    }

    #[test]
    fn content_equality_alone_is_not_rename_lineage() {
        let baseline = inventory(vec![file("old", "same")]);
        let local = inventory(vec![file("left", "same")]);
        let remote = inventory(vec![file("right", "same")]);
        let plan = plan_bidirectional_sync(&baseline, &local, &remote).unwrap();
        assert!(!plan.has_conflicts());
        assert_eq!(
            plan.merged_manifest(),
            Some(inventory(vec![file("left", "same"), file("right", "same")]))
        );
    }

    #[test]
    fn malformed_public_manifests_are_refused_before_planning() {
        let empty = inventory(vec![]);
        let mut mismatch = singleton(Some("content"));
        mismatch.entries.get_mut(&path("item")).unwrap().path = path("other");
        let mut missing_digest = singleton(Some("content"));
        missing_digest
            .entries
            .get_mut(&path("item"))
            .unwrap()
            .content_id = None;
        let missing_parent = inventory(vec![file("dir/a", "content")]);
        let file_parent = inventory(vec![file("dir", "content"), file("dir/a", "child")]);
        let symlink_without_target = inventory(vec![DirectoryManifestEntry::new(
            path("link"),
            DirectoryEntryKind::Symlink,
            None,
            DirectoryEntryMetadata::default(),
        )]);
        for malformed in [
            mismatch,
            missing_digest,
            missing_parent,
            file_parent,
            symlink_without_target,
        ] {
            assert!(matches!(
                plan_bidirectional_sync(&empty, &malformed, &empty),
                Err(BidirectionalSyncError::InvalidManifest { side: "local", .. })
            ));
        }
    }

    #[test]
    fn deserialization_cannot_bypass_relative_path_validation() {
        let empty = inventory(vec![]);
        for raw in [
            "../escape",
            "/absolute",
            "dir//file",
            "dir/./file",
            "C:drive",
        ] {
            let mut value = serde_json::to_value(singleton(Some("content"))).unwrap();
            let entries = value["entries"].as_object_mut().unwrap();
            let mut entry = entries.remove("item").unwrap();
            entry["path"] = serde_json::Value::String(raw.to_string());
            entries.insert(raw.to_string(), entry);
            let malformed: DirectoryManifest = serde_json::from_value(value).unwrap();
            assert!(
                plan_bidirectional_sync(&empty, &malformed, &empty).is_err(),
                "{raw}"
            );
        }
    }

    #[test]
    fn path_policy_and_case_ancestor_ambiguity_are_refused() {
        let empty = inventory(vec![]);
        let mut different_rules = empty.clone();
        different_rules.path_rules.normalize_backslashes = false;
        assert_eq!(
            plan_bidirectional_sync(&empty, &different_rules, &empty),
            Err(BidirectionalSyncError::IncompatiblePathRules)
        );
        let mut insensitive = empty;
        insensitive.path_rules.case_sensitive = false;
        for entries in [
            vec![file("A", "first"), file("a", "second")],
            vec![directory("Dir"), file("dir/file", "content")],
        ] {
            let mut ambiguous = inventory(entries);
            ambiguous.path_rules = insensitive.path_rules;
            assert!(plan_bidirectional_sync(&insensitive, &ambiguous, &insensitive).is_err());
        }
    }

    #[test]
    fn plans_are_deterministic_and_serializable_without_mutating_inputs() {
        let baseline = inventory(vec![]);
        let local = inventory(vec![file("z", "last"), file("a", "first")]);
        let remote = inventory(vec![file("m", "middle")]);
        let before = (baseline.clone(), local.clone(), remote.clone());
        let plan = plan_bidirectional_sync(&baseline, &local, &remote).unwrap();
        assert_eq!(
            plan.decisions
                .iter()
                .map(|decision| decision.path.as_str())
                .collect::<Vec<_>>(),
            ["a", "m", "z"]
        );
        let encoded = serde_json::to_vec(&plan).unwrap();
        let restored: BidirectionalSyncPlan = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(restored, plan);
        assert_eq!(restored.merged_manifest(), plan.merged_manifest());
        assert_eq!((baseline, local, remote), before);
        assert!(!plan.has_destructive_actions());
    }
}
