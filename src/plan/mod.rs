//! Plan DAG IR for concurrency combinators.
//!
//! This module defines a minimal DAG representation for join/race/timeout
//! structures. It is intentionally lightweight and uses safe Rust only.

use crate::util::{DetHashMap, DetHashSet};
use std::collections::BTreeSet;
use std::mem;
use std::time::Duration;

/// Node identifier for a plan DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanId(usize);

impl PlanId {
    /// Creates a new plan id from a raw index.
    #[inline]
    #[must_use]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    /// Returns the underlying index.
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// Plan node describing a combinator and its dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanNode {
    /// Leaf computation (e.g., an opaque task).
    Leaf {
        /// Human-readable label for debugging.
        label: String,
    },
    /// Join of all children.
    Join {
        /// Child nodes that must all complete.
        children: Vec<PlanId>,
    },
    /// Race of children.
    Race {
        /// Child nodes that race for first completion.
        children: Vec<PlanId>,
    },
    /// Timeout applied to a child computation.
    Timeout {
        /// Child node being timed.
        child: PlanId,
        /// Timeout duration.
        duration: Duration,
    },
}

impl PlanNode {
    fn children(&self) -> Box<dyn Iterator<Item = PlanId> + '_> {
        match self {
            Self::Leaf { .. } => Box::new(std::iter::empty()),
            Self::Join { children } | Self::Race { children } => Box::new(children.iter().copied()),
            Self::Timeout { child, .. } => Box::new(std::iter::once(*child)),
        }
    }
}

/// Errors returned when validating a plan DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// A node referenced a missing child id.
    MissingNode {
        /// Parent node id.
        parent: PlanId,
        /// Missing child id.
        child: PlanId,
    },
    /// A join/race node had no children.
    EmptyChildren {
        /// Node with empty child list.
        parent: PlanId,
    },
    /// A cycle was detected in the graph.
    Cycle {
        /// Node where cycle detection occurred.
        at: PlanId,
    },
}

/// Plan DAG builder and container.
#[derive(Debug, Default, Clone)]
pub struct PlanDag {
    /// Nodes stored in insertion order.
    pub(super) nodes: Vec<PlanNode>,
    /// Root node id, if set.
    pub(super) root: Option<PlanId>,
}

impl PlanDag {
    /// Creates an empty plan DAG.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a leaf node and returns its id.
    pub fn leaf(&mut self, label: impl Into<String>) -> PlanId {
        self.push_node(PlanNode::Leaf {
            label: label.into(),
        })
    }

    /// Adds a join node and returns its id.
    pub fn join(&mut self, children: Vec<PlanId>) -> PlanId {
        self.push_node(PlanNode::Join { children })
    }

    /// Adds a race node and returns its id.
    pub fn race(&mut self, children: Vec<PlanId>) -> PlanId {
        self.push_node(PlanNode::Race { children })
    }

    /// Adds a timeout node and returns its id.
    pub fn timeout(&mut self, child: PlanId, duration: Duration) -> PlanId {
        self.push_node(PlanNode::Timeout { child, duration })
    }

    /// Sets the root node for this plan.
    pub fn set_root(&mut self, root: PlanId) {
        self.root = Some(root);
    }

    /// Returns the root node, if set.
    #[inline]
    #[must_use]
    pub const fn root(&self) -> Option<PlanId> {
        self.root
    }

    /// Returns a reference to a node by id.
    #[inline]
    #[must_use]
    pub fn node(&self, id: PlanId) -> Option<&PlanNode> {
        self.nodes.get(id.index())
    }

    /// Returns a mutable reference to a node by id.
    #[must_use]
    pub fn node_mut(&mut self, id: PlanId) -> Option<&mut PlanNode> {
        self.nodes.get_mut(id.index())
    }

    /// Returns the number of nodes in this DAG.
    #[inline]
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Validates the DAG for structural correctness.
    pub fn validate(&self) -> Result<(), PlanError> {
        let Some(root) = self.root else {
            return Ok(());
        };

        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        self.validate_from(root, &mut visiting, &mut visited)?;
        Ok(())
    }

    fn validate_from(
        &self,
        id: PlanId,
        visiting: &mut BTreeSet<PlanId>,
        visited: &mut BTreeSet<PlanId>,
    ) -> Result<(), PlanError> {
        if visited.contains(&id) {
            return Ok(());
        }
        if !visiting.insert(id) {
            return Err(PlanError::Cycle { at: id });
        }

        let node = self.node(id).ok_or(PlanError::MissingNode {
            parent: id,
            child: id,
        })?;

        match node {
            PlanNode::Join { children } | PlanNode::Race { children } => {
                if children.is_empty() {
                    return Err(PlanError::EmptyChildren { parent: id });
                }
            }
            PlanNode::Leaf { .. } | PlanNode::Timeout { .. } => {}
        }

        for child in node.children() {
            if self.node(child).is_none() {
                return Err(PlanError::MissingNode { parent: id, child });
            }
            self.validate_from(child, visiting, visited)?;
        }

        visiting.remove(&id);
        visited.insert(id);
        Ok(())
    }

    pub(super) fn push_node(&mut self, node: PlanNode) -> PlanId {
        let id = PlanId::new(self.nodes.len());
        self.nodes.push(node);
        id
    }
}

/// Builder facade for capturing a combinator-shaped [`PlanDag`].
///
/// `PlanBuilder` is intentionally thin: it records plan structure only and
/// does not execute, poll, spawn, cancel, or rewrite anything. That keeps plan
/// capture zero-cost when unused and preserves the existing direct combinator
/// execution path until an explicit interpreter is selected.
///
/// ```
/// use asupersync::plan::{PlanNode, capture};
/// use std::time::Duration;
///
/// let plan = capture(|p| {
///     let fast = p.leaf("fast");
///     let slow_leaf = p.leaf("slow");
///     let slow = p.timeout(slow_leaf, Duration::from_millis(50));
///     p.race([fast, slow])
/// }).expect("captured plan should validate");
///
/// assert_eq!(plan.node_count(), 4);
/// assert!(matches!(plan.root().and_then(|id| plan.node(id)), Some(PlanNode::Race { .. })));
/// ```
#[derive(Debug, Default, Clone)]
pub struct PlanBuilder {
    dag: PlanDag,
}

impl PlanBuilder {
    /// Creates an empty plan builder.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Captures a leaf computation placeholder.
    pub fn leaf(&mut self, label: impl Into<String>) -> PlanId {
        self.dag.leaf(label)
    }

    /// Captures a join node.
    pub fn join(&mut self, children: impl IntoIterator<Item = PlanId>) -> PlanId {
        self.dag.join(children.into_iter().collect())
    }

    /// Captures a race node.
    pub fn race(&mut self, children: impl IntoIterator<Item = PlanId>) -> PlanId {
        self.dag.race(children.into_iter().collect())
    }

    /// Captures a timeout wrapper.
    pub fn timeout(&mut self, child: PlanId, duration: Duration) -> PlanId {
        self.dag.timeout(child, duration)
    }

    /// Sets the plan root explicitly.
    pub fn set_root(&mut self, root: PlanId) {
        self.dag.set_root(root);
    }

    /// Returns a read-only view of the partially captured DAG.
    #[inline]
    #[must_use]
    pub const fn dag(&self) -> &PlanDag {
        &self.dag
    }

    /// Finishes capture after validating the root-reachable DAG.
    pub fn build(self) -> Result<PlanDag, PlanError> {
        self.dag.validate()?;
        Ok(self.dag)
    }
}

/// Captures a combinator-shaped plan with the returned node as the root.
///
/// The closure records structure through [`PlanBuilder`] and returns the root
/// node. Validation runs before the DAG is returned, so empty joins/races,
/// missing child ids, and cycles fail at capture time.
pub fn capture(build: impl FnOnce(&mut PlanBuilder) -> PlanId) -> Result<PlanDag, PlanError> {
    let mut builder = PlanBuilder::new();
    let root = build(&mut builder);
    builder.set_root(root);
    builder.build()
}

// ---------------------------------------------------------------------------
// E-graph core (deterministic hashcons + union-find)
// ---------------------------------------------------------------------------

/// Identifier for an equivalence class in the e-graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EClassId(usize);

impl EClassId {
    /// Creates a new class id from a raw index.
    #[inline]
    #[must_use]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    /// Returns the underlying index.
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// An e-graph node for plan expressions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ENode {
    /// Leaf computation (opaque).
    Leaf {
        /// Human-readable label.
        label: String,
    },
    /// Join of all children.
    Join {
        /// Child classes that must all complete.
        children: Vec<EClassId>,
    },
    /// Race among children.
    Race {
        /// Child classes that race for first completion.
        children: Vec<EClassId>,
    },
    /// Timeout applied to a child computation.
    Timeout {
        /// Child class being timed.
        child: EClassId,
        /// Timeout duration.
        duration: Duration,
    },
}

/// An equivalence class of e-nodes.
///
/// Nodes are stored in a shared arena (`EGraph::node_arena`) and referenced
/// by index. This avoids per-class heap allocations for node storage and
/// makes merge operations cheaper (moving `u32` indices instead of `ENode`s).
#[derive(Debug, Clone)]
pub struct EClass {
    id: EClassId,
    /// Indices into `EGraph::node_arena`.
    node_indices: Vec<u32>,
}

impl EClass {
    /// Returns the class id.
    #[inline]
    #[must_use]
    pub const fn id(&self) -> EClassId {
        self.id
    }
}

/// Deterministic e-graph core for plan rewrites.
///
/// This structure provides:
/// - hashconsed node insertion (deduplication)
/// - union-find for class merging
/// - deterministic canonical ids (smallest id wins)
/// - arena-backed node storage for cache-friendly iteration
///
/// All e-nodes are stored in a single contiguous `node_arena`. Each class
/// holds `Vec<u32>` indices into this arena, making merge operations cheaper
/// (moving 4-byte indices rather than full `ENode` values).
#[derive(Debug, Default)]
pub struct EGraph {
    /// Flat arena for all e-nodes. Append-only; indices are stable.
    node_arena: Vec<ENode>,
    /// Per-class metadata with node arena indices.
    classes: Vec<EClass>,
    parent: Vec<EClassId>,
    hashcons: DetHashMap<ENode, EClassId>,
}

#[inline]
fn arena_index_from_len(len: usize) -> u32 {
    u32::try_from(len).expect("egraph node arena exceeded u32::MAX entries")
}

impl EGraph {
    /// Creates an empty e-graph.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a leaf node and returns its class id.
    pub fn add_leaf(&mut self, label: impl Into<String>) -> EClassId {
        self.add_enode(ENode::Leaf {
            label: label.into(),
        })
    }

    /// Inserts a join node and returns its class id.
    pub fn add_join(&mut self, children: Vec<EClassId>) -> EClassId {
        self.add_enode(ENode::Join { children })
    }

    /// Inserts a race node and returns its class id.
    pub fn add_race(&mut self, children: Vec<EClassId>) -> EClassId {
        self.add_enode(ENode::Race { children })
    }

    /// Inserts a timeout node and returns its class id.
    pub fn add_timeout(&mut self, child: EClassId, duration: Duration) -> EClassId {
        self.add_enode(ENode::Timeout { child, duration })
    }

    /// Inserts an e-node with hashconsing.
    pub fn add_enode(&mut self, node: ENode) -> EClassId {
        let canonical = self.canonicalize_enode(node);
        if let Some(existing) = self.hashcons.get(&canonical) {
            return self.find(*existing);
        }

        let arena_idx = arena_index_from_len(self.node_arena.len());
        self.node_arena.push(canonical.clone());

        let id = EClassId::new(self.classes.len());
        self.classes.push(EClass {
            id,
            node_indices: vec![arena_idx],
        });
        self.parent.push(id);
        self.hashcons.insert(canonical, id);
        id
    }

    /// Returns the canonical representative for a class id.
    pub fn canonical_id(&mut self, id: EClassId) -> EClassId {
        self.find(id)
    }

    /// Returns the canonical class for an id, if present.
    pub fn class(&mut self, id: EClassId) -> Option<&EClass> {
        let root = self.find(id);
        self.classes.get(root.index())
    }

    /// Returns cloned nodes for a class, resolved from the arena.
    ///
    /// This is the primary way to read class nodes. Nodes live in a shared
    /// arena; this method collects them into an owned `Vec` for the caller.
    pub fn class_nodes_cloned(&mut self, id: EClassId) -> Option<Vec<ENode>> {
        let root = self.find(id);
        let class = self.classes.get(root.index())?;
        Some(
            class
                .node_indices
                .iter()
                .map(|&idx| self.node_arena[idx as usize].clone())
                .collect(),
        )
    }

    /// Merges two classes and returns the canonical representative.
    ///
    /// Determinism rule: the smallest id always wins.
    pub fn merge(&mut self, a: EClassId, b: EClassId) -> EClassId {
        let (winner, _) = self.merge_internal(a, b);
        self.rebuild_hashcons();
        winner
    }

    fn merge_internal(&mut self, a: EClassId, b: EClassId) -> (EClassId, bool) {
        let root_a = self.find(a);
        let root_b = self.find(b);
        if root_a == root_b {
            return (root_a, false);
        }

        let (winner, loser) = if root_a.index() <= root_b.index() {
            (root_a, root_b)
        } else {
            (root_b, root_a)
        };

        self.parent[loser.index()] = winner;

        let mut moved = mem::take(&mut self.classes[loser.index()].node_indices);
        self.classes[winner.index()].node_indices.append(&mut moved);

        (winner, true)
    }

    fn find(&mut self, id: EClassId) -> EClassId {
        let mut idx = id.index();
        let mut root = idx;
        while self.parent[root].index() != root {
            root = self.parent[root].index();
        }

        while self.parent[idx].index() != root {
            let next = self.parent[idx].index();
            self.parent[idx] = EClassId::new(root);
            idx = next;
        }

        EClassId::new(root)
    }

    fn canonicalize_enode(&mut self, node: ENode) -> ENode {
        match node {
            ENode::Leaf { label } => ENode::Leaf { label },
            ENode::Join { children } => ENode::Join {
                children: self.canonicalize_children(children),
            },
            ENode::Race { children } => ENode::Race {
                children: self.canonicalize_children(children),
            },
            ENode::Timeout { child, duration } => ENode::Timeout {
                child: self.find(child),
                duration,
            },
        }
    }

    fn canonicalize_children(&mut self, children: Vec<EClassId>) -> Vec<EClassId> {
        let mut canonical: Vec<EClassId> = children.into_iter().map(|id| self.find(id)).collect();
        canonical.sort_unstable();
        canonical
    }

    fn rebuild_hashcons(&mut self) {
        loop {
            self.hashcons.clear();
            let mut merges: Vec<(EClassId, EClassId)> = Vec::new();

            for idx in 0..self.classes.len() {
                let id = EClassId::new(idx);
                if self.find(id) != id {
                    continue;
                }

                let indices = mem::take(&mut self.classes[idx].node_indices);
                let mut seen: DetHashSet<ENode> = DetHashSet::default();
                let mut rebuilt_indices = Vec::new();

                for &ni in &indices {
                    let node = self.node_arena[ni as usize].clone();
                    let canonical = self.canonicalize_enode(node);
                    // Update the arena slot in place (avoids arena growth).
                    self.node_arena[ni as usize] = canonical.clone();
                    if seen.insert(canonical.clone()) {
                        rebuilt_indices.push(ni);
                    }
                    if let Some(existing) = self.hashcons.get(&canonical) {
                        let existing_root = self.find(*existing);
                        let id_root = self.find(id);
                        if existing_root != id_root {
                            let (a, b) = if existing_root.index() <= id_root.index() {
                                (existing_root, id_root)
                            } else {
                                (id_root, existing_root)
                            };
                            merges.push((a, b));
                        }
                    } else {
                        self.hashcons.insert(canonical, id);
                    }
                }

                self.classes[idx].node_indices = rebuilt_indices;
            }

            if merges.is_empty() {
                break;
            }

            merges.sort();
            merges.dedup();
            for (a, b) in merges {
                self.merge_internal(a, b);
            }
        }
    }
}

pub mod analysis;
pub mod certificate;
pub mod execute;
pub mod extractor;
pub mod fixtures;
pub mod latency_algebra;
pub mod rewrite;
pub use analysis::{
    BudgetEffect, CancelSafety, DeadlineMicros, IndependenceRelation, IndependenceResult,
    NodeAnalysis, ObligationFlow, ObligationSafety, PlanAnalysis, PlanAnalyzer,
    SideConditionChecker, TraceEquivalenceHint,
};
pub use certificate::{
    CertificateVersion, PlanHash, RewriteCertificate, StepVerifyError, VerifyError,
};
pub use extractor::{ExtractionCertificate, ExtractionVerifyError, Extractor, PlanCost};
pub use rewrite::{AlgebraicLaw, RewritePolicy, RewriteReport, RewriteRule, RewriteRuleSchema};

#[cfg(test)]
#[path = "mod_inline_tests.rs"]
mod tests;
