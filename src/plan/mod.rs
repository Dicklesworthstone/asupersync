//! Plan DAG IR for concurrency combinators.
//!
//! This module defines a minimal DAG representation for join/race/timeout
//! structures. It is intentionally lightweight and uses safe Rust only.

use crate::util::{DetHashMap, DetHashSet};
use std::collections::HashSet;
use std::mem;
use std::time::Duration;

/// Node identifier for a plan DAG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlanId(usize);

impl PlanId {
    /// Creates a new plan id from a raw index.
    #[must_use]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    /// Returns the underlying index.
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
#[derive(Debug, Default)]
pub struct PlanDag {
    /// Nodes stored in insertion order.
    pub(super) nodes: Vec<PlanNode>,
    /// Root node id, if set.
    pub(super) root: Option<PlanId>,
}

impl PlanDag {
    /// Creates an empty plan DAG.
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
    #[must_use]
    pub const fn root(&self) -> Option<PlanId> {
        self.root
    }

    /// Returns a reference to a node by id.
    #[must_use]
    pub fn node(&self, id: PlanId) -> Option<&PlanNode> {
        self.nodes.get(id.index())
    }

    /// Returns a mutable reference to a node by id.
    #[must_use]
    pub fn node_mut(&mut self, id: PlanId) -> Option<&mut PlanNode> {
        self.nodes.get_mut(id.index())
    }

    /// Validates the DAG for structural correctness.
    pub fn validate(&self) -> Result<(), PlanError> {
        let Some(root) = self.root else {
            return Ok(());
        };

        let mut visiting = HashSet::new();
        let mut visited = HashSet::new();
        self.validate_from(root, &mut visiting, &mut visited)?;
        Ok(())
    }

    fn validate_from(
        &self,
        id: PlanId,
        visiting: &mut HashSet<PlanId>,
        visited: &mut HashSet<PlanId>,
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

// ---------------------------------------------------------------------------
// E-graph core (deterministic hashcons + union-find)
// ---------------------------------------------------------------------------

/// Identifier for an equivalence class in the e-graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EClassId(usize);

impl EClassId {
    /// Creates a new class id from a raw index.
    #[must_use]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    /// Returns the underlying index.
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
#[derive(Debug, Clone)]
pub struct EClass {
    id: EClassId,
    nodes: Vec<ENode>,
}

impl EClass {
    /// Returns the class id.
    #[must_use]
    pub const fn id(&self) -> EClassId {
        self.id
    }

    /// Returns the nodes in this class (in deterministic insertion order).
    #[must_use]
    pub fn nodes(&self) -> &[ENode] {
        &self.nodes
    }
}

/// Deterministic e-graph core for plan rewrites.
///
/// This structure provides:
/// - hashconsed node insertion (deduplication)
/// - union-find for class merging
/// - deterministic canonical ids (smallest id wins)
#[derive(Debug, Default)]
pub struct EGraph {
    classes: Vec<EClass>,
    parent: Vec<EClassId>,
    hashcons: DetHashMap<ENode, EClassId>,
}

impl EGraph {
    /// Creates an empty e-graph.
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

        let id = EClassId::new(self.classes.len());
        self.classes.push(EClass {
            id,
            nodes: vec![canonical.clone()],
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

    /// Merges two classes and returns the canonical representative.
    ///
    /// Determinism rule: the smallest id always wins.
    pub fn merge(&mut self, a: EClassId, b: EClassId) -> EClassId {
        let root_a = self.find(a);
        let root_b = self.find(b);
        if root_a == root_b {
            return root_a;
        }

        let (winner, loser) = if root_a.index() <= root_b.index() {
            (root_a, root_b)
        } else {
            (root_b, root_a)
        };

        self.parent[loser.index()] = winner;

        let mut moved = mem::take(&mut self.classes[loser.index()].nodes);
        self.classes[winner.index()].nodes.append(&mut moved);

        self.rebuild_hashcons();
        winner
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
                children: children.into_iter().map(|id| self.find(id)).collect(),
            },
            ENode::Race { children } => ENode::Race {
                children: children.into_iter().map(|id| self.find(id)).collect(),
            },
            ENode::Timeout { child, duration } => ENode::Timeout {
                child: self.find(child),
                duration,
            },
        }
    }

    fn rebuild_hashcons(&mut self) {
        self.hashcons.clear();
        for idx in 0..self.classes.len() {
            let id = EClassId::new(idx);
            if self.find(id) != id {
                continue;
            }

            let nodes = mem::take(&mut self.classes[idx].nodes);
            let mut seen: DetHashSet<ENode> = DetHashSet::default();
            let mut rebuilt = Vec::new();

            for node in nodes {
                let canonical = self.canonicalize_enode(node);
                if seen.insert(canonical.clone()) {
                    rebuilt.push(canonical.clone());
                }
                self.hashcons.insert(canonical, id);
            }

            self.classes[idx].nodes = rebuilt;
        }
    }
}

pub mod certificate;
pub mod fixtures;
pub mod rewrite;
pub use certificate::{
    CertificateVersion, PlanHash, RewriteCertificate, StepVerifyError, VerifyError,
};
pub use rewrite::{RewritePolicy, RewriteReport, RewriteRule};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;
    use crate::types::Outcome;
    use crate::{cx::Cx, runtime::task_handle::JoinError, types::Budget};
    use std::collections::{BTreeSet, HashMap};
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    fn init_test(name: &str) {
        init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn build_join_race_timeout_plan() {
        init_test("build_join_race_timeout_plan");
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        let raced = dag.race(vec![join]);
        let timed = dag.timeout(raced, Duration::from_secs(1));
        dag.set_root(timed);

        assert!(dag.validate().is_ok());
        crate::test_complete!("build_join_race_timeout_plan");
    }

    #[test]
    fn invalid_missing_child_is_reported() {
        init_test("invalid_missing_child_is_reported");
        let mut dag = PlanDag::new();
        let bad = PlanId::new(99);
        let join = dag.join(vec![bad]);
        dag.set_root(join);
        let err = dag.validate().expect_err("missing child should fail");
        assert_eq!(
            err,
            PlanError::MissingNode {
                parent: join,
                child: bad
            }
        );
        crate::test_complete!("invalid_missing_child_is_reported");
    }

    #[test]
    fn empty_children_is_reported() {
        init_test("empty_children_is_reported");
        let mut dag = PlanDag::new();
        let join = dag.join(Vec::new());
        dag.set_root(join);
        let err = dag.validate().expect_err("empty children should fail");
        assert_eq!(err, PlanError::EmptyChildren { parent: join });
        crate::test_complete!("empty_children_is_reported");
    }

    #[test]
    fn cycle_is_reported() {
        init_test("cycle_is_reported");
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let timeout = dag.timeout(a, Duration::from_millis(5));
        dag.nodes[a.index()] = PlanNode::Timeout {
            child: timeout,
            duration: Duration::from_millis(1),
        };
        dag.set_root(timeout);

        let err = dag.validate().expect_err("cycle should fail");
        assert_eq!(err, PlanError::Cycle { at: timeout });
        crate::test_complete!("cycle_is_reported");
    }

    #[test]
    fn dedup_race_join_rewrite_applies() {
        init_test("dedup_race_join_rewrite_applies");
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let join1 = dag.join(vec![a, b]);
        let join2 = dag.join(vec![a, c]);
        let race = dag.race(vec![join1, join2]);
        dag.set_root(race);

        let rules = [RewriteRule::DedupRaceJoin];
        let report = dag.apply_rewrites(RewritePolicy::Conservative, &rules);
        crate::assert_with_log!(
            report.steps().len() == 1,
            "rewrite count",
            1,
            report.steps().len()
        );

        let Some(new_root) = dag.root() else {
            crate::assert_with_log!(false, "root exists after rewrite", true, false);
            return;
        };
        let Some(root_node) = dag.node(new_root) else {
            crate::assert_with_log!(false, "root node exists after rewrite", true, false);
            return;
        };
        let PlanNode::Join { children } = root_node else {
            crate::assert_with_log!(false, "root is join after rewrite", true, false);
            return;
        };
        crate::assert_with_log!(
            children.contains(&a),
            "shared child",
            true,
            children.contains(&a)
        );
        let race_child = children.iter().copied().find(|id| *id != a);
        let Some(race_child) = race_child else {
            crate::assert_with_log!(false, "race child exists", true, false);
            return;
        };
        let Some(race_node) = dag.node(race_child) else {
            crate::assert_with_log!(false, "race node exists", true, false);
            return;
        };
        let PlanNode::Race {
            children: race_children,
        } = race_node
        else {
            crate::assert_with_log!(false, "race child is race", true, false);
            return;
        };
        crate::assert_with_log!(
            race_children.len() == 2,
            "race children",
            2,
            race_children.len()
        );
        crate::assert_with_log!(
            race_children.contains(&b),
            "race contains b",
            true,
            race_children.contains(&b)
        );
        crate::assert_with_log!(
            race_children.contains(&c),
            "race contains c",
            true,
            race_children.contains(&c)
        );
        crate::assert_with_log!(
            dag.validate().is_ok(),
            "validate",
            true,
            dag.validate().is_ok()
        );
        crate::test_complete!("dedup_race_join_rewrite_applies");
    }

    #[test]
    fn dedup_race_join_rewrite_skips_non_join_children() {
        init_test("dedup_race_join_rewrite_skips_non_join_children");
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let join = dag.join(vec![a, b]);
        let race = dag.race(vec![a, join]);
        dag.set_root(race);

        let rules = [RewriteRule::DedupRaceJoin];
        let report = dag.apply_rewrites(RewritePolicy::Conservative, &rules);
        crate::assert_with_log!(report.is_empty(), "no rewrite", true, report.is_empty());
        crate::assert_with_log!(
            dag.root() == Some(race),
            "root unchanged",
            Some(race),
            dag.root()
        );
        crate::test_complete!("dedup_race_join_rewrite_skips_non_join_children");
    }

    #[test]
    fn dedup_race_join_rewrite_preserves_outcomes() {
        init_test("dedup_race_join_rewrite_preserves_outcomes");
        let mut dag = PlanDag::new();
        let a = dag.leaf("a");
        let b = dag.leaf("b");
        let c = dag.leaf("c");
        let join1 = dag.join(vec![a, b]);
        let join2 = dag.join(vec![a, c]);
        let race = dag.race(vec![join1, join2]);
        dag.set_root(race);

        let Some(root) = dag.root() else {
            crate::assert_with_log!(false, "root set", true, false);
            return;
        };
        let before = outcome_sets(&dag, root);
        crate::assert_with_log!(
            dag.validate().is_ok(),
            "validate before",
            true,
            dag.validate().is_ok()
        );

        let rules = [RewriteRule::DedupRaceJoin];
        let report = dag.apply_rewrites(RewritePolicy::Conservative, &rules);
        crate::assert_with_log!(
            report.steps().len() == 1,
            "rewrite count",
            1,
            report.steps().len()
        );

        let Some(new_root) = dag.root() else {
            crate::assert_with_log!(false, "root set after rewrite", true, false);
            return;
        };
        let after = outcome_sets(&dag, new_root);
        crate::assert_with_log!(before == after, "outcome sets", before, after);
        crate::assert_with_log!(
            dag.validate().is_ok(),
            "validate after",
            true,
            dag.validate().is_ok()
        );
        crate::test_complete!("dedup_race_join_rewrite_preserves_outcomes");
    }

    fn outcome_sets(dag: &PlanDag, id: PlanId) -> BTreeSet<Vec<String>> {
        let mut memo = HashMap::new();
        outcome_sets_inner(dag, id, &mut memo)
    }

    fn outcome_sets_inner(
        dag: &PlanDag,
        id: PlanId,
        memo: &mut HashMap<PlanId, BTreeSet<Vec<String>>>,
    ) -> BTreeSet<Vec<String>> {
        if let Some(cached) = memo.get(&id) {
            return cached.clone();
        }

        let Some(node) = dag.node(id) else {
            return BTreeSet::new();
        };

        let result = match node {
            PlanNode::Leaf { label } => {
                let mut set = BTreeSet::new();
                set.insert(vec![label.clone()]);
                set
            }
            PlanNode::Join { children } => {
                let mut acc = BTreeSet::new();
                acc.insert(Vec::new());
                for child in children {
                    let child_sets = outcome_sets_inner(dag, *child, memo);
                    let mut next = BTreeSet::new();
                    for base in &acc {
                        for child_set in &child_sets {
                            let mut merged = base.clone();
                            merged.extend(child_set.iter().cloned());
                            merged.sort();
                            merged.dedup();
                            next.insert(merged);
                        }
                    }
                    acc = next;
                }
                acc
            }
            PlanNode::Race { children } => {
                let mut acc = BTreeSet::new();
                for child in children {
                    let child_sets = outcome_sets_inner(dag, *child, memo);
                    acc.extend(child_sets);
                }
                acc
            }
            PlanNode::Timeout { child, .. } => outcome_sets_inner(dag, *child, memo),
        };

        memo.insert(id, result.clone());
        result
    }

    #[derive(Debug, Clone, Copy)]
    enum ProgramKind {
        Original,
        Rewritten,
    }

    struct YieldOnce {
        yielded: bool,
    }

    impl Future for YieldOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    async fn yield_n(count: usize) {
        for _ in 0..count {
            YieldOnce { yielded: false }.await;
        }
    }

    type LeafOutcome = Outcome<&'static str, crate::error::Error>;
    type LeafHandle = crate::runtime::TaskHandle<LeafOutcome>;

    async fn leaf_task(label: &'static str, yields: usize) -> LeafOutcome {
        for _ in 0..yields {
            if let Some(cx) = Cx::current() {
                if cx.checkpoint().is_err() {
                    return Outcome::Cancelled(crate::types::CancelReason::race_loser());
                }
            }
            yield_n(1).await;
        }
        if let Some(cx) = Cx::current() {
            if cx.checkpoint().is_err() {
                return Outcome::Cancelled(crate::types::CancelReason::race_loser());
            }
        }
        Outcome::Ok(label)
    }

    fn result_to_label(result: &Result<LeafOutcome, JoinError>) -> Option<&'static str> {
        match result {
            Ok(Outcome::Ok(label)) => Some(label),
            _ => None,
        }
    }

    async fn join_branch(cx: &Cx, left: &LeafHandle, right: &LeafHandle) -> BTreeSet<&'static str> {
        let left_result = left.join(cx).await;
        let right_result = right.join(cx).await;
        let mut set = BTreeSet::new();
        if let Some(label) = result_to_label(&left_result) {
            set.insert(label);
        }
        if let Some(label) = result_to_label(&right_result) {
            set.insert(label);
        }
        set
    }

    async fn race_branch(cx: &Cx, left: LeafHandle, right: LeafHandle) -> Option<&'static str> {
        let winner =
            crate::combinator::Select::new(Box::pin(left.join(cx)), Box::pin(right.join(cx))).await;
        match winner {
            crate::combinator::Either::Left(result) => {
                right.abort_with_reason(crate::types::CancelReason::race_loser());
                let _ = right.join(cx).await;
                result_to_label(&result)
            }
            crate::combinator::Either::Right(result) => {
                left.abort_with_reason(crate::types::CancelReason::race_loser());
                let _ = left.join(cx).await;
                result_to_label(&result)
            }
        }
    }

    struct Join2<F1: Future, F2: Future> {
        left: F1,
        right: F2,
        left_out: Option<F1::Output>,
        right_out: Option<F2::Output>,
    }

    impl<F1: Future, F2: Future> Join2<F1, F2> {
        fn new(left: F1, right: F2) -> Self {
            Self {
                left,
                right,
                left_out: None,
                right_out: None,
            }
        }
    }

    impl<F1, F2> Future for Join2<F1, F2>
    where
        F1: Future + Unpin,
        F2: Future + Unpin,
        F1::Output: Unpin,
        F2::Output: Unpin,
    {
        type Output = (F1::Output, F2::Output);

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();

            if this.left_out.is_none() {
                if let Poll::Ready(value) = Pin::new(&mut this.left).poll(cx) {
                    this.left_out = Some(value);
                }
            }

            if this.right_out.is_none() {
                if let Poll::Ready(value) = Pin::new(&mut this.right).poll(cx) {
                    this.right_out = Some(value);
                }
            }

            if this.left_out.is_some() && this.right_out.is_some() {
                return Poll::Ready((
                    this.left_out.take().expect("left ready"),
                    this.right_out.take().expect("right ready"),
                ));
            }

            Poll::Pending
        }
    }

    #[allow(clippy::too_many_lines)]
    fn run_program(seed: u64, kind: ProgramKind) -> BTreeSet<&'static str> {
        crate::lab::runtime::test(seed, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);

            let (_driver_id, driver_handle, scheduled) = match kind {
                ProgramKind::Original => {
                    let (a1_id, a1_handle) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, leaf_task("a", 2))
                        .expect("spawn a1");
                    let (b_id, b_handle) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, leaf_task("b", 1))
                        .expect("spawn b");
                    let (a2_id, a2_handle) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, leaf_task("a", 2))
                        .expect("spawn a2");
                    let (c_id, c_handle) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, leaf_task("c", 3))
                        .expect("spawn c");

                    let driver_future = async move {
                        let cx = Cx::current().expect("cx set");
                        let join_left = join_branch(&cx, &a1_handle, &b_handle);
                        let join_right = join_branch(&cx, &a2_handle, &c_handle);
                        match crate::combinator::Select::new(
                            Box::pin(join_left),
                            Box::pin(join_right),
                        )
                        .await
                        {
                            crate::combinator::Either::Left(result) => {
                                a2_handle
                                    .abort_with_reason(crate::types::CancelReason::race_loser());
                                c_handle
                                    .abort_with_reason(crate::types::CancelReason::race_loser());
                                let _ = a2_handle.join(&cx).await;
                                let _ = c_handle.join(&cx).await;
                                result
                            }
                            crate::combinator::Either::Right(result) => {
                                a1_handle
                                    .abort_with_reason(crate::types::CancelReason::race_loser());
                                b_handle
                                    .abort_with_reason(crate::types::CancelReason::race_loser());
                                let _ = a1_handle.join(&cx).await;
                                let _ = b_handle.join(&cx).await;
                                result
                            }
                        }
                    };

                    let (driver_id, driver_handle) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, driver_future)
                        .expect("spawn driver");

                    let scheduled = vec![a1_id, b_id, a2_id, c_id, driver_id];
                    (driver_id, driver_handle, scheduled)
                }
                ProgramKind::Rewritten => {
                    let (a_id, a_handle) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, leaf_task("a", 2))
                        .expect("spawn a");
                    let (b_id, b_handle) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, leaf_task("b", 1))
                        .expect("spawn b");
                    let (c_id, c_handle) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, leaf_task("c", 3))
                        .expect("spawn c");

                    let driver_future = async move {
                        let cx = Cx::current().expect("cx set");
                        let race = race_branch(&cx, b_handle, c_handle);
                        let join = Join2::new(Box::pin(a_handle.join(&cx)), Box::pin(race));
                        let (left_result, right_label) = join.await;
                        let mut set = BTreeSet::new();
                        if let Some(label) = result_to_label(&left_result) {
                            set.insert(label);
                        }
                        if let Some(label) = right_label {
                            set.insert(label);
                        }
                        set
                    };

                    let (driver_id, driver_handle) = runtime
                        .state
                        .create_task(region, Budget::INFINITE, driver_future)
                        .expect("spawn driver");

                    let scheduled = vec![a_id, b_id, c_id, driver_id];
                    (driver_id, driver_handle, scheduled)
                }
            };

            let mut sched = runtime.scheduler.lock().expect("scheduler lock");
            for task_id in &scheduled {
                sched.schedule(*task_id, 0);
            }
            drop(sched);

            runtime.run_until_quiescent();

            crate::assert_with_log!(
                runtime.is_quiescent(),
                "runtime quiescent",
                true,
                runtime.is_quiescent()
            );

            driver_handle
                .try_join()
                .expect("driver join ok")
                .expect("driver ready")
        })
    }

    fn expected_sets() -> [BTreeSet<&'static str>; 2] {
        let mut first = BTreeSet::new();
        first.insert("a");
        first.insert("b");
        let mut second = BTreeSet::new();
        second.insert("a");
        second.insert("c");
        [first, second]
    }

    #[test]
    fn dedup_rewrite_lab_equivalence() {
        init_test("dedup_rewrite_lab_equivalence");
        let expected = expected_sets();
        let mut original_seen = BTreeSet::new();
        let mut rewritten_seen = BTreeSet::new();
        for seed in 0..6 {
            let original = run_program(seed, ProgramKind::Original);
            let rewritten = run_program(seed, ProgramKind::Rewritten);
            original_seen.insert(original.iter().copied().collect::<Vec<_>>());
            rewritten_seen.insert(rewritten.iter().copied().collect::<Vec<_>>());

            let original_matches = expected.iter().any(|set| set == &original);
            crate::assert_with_log!(
                original_matches,
                "original outcome matches expected",
                expected,
                original
            );
            let rewritten_matches = expected.iter().any(|set| set == &rewritten);
            crate::assert_with_log!(
                rewritten_matches,
                "rewritten outcome matches expected",
                expected,
                rewritten
            );
        }
        crate::assert_with_log!(
            original_seen == rewritten_seen,
            "observed outcome sets match",
            original_seen,
            rewritten_seen
        );
        crate::test_complete!("dedup_rewrite_lab_equivalence");
    }

    #[test]
    fn egraph_hashcons_dedup() {
        init_test("egraph_hashcons_dedup");
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a");
        let b = eg.add_leaf("b");
        let join1 = eg.add_join(vec![a, b]);
        let join2 = eg.add_join(vec![a, b]);
        assert_eq!(eg.canonical_id(join1), eg.canonical_id(join2));
        crate::test_complete!("egraph_hashcons_dedup");
    }

    #[test]
    fn egraph_union_find_canonical_is_min() {
        init_test("egraph_union_find_canonical_is_min");
        let mut eg = EGraph::new();
        let a = eg.add_leaf("a"); // smallest id
        let b = eg.add_leaf("b");
        let c = eg.add_leaf("c");

        let root1 = eg.merge(b, a);
        assert_eq!(root1, a);
        let root2 = eg.merge(c, b);
        assert_eq!(root2, a);
        assert_eq!(eg.canonical_id(b), a);
        assert_eq!(eg.canonical_id(c), a);
        crate::test_complete!("egraph_union_find_canonical_is_min");
    }
}
