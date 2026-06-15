//! Opt-in plan capture with **real futures** plus a direct interpreter.
//!
//! The structural [`PlanDag`](super::PlanDag) in [`super`] describes combinator
//! shapes for the e-graph rewrite engine, but its leaves are labels — it cannot
//! be *executed*. This module adds the missing half: a [`PlanCapture`] builder
//! whose leaves carry type-erased [`BoxFut`] slots, and an interpreter
//! ([`ExecPlan::execute`]) that drives those slots through the runtime's real
//! combinator machinery (`SelectAll` for races, the `join!` concurrent
//! `poll_fn` discipline for joins, [`crate::time::timeout`] for timeouts).
//!
//! # Design invariants
//!
//! * **Reuse, never reimplement.** Race nesting reuses the same
//!   [`SelectAll`](crate::combinator::SelectAll) future that `Cx::race` drives;
//!   timeouts reuse [`crate::time::timeout`]; joins mirror the `join!` macro's
//!   concurrent `poll_fn` loop verbatim. A second scheduling engine would be a
//!   correctness disaster, so there is none — only the existing internals.
//! * **Semantically identical to direct nesting.** Executing a captured plan
//!   produces the same outcome, cancellation behavior (losers dropped), and
//!   obligation resolution as the equivalent hand-written combinator nesting.
//!   This equivalence is the proof obligation that the differential lab tests
//!   (tjrmwz.3) generalize.
//! * **Zero-cost when unused.** Nothing here touches the direct combinator
//!   paths. A program that never calls [`capture`] pays nothing.
//! * **One user-visible output type.** Leaves are erased to `BoxFut<'a, T>`,
//!   but the root is extracted as a concrete [`PlanValue<T>`] (`Scalar` for
//!   single-winner kinds, `Vector` for aggregating kinds). No `Any` ever
//!   escapes to the caller.
//!
//! # Interpreter overhead (honestly stated)
//!
//! The direct combinator paths are untouched, so a program that never captures
//! pays nothing (AC3). When a plan *is* executed, the interpreter's tax over the
//! equivalent hand-written nesting is:
//!
//! * one heap allocation per leaf (the `Box::pin` erasure slot) plus one per
//!   interior node (the `Box::pin`'d recursive `eval` future);
//! * one extra `poll_fn`/`Future` indirection layer per interior node (each
//!   wake re-polls through the boxed `eval` future);
//! * the one-time arena→tree conversion ([`ExecPlan::into_owned`]) at the start
//!   of [`ExecPlan::execute`], which is `O(nodes)` and allocates the owned tree.
//!
//! There is no per-poll allocation and no scheduler involvement beyond what the
//! reused combinators already do. The tax is `O(nodes)` allocations once plus a
//! constant indirection factor per poll — acceptable for the opt-in path and
//! the price of dynamic (vs. monomorphized) combinator shapes.
//!
//! # Node kinds (the law-sheet-covered set)
//!
//! `race`, `join`, `timeout`, `first_ok`, and `quorum`. The first three map
//! 1:1 onto [`super::PlanNode`] and can be re-emitted as a structural
//! [`PlanDag`](super::PlanDag) via [`ExecPlan::try_structure`] for the rewrite
//! engine to consume (tjrmwz.2). `first_ok`/`quorum` execute here but have no
//! structural IR node yet; `try_structure` reports that honestly.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use crate::combinator::SelectAll;
use crate::cx::{Cx, cap};
use crate::util::{DetHashMap, DetHashSet};

use super::{PlanDag, PlanId, PlanNode, RewriteCertificate, RewritePolicy, RewriteRule};

/// Type-erased, single-poll leaf future slot keyed (positionally) by node id.
///
/// Leaves are one-shot: a captured plan executes exactly once. The erased
/// `dyn Future` keeps the builder ergonomic (heterogeneous leaf *expressions*
/// collapse to one slot type) while the root stays concretely typed.
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Success classifier for `first_ok`/`quorum` over the homogeneous leaf type.
///
/// A captured `first_ok`/`quorum` node has no intrinsic notion of "success"
/// for an arbitrary `T`, so the caller supplies one at capture time.
pub type SuccessPred<T> = Arc<dyn Fn(&T) -> bool + Send + Sync>;

/// Identifier for a node in an [`ExecPlan`] (index into the node arena).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(usize);

impl NodeId {
    /// Returns the underlying arena index.
    #[inline]
    #[must_use]
    pub const fn index(self) -> usize {
        self.0
    }
}

/// The single user-visible output of executing a captured plan.
///
/// Single-winner combinators (`leaf`, `race`, `timeout`, `first_ok`) resolve to
/// [`PlanValue::Scalar`]; aggregating combinators (`join`, `quorum`) resolve to
/// [`PlanValue::Vector`]. The variant is statically knowable from the root node
/// kind, so callers use [`PlanValue::into_scalar`]/[`PlanValue::into_vector`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanValue<T> {
    /// A single value from a single-winner combinator.
    Scalar(T),
    /// Ordered values from an aggregating combinator.
    Vector(Vec<T>),
}

impl<T> PlanValue<T> {
    /// Extracts the scalar value, or errors if the root aggregated.
    pub fn into_scalar(self) -> Result<T, PlanExecError> {
        match self {
            Self::Scalar(t) => Ok(t),
            Self::Vector(_) => Err(PlanExecError::UnexpectedShape),
        }
    }

    /// Extracts the ordered values, or errors if the root was single-winner.
    pub fn into_vector(self) -> Result<Vec<T>, PlanExecError> {
        match self {
            Self::Vector(v) => Ok(v),
            Self::Scalar(_) => Err(PlanExecError::UnexpectedShape),
        }
    }

    /// Flattens this value into its constituent leaf values, in order.
    fn into_flat(self) -> Vec<T> {
        match self {
            Self::Scalar(t) => vec![t],
            Self::Vector(v) => v,
        }
    }
}

/// Errors raised while building or executing a captured plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanExecError {
    /// No root node was set before [`PlanCapture::finish`].
    MissingRoot,
    /// A node referenced a child id outside the arena.
    MissingChild {
        /// The referencing parent.
        parent: NodeId,
        /// The dangling child id.
        child: NodeId,
    },
    /// A `join`/`race`/`first_ok`/`quorum` node had no children.
    EmptyChildren {
        /// The offending node.
        parent: NodeId,
    },
    /// A node id was used as a child by more than one parent (plans are trees:
    /// a one-shot leaf future cannot be shared).
    SharedNode {
        /// The node referenced more than once.
        node: NodeId,
    },
    /// A `quorum` threshold was zero or exceeded the child count.
    InvalidQuorum {
        /// The offending node.
        parent: NodeId,
        /// The requested threshold.
        required: usize,
        /// The available child count.
        available: usize,
    },
    /// A `timeout` node's deadline elapsed before its child completed.
    Timeout {
        /// The timed-out node.
        node: NodeId,
    },
    /// A `race` produced no result (the underlying `SelectAll` was empty —
    /// structurally impossible after validation, surfaced defensively).
    RaceProducedNothing,
    /// A `first_ok` node exhausted every child without a success.
    FirstOkExhausted {
        /// The offending node.
        node: NodeId,
    },
    /// A `quorum` node finished below threshold.
    QuorumNotMet {
        /// The offending node.
        node: NodeId,
        /// Successes achieved.
        achieved: usize,
        /// Successes required.
        required: usize,
    },
    /// [`PlanValue::into_scalar`]/[`into_vector`](PlanValue::into_vector) was
    /// called on the wrong shape, or a `first_ok`/`quorum` child resolved to an
    /// aggregate value (its success cannot be classified leaf-wise).
    UnexpectedShape,
    /// A `first_ok`/`quorum` node is present, so the plan has no structural
    /// [`PlanDag`](super::PlanDag) representation yet (tjrmwz.2 IR gap).
    NotRepresentable {
        /// The node with no structural counterpart.
        node: NodeId,
    },
}

impl std::fmt::Display for PlanExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRoot => write!(f, "captured plan has no root node"),
            Self::MissingChild { parent, child } => write!(
                f,
                "node {} references missing child {}",
                parent.index(),
                child.index()
            ),
            Self::EmptyChildren { parent } => {
                write!(f, "node {} has no children", parent.index())
            }
            Self::SharedNode { node } => write!(
                f,
                "node {} is referenced by more than one parent (plans must be trees)",
                node.index()
            ),
            Self::InvalidQuorum {
                parent,
                required,
                available,
            } => write!(
                f,
                "node {} quorum threshold {required} invalid for {available} children",
                parent.index()
            ),
            Self::Timeout { node } => write!(f, "node {} timed out", node.index()),
            Self::RaceProducedNothing => write!(f, "race produced no result"),
            Self::FirstOkExhausted { node } => {
                write!(
                    f,
                    "node {} first_ok exhausted with no success",
                    node.index()
                )
            }
            Self::QuorumNotMet {
                node,
                achieved,
                required,
            } => write!(
                f,
                "node {} quorum not met: {achieved}/{required}",
                node.index()
            ),
            Self::UnexpectedShape => write!(f, "captured plan produced an unexpected value shape"),
            Self::NotRepresentable { node } => write!(
                f,
                "node {} has no structural PlanDag representation",
                node.index()
            ),
        }
    }
}

impl std::error::Error for PlanExecError {}

/// A captured node in the flat builder arena.
enum CaptureNode<'a, T> {
    Leaf {
        label: String,
        fut: BoxFut<'a, T>,
    },
    Join(Vec<NodeId>),
    Race(Vec<NodeId>),
    Timeout {
        child: NodeId,
        duration: Duration,
    },
    FirstOk {
        children: Vec<NodeId>,
        is_success: SuccessPred<T>,
    },
    Quorum {
        children: Vec<NodeId>,
        required: usize,
        is_success: SuccessPred<T>,
    },
}

/// Builder that captures a combinator tree whose leaves are real futures.
///
/// The shapes mirror the direct combinator API so a captured plan reads like
/// the nesting it replaces. Construct with [`PlanCapture::new`] or, more
/// commonly, via the [`capture`] free function.
///
/// ```
/// use asupersync::plan::execute::PlanCapture;
///
/// let mut b: PlanCapture<u32> = PlanCapture::new();
/// let a = b.leaf(async { 1 });
/// let c = b.leaf(async { 2 });
/// let root = b.join([a, c]);
/// b.set_root(root);
/// let plan = b.finish().expect("valid tree");
/// assert_eq!(plan.node_count(), 3);
/// ```
pub struct PlanCapture<'a, T> {
    nodes: Vec<CaptureNode<'a, T>>,
    root: Option<NodeId>,
}

impl<T> Default for PlanCapture<'_, T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Captures an executable combinator plan, using the returned node as the root.
///
/// The closure records structure (and real leaf futures) through
/// [`PlanCapture`] and returns the root node; validation runs before the plan
/// is returned, so structural errors fail at capture time rather than at
/// execution.
///
/// ```
/// use asupersync::plan::execute::capture;
///
/// let plan = capture(|p| {
///     let a = p.leaf(async { 1u32 });
///     let b = p.leaf(async { 2u32 });
///     p.join([a, b])
/// })
/// .expect("captured plan should validate");
/// assert_eq!(plan.node_count(), 3);
/// ```
pub fn capture<'a, T, F>(build: F) -> Result<ExecPlan<'a, T>, PlanExecError>
where
    F: FnOnce(&mut PlanCapture<'a, T>) -> NodeId,
{
    let mut builder = PlanCapture::new();
    let root = build(&mut builder);
    builder.set_root(root);
    builder.finish()
}

impl<'a, T> PlanCapture<'a, T> {
    /// Creates an empty capture builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            root: None,
        }
    }

    fn push(&mut self, node: CaptureNode<'a, T>) -> NodeId {
        let id = NodeId(self.nodes.len());
        self.nodes.push(node);
        id
    }

    /// Captures a leaf future with an auto-generated label.
    pub fn leaf<F>(&mut self, fut: F) -> NodeId
    where
        F: Future<Output = T> + 'a,
    {
        let label = format!("leaf{}", self.nodes.len());
        self.push(CaptureNode::Leaf {
            label,
            fut: Box::pin(fut),
        })
    }

    /// Captures a leaf future with an explicit label (used by debug/structure).
    pub fn labeled_leaf<F>(&mut self, label: impl Into<String>, fut: F) -> NodeId
    where
        F: Future<Output = T> + 'a,
    {
        self.push(CaptureNode::Leaf {
            label: label.into(),
            fut: Box::pin(fut),
        })
    }

    /// Captures a `join` over all children (waits for all, aggregates in order).
    pub fn join(&mut self, children: impl IntoIterator<Item = NodeId>) -> NodeId {
        self.push(CaptureNode::Join(children.into_iter().collect()))
    }

    /// Captures a `race` over all children (first to complete wins, losers drop).
    pub fn race(&mut self, children: impl IntoIterator<Item = NodeId>) -> NodeId {
        self.push(CaptureNode::Race(children.into_iter().collect()))
    }

    /// Captures a `timeout` wrapping a single child.
    pub fn timeout(&mut self, child: NodeId, duration: Duration) -> NodeId {
        self.push(CaptureNode::Timeout { child, duration })
    }

    /// Captures a `first_ok`: the first child whose value satisfies `is_success`.
    pub fn first_ok<P>(
        &mut self,
        children: impl IntoIterator<Item = NodeId>,
        is_success: P,
    ) -> NodeId
    where
        P: Fn(&T) -> bool + Send + Sync + 'static,
    {
        self.push(CaptureNode::FirstOk {
            children: children.into_iter().collect(),
            is_success: Arc::new(is_success),
        })
    }

    /// Captures a `quorum`: succeeds once `required` children satisfy `is_success`.
    pub fn quorum<P>(
        &mut self,
        children: impl IntoIterator<Item = NodeId>,
        required: usize,
        is_success: P,
    ) -> NodeId
    where
        P: Fn(&T) -> bool + Send + Sync + 'static,
    {
        self.push(CaptureNode::Quorum {
            children: children.into_iter().collect(),
            required,
            is_success: Arc::new(is_success),
        })
    }

    /// Sets the root node returned by the capture closure.
    pub fn set_root(&mut self, root: NodeId) {
        self.root = Some(root);
    }

    /// Validates structure and finalizes the executable plan.
    ///
    /// Validation checks: a root is set, every referenced child id exists, no
    /// `join`/`race`/`first_ok`/`quorum` node is childless, every `quorum`
    /// threshold is in `1..=children`, and the graph is a tree (no node is
    /// referenced by two parents — one-shot leaves cannot be shared).
    pub fn finish(self) -> Result<ExecPlan<'a, T>, PlanExecError> {
        let Some(root) = self.root else {
            return Err(PlanExecError::MissingRoot);
        };

        let mut ref_count = vec![0usize; self.nodes.len()];
        for (idx, node) in self.nodes.iter().enumerate() {
            let parent = NodeId(idx);
            match node {
                CaptureNode::Leaf { .. } => {}
                CaptureNode::Join(children)
                | CaptureNode::Race(children)
                | CaptureNode::FirstOk { children, .. } => {
                    if children.is_empty() {
                        return Err(PlanExecError::EmptyChildren { parent });
                    }
                    for &c in children {
                        bump_ref(&mut ref_count, parent, c)?;
                    }
                }
                CaptureNode::Quorum {
                    children, required, ..
                } => {
                    if children.is_empty() {
                        return Err(PlanExecError::EmptyChildren { parent });
                    }
                    if *required == 0 || *required > children.len() {
                        return Err(PlanExecError::InvalidQuorum {
                            parent,
                            required: *required,
                            available: children.len(),
                        });
                    }
                    for &c in children {
                        bump_ref(&mut ref_count, parent, c)?;
                    }
                }
                CaptureNode::Timeout { child, .. } => {
                    bump_ref(&mut ref_count, parent, *child)?;
                }
            }
        }

        if root.index() >= self.nodes.len() {
            return Err(PlanExecError::MissingChild {
                parent: root,
                child: root,
            });
        }

        Ok(ExecPlan {
            nodes: self.nodes,
            root,
        })
    }
}

fn bump_ref(ref_count: &mut [usize], parent: NodeId, child: NodeId) -> Result<(), PlanExecError> {
    let slot = ref_count
        .get_mut(child.index())
        .ok_or(PlanExecError::MissingChild { parent, child })?;
    *slot += 1;
    if *slot > 1 {
        return Err(PlanExecError::SharedNode { node: child });
    }
    Ok(())
}

/// A validated, executable captured plan.
///
/// Build one with [`capture`] or [`PlanCapture::finish`], then run it with
/// [`ExecPlan::execute`] (or the typed [`execute_scalar`](ExecPlan::execute_scalar)
/// / [`execute_all`](ExecPlan::execute_all) helpers).
pub struct ExecPlan<'a, T> {
    nodes: Vec<CaptureNode<'a, T>>,
    root: NodeId,
}

/// An owned recursive node — the arena converted into a tree so that sibling
/// subtrees own disjoint futures and can be driven concurrently.
enum OwnedNode<'a, T> {
    Leaf(BoxFut<'a, T>),
    Join(Vec<OwnedNode<'a, T>>),
    Race(Vec<OwnedNode<'a, T>>),
    Timeout {
        child: Box<OwnedNode<'a, T>>,
        duration: Duration,
        node: NodeId,
    },
    FirstOk {
        children: Vec<OwnedNode<'a, T>>,
        is_success: SuccessPred<T>,
        node: NodeId,
    },
    Quorum {
        children: Vec<OwnedNode<'a, T>>,
        required: usize,
        is_success: SuccessPred<T>,
        node: NodeId,
    },
}

impl<'a, T> ExecPlan<'a, T> {
    /// Returns the number of nodes in the plan.
    #[inline]
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Re-emits the structural [`PlanDag`](super::PlanDag) for the rewrite engine.
    ///
    /// `leaf`/`join`/`race`/`timeout` map 1:1 onto [`super::PlanNode`].
    /// `first_ok`/`quorum` have no structural node yet, so this returns
    /// [`PlanExecError::NotRepresentable`] when one is present.
    pub fn try_structure(&self) -> Result<PlanDag, PlanExecError> {
        let mut dag = PlanDag::new();
        let mut mapping = vec![None; self.nodes.len()];
        let root = self.structure_from(self.root, &mut dag, &mut mapping)?;
        dag.set_root(root);
        Ok(dag)
    }

    fn structure_from(
        &self,
        id: NodeId,
        dag: &mut PlanDag,
        mapping: &mut [Option<PlanId>],
    ) -> Result<PlanId, PlanExecError> {
        if let Some(existing) = mapping[id.index()] {
            return Ok(existing);
        }
        let plan_id = match &self.nodes[id.index()] {
            CaptureNode::Leaf { label, .. } => dag.leaf(label.clone()),
            CaptureNode::Join(children) => {
                let mapped = self.structure_children(children, dag, mapping)?;
                dag.join(mapped)
            }
            CaptureNode::Race(children) => {
                let mapped = self.structure_children(children, dag, mapping)?;
                dag.race(mapped)
            }
            CaptureNode::Timeout { child, duration } => {
                let mapped = self.structure_from(*child, dag, mapping)?;
                dag.timeout(mapped, *duration)
            }
            CaptureNode::FirstOk { .. } | CaptureNode::Quorum { .. } => {
                return Err(PlanExecError::NotRepresentable { node: id });
            }
        };
        mapping[id.index()] = Some(plan_id);
        Ok(plan_id)
    }

    fn structure_children(
        &self,
        children: &[NodeId],
        dag: &mut PlanDag,
        mapping: &mut [Option<PlanId>],
    ) -> Result<Vec<PlanId>, PlanExecError> {
        children
            .iter()
            .map(|&c| self.structure_from(c, dag, mapping))
            .collect()
    }

    fn into_owned(mut self) -> OwnedNode<'a, T> {
        // Validation in `finish` guarantees a tree with in-range ids, so the
        // `take_owned` recursion never hits a `None` slot or a missing id.
        let mut slots: Vec<Option<CaptureNode<'a, T>>> = self.nodes.drain(..).map(Some).collect();
        take_owned(&mut slots, self.root)
    }

    /// Consumes the plan into (structural [`PlanDag`], leaf futures indexed
    /// densely, map from each leaf's `PlanId` to its leaf-store index).
    ///
    /// Only called after [`Self::try_structure`] confirms representability, so
    /// no `first_ok`/`quorum` node is ever encountered. The leaf-store index is
    /// stable across rewrites (rewrites preserve leaf `PlanId`s), which is what
    /// lets [`owned_from_dag`] re-associate the real futures afterward.
    fn dismantle(
        self,
    ) -> (
        PlanDag,
        Vec<Option<BoxFut<'a, T>>>,
        DetHashMap<PlanId, usize>,
    ) {
        let mut slots: Vec<Option<CaptureNode<'a, T>>> = self.nodes.into_iter().map(Some).collect();
        let mut dag = PlanDag::new();
        let mut leaf_store: Vec<Option<BoxFut<'a, T>>> = Vec::new();
        let mut leaf_pid_to_idx = DetHashMap::default();
        let root = dismantle_node(
            &mut slots,
            self.root,
            &mut dag,
            &mut leaf_store,
            &mut leaf_pid_to_idx,
        );
        dag.set_root(root);
        (dag, leaf_store, leaf_pid_to_idx)
    }

    /// Executes the captured plan, reusing the real combinator internals.
    ///
    /// The result is the typed [`PlanValue<T>`] of the root node. See the
    /// module docs for the per-kind semantics and the equivalence guarantee.
    ///
    /// The returned future is intentionally `!Send`: like the `join!`/`race!`
    /// macro expansions it drives, it runs the captured combinators inline in a
    /// single task, so the leaf slots need not be `Send` (a captured plan may
    /// hold `Rc`-bearing leaf futures).
    #[allow(clippy::future_not_send)]
    pub async fn execute<Caps>(self, cx: &Cx<Caps>) -> Result<PlanValue<T>, PlanExecError>
    where
        Caps: cap::HasTime,
        T: 'a,
    {
        let owned = self.into_owned();
        eval(owned, cx).await
    }

    /// Executes and extracts a single scalar (errors if the root aggregates).
    #[allow(clippy::future_not_send)] // inline single-task driver; see `execute`
    pub async fn execute_scalar<Caps>(self, cx: &Cx<Caps>) -> Result<T, PlanExecError>
    where
        Caps: cap::HasTime,
        T: 'a,
    {
        self.execute(cx).await?.into_scalar()
    }

    /// Executes and extracts ordered values (errors if the root is single-winner).
    #[allow(clippy::future_not_send)] // inline single-task driver; see `execute`
    pub async fn execute_all<Caps>(self, cx: &Cx<Caps>) -> Result<Vec<T>, PlanExecError>
    where
        Caps: cap::HasTime,
        T: 'a,
    {
        self.execute(cx).await?.into_vector()
    }
}

fn take_owned<'a, T>(slots: &mut [Option<CaptureNode<'a, T>>], id: NodeId) -> OwnedNode<'a, T> {
    let node = slots[id.index()]
        .take()
        .expect("validated tree: each node is taken exactly once");
    match node {
        CaptureNode::Leaf { fut, .. } => OwnedNode::Leaf(fut),
        CaptureNode::Join(children) => {
            OwnedNode::Join(children.into_iter().map(|c| take_owned(slots, c)).collect())
        }
        CaptureNode::Race(children) => {
            OwnedNode::Race(children.into_iter().map(|c| take_owned(slots, c)).collect())
        }
        CaptureNode::Timeout { child, duration } => OwnedNode::Timeout {
            child: Box::new(take_owned(slots, child)),
            duration,
            node: id,
        },
        CaptureNode::FirstOk {
            children,
            is_success,
        } => OwnedNode::FirstOk {
            children: children.into_iter().map(|c| take_owned(slots, c)).collect(),
            is_success,
            node: id,
        },
        CaptureNode::Quorum {
            children,
            required,
            is_success,
        } => OwnedNode::Quorum {
            children: children.into_iter().map(|c| take_owned(slots, c)).collect(),
            required,
            is_success,
            node: id,
        },
    }
}

fn dismantle_node<'a, T>(
    slots: &mut [Option<CaptureNode<'a, T>>],
    id: NodeId,
    dag: &mut PlanDag,
    leaf_store: &mut Vec<Option<BoxFut<'a, T>>>,
    leaf_pid_to_idx: &mut DetHashMap<PlanId, usize>,
) -> PlanId {
    let node = slots[id.index()]
        .take()
        .expect("validated representable tree: each node is taken exactly once");
    match node {
        CaptureNode::Leaf { label, fut } => {
            let pid = dag.leaf(label);
            let idx = leaf_store.len();
            leaf_store.push(Some(fut));
            leaf_pid_to_idx.insert(pid, idx);
            pid
        }
        CaptureNode::Join(children) => {
            let mut kids = Vec::with_capacity(children.len());
            for c in children {
                kids.push(dismantle_node(slots, c, dag, leaf_store, leaf_pid_to_idx));
            }
            dag.join(kids)
        }
        CaptureNode::Race(children) => {
            let mut kids = Vec::with_capacity(children.len());
            for c in children {
                kids.push(dismantle_node(slots, c, dag, leaf_store, leaf_pid_to_idx));
            }
            dag.race(kids)
        }
        CaptureNode::Timeout { child, duration } => {
            let c = dismantle_node(slots, child, dag, leaf_store, leaf_pid_to_idx);
            dag.timeout(c, duration)
        }
        CaptureNode::FirstOk { .. } | CaptureNode::Quorum { .. } => {
            unreachable!("dismantle runs only after try_structure confirms representability")
        }
    }
}

type EvalFut<'b, T> = Pin<Box<dyn Future<Output = Result<PlanValue<T>, PlanExecError>> + 'b>>;

fn eval<'a, 'b, T, Caps>(node: OwnedNode<'a, T>, cx: &'b Cx<Caps>) -> EvalFut<'b, T>
where
    'a: 'b,
    T: 'a,
    Caps: cap::HasTime,
{
    Box::pin(async move {
        match node {
            OwnedNode::Leaf(fut) => Ok(PlanValue::Scalar(fut.await)),

            OwnedNode::Join(children) => {
                // Mirror the `join!` macro: pin each child once, poll every
                // not-yet-ready branch on each wake, aggregate in input order.
                let futs: Vec<EvalFut<'b, T>> = children.into_iter().map(|c| eval(c, cx)).collect();
                let results = drive_all(futs).await;
                let mut flat = Vec::new();
                for r in results {
                    flat.extend(r?.into_flat());
                }
                Ok(PlanValue::Vector(flat))
            }

            OwnedNode::Race(children) => {
                // Reuse the exact race engine `Cx::race` uses: `SelectAll`
                // resolves to the first ready branch and drops (cancels) losers.
                let futs: Vec<EvalFut<'b, T>> = children.into_iter().map(|c| eval(c, cx)).collect();
                match SelectAll::new(futs).await {
                    Ok((inner, _idx)) => inner,
                    Err(_) => Err(PlanExecError::RaceProducedNothing),
                }
            }

            OwnedNode::Timeout {
                child,
                duration,
                node,
            } => {
                // Reuse `crate::time::timeout`; on elapse the child is dropped.
                let child_fut = eval(*child, cx);
                let now = cx.now();
                match crate::time::timeout(now, duration, child_fut).await {
                    Ok(inner) => inner,
                    Err(_elapsed) => Err(PlanExecError::Timeout { node }),
                }
            }

            OwnedNode::FirstOk {
                children,
                is_success,
                node,
            } => {
                let futs: Vec<EvalFut<'b, T>> = children.into_iter().map(|c| eval(c, cx)).collect();
                let results = drive_all(futs).await;
                for r in results {
                    let value = r?;
                    let scalar = value.into_scalar()?;
                    if is_success(&scalar) {
                        return Ok(PlanValue::Scalar(scalar));
                    }
                }
                Err(PlanExecError::FirstOkExhausted { node })
            }

            OwnedNode::Quorum {
                children,
                required,
                is_success,
                node,
            } => {
                let futs: Vec<EvalFut<'b, T>> = children.into_iter().map(|c| eval(c, cx)).collect();
                let results = drive_all(futs).await;
                let mut wins = Vec::new();
                for r in results {
                    let scalar = r?.into_scalar()?;
                    if is_success(&scalar) {
                        wins.push(scalar);
                    }
                }
                if wins.len() >= required {
                    Ok(PlanValue::Vector(wins))
                } else {
                    Err(PlanExecError::QuorumNotMet {
                        node,
                        achieved: wins.len(),
                        required,
                    })
                }
            }
        }
    })
}

/// Drives every future concurrently within one task and collects results in
/// input order. This is the `join!` macro's concurrent `poll_fn` discipline,
/// lifted to a runtime-sized `Vec` (each branch is already pinned as a
/// `BoxFut`, so a `Pending` branch never starves the others).
#[allow(clippy::future_not_send)] // inline single-task driver; see `ExecPlan::execute`
async fn drive_all<'f, R>(mut futs: Vec<Pin<Box<dyn Future<Output = R> + 'f>>>) -> Vec<R> {
    let mut outs: Vec<Option<R>> = (0..futs.len()).map(|_| None).collect();
    poll_fn(|task_cx| {
        let mut pending = false;
        for (i, fut) in futs.iter_mut().enumerate() {
            if outs[i].is_none() {
                match fut.as_mut().poll(task_cx) {
                    Poll::Ready(v) => outs[i] = Some(v),
                    Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    })
    .await;
    outs.into_iter()
        .map(|o| o.expect("drive_all resolved only after every branch was Ready"))
        .collect()
}

// ---------------------------------------------------------------------------
// Certified rewrite application (tjrmwz.2)
//
// The fail-closed ladder: capture (I1) -> structural PlanDag -> conservative
// certified rewrite (the e-graph engine, which already verifies side-conditions
// per rule) -> leaf-conservation guard -> execute the rewritten DAG, OR run the
// original plan unchanged. Optimization is *always* optional: the rewrite never
// turns into a hard error, only a logged fallback. The certificate is always
// surfaced.
// ---------------------------------------------------------------------------

/// The conservative rule set offered to the rewrite engine. [`RewritePolicy`]
/// itself gates which actually fire (conservative disables commutativity), so a
/// rule appearing here is necessary-but-not-sufficient for it to run.
const CONSERVATIVE_RULES: [RewriteRule; 6] = [
    RewriteRule::JoinAssoc,
    RewriteRule::RaceAssoc,
    RewriteRule::JoinCommute,
    RewriteRule::RaceCommute,
    RewriteRule::TimeoutMin,
    RewriteRule::DedupRaceJoin,
];

/// Outcome of [`capture_optimized`]: the executed value plus the machine-checkable
/// certificate describing the rewrite that was attempted.
#[derive(Debug)]
pub struct OptimizedExecution<T> {
    /// The root value — from the rewritten plan when `rewritten`, else the original.
    pub value: PlanValue<T>,
    /// The versioned rewrite certificate. `None` only when the plan has no
    /// structural IR (it contains `first_ok`/`quorum`); otherwise present and
    /// `is_identity()` when no rule fired.
    pub certificate: Option<RewriteCertificate>,
    /// Whether the *rewritten* DAG was executed (vs. the fail-closed fallback).
    pub rewritten: bool,
    /// Rules that fired during rewriting, in order.
    pub fired_rules: Vec<RewriteRule>,
    /// Why the original (unrewritten) plan ran, when it did.
    pub fallback_reason: Option<String>,
}

/// Captures a plan, applies the conservative *certified* rewrite pass, and
/// executes the result.
///
/// Falls closed to the original plan (never erroring on the optimization itself)
/// whenever the rewrite is absent, unverifiable, or not execution-safe. The
/// certificate is always surfaced.
///
/// Fail-closed conditions (each runs the original plan with a logged reason):
/// * the plan contains `first_ok`/`quorum` (no structural rewrite IR);
/// * no conservative rule fired (identity certificate);
/// * the rewritten DAG fails structural validation; or
/// * the rewrite is not leaf-conserving — a one-shot leaf future would be
///   duplicated or dropped (the execution-safety contract).
#[allow(clippy::future_not_send)] // inline single-task driver; see `ExecPlan::execute`
pub async fn capture_optimized<'a, T, Caps, F>(
    cx: &Cx<Caps>,
    build: F,
) -> Result<OptimizedExecution<T>, PlanExecError>
where
    F: FnOnce(&mut PlanCapture<'a, T>) -> NodeId,
    Caps: cap::HasTime,
    T: 'a,
{
    let plan = capture(build)?;

    // Plans with first_ok/quorum have no structural IR: execute directly.
    match plan.try_structure() {
        Ok(_) => {}
        Err(PlanExecError::NotRepresentable { .. }) => {
            let value = plan.execute(cx).await?;
            return Ok(OptimizedExecution {
                value,
                certificate: None,
                rewritten: false,
                fired_rules: Vec::new(),
                fallback_reason: Some(
                    "plan contains first_ok/quorum; no structural rewrite IR".to_string(),
                ),
            });
        }
        Err(e) => return Err(e),
    }

    // Dismantle into (original structure, leaf futures by index, leaf-PlanId map).
    let (original_dag, mut leaf_store, leaf_pid_to_idx) = plan.dismantle();

    let mut rewritten_dag = original_dag.clone();
    let (report, certificate) =
        rewritten_dag.apply_rewrites_certified(RewritePolicy::conservative(), &CONSERVATIVE_RULES);
    let fired_rules: Vec<RewriteRule> = report.steps().iter().map(|step| step.rule).collect();

    // Decide the execution path, fail-closed.
    let (exec_dag, rewritten, fallback_reason) = if report.is_empty() {
        (
            &original_dag,
            false,
            Some("no conservative rewrite applied".to_string()),
        )
    } else if rewritten_dag.validate().is_err() {
        (
            &original_dag,
            false,
            Some("rewritten plan failed structural validation; ran original".to_string()),
        )
    } else if leaves_conserved(&rewritten_dag, &leaf_pid_to_idx) {
        (&rewritten_dag, true, None)
    } else {
        (
            &original_dag,
            false,
            Some(
                "rewrite not leaf-conserving (a one-shot leaf would be duplicated or dropped); ran original"
                    .to_string(),
            ),
        )
    };

    let root = exec_dag.root().ok_or(PlanExecError::MissingRoot)?;
    let owned = owned_from_dag(exec_dag, root, &mut leaf_store, &leaf_pid_to_idx)?;
    let value = eval(owned, cx).await?;

    Ok(OptimizedExecution {
        value,
        certificate: Some(certificate),
        rewritten,
        fired_rules,
        fallback_reason,
    })
}

/// Returns true iff the tree reachable from `dag`'s root references exactly the
/// original leaf set, each leaf exactly once, with no shared (re-executed)
/// subtree — the precondition for moving one-shot leaf futures into the
/// rewritten structure.
fn leaves_conserved(dag: &PlanDag, leaf_pid_to_idx: &DetHashMap<PlanId, usize>) -> bool {
    let Some(root) = dag.root() else {
        return false;
    };
    let mut seen = DetHashSet::default();
    let mut leaf_indices = Vec::new();
    if !collect_tree_leaves(dag, root, &mut seen, &mut leaf_indices, leaf_pid_to_idx) {
        return false;
    }
    // Every original leaf used exactly once (bijection).
    if leaf_indices.len() != leaf_pid_to_idx.len() {
        return false;
    }
    leaf_indices.sort_unstable();
    leaf_indices.dedup();
    leaf_indices.len() == leaf_pid_to_idx.len()
}

fn collect_tree_leaves(
    dag: &PlanDag,
    id: PlanId,
    seen: &mut DetHashSet<PlanId>,
    leaf_indices: &mut Vec<usize>,
    leaf_pid_to_idx: &DetHashMap<PlanId, usize>,
) -> bool {
    if !seen.insert(id) {
        return false; // shared node — execution would re-run a subtree
    }
    match dag.node(id) {
        None => false,
        Some(PlanNode::Leaf { .. }) => match leaf_pid_to_idx.get(&id) {
            Some(idx) => {
                leaf_indices.push(*idx);
                true
            }
            None => false,
        },
        Some(PlanNode::Join { children } | PlanNode::Race { children }) => children
            .iter()
            .all(|&c| collect_tree_leaves(dag, c, seen, leaf_indices, leaf_pid_to_idx)),
        Some(PlanNode::Timeout { child, .. }) => {
            collect_tree_leaves(dag, *child, seen, leaf_indices, leaf_pid_to_idx)
        }
    }
}

/// Rebuilds an owned execution tree from a (possibly rewritten) [`PlanDag`],
/// moving each leaf's real future out of `leaf_store` by its `PlanId`. Reuses
/// the single [`eval`] engine — no second interpreter.
fn owned_from_dag<'a, T>(
    dag: &PlanDag,
    id: PlanId,
    leaf_store: &mut [Option<BoxFut<'a, T>>],
    leaf_pid_to_idx: &DetHashMap<PlanId, usize>,
) -> Result<OwnedNode<'a, T>, PlanExecError> {
    let node = NodeId(id.index());
    match dag.node(id).ok_or(PlanExecError::MissingChild {
        parent: node,
        child: node,
    })? {
        PlanNode::Leaf { .. } => {
            let idx = *leaf_pid_to_idx
                .get(&id)
                .ok_or(PlanExecError::MissingChild {
                    parent: node,
                    child: node,
                })?;
            let fut = leaf_store[idx]
                .take()
                .ok_or(PlanExecError::SharedNode { node })?;
            Ok(OwnedNode::Leaf(fut))
        }
        PlanNode::Join { children } => {
            let mut kids = Vec::with_capacity(children.len());
            for &c in children {
                kids.push(owned_from_dag(dag, c, leaf_store, leaf_pid_to_idx)?);
            }
            Ok(OwnedNode::Join(kids))
        }
        PlanNode::Race { children } => {
            let mut kids = Vec::with_capacity(children.len());
            for &c in children {
                kids.push(owned_from_dag(dag, c, leaf_store, leaf_pid_to_idx)?);
            }
            Ok(OwnedNode::Race(kids))
        }
        PlanNode::Timeout { child, duration } => Ok(OwnedNode::Timeout {
            child: Box::new(owned_from_dag(dag, *child, leaf_store, leaf_pid_to_idx)?),
            duration: *duration,
            node,
        }),
    }
}
