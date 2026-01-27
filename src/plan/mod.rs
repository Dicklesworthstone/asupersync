//! Plan DAG IR for concurrency combinators.
//!
//! This module defines a minimal DAG representation for join/race/timeout
//! structures. It is intentionally lightweight and uses safe Rust only.

use std::collections::HashSet;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_logging;

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

        let report = dag.apply_rewrites(RewriteConfig::default());
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

        let report = dag.apply_rewrites(RewriteConfig::default());
        crate::assert_with_log!(report.is_empty(), "no rewrite", true, report.is_empty());
        crate::assert_with_log!(
            dag.root() == Some(race),
            "root unchanged",
            Some(race),
            dag.root()
        );
        crate::test_complete!("dedup_race_join_rewrite_skips_non_join_children");
    }
}
