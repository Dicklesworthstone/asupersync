//! Deterministic consistent hashing ring with virtual nodes.
//!
//! Used for stable key-to-replica assignment with minimal remapping when
//! replicas are added or removed. For ephemeral routing decisions over a
//! transient candidate set, prefer the salted HRW helpers below so callers do
//! not pay to rebuild and sort a virtual-node ring on every lookup.

use crate::util::det_hash::DetHasher;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};

/// Errors returned by fallible HashRing constructors.
///
/// br-asupersync-un962v.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsistentHashError {
    /// `HashRing::try_new` was called with `vnodes_per_node == 0`. A
    /// ring with zero virtual nodes silently blackholes routing —
    /// every key returns `None` from `node_for_key`. The fallible
    /// constructor rejects this configuration up front so a misset
    /// config does not produce a healthy-looking ring with no
    /// reachable replicas.
    ZeroVnodes,
}

impl std::fmt::Display for ConsistentHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroVnodes => write!(
                f,
                "consistent-hash ring requires vnodes_per_node >= 1 \
                 (zero-vnode rings silently blackhole all routing; br-asupersync-un962v)"
            ),
        }
    }
}

impl std::error::Error for ConsistentHashError {}

/// Configuration for bounded-load consistent-hash lookups.
///
/// The limit is computed as:
///
/// ```text
/// ceil(((total_load + 1) / node_count) * (1 + epsilon_per_mille / 1000))
/// ```
///
/// where `total_load` is the caller-visible load before assigning the current
/// key. `epsilon_per_mille = 0` gives the strictest bound; higher values allow
/// bounded skew in exchange for fewer fallback walks away from the primary
/// vnode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedLoadConfig {
    epsilon_per_mille: u16,
}

impl BoundedLoadConfig {
    /// Strict bounded-load routing: no intentional skew beyond the ceiling of
    /// the current mean load.
    pub const STRICT: Self = Self {
        epsilon_per_mille: 0,
    };

    /// Create a bounded-load configuration.
    #[inline]
    #[must_use]
    pub const fn new(epsilon_per_mille: u16) -> Self {
        Self { epsilon_per_mille }
    }

    /// Return the allowed skew above mean, expressed in per-mille.
    #[inline]
    #[must_use]
    pub const fn epsilon_per_mille(self) -> u16 {
        self.epsilon_per_mille
    }

    /// Compute the inclusive per-node load limit after assigning one more key.
    #[must_use]
    pub fn load_limit(self, total_load: u64, node_count: usize) -> u64 {
        if node_count == 0 {
            return 0;
        }

        let total_after_assignment = u128::from(total_load).saturating_add(1);
        let skew_per_mille = u128::from(1000_u16.saturating_add(self.epsilon_per_mille));
        let denominator = (node_count as u128).saturating_mul(1000);
        let numerator = total_after_assignment.saturating_mul(skew_per_mille);
        let limit = ceil_div_u128(numerator, denominator).max(1);
        u64::try_from(limit).unwrap_or(u64::MAX)
    }
}

/// Whether a bounded-load lookup used the primary vnode or a fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedLoadFallback {
    /// The primary vnode was below the configured load cap.
    Primary,
    /// The lookup walked forward on the ring and selected another node under
    /// the cap.
    RingWalk,
    /// Every node was at or over the computed cap, so the deterministic
    /// least-loaded node was selected. This keeps routing total and observable
    /// when callers pass externally skewed load snapshots.
    LeastLoaded,
}

/// Full receipt for a bounded-load consistent-hash lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedLoadDecision<'a> {
    /// Node selected by the ordinary consistent-hash lookup before load checks.
    pub primary_node: &'a str,
    /// Node selected after bounded-load fallback, if any.
    pub selected_node: &'a str,
    /// Load observed for `selected_node` before assigning the current key.
    pub selected_load: u64,
    /// Inclusive per-node cap computed for this lookup.
    pub load_limit: u64,
    /// Total caller-visible load before assigning the current key.
    pub total_load: u64,
    /// Number of unique nodes available in the ring.
    pub node_count: usize,
    /// Fallback path used for the decision.
    pub fallback: BoundedLoadFallback,
}

/// A consistent hash ring with virtual nodes.
///
/// br-asupersync-rnybb1: vnode placement is salted with a per-ring
/// `seed`. Pre-fix the ring used `DetHasher::default()` (FNV-1a with
/// a publicly-known fixed seed) for both vnode placement and key
/// hashing — an attacker who could control any portion of the
/// hashed key space could compute keys that all hashed into the
/// same vnode bucket and pin the entire load to one replica
/// (load-pinning DoS). Post-fix, every hash is salted with the
/// `seed` field which production callers populate from
/// [`crate::util::OsEntropy`] (per-deployment random) and tests /
/// lab callers populate with a fixed value for replay determinism.
#[derive(Debug, Clone)]
pub struct HashRing {
    vnodes_per_node: usize,
    nodes: BTreeSet<String>,
    ring: Vec<VirtualNode>,
    /// br-asupersync-rnybb1: per-ring hash salt. Mixed into every
    /// `vnode_hash` and `hash_value` call so that an attacker who
    /// reverse-engineers the FNV-1a algorithm cannot pre-compute
    /// colliding keys without ALSO knowing this seed. Production
    /// rings should source it from `OsEntropy::next_u64()` at
    /// construction time; tests / lab use a fixed value.
    seed: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct VirtualNode {
    hash: u64,
    node_id: String,
    vnode: u32,
}

impl HashRing {
    /// Create a new hash ring with the given number of virtual nodes
    /// per node and an explicit hash salt.
    ///
    /// br-asupersync-rnybb1: `seed` SHOULD be unique per deployment
    /// (e.g., sourced from [`crate::util::EntropySource::next_u64`] on
    /// [`crate::util::OsEntropy`] at
    /// startup) so that an attacker cannot pre-compute keys that
    /// collide on a known seed. Tests, lab runs, and any caller that
    /// requires byte-for-byte ring reproducibility should pass a
    /// fixed seed (e.g., `0`) — the security gate is only meaningful
    /// when keys are attacker-influenced.
    ///
    /// br-asupersync-un962v: `vnodes_per_node` is clamped to `>= 1`
    /// to avoid silently constructing a blackhole ring. A ring with
    /// zero virtual nodes accepts `add_node` calls but every key
    /// lookup returns `None` — a config-validation gap that any
    /// caller treating `node_count > 0` as healthy would silently
    /// route into. Callers that want to surface zero-vnode errors
    /// should use [`Self::try_new`] instead of clamping silently.
    #[must_use]
    pub fn new(vnodes_per_node: usize, seed: u64) -> Self {
        Self {
            // br-asupersync-un962v: clamp to at least 1 vnode so the
            // resulting ring is never a blackhole. Mirrors the
            // niczb3 worker_count clamp pattern in three_lane.rs.
            vnodes_per_node: vnodes_per_node.max(1),
            nodes: BTreeSet::new(),
            ring: Vec::new(),
            seed,
        }
    }

    /// br-asupersync-un962v: fallible constructor that rejects
    /// zero-vnode configurations up front with
    /// [`ConsistentHashError::ZeroVnodes`]. Use this from
    /// configuration-validation paths that want to surface
    /// misconfigured rings instead of accepting a silently-clamped
    /// fallback.
    pub fn try_new(vnodes_per_node: usize, seed: u64) -> Result<Self, ConsistentHashError> {
        if vnodes_per_node == 0 {
            return Err(ConsistentHashError::ZeroVnodes);
        }
        Ok(Self {
            vnodes_per_node,
            nodes: BTreeSet::new(),
            ring: Vec::new(),
            seed,
        })
    }

    /// Construct a HashRing seeded from OS entropy. Equivalent to
    /// `HashRing::new(vnodes_per_node, OsEntropy.next_u64())`.
    /// Production-grade default for new rings; tests should use
    /// `HashRing::new(vnodes_per_node, fixed_seed)` for determinism.
    ///
    /// br-asupersync-rnybb1.
    #[must_use]
    pub fn with_os_entropy(vnodes_per_node: usize) -> Self {
        use crate::util::EntropySource;
        let seed = crate::util::OsEntropy.next_u64();
        Self::new(vnodes_per_node, seed)
    }

    /// Returns the hash salt used by this ring. Exposed for diagnostics
    /// and replay-stability assertions; do not log this value
    /// alongside attacker-influenced keys.
    #[must_use]
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// Returns the number of registered nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the number of virtual nodes in the ring.
    #[must_use]
    pub fn vnode_count(&self) -> usize {
        self.ring.len()
    }

    /// Returns true if the ring has no virtual nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ring.is_empty()
    }

    /// Adds a node to the ring. Returns false if the node already exists.
    pub fn add_node(&mut self, node_id: impl Into<String>) -> bool {
        let node_id = node_id.into();
        if self.nodes.contains(&node_id) {
            return false;
        }
        self.nodes.insert(node_id.clone());

        if self.vnodes_per_node == 0 {
            return true;
        }

        for vnode in 0..self.vnodes_per_node {
            let hash = vnode_hash(self.seed, &node_id, vnode as u32);
            self.ring.push(VirtualNode {
                hash,
                node_id: node_id.clone(),
                vnode: vnode as u32,
            });
        }

        self.ring.sort_by(|a, b| {
            a.hash
                .cmp(&b.hash)
                .then_with(|| a.node_id.cmp(&b.node_id))
                .then_with(|| a.vnode.cmp(&b.vnode))
        });
        true
    }

    /// Removes a node and all its virtual nodes. Returns count of removed vnodes.
    pub fn remove_node(&mut self, node_id: &str) -> usize {
        if !self.nodes.remove(node_id) {
            return 0;
        }
        let before = self.ring.len();
        self.ring.retain(|vn| vn.node_id != node_id);
        before.saturating_sub(self.ring.len())
    }

    /// Returns the node responsible for a key, if any.
    #[must_use]
    pub fn node_for_key<K: Hash>(&self, key: &K) -> Option<&str> {
        if self.ring.is_empty() {
            return None;
        }
        let key_hash = hash_value(self.seed, key);
        let idx = self.ring.partition_point(|vn| vn.hash < key_hash);
        let idx = if idx == self.ring.len() { 0 } else { idx };
        Some(self.ring[idx].node_id.as_str())
    }

    /// Returns the node responsible for a key, capped by caller-supplied load.
    ///
    /// This is the bounded-loads variant of consistent hashing: choose the
    /// ordinary primary node while it is below the configured cap, otherwise
    /// walk the ring in vnode order to the first unique node below the cap.
    /// The existing [`Self::node_for_key`] path remains the unbounded variant.
    pub fn bounded_node_for_key<K, Load>(
        &self,
        key: &K,
        total_load: u64,
        config: BoundedLoadConfig,
        load: Load,
    ) -> Option<BoundedLoadDecision<'_>>
    where
        K: Hash,
        Load: Fn(&str) -> u64,
    {
        if self.ring.is_empty() {
            return None;
        }

        let key_hash = hash_value(self.seed, key);
        let start_idx = self.ring.partition_point(|vn| vn.hash < key_hash);
        let start_idx = if start_idx == self.ring.len() {
            0
        } else {
            start_idx
        };
        let load_limit = config.load_limit(total_load, self.nodes.len());

        let mut seen_nodes = BTreeSet::new();
        let mut primary_node = None;
        let mut least_loaded = None::<(&str, u64)>;

        for offset in 0..self.ring.len() {
            let vnode_idx = (start_idx + offset) % self.ring.len();
            let node = self.ring[vnode_idx].node_id.as_str();
            if !seen_nodes.insert(node) {
                continue;
            }

            let node_load = load(node);
            if primary_node.is_none() {
                primary_node = Some((node, node_load));
            }
            if least_loaded.is_none_or(|(best_node, best_load)| {
                node_load < best_load || (node_load == best_load && node < best_node)
            }) {
                least_loaded = Some((node, node_load));
            }

            if node_load < load_limit {
                let (primary, _) = primary_node.expect("first unique vnode sets primary");
                return Some(BoundedLoadDecision {
                    primary_node: primary,
                    selected_node: node,
                    selected_load: node_load,
                    load_limit,
                    total_load,
                    node_count: self.nodes.len(),
                    fallback: if offset == 0 {
                        BoundedLoadFallback::Primary
                    } else {
                        BoundedLoadFallback::RingWalk
                    },
                });
            }
        }

        let (primary, _) = primary_node.expect("non-empty ring has a primary node");
        let (selected, selected_load) =
            least_loaded.expect("non-empty ring has a least-loaded node");
        Some(BoundedLoadDecision {
            primary_node: primary,
            selected_node: selected,
            selected_load,
            load_limit,
            total_load,
            node_count: self.nodes.len(),
            fallback: BoundedLoadFallback::LeastLoaded,
        })
    }

    /// Convenience wrapper around [`Self::bounded_node_for_key`] when callers
    /// only need the selected node identifier.
    pub fn node_for_key_bounded_load<K, Load>(
        &self,
        key: &K,
        total_load: u64,
        config: BoundedLoadConfig,
        load: Load,
    ) -> Option<&str>
    where
        K: Hash,
        Load: Fn(&str) -> u64,
    {
        self.bounded_node_for_key(key, total_load, config, load)
            .map(|decision| decision.selected_node)
    }

    /// Returns node identifiers in deterministic sorted order.
    pub fn nodes(&self) -> impl Iterator<Item = &str> {
        self.nodes.iter().map(String::as_str)
    }
}

fn ceil_div_u128(numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        return 0;
    }
    numerator.div_ceil(denominator)
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct HrwScore {
    score: f64,
    tie_break: u64,
}

impl Eq for HrwScore {}

impl PartialOrd for HrwScore {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HrwScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score
            .total_cmp(&other.score)
            .then_with(|| self.tie_break.cmp(&other.tie_break))
    }
}

/// Salted Highest Random Weight (rendezvous) selection over a transient
/// candidate set.
///
/// This is the preferred hot-path scoring primitive when the membership set is
/// not persistent enough to justify materializing a [`HashRing`].
#[must_use]
pub(crate) fn select_hrw<'a, I, T, K, N, Node, Weight>(
    candidates: I,
    key: &K,
    seed: u64,
    node_id: Node,
    weight: Weight,
) -> Option<&'a T>
where
    I: IntoIterator<Item = &'a T>,
    K: Hash,
    N: Hash + ?Sized + 'a,
    Node: Fn(&'a T) -> &'a N,
    Weight: Fn(&T) -> u32,
{
    let mut best = None;
    for candidate in candidates {
        let candidate_node = node_id(candidate);
        let Some(score) = hrw_score(seed, key, candidate_node, weight(candidate)) else {
            continue;
        };
        if best.is_none_or(|(best_score, _)| score > best_score) {
            best = Some((score, candidate));
        }
    }
    best.map(|(_, candidate)| candidate)
}

/// Exact duplicate-free top-k HRW selection over a transient candidate set.
///
/// For the small `k` used in routing and placement policies, keeping a sorted
/// in-memory winner buffer avoids the old ring-build churn without introducing
/// heap traffic.
#[must_use]
#[allow(dead_code)]
pub(crate) fn select_top_k_hrw<'a, I, T, K, N, Node, Weight>(
    candidates: I,
    limit: usize,
    key: &K,
    seed: u64,
    node_id: Node,
    weight: Weight,
) -> Vec<&'a T>
where
    I: IntoIterator<Item = &'a T>,
    K: Hash,
    N: Hash + ?Sized + 'a,
    Node: Fn(&'a T) -> &'a N,
    Weight: Fn(&T) -> u32,
{
    if limit == 0 {
        return Vec::new();
    }

    let mut winners = Vec::with_capacity(limit);
    for candidate in candidates {
        let candidate_node = node_id(candidate);
        let Some(score) = hrw_score(seed, key, candidate_node, weight(candidate)) else {
            continue;
        };

        let insert_at = winners.partition_point(|(winner_score, _)| *winner_score > score);
        if insert_at >= limit {
            continue;
        }
        winners.insert(insert_at, (score, candidate));
        if winners.len() > limit {
            winners.pop();
        }
    }

    winners
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect()
}

/// br-asupersync-rnybb1: salted vnode placement hash. The `seed` is
/// hashed FIRST so that two HashRings with different seeds produce
/// disjoint vnode placements even for identical (node_id, vnode)
/// inputs. This defeats pre-computed collision attacks against the
/// known FNV-1a default seed.
fn vnode_hash(seed: u64, node_id: &str, vnode: u32) -> u64 {
    let mut hasher = DetHasher::default();
    seed.hash(&mut hasher);
    node_id.hash(&mut hasher);
    vnode.hash(&mut hasher);
    hasher.finish()
}

/// br-asupersync-rnybb1: salted key hash. Mirrors `vnode_hash` so
/// that key-to-vnode mapping uses the same salt domain.
fn hash_value<T: Hash>(seed: u64, value: &T) -> u64 {
    let mut hasher = DetHasher::default();
    seed.hash(&mut hasher);
    value.hash(&mut hasher);
    hasher.finish()
}

#[allow(clippy::cast_precision_loss)]
fn hrw_score<K: Hash, N: Hash + ?Sized>(
    seed: u64,
    key: &K,
    node_id: &N,
    weight: u32,
) -> Option<HrwScore> {
    if weight == 0 {
        return None;
    }

    let mut hasher = DetHasher::default();
    seed.hash(&mut hasher);
    "hrw-score".hash(&mut hasher);
    key.hash(&mut hasher);
    node_id.hash(&mut hasher);
    let hash = hasher.finish();

    let mut tie_break_hasher = DetHasher::default();
    seed.hash(&mut tie_break_hasher);
    "hrw-tie-break".hash(&mut tie_break_hasher);
    node_id.hash(&mut tie_break_hasher);
    let tie_break = tie_break_hasher.finish();

    let unit = (hash as f64 + 1.0) / (u64::MAX as f64 + 1.0);
    Some(HrwScore {
        score: hrw_score_from_unit(weight, unit),
        tie_break,
    })
}

/// Map a uniform `unit` in `(0, 1]` and a weight to a weighted-rendezvous score.
///
/// br-asupersync-xw4sbk: at `unit == 1.0` — reachable because the top ~2048
/// `u64` hash values round up to `2^64` in `f64`, making `unit = 2^64/2^64 =
/// 1.0` — `unit.ln()` is `+0.0`, so `weight / -(+0.0)` is `-inf`. That would
/// invert the score and make the maximal-hash node (the strongest rendezvous
/// candidate) the weakest, so it would never be selected. The score is
/// monotonically increasing as `unit -> 1`, so the boundary is the `+inf`
/// limit; clamp to it instead of flipping the sign.
fn hrw_score_from_unit(weight: u32, unit: f64) -> f64 {
    if unit < 1.0 {
        f64::from(weight) / -unit.ln()
    } else {
        f64::INFINITY
    }
}

#[cfg(test)]
#[path = "consistent_hash_inline_tests.rs"]
mod tests;
