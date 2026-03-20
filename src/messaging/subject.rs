//! Shared subject-language primitives for FABRIC declarations and placement.

#![allow(dead_code)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::use_self)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::missing_fields_in_debug)]
#![allow(clippy::uninlined_format_args)]

use crate::util::DetHasher;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::hash::{Hash, Hasher};
use thiserror::Error;

/// Canonical subject token used for routing and matching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SubjectToken {
    /// Literal subject segment.
    Literal(String),
    /// Single-segment wildcard (`*`).
    One,
    /// Tail wildcard (`>`), which must be terminal.
    Tail,
}

impl fmt::Display for SubjectToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(value) => write!(f, "{value}"),
            Self::One => write!(f, "*"),
            Self::Tail => write!(f, ">"),
        }
    }
}

/// Errors produced while parsing subject patterns or concrete subjects.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SubjectPatternError {
    /// The parsed subject contained no non-empty segments.
    #[error("subject pattern must contain at least one segment")]
    EmptyPattern,
    /// Empty path segments such as `a..b` are not legal subject syntax.
    #[error("subject pattern must not contain empty segments")]
    EmptySegment,
    /// Whitespace inside a token would make canonical matching ambiguous.
    #[error("subject segment `{0}` must not contain whitespace")]
    WhitespaceInSegment(String),
    /// A tail wildcard appeared anywhere other than the final segment.
    #[error("tail wildcard `>` must be terminal")]
    TailWildcardMustBeTerminal,
    /// More than one terminal tail wildcard was present.
    #[error("subject pattern may not contain more than one tail wildcard")]
    MultipleTailWildcards,
    /// A literal segment embedded wildcard characters rather than being a pure token.
    #[error("literal segment `{0}` embeds wildcard characters")]
    EmbeddedWildcard(String),
    /// Prefix morphisms only permit exact literal segment rewrites.
    #[error("pattern `{0}` must contain only literal segments for prefix morphisms")]
    LiteralOnlyPatternRequired(String),
    /// Concrete subjects cannot carry wildcard tokens.
    #[error("subject `{0}` must not contain wildcard tokens")]
    WildcardsNotAllowed(String),
}

/// Parsed subject pattern with NATS-style wildcard support.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubjectPattern {
    raw: String,
    segments: Vec<SubjectToken>,
}

impl SubjectPattern {
    /// Construct a validated subject pattern from the canonical dotted representation.
    #[must_use]
    pub fn new(pattern: impl AsRef<str>) -> Self {
        Self::parse(pattern.as_ref()).expect("subject pattern must be syntactically valid")
    }

    /// Parse and canonicalize a subject pattern.
    pub fn parse(raw: &str) -> Result<Self, SubjectPatternError> {
        let segments = parse_pattern_tokens(raw)?;
        Self::from_tokens(segments)
    }

    /// Build a pattern from already-tokenized segments.
    pub fn from_tokens(segments: Vec<SubjectToken>) -> Result<Self, SubjectPatternError> {
        validate_pattern_tokens(&segments)?;
        Ok(Self {
            raw: canonicalize_tokens(&segments),
            segments,
        })
    }

    /// Return the canonical dotted subject string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Return a stable string key used for hashing and diagnostics.
    #[must_use]
    pub fn canonical_key(&self) -> String {
        self.raw.clone()
    }

    /// Return the canonical pattern segments.
    #[must_use]
    pub fn segments(&self) -> &[SubjectToken] {
        &self.segments
    }

    /// Return true when the pattern ends in a tail wildcard.
    #[must_use]
    pub fn is_full_wildcard(&self) -> bool {
        matches!(self.segments.last(), Some(SubjectToken::Tail))
    }

    /// Return true when the pattern contains any wildcard tokens.
    #[must_use]
    pub fn has_wildcards(&self) -> bool {
        self.segments
            .iter()
            .any(|segment| !matches!(segment, SubjectToken::Literal(_)))
    }

    /// Return true if this pattern matches the provided concrete subject.
    #[must_use]
    pub fn matches(&self, subject: &Subject) -> bool {
        matches_subject_tokens(&self.segments, subject.tokens())
    }

    /// Return true if two patterns can match at least one common subject.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        overlaps_tokens(&self.segments, &other.segments)
    }
}

impl Default for SubjectPattern {
    fn default() -> Self {
        Self::new("fabric.default")
    }
}

impl fmt::Display for SubjectPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for SubjectPattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SubjectPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// Concrete subject without wildcard tokens.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Subject {
    raw: String,
    tokens: Vec<String>,
}

impl Subject {
    /// Construct a validated concrete subject.
    #[must_use]
    pub fn new(subject: impl AsRef<str>) -> Self {
        Self::parse(subject.as_ref()).expect("subject must be syntactically valid")
    }

    /// Parse and canonicalize a concrete subject.
    pub fn parse(raw: &str) -> Result<Self, SubjectPatternError> {
        let pattern = SubjectPattern::parse(raw)?;
        if pattern.has_wildcards() {
            return Err(SubjectPatternError::WildcardsNotAllowed(
                pattern.as_str().to_owned(),
            ));
        }

        let tokens = pattern
            .segments()
            .iter()
            .map(|segment| match segment {
                SubjectToken::Literal(value) => value.clone(),
                SubjectToken::One | SubjectToken::Tail => unreachable!("wildcards rejected above"),
            })
            .collect::<Vec<_>>();

        Ok(Self {
            raw: pattern.as_str().to_owned(),
            tokens,
        })
    }

    /// Return the canonical dotted subject string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Return the literal subject tokens.
    #[must_use]
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Subject {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Subject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

impl From<&Subject> for SubjectPattern {
    fn from(subject: &Subject) -> Self {
        let segments = subject
            .tokens()
            .iter()
            .cloned()
            .map(SubjectToken::Literal)
            .collect::<Vec<_>>();
        Self::from_tokens(segments).expect("concrete subjects always form valid patterns")
    }
}

fn parse_pattern_tokens(raw: &str) -> Result<Vec<SubjectToken>, SubjectPatternError> {
    let normalized = raw.trim();
    if normalized.is_empty() {
        return Err(SubjectPatternError::EmptyPattern);
    }

    let mut segments = Vec::new();
    for segment in normalized.split('.') {
        if segment.is_empty() {
            return Err(SubjectPatternError::EmptySegment);
        }
        if segment.chars().any(char::is_whitespace) {
            return Err(SubjectPatternError::WhitespaceInSegment(segment.to_owned()));
        }

        let token = match segment {
            "*" => SubjectToken::One,
            ">" => SubjectToken::Tail,
            literal if literal.contains('*') || literal.contains('>') => {
                return Err(SubjectPatternError::EmbeddedWildcard(literal.to_owned()));
            }
            literal => SubjectToken::Literal(literal.to_owned()),
        };
        segments.push(token);
    }

    validate_pattern_tokens(&segments)?;
    Ok(segments)
}

fn validate_pattern_tokens(segments: &[SubjectToken]) -> Result<(), SubjectPatternError> {
    if segments.is_empty() {
        return Err(SubjectPatternError::EmptyPattern);
    }

    let tail_count = segments
        .iter()
        .filter(|segment| matches!(segment, SubjectToken::Tail))
        .count();
    if tail_count > 1 {
        return Err(SubjectPatternError::MultipleTailWildcards);
    }

    if let Some(position) = segments
        .iter()
        .position(|segment| matches!(segment, SubjectToken::Tail))
        && position + 1 != segments.len()
    {
        return Err(SubjectPatternError::TailWildcardMustBeTerminal);
    }

    Ok(())
}

fn canonicalize_tokens(segments: &[SubjectToken]) -> String {
    segments
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn matches_subject_tokens(pattern: &[SubjectToken], subject: &[String]) -> bool {
    match (pattern.split_first(), subject.split_first()) {
        (None, None) | (Some((SubjectToken::Tail, _)), Some(_)) => true,
        (Some((SubjectToken::One, pattern_tail)), Some((_, subject_tail))) => {
            matches_subject_tokens(pattern_tail, subject_tail)
        }
        (Some((SubjectToken::Literal(expected), pattern_tail)), Some((actual, subject_tail)))
            if expected == actual =>
        {
            matches_subject_tokens(pattern_tail, subject_tail)
        }
        _ => false,
    }
}

fn overlaps_tokens(left: &[SubjectToken], right: &[SubjectToken]) -> bool {
    match (left.split_first(), right.split_first()) {
        (None, Some(_)) | (Some(_), None) => false,
        (None, None)
        | (Some((SubjectToken::Tail, _)), Some(_))
        | (Some(_), Some((SubjectToken::Tail, _))) => true,
        (Some((left_head, left_tail)), Some((right_head, right_tail))) => {
            if segments_can_match(left_head, right_head) {
                overlaps_tokens(left_tail, right_tail)
            } else {
                false
            }
        }
    }
}

fn segments_can_match(left: &SubjectToken, right: &SubjectToken) -> bool {
    match (left, right) {
        (SubjectToken::Literal(left), SubjectToken::Literal(right)) => left == right,
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Sublist: trie-based subject routing engine
// ---------------------------------------------------------------------------

use parking_lot::{Mutex, RwLock};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Opaque subscription identifier assigned by the [`Sublist`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId(u64);

impl SubscriptionId {
    /// Return the raw numeric identifier.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sub-{}", self.0)
    }
}

/// Subscriber entry stored inside the trie.
#[derive(Debug, Clone)]
struct Subscriber {
    id: SubscriptionId,
    /// Optional queue group name. Only one subscriber per group per message.
    queue_group: Option<String>,
}

/// Internal trie node keyed by subject token.
#[derive(Debug, Default)]
struct TrieNode {
    /// Literal-token children.
    children: BTreeMap<String, TrieNode>,
    /// Single-wildcard (`*`) child.
    wildcard_child: Option<Box<TrieNode>>,
    /// Tail-wildcard (`>`) leaf subscribers.
    tail_subscribers: Vec<Subscriber>,
    /// Exact-match leaf subscribers (no further tokens).
    leaf_subscribers: Vec<Subscriber>,
}

impl TrieNode {
    fn is_empty(&self) -> bool {
        self.children.is_empty()
            && self.wildcard_child.is_none()
            && self.tail_subscribers.is_empty()
            && self.leaf_subscribers.is_empty()
    }

    /// Remove subscriber by id from all positions in this node, returning
    /// true if anything was removed.
    fn remove_subscriber(&mut self, id: SubscriptionId) -> bool {
        let mut removed = false;

        let before = self.leaf_subscribers.len();
        self.leaf_subscribers.retain(|sub| sub.id != id);
        if self.leaf_subscribers.len() != before {
            removed = true;
        }

        let before = self.tail_subscribers.len();
        self.tail_subscribers.retain(|sub| sub.id != id);
        if self.tail_subscribers.len() != before {
            removed = true;
        }

        removed
    }
}

/// Result set from a [`Sublist::lookup`] call.
#[derive(Debug, Clone, Default)]
pub struct SublistResult {
    /// All non-queue-group subscribers that match.
    pub subscribers: Vec<SubscriptionId>,
    /// For each queue group, exactly one selected subscriber.
    pub queue_group_picks: Vec<(String, SubscriptionId)>,
}

impl SublistResult {
    /// Return total number of subscriptions that will receive the message.
    #[must_use]
    pub fn total(&self) -> usize {
        self.subscribers.len() + self.queue_group_picks.len()
    }

    fn extend(&mut self, mut other: Self) {
        self.subscribers.append(&mut other.subscribers);
        self.queue_group_picks.append(&mut other.queue_group_picks);
    }
}

/// Thread-safe trie-based subject routing engine with generation-invalidated
/// caching, queue group support, and cancel-correct subscription guards.
///
/// Inspired by NATS server/sublist.go, adapted for Asupersync's structured
/// concurrency model.
pub struct Sublist {
    /// The core trie protected by an RwLock for concurrent reads.
    trie: RwLock<TrieNode>,
    /// Monotonic generation counter bumped on every mutation.
    generation: AtomicU64,
    /// Next subscription id counter.
    next_id: AtomicU64,
    /// Cache of literal-subject lookups, invalidated by generation changes.
    cache: RwLock<SublistCache>,
    /// Round-robin counter per queue group for deterministic selection.
    queue_round_robin: Mutex<HashMap<String, u64>>,
}

/// Generation-tagged cache entry storing raw matched subscriber info
/// (before queue group selection, which must run fresh each time).
#[derive(Debug, Clone)]
struct CacheEntry {
    generation: u64,
    /// Non-queue-group subscriber ids.
    plain_ids: Vec<SubscriptionId>,
    /// Queue-group subscriber ids grouped by group name.
    queue_groups: Vec<(String, Vec<SubscriptionId>)>,
}

/// Literal-subject lookup cache.
#[derive(Debug, Default)]
struct SublistCache {
    entries: HashMap<String, CacheEntry>,
}

/// Per-link hot cache for recently resolved literal subjects.
///
/// Links or sessions can keep one of these alongside their own state to avoid
/// re-walking the trie on repeated hot subjects while still respecting the
/// sublist generation counter.
#[derive(Debug)]
pub struct SublistLinkCache {
    capacity: usize,
    entries: HashMap<String, CacheEntry>,
    order: VecDeque<String>,
}

impl Default for SublistLinkCache {
    fn default() -> Self {
        Self::new(64)
    }
}

impl SublistLinkCache {
    /// Create a per-link cache with a bounded entry capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Return the number of currently cached subjects.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true when the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn get(&self, subject: &str, generation: u64) -> Option<&CacheEntry> {
        self.entries
            .get(subject)
            .filter(|entry| entry.generation == generation)
    }

    fn insert(&mut self, subject: String, entry: CacheEntry) {
        if self.entries.contains_key(&subject) {
            self.entries.insert(subject, entry);
            return;
        }

        if self.entries.len() >= self.capacity {
            while let Some(oldest) = self.order.pop_front() {
                if self.entries.remove(&oldest).is_some() {
                    break;
                }
            }
        }

        self.order.push_back(subject.clone());
        self.entries.insert(subject, entry);
    }
}

impl Default for Sublist {
    fn default() -> Self {
        Self::new()
    }
}

impl Sublist {
    /// Create an empty routing engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            trie: RwLock::new(TrieNode::default()),
            generation: AtomicU64::new(0),
            next_id: AtomicU64::new(1),
            cache: RwLock::new(SublistCache::default()),
            queue_round_robin: Mutex::new(HashMap::new()),
        }
    }

    /// Return the current generation counter.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Insert a subscription for the given pattern, returning a guard that
    /// removes the subscription on drop (cancel-correct).
    pub fn subscribe(
        self: &Arc<Self>,
        pattern: &SubjectPattern,
        queue_group: Option<String>,
    ) -> SubscriptionGuard {
        let id = SubscriptionId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let subscriber = Subscriber { id, queue_group };

        {
            let mut trie = self.trie.write();
            insert_into_trie(&mut trie, pattern.segments(), subscriber);
        }

        self.generation.fetch_add(1, Ordering::Release);

        SubscriptionGuard {
            id,
            pattern: pattern.clone(),
            sublist: Arc::clone(self),
        }
    }

    /// Remove a subscription by id and pattern. Called by [`SubscriptionGuard`]
    /// on drop.
    fn unsubscribe(&self, id: SubscriptionId, pattern: &SubjectPattern) {
        let mut trie = self.trie.write();
        remove_from_trie(&mut trie, pattern.segments(), id);
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Look up all matching subscriptions for a concrete subject.
    ///
    /// For queue groups, exactly one subscriber per group is selected using
    /// round-robin. Queue group selection always runs fresh (not cached) so
    /// round-robin advances correctly on each call.
    #[must_use]
    pub fn lookup(&self, subject: &Subject) -> SublistResult {
        let current_gen = self.generation.load(Ordering::Acquire);
        let entry = self.resolve_entry(subject, current_gen);
        self.apply_queue_selection(entry.plain_ids.clone(), &entry.queue_groups)
    }

    /// Look up a concrete subject using a caller-owned per-link cache.
    ///
    /// The cache stores raw match sets keyed by the sublist generation, so
    /// queue-group round-robin still advances fresh on every lookup.
    #[must_use]
    pub fn lookup_with_link_cache(
        &self,
        subject: &Subject,
        link_cache: &mut SublistLinkCache,
    ) -> SublistResult {
        let current_gen = self.generation.load(Ordering::Acquire);
        if let Some(entry) = link_cache.get(subject.as_str(), current_gen) {
            return self.apply_queue_selection(entry.plain_ids.clone(), &entry.queue_groups);
        }

        let entry = self.resolve_entry(subject, current_gen);
        link_cache.insert(subject.as_str().to_owned(), entry.clone());
        self.apply_queue_selection(entry.plain_ids.clone(), &entry.queue_groups)
    }

    /// Return the count of all registered subscriptions.
    #[must_use]
    pub fn count(&self) -> usize {
        let trie = self.trie.read();
        count_subscribers(&trie)
    }

    /// Split raw matches into plain subscriber ids and queue-group buckets.
    fn split_matches(
        raw_matches: &[&Subscriber],
    ) -> (Vec<SubscriptionId>, Vec<(String, Vec<SubscriptionId>)>) {
        let mut plain = Vec::new();
        let mut groups: BTreeMap<String, Vec<SubscriptionId>> = BTreeMap::new();

        for sub in raw_matches {
            if let Some(group) = &sub.queue_group {
                groups.entry(group.clone()).or_default().push(sub.id);
            } else {
                plain.push(sub.id);
            }
        }

        let queue_groups = groups.into_iter().collect();
        (plain, queue_groups)
    }

    fn resolve_entry(&self, subject: &Subject, current_gen: u64) -> CacheEntry {
        // Check cache first (read lock only). Cache stores raw match sets;
        // queue group selection runs fresh each time.
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.entries.get(subject.as_str())
                && entry.generation == current_gen
            {
                return entry.clone();
            }
        }

        // Cache miss — walk the trie.
        let trie = self.trie.read();
        let mut raw_matches: Vec<&Subscriber> = Vec::new();
        collect_matches(&trie, subject.tokens(), &mut raw_matches);

        // Split into plain and queue-group buckets.
        let (plain_ids, queue_groups) = Self::split_matches(&raw_matches);
        let entry = CacheEntry {
            generation: current_gen,
            plain_ids,
            queue_groups,
        };

        // Store in cache (generation-tagged).
        {
            let mut cache = self.cache.write();
            cache
                .entries
                .insert(subject.as_str().to_owned(), entry.clone());
        }

        entry
    }

    /// Apply round-robin queue group selection to produce the final result.
    fn apply_queue_selection(
        &self,
        subscribers: Vec<SubscriptionId>,
        queue_groups: &[(String, Vec<SubscriptionId>)],
    ) -> SublistResult {
        let mut queue_group_picks = Vec::new();
        if !queue_groups.is_empty() {
            let mut rr = self.queue_round_robin.lock();
            for (group, members) in queue_groups {
                if members.is_empty() {
                    continue;
                }
                let counter = rr.entry(group.clone()).or_insert(0);
                let index = (*counter as usize) % members.len();
                queue_group_picks.push((group.clone(), members[index]));
                *counter = counter.wrapping_add(1);
            }
        }

        SublistResult {
            subscribers,
            queue_group_picks,
        }
    }
}

impl fmt::Debug for Sublist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sublist")
            .field("generation", &self.generation.load(Ordering::Relaxed))
            .field("count", &self.count())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShardRoute {
    Concrete(usize),
    Fallback,
}

/// Sharded subject index that wraps multiple [`Sublist`] instances.
///
/// Concrete literal prefixes are deterministically assigned to a single shard.
/// Broad wildcard prefixes that cannot be routed by the configured prefix
/// depth fall back to a dedicated shard so wildcard lookups remain correct
/// without replicating subscriptions across every shard.
#[derive(Debug, Clone)]
pub struct ShardedSublist {
    prefix_depth: usize,
    shards: Vec<Arc<Sublist>>,
    fallback: Arc<Sublist>,
}

impl Default for ShardedSublist {
    fn default() -> Self {
        Self::new(default_subject_shard_count())
    }
}

impl ShardedSublist {
    /// Create a sharded subject index using the default prefix depth of `1`.
    #[must_use]
    pub fn new(shard_count: usize) -> Self {
        Self::with_prefix_depth(shard_count, 1)
    }

    /// Create a sharded subject index with an explicit literal prefix depth.
    ///
    /// Patterns that do not expose at least `prefix_depth` literal segments
    /// are routed into the fallback shard.
    #[must_use]
    pub fn with_prefix_depth(shard_count: usize, prefix_depth: usize) -> Self {
        let shard_count = shard_count.max(1);
        let prefix_depth = prefix_depth.max(1);
        let shards = (0..shard_count)
            .map(|_| Arc::new(Sublist::new()))
            .collect::<Vec<_>>();
        Self {
            prefix_depth,
            shards,
            fallback: Arc::new(Sublist::new()),
        }
    }

    /// Return the number of concrete shards.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Return the configured shard prefix depth.
    #[must_use]
    pub fn prefix_depth(&self) -> usize {
        self.prefix_depth
    }

    /// Return the concrete shard generation, if the shard exists.
    #[must_use]
    pub fn shard_generation(&self, index: usize) -> Option<u64> {
        self.shards.get(index).map(|shard| shard.generation())
    }

    /// Return the fallback shard generation.
    #[must_use]
    pub fn fallback_generation(&self) -> u64 {
        self.fallback.generation()
    }

    /// Return the assigned concrete shard for a subject pattern when the
    /// pattern exposes enough literal prefix segments.
    #[must_use]
    pub fn shard_index_for_pattern(&self, pattern: &SubjectPattern) -> Option<usize> {
        match self.route_for_pattern(pattern) {
            ShardRoute::Concrete(index) => Some(index),
            ShardRoute::Fallback => None,
        }
    }

    /// Return the concrete shard index for a concrete subject lookup.
    #[must_use]
    pub fn shard_index_for_subject(&self, subject: &Subject) -> usize {
        self.hash_subject_prefix(subject) % self.shards.len()
    }

    /// Subscribe to a pattern within the appropriate shard.
    #[must_use]
    pub fn subscribe(
        &self,
        pattern: &SubjectPattern,
        queue_group: Option<String>,
    ) -> ShardedSubscriptionGuard {
        let route = self.route_for_pattern(pattern);
        let inner = match route {
            ShardRoute::Concrete(index) => self.shards[index].subscribe(pattern, queue_group),
            ShardRoute::Fallback => self.fallback.subscribe(pattern, queue_group),
        };

        ShardedSubscriptionGuard { route, inner }
    }

    /// Look up matching subscriptions for a concrete subject.
    ///
    /// The concrete shard handles the hot path, and the fallback shard is
    /// consulted for broad wildcard prefixes that cannot be assigned to one
    /// concrete shard.
    #[must_use]
    pub fn lookup(&self, subject: &Subject) -> SublistResult {
        let concrete_index = self.shard_index_for_subject(subject);
        let mut result = self.shards[concrete_index].lookup(subject);
        result.extend(self.fallback.lookup(subject));
        result
    }

    /// Return the total number of registered subscriptions across all shards.
    #[must_use]
    pub fn count(&self) -> usize {
        self.fallback.count() + self.shards.iter().map(|shard| shard.count()).sum::<usize>()
    }

    fn route_for_pattern(&self, pattern: &SubjectPattern) -> ShardRoute {
        match self.hash_pattern_prefix(pattern) {
            Some(hash) => ShardRoute::Concrete(hash % self.shards.len()),
            None => ShardRoute::Fallback,
        }
    }

    fn hash_pattern_prefix(&self, pattern: &SubjectPattern) -> Option<usize> {
        let mut hasher = DetHasher::default();
        let mut literal_count = 0;

        for segment in pattern.segments() {
            if literal_count == self.prefix_depth {
                break;
            }

            match segment {
                SubjectToken::Literal(value) => {
                    value.hash(&mut hasher);
                    literal_count += 1;
                }
                SubjectToken::One | SubjectToken::Tail => return None,
            }
        }

        if literal_count == self.prefix_depth {
            Some(hasher.finish() as usize)
        } else {
            None
        }
    }

    fn hash_subject_prefix(&self, subject: &Subject) -> usize {
        let mut hasher = DetHasher::default();

        for token in subject.tokens().iter().take(self.prefix_depth) {
            token.hash(&mut hasher);
        }

        hasher.finish() as usize
    }
}

/// Subscription guard returned by [`ShardedSublist::subscribe`].
#[derive(Debug)]
pub struct ShardedSubscriptionGuard {
    route: ShardRoute,
    inner: SubscriptionGuard,
}

impl ShardedSubscriptionGuard {
    /// Return the subscription identifier.
    #[must_use]
    pub fn id(&self) -> SubscriptionId {
        self.inner.id()
    }

    /// Return the subscribed pattern.
    #[must_use]
    pub fn pattern(&self) -> &SubjectPattern {
        self.inner.pattern()
    }

    /// Return the concrete shard index when the subscription lives in a
    /// concrete shard, or `None` when it lives in the fallback shard.
    #[must_use]
    pub fn shard_index(&self) -> Option<usize> {
        match self.route {
            ShardRoute::Concrete(index) => Some(index),
            ShardRoute::Fallback => None,
        }
    }
}

/// RAII guard that removes the subscription from the [`Sublist`] on drop.
///
/// This ensures cancel-correctness: when a subscriber's scope/task is
/// cancelled, the subscription is automatically cleaned up with no ghost
/// interest remaining.
pub struct SubscriptionGuard {
    id: SubscriptionId,
    pattern: SubjectPattern,
    sublist: Arc<Sublist>,
}

impl SubscriptionGuard {
    /// Return the subscription identifier.
    #[must_use]
    pub fn id(&self) -> SubscriptionId {
        self.id
    }

    /// Return the subscribed pattern.
    #[must_use]
    pub fn pattern(&self) -> &SubjectPattern {
        &self.pattern
    }
}

impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        self.sublist.unsubscribe(self.id, &self.pattern);
    }
}

impl fmt::Debug for SubscriptionGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionGuard")
            .field("id", &self.id)
            .field("pattern", &self.pattern)
            .finish()
    }
}

fn default_subject_shard_count() -> usize {
    std::thread::available_parallelism()
        .map_or(16, usize::from)
        .next_power_of_two()
}

// --- Trie operations ---

fn insert_into_trie(node: &mut TrieNode, segments: &[SubjectToken], subscriber: Subscriber) {
    match segments.split_first() {
        None => {
            // End of pattern — register as leaf subscriber.
            node.leaf_subscribers.push(subscriber);
        }
        Some((SubjectToken::Tail, _)) => {
            // Tail wildcard — register as tail subscriber at this node.
            node.tail_subscribers.push(subscriber);
        }
        Some((SubjectToken::One, rest)) => {
            // Single wildcard — descend into wildcard child.
            let child = node
                .wildcard_child
                .get_or_insert_with(|| Box::new(TrieNode::default()));
            insert_into_trie(child, rest, subscriber);
        }
        Some((SubjectToken::Literal(key), rest)) => {
            // Literal token — descend into named child.
            let child = node.children.entry(key.clone()).or_default();
            insert_into_trie(child, rest, subscriber);
        }
    }
}

fn remove_from_trie(node: &mut TrieNode, segments: &[SubjectToken], id: SubscriptionId) -> bool {
    match segments.split_first() {
        None => node.remove_subscriber(id),
        Some((SubjectToken::Tail, _)) => {
            let before = node.tail_subscribers.len();
            node.tail_subscribers.retain(|sub| sub.id != id);
            node.tail_subscribers.len() != before
        }
        Some((SubjectToken::One, rest)) => {
            let Some(child) = node.wildcard_child.as_mut() else {
                return false;
            };
            let removed = remove_from_trie(child, rest, id);
            if child.is_empty() {
                node.wildcard_child = None;
            }
            removed
        }
        Some((SubjectToken::Literal(key), rest)) => {
            let Some(child) = node.children.get_mut(key) else {
                return false;
            };
            let removed = remove_from_trie(child, rest, id);
            if child.is_empty() {
                node.children.remove(key);
            }
            removed
        }
    }
}

fn collect_matches<'a>(
    node: &'a TrieNode,
    subject_tokens: &[String],
    results: &mut Vec<&'a Subscriber>,
) {
    // Tail-wildcard subscribers at this node match any remaining tokens.
    if !subject_tokens.is_empty() {
        results.extend(node.tail_subscribers.iter());
    }

    match subject_tokens.split_first() {
        None => {
            // End of subject — collect leaf subscribers.
            results.extend(node.leaf_subscribers.iter());
        }
        Some((token, rest)) => {
            // Literal child match.
            if let Some(child) = node.children.get(token) {
                collect_matches(child, rest, results);
            }

            // Single-wildcard child match.
            if let Some(child) = node.wildcard_child.as_ref() {
                collect_matches(child, rest, results);
            }
        }
    }
}

fn count_subscribers(node: &TrieNode) -> usize {
    let mut count = node.leaf_subscribers.len() + node.tail_subscribers.len();
    for child in node.children.values() {
        count += count_subscribers(child);
    }
    if let Some(child) = node.wildcard_child.as_ref() {
        count += count_subscribers(child);
    }
    count
}

// ---------------------------------------------------------------------------
// SubjectRegistry: concurrent schema registry with family classification
// ---------------------------------------------------------------------------

/// Semantic family classification for registered subject entries.
///
/// This is a local mirror of the FABRIC IR `SubjectFamily` enum so the subject
/// registry stays independent from the higher-level IR module, including the
/// standalone IR contract tests that path-include `ir.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum RegistryFamily {
    /// Fire-and-forget command subjects.
    Command,
    /// Notification event subjects.
    #[default]
    Event,
    /// Reply subjects for request/reply patterns.
    Reply,
    /// Control-plane subjects (typically `$SYS.*`).
    Control,
    /// Protocol-step subjects for multi-step sessions.
    ProtocolStep,
    /// Subjects used as capture selectors (must contain wildcards).
    CaptureSelector,
    /// Derived or computed view subjects.
    DerivedView,
}

impl fmt::Display for RegistryFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command => write!(f, "command"),
            Self::Event => write!(f, "event"),
            Self::Reply => write!(f, "reply"),
            Self::Control => write!(f, "control"),
            Self::ProtocolStep => write!(f, "protocol-step"),
            Self::CaptureSelector => write!(f, "capture-selector"),
            Self::DerivedView => write!(f, "derived-view"),
        }
    }
}

/// A registered subject entry in the [`SubjectRegistry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    /// Subject pattern for matching.
    pub pattern: SubjectPattern,
    /// Semantic family classification.
    pub family: RegistryFamily,
    /// Optional human-readable description.
    pub description: String,
}

impl RegistryEntry {
    fn validate(&self) -> Result<(), SubjectRegistryError> {
        match self.family {
            RegistryFamily::Control => {
                if !self.pattern.as_str().starts_with("$SYS.")
                    && !self.pattern.as_str().starts_with("sys.")
                {
                    return Err(SubjectRegistryError::InvalidEntry {
                        pattern: self.pattern.as_str().to_owned(),
                        family: self.family,
                        message: "control subjects must live under `$SYS.` or `sys.`".to_owned(),
                    });
                }
            }
            RegistryFamily::CaptureSelector => {
                if !self.pattern.has_wildcards() {
                    return Err(SubjectRegistryError::InvalidEntry {
                        pattern: self.pattern.as_str().to_owned(),
                        family: self.family,
                        message: "capture-selector subjects must include `*` or `>`".to_owned(),
                    });
                }
            }
            RegistryFamily::Command
            | RegistryFamily::Event
            | RegistryFamily::Reply
            | RegistryFamily::ProtocolStep
            | RegistryFamily::DerivedView => {}
        }

        Ok(())
    }
}

/// Errors from the subject registry.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SubjectRegistryError {
    /// The entry violates family-specific subject rules.
    #[error("subject pattern `{pattern}` is invalid for family `{family}`: {message}")]
    InvalidEntry {
        /// The rejected subject pattern.
        pattern: String,
        /// The subject family that rejected the pattern.
        family: RegistryFamily,
        /// Human-readable validation failure.
        message: String,
    },
    /// A schema with a conflicting (overlapping) pattern is already registered.
    #[error("subject pattern `{pattern}` conflicts with existing registration `{existing}`")]
    ConflictingPattern {
        /// The pattern being registered.
        pattern: String,
        /// The existing pattern that conflicts.
        existing: String,
    },
    /// The pattern was not found in the registry.
    #[error("subject pattern `{pattern}` is not registered")]
    NotFound {
        /// The pattern that was not found.
        pattern: String,
    },
}

/// Thread-safe registry of subject entries indexed by pattern.
///
/// The registry validates family-specific pattern rules and rejects only
/// ambiguous overlaps on registration. Broader wildcard entries may coexist
/// with more-specific entries, and lookup resolves those by specificity.
/// Thread-safety follows the same `RwLock` pattern as [`Sublist`].
pub struct SubjectRegistry {
    entries: RwLock<BTreeMap<String, RegistryEntry>>,
}

impl Default for SubjectRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SubjectRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
        }
    }

    /// Register a subject entry. Returns an error if the pattern overlaps
    /// ambiguously with an already-registered entry or violates family rules.
    pub fn register(&self, entry: RegistryEntry) -> Result<(), SubjectRegistryError> {
        let mut entries = self.entries.write();
        let key = entry.pattern.as_str().to_owned();
        entry.validate()?;

        for (existing_key, existing) in entries.iter() {
            if registry_patterns_conflict(&entry, existing) {
                return Err(SubjectRegistryError::ConflictingPattern {
                    pattern: key,
                    existing: existing_key.clone(),
                });
            }
        }

        entries.insert(key, entry);
        Ok(())
    }

    /// Remove an entry by its exact pattern string.
    pub fn deregister(&self, pattern: &str) -> Result<RegistryEntry, SubjectRegistryError> {
        let mut entries = self.entries.write();
        entries
            .remove(pattern)
            .ok_or_else(|| SubjectRegistryError::NotFound {
                pattern: pattern.to_owned(),
            })
    }

    /// Look up the most specific matching entry for a concrete subject.
    ///
    /// "Most specific" is the entry whose pattern has the most literal
    /// segments. When specificity ties, the pattern string breaks the tie so
    /// lookup stays deterministic even if registration rules are widened later.
    #[must_use]
    pub fn lookup(&self, subject: &Subject) -> Option<RegistryEntry> {
        let entries = self.entries.read();
        entries
            .values()
            .filter(|entry| entry.pattern.matches(subject))
            .max_by(|left, right| {
                specificity_score(&left.pattern)
                    .cmp(&specificity_score(&right.pattern))
                    .then_with(|| right.pattern.as_str().cmp(left.pattern.as_str()))
            })
            .cloned()
    }

    /// List all entries belonging to a specific family.
    #[must_use]
    pub fn list_by_family(&self, family: RegistryFamily) -> Vec<RegistryEntry> {
        let entries = self.entries.read();
        entries
            .values()
            .filter(|entry| entry.family == family)
            .cloned()
            .collect()
    }

    /// Return the count of registered entries.
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.read().len()
    }
}

impl fmt::Debug for SubjectRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubjectRegistry")
            .field("count", &self.count())
            .finish()
    }
}

/// Score a pattern by specificity: more literal segments = higher score.
fn specificity_score(pattern: &SubjectPattern) -> (usize, usize) {
    let literals = pattern
        .segments()
        .iter()
        .filter(|s| matches!(s, SubjectToken::Literal(_)))
        .count();
    let total = pattern.segments().len();
    (literals, total)
}

fn registry_patterns_conflict(left: &RegistryEntry, right: &RegistryEntry) -> bool {
    left.pattern.overlaps(&right.pattern)
        && specificity_score(&left.pattern) == specificity_score(&right.pattern)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lit(value: &str) -> SubjectToken {
        SubjectToken::Literal(value.to_owned())
    }

    #[test]
    fn parses_valid_subject_patterns() {
        for raw in ["foo.bar.baz", "tenant.orders.*", "sys.>"] {
            let pattern = SubjectPattern::parse(raw).expect("pattern should parse");
            assert_eq!(pattern.as_str(), raw);
        }
    }

    #[test]
    fn rejects_invalid_subject_patterns() {
        assert_eq!(
            SubjectPattern::parse(""),
            Err(SubjectPatternError::EmptyPattern)
        );
        assert_eq!(
            SubjectPattern::parse("foo..bar"),
            Err(SubjectPatternError::EmptySegment)
        );
        assert_eq!(
            SubjectPattern::parse("sys.>.health"),
            Err(SubjectPatternError::TailWildcardMustBeTerminal)
        );
    }

    #[test]
    fn subject_matching_respects_literal_and_wildcard_tokens() {
        let literal = SubjectPattern::parse("tenant.orders.eu").expect("literal pattern");
        let single = SubjectPattern::parse("tenant.orders.*").expect("single wildcard");
        let tail = SubjectPattern::parse("tenant.orders.>").expect("tail wildcard");
        let subject = Subject::parse("tenant.orders.eu").expect("subject");

        assert!(literal.matches(&subject));
        assert!(single.matches(&subject));
        assert!(tail.matches(&subject));
        assert!(
            !SubjectPattern::parse("tenant.payments.*")
                .expect("payments wildcard")
                .matches(&subject)
        );
    }

    #[test]
    fn round_trips_patterns_through_string_and_serde() {
        let pattern = SubjectPattern::parse("tenant.orders.*").expect("pattern");
        let json = serde_json::to_string(&pattern).expect("serialize");
        let decoded: SubjectPattern = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded, pattern);
        assert_eq!(decoded.as_str(), "tenant.orders.*");
    }

    #[test]
    fn trims_outer_whitespace_but_preserves_literal_case() {
        let pattern = SubjectPattern::parse("  $SYS.Health.*  ").expect("pattern");
        let subject = Subject::parse("  Tenant.Orders.EU.123  ").expect("subject");

        assert_eq!(pattern.as_str(), "$SYS.Health.*");
        assert_eq!(subject.as_str(), "Tenant.Orders.EU.123");
    }

    #[test]
    fn subject_rejects_wildcards() {
        assert_eq!(
            Subject::parse("tenant.orders.*"),
            Err(SubjectPatternError::WildcardsNotAllowed(
                "tenant.orders.*".to_owned()
            ))
        );
    }

    #[test]
    fn tail_wildcard_requires_at_least_one_suffix_segment() {
        let wildcard = SubjectPattern::parse("orders.>").expect("wildcard");
        let expanded = Subject::parse("orders.created").expect("expanded");
        let bare_prefix = Subject::parse("orders").expect("bare prefix");

        assert!(wildcard.matches(&expanded));
        assert!(!wildcard.matches(&bare_prefix));
    }

    #[test]
    fn subject_pattern_parsing_matrix_covers_common_and_edge_shapes() {
        let valid_cases = [
            ("tenant", vec![lit("tenant")]),
            ("tenant.orders", vec![lit("tenant"), lit("orders")]),
            (
                "tenant.orders.*",
                vec![lit("tenant"), lit("orders"), SubjectToken::One],
            ),
            (
                "tenant.orders.>",
                vec![lit("tenant"), lit("orders"), SubjectToken::Tail],
            ),
            (
                "$SYS.health.*",
                vec![lit("$SYS"), lit("health"), SubjectToken::One],
            ),
            (
                "sys.audit.>",
                vec![lit("sys"), lit("audit"), SubjectToken::Tail],
            ),
            (
                "tenant.orders.eu.west.1",
                vec![
                    lit("tenant"),
                    lit("orders"),
                    lit("eu"),
                    lit("west"),
                    lit("1"),
                ],
            ),
            ("_INBOX.reply", vec![lit("_INBOX"), lit("reply")]),
            ("Tenant.Orders", vec![lit("Tenant"), lit("Orders")]),
            (
                "  tenant.trimmed.*  ",
                vec![lit("tenant"), lit("trimmed"), SubjectToken::One],
            ),
        ];

        for (raw, expected_segments) in valid_cases {
            let pattern = SubjectPattern::parse(raw).expect("valid pattern should parse");
            assert_eq!(
                pattern.segments(),
                expected_segments.as_slice(),
                "segments mismatch for {raw}"
            );
        }

        let invalid_cases = [
            ("", SubjectPatternError::EmptyPattern),
            ("   ", SubjectPatternError::EmptyPattern),
            (".tenant", SubjectPatternError::EmptySegment),
            ("tenant.", SubjectPatternError::EmptySegment),
            ("tenant..orders", SubjectPatternError::EmptySegment),
            (
                "tenant.order status",
                SubjectPatternError::WhitespaceInSegment("order status".to_owned()),
            ),
            (
                "tenant.>.orders",
                SubjectPatternError::TailWildcardMustBeTerminal,
            ),
            ("tenant.>.>", SubjectPatternError::MultipleTailWildcards),
            (
                "tenant.or*ders",
                SubjectPatternError::EmbeddedWildcard("or*ders".to_owned()),
            ),
            (
                "tenant.or>ders",
                SubjectPatternError::EmbeddedWildcard("or>ders".to_owned()),
            ),
        ];

        for (raw, expected_error) in invalid_cases {
            assert_eq!(
                SubjectPattern::parse(raw),
                Err(expected_error),
                "unexpected parse result for {raw}"
            );
        }
    }

    #[test]
    fn overlap_matrix_covers_literal_single_and_tail_wildcards() {
        let cases = [
            ("tenant.orders.*", "tenant.orders.eu", true),
            ("tenant.orders.*", "tenant.orders.*", true),
            ("tenant.orders.*", "tenant.payments.*", false),
            ("tenant.orders.>", "tenant.orders.*.*", true),
            ("tenant.orders.>", "tenant.payments.>", false),
            ("tenant.*.created", "tenant.orders.*", true),
            ("tenant.*.created", "tenant.orders.cancelled", false),
            ("tenant.orders.*", "tenant.orders.*.*", false),
        ];

        for (left, right, expected) in cases {
            let left = SubjectPattern::parse(left).expect("left pattern");
            let right = SubjectPattern::parse(right).expect("right pattern");
            assert_eq!(
                left.overlaps(&right),
                expected,
                "unexpected overlap result for {} vs {}",
                left,
                right
            );
            assert_eq!(
                right.overlaps(&left),
                expected,
                "unexpected symmetric overlap result for {} vs {}",
                right,
                left
            );
        }
    }

    #[test]
    fn pattern_from_tokens_and_subject_conversion_preserve_canonical_literals() {
        let pattern =
            SubjectPattern::from_tokens(vec![lit("tenant"), SubjectToken::One, lit("reply")])
                .expect("pattern from tokens");
        assert_eq!(pattern.as_str(), "tenant.*.reply");
        assert!(pattern.has_wildcards());
        assert!(!pattern.is_full_wildcard());

        let invalid =
            SubjectPattern::from_tokens(vec![lit("tenant"), SubjectToken::Tail, lit("reply")]);
        assert_eq!(
            invalid,
            Err(SubjectPatternError::TailWildcardMustBeTerminal)
        );

        let subject = Subject::parse("tenant.orders.reply").expect("concrete subject");
        let subject_pattern = SubjectPattern::from(&subject);
        assert_eq!(subject_pattern.as_str(), "tenant.orders.reply");
        assert_eq!(
            subject_pattern.segments(),
            &[lit("tenant"), lit("orders"), lit("reply")]
        );
        assert!(!subject_pattern.has_wildcards());
    }

    // -----------------------------------------------------------------------
    // Sublist routing engine tests
    // -----------------------------------------------------------------------

    fn sublist() -> Arc<Sublist> {
        Arc::new(Sublist::new())
    }

    #[test]
    fn sublist_literal_exact_match() {
        let sl = sublist();
        let pattern = SubjectPattern::new("foo.bar.baz");
        let _guard = sl.subscribe(&pattern, None);

        let hit = Subject::new("foo.bar.baz");
        let miss = Subject::new("foo.bar.qux");

        assert_eq!(sl.lookup(&hit).total(), 1);
        assert_eq!(sl.lookup(&miss).total(), 0);
    }

    #[test]
    fn sublist_single_wildcard_matches_one_token() {
        let sl = sublist();
        let pattern = SubjectPattern::new("foo.*");
        let _guard = sl.subscribe(&pattern, None);

        assert_eq!(sl.lookup(&Subject::new("foo.bar")).total(), 1);
        assert_eq!(sl.lookup(&Subject::new("foo.baz")).total(), 1);
        assert_eq!(sl.lookup(&Subject::new("foo.bar.baz")).total(), 0);
        assert_eq!(sl.lookup(&Subject::new("qux.bar")).total(), 0);
    }

    #[test]
    fn sublist_tail_wildcard_matches_one_or_more_tokens() {
        let sl = sublist();
        let pattern = SubjectPattern::new("foo.>");
        let _guard = sl.subscribe(&pattern, None);

        assert_eq!(sl.lookup(&Subject::new("foo.bar")).total(), 1);
        assert_eq!(sl.lookup(&Subject::new("foo.bar.baz")).total(), 1);
        assert_eq!(sl.lookup(&Subject::new("foo.bar.baz.qux")).total(), 1);
        // Tail wildcard requires at least one suffix token.
        assert_eq!(sl.lookup(&Subject::new("foo")).total(), 0);
    }

    #[test]
    fn sublist_combined_wildcards() {
        let sl = sublist();
        let p1 = SubjectPattern::new("foo.*.>");
        let _g1 = sl.subscribe(&p1, None);

        assert_eq!(sl.lookup(&Subject::new("foo.bar.baz")).total(), 1);
        assert_eq!(sl.lookup(&Subject::new("foo.qux.a.b.c")).total(), 1);
        assert_eq!(sl.lookup(&Subject::new("foo.bar")).total(), 0);
    }

    #[test]
    fn sublist_multiple_subscribers_same_pattern() {
        let sl = sublist();
        let pattern = SubjectPattern::new("orders.created");
        let _g1 = sl.subscribe(&pattern, None);
        let _g2 = sl.subscribe(&pattern, None);

        assert_eq!(
            sl.lookup(&Subject::new("orders.created")).subscribers.len(),
            2
        );
        assert_eq!(sl.count(), 2);
    }

    #[test]
    fn sublist_multiple_patterns_same_subject() {
        let sl = sublist();
        let _g1 = sl.subscribe(&SubjectPattern::new("orders.created"), None);
        let _g2 = sl.subscribe(&SubjectPattern::new("orders.*"), None);
        let _g3 = sl.subscribe(&SubjectPattern::new("orders.>"), None);

        let result = sl.lookup(&Subject::new("orders.created"));
        assert_eq!(result.subscribers.len(), 3);
    }

    #[test]
    fn sublist_drop_guard_removes_subscription() {
        let sl = sublist();
        let pattern = SubjectPattern::new("orders.created");
        let guard = sl.subscribe(&pattern, None);
        assert_eq!(sl.count(), 1);

        drop(guard);
        assert_eq!(sl.count(), 0);
        assert_eq!(sl.lookup(&Subject::new("orders.created")).total(), 0);
    }

    #[test]
    fn sublist_cancel_correctness_no_ghost_interest() {
        let sl = sublist();
        let pattern = SubjectPattern::new("events.>");
        let guard = sl.subscribe(&pattern, None);
        let id = guard.id();

        // Subscriber exists.
        let result = sl.lookup(&Subject::new("events.user.created"));
        assert!(result.subscribers.contains(&id));

        // Drop the guard (simulating cancel/scope exit).
        drop(guard);

        // Subscriber is gone — no ghost interest.
        let result = sl.lookup(&Subject::new("events.user.created"));
        assert!(!result.subscribers.contains(&id));
        assert_eq!(result.total(), 0);
    }

    #[test]
    fn sublist_queue_group_single_delivery() {
        let sl = sublist();
        let pattern = SubjectPattern::new("work.items");
        let _g1 = sl.subscribe(&pattern, Some("workers".to_owned()));
        let _g2 = sl.subscribe(&pattern, Some("workers".to_owned()));
        let _g3 = sl.subscribe(&pattern, Some("workers".to_owned()));

        let result = sl.lookup(&Subject::new("work.items"));
        // No non-queue subscribers.
        assert_eq!(result.subscribers.len(), 0);
        // Exactly one pick for the "workers" group.
        assert_eq!(result.queue_group_picks.len(), 1);
        assert_eq!(result.queue_group_picks[0].0, "workers");
    }

    #[test]
    fn sublist_queue_group_round_robin() {
        let sl = sublist();
        let pattern = SubjectPattern::new("work.items");
        let g1 = sl.subscribe(&pattern, Some("workers".to_owned()));
        let g2 = sl.subscribe(&pattern, Some("workers".to_owned()));

        let subject = Subject::new("work.items");
        let pick1 = sl.lookup(&subject).queue_group_picks[0].1;
        let pick2 = sl.lookup(&subject).queue_group_picks[0].1;

        // Round-robin should alternate between the two subscribers.
        assert_ne!(pick1, pick2);
        assert!(pick1 == g1.id() || pick1 == g2.id());
        assert!(pick2 == g1.id() || pick2 == g2.id());
    }

    #[test]
    fn sublist_multiple_queue_groups() {
        let sl = sublist();
        let pattern = SubjectPattern::new("work.items");
        let _g1 = sl.subscribe(&pattern, Some("group-a".to_owned()));
        let _g2 = sl.subscribe(&pattern, Some("group-a".to_owned()));
        let _g3 = sl.subscribe(&pattern, Some("group-b".to_owned()));
        let _g4 = sl.subscribe(&pattern, None); // Non-queue subscriber.

        let result = sl.lookup(&Subject::new("work.items"));
        assert_eq!(result.subscribers.len(), 1); // Non-queue subscriber.
        assert_eq!(result.queue_group_picks.len(), 2); // One per group.
    }

    #[test]
    fn sublist_queue_group_removal() {
        let sl = sublist();
        let pattern = SubjectPattern::new("work.items");
        let g1 = sl.subscribe(&pattern, Some("workers".to_owned()));
        let g2 = sl.subscribe(&pattern, Some("workers".to_owned()));

        drop(g1);
        let result = sl.lookup(&Subject::new("work.items"));
        assert_eq!(result.queue_group_picks.len(), 1);
        assert_eq!(result.queue_group_picks[0].1, g2.id());
    }

    #[test]
    fn sublist_cache_hit_returns_same_result() {
        let sl = sublist();
        let _guard = sl.subscribe(&SubjectPattern::new("foo.bar"), None);

        let subject = Subject::new("foo.bar");
        let r1 = sl.lookup(&subject);
        let r2 = sl.lookup(&subject);

        assert_eq!(r1.subscribers, r2.subscribers);
    }

    #[test]
    fn sublist_link_cache_hit_returns_same_result() {
        let sl = sublist();
        let _guard = sl.subscribe(&SubjectPattern::new("foo.bar"), None);
        let subject = Subject::new("foo.bar");
        let mut link_cache = SublistLinkCache::new(4);

        let r1 = sl.lookup_with_link_cache(&subject, &mut link_cache);
        let r2 = sl.lookup_with_link_cache(&subject, &mut link_cache);

        assert_eq!(link_cache.len(), 1);
        assert_eq!(r1.subscribers, r2.subscribers);
    }

    #[test]
    fn sublist_cache_invalidated_on_mutation() {
        let sl = sublist();
        let pattern = SubjectPattern::new("foo.bar");
        let _g1 = sl.subscribe(&pattern, None);

        let subject = Subject::new("foo.bar");
        let gen_before = sl.generation();
        let _g2 = sl.subscribe(&pattern, None);
        let gen_after = sl.generation();

        assert!(gen_after > gen_before);
        // After mutation, lookup should reflect the new state.
        assert_eq!(sl.lookup(&subject).subscribers.len(), 2);
    }

    #[test]
    fn sublist_link_cache_invalidated_on_mutation() {
        let sl = sublist();
        let pattern = SubjectPattern::new("foo.bar");
        let _g1 = sl.subscribe(&pattern, None);
        let subject = Subject::new("foo.bar");
        let mut link_cache = SublistLinkCache::new(4);

        assert_eq!(
            sl.lookup_with_link_cache(&subject, &mut link_cache)
                .subscribers
                .len(),
            1
        );

        let _g2 = sl.subscribe(&pattern, None);
        assert_eq!(
            sl.lookup_with_link_cache(&subject, &mut link_cache)
                .subscribers
                .len(),
            2
        );
    }

    #[test]
    fn sublist_link_cache_evicts_oldest_subject() {
        let sl = sublist();
        let _ga = sl.subscribe(&SubjectPattern::new("foo.a"), None);
        let _gb = sl.subscribe(&SubjectPattern::new("foo.b"), None);
        let _gc = sl.subscribe(&SubjectPattern::new("foo.c"), None);
        let mut link_cache = SublistLinkCache::new(2);

        let _ = sl.lookup_with_link_cache(&Subject::new("foo.a"), &mut link_cache);
        let _ = sl.lookup_with_link_cache(&Subject::new("foo.b"), &mut link_cache);
        assert!(link_cache.entries.contains_key("foo.a"));
        assert!(link_cache.entries.contains_key("foo.b"));

        let _ = sl.lookup_with_link_cache(&Subject::new("foo.c"), &mut link_cache);

        assert_eq!(link_cache.len(), 2);
        assert!(!link_cache.entries.contains_key("foo.a"));
        assert!(link_cache.entries.contains_key("foo.b"));
        assert!(link_cache.entries.contains_key("foo.c"));
    }

    #[test]
    fn sublist_link_cache_keeps_queue_round_robin_live() {
        let sl = sublist();
        let pattern = SubjectPattern::new("work.items");
        let g1 = sl.subscribe(&pattern, Some("workers".to_owned()));
        let g2 = sl.subscribe(&pattern, Some("workers".to_owned()));
        let mut link_cache = SublistLinkCache::new(4);
        let subject = Subject::new("work.items");

        let pick1 = sl
            .lookup_with_link_cache(&subject, &mut link_cache)
            .queue_group_picks[0]
            .1;
        let pick2 = sl
            .lookup_with_link_cache(&subject, &mut link_cache)
            .queue_group_picks[0]
            .1;

        assert_ne!(pick1, pick2);
        assert!(pick1 == g1.id() || pick1 == g2.id());
        assert!(pick2 == g1.id() || pick2 == g2.id());
    }

    #[test]
    fn sublist_generation_bumps_on_subscribe_and_unsubscribe() {
        let sl = sublist();
        let gen0 = sl.generation();

        let guard = sl.subscribe(&SubjectPattern::new("test"), None);
        let gen1 = sl.generation();
        assert!(gen1 > gen0);

        drop(guard);
        let gen2 = sl.generation();
        assert!(gen2 > gen1);
    }

    #[test]
    fn sublist_empty_lookup_returns_empty_result() {
        let sl = sublist();
        let result = sl.lookup(&Subject::new("nonexistent.subject"));
        assert_eq!(result.total(), 0);
    }

    #[test]
    fn sublist_single_token_subject() {
        let sl = sublist();
        let _guard = sl.subscribe(&SubjectPattern::new("orders"), None);

        assert_eq!(sl.lookup(&Subject::new("orders")).total(), 1);
        assert_eq!(sl.lookup(&Subject::new("payments")).total(), 0);
    }

    #[test]
    fn sublist_deep_nesting() {
        let sl = sublist();
        let deep = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t";
        let _guard = sl.subscribe(&SubjectPattern::new(deep), None);
        assert_eq!(sl.lookup(&Subject::new(deep)).total(), 1);
    }

    #[test]
    fn sublist_wildcard_at_various_positions() {
        let sl = sublist();
        let _g1 = sl.subscribe(&SubjectPattern::new("*.bar.baz"), None);
        let _g2 = sl.subscribe(&SubjectPattern::new("foo.*.baz"), None);
        let _g3 = sl.subscribe(&SubjectPattern::new("foo.bar.*"), None);

        let subject = Subject::new("foo.bar.baz");
        assert_eq!(sl.lookup(&subject).subscribers.len(), 3);
    }

    #[test]
    fn sublist_multiple_wildcards_in_pattern() {
        let sl = sublist();
        let _guard = sl.subscribe(&SubjectPattern::new("*.*.*"), None);

        assert_eq!(sl.lookup(&Subject::new("a.b.c")).total(), 1);
        assert_eq!(sl.lookup(&Subject::new("a.b")).total(), 0);
        assert_eq!(sl.lookup(&Subject::new("a.b.c.d")).total(), 0);
    }

    #[test]
    fn sublist_tail_wildcard_alone() {
        let sl = sublist();
        // ">" alone is not valid — needs at least one prefix segment.
        // But "foo.>" is valid: matches foo.anything.
        let _guard = sl.subscribe(&SubjectPattern::new("tenant.>"), None);

        assert_eq!(sl.lookup(&Subject::new("tenant.a")).total(), 1);
        assert_eq!(sl.lookup(&Subject::new("tenant.a.b")).total(), 1);
        assert_eq!(sl.lookup(&Subject::new("other.a")).total(), 0);
    }

    #[test]
    fn sublist_concurrent_read_access() {
        use std::thread;

        let sl = sublist();
        let _g1 = sl.subscribe(&SubjectPattern::new("orders.*"), None);
        let _g2 = sl.subscribe(&SubjectPattern::new("orders.>"), None);

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let sl_clone = Arc::clone(&sl);
                thread::spawn(move || {
                    for _ in 0..100 {
                        let result = sl_clone.lookup(&Subject::new("orders.created"));
                        assert!(result.total() >= 2);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }
    }

    #[test]
    fn sublist_concurrent_subscribe_unsubscribe_lookup() {
        use std::thread;

        let sl = sublist();
        let barrier = Arc::new(std::sync::Barrier::new(3));

        let sl1 = Arc::clone(&sl);
        let b1 = Arc::clone(&barrier);
        let writer1 = thread::spawn(move || {
            b1.wait();
            for _ in 0..50 {
                let guard = sl1.subscribe(&SubjectPattern::new("test.subject"), None);
                let _ = sl1.lookup(&Subject::new("test.subject"));
                drop(guard);
            }
        });

        let sl2 = Arc::clone(&sl);
        let b2 = Arc::clone(&barrier);
        let writer2 = thread::spawn(move || {
            b2.wait();
            for _ in 0..50 {
                let guard = sl2.subscribe(&SubjectPattern::new("test.*"), None);
                let _ = sl2.lookup(&Subject::new("test.subject"));
                drop(guard);
            }
        });

        let sl3 = Arc::clone(&sl);
        let b3 = Arc::clone(&barrier);
        let reader = thread::spawn(move || {
            b3.wait();
            for _ in 0..200 {
                let _ = sl3.lookup(&Subject::new("test.subject"));
            }
        });

        writer1.join().expect("writer1");
        writer2.join().expect("writer2");
        reader.join().expect("reader");

        // After all threads complete, no subscriptions should remain.
        assert_eq!(sl.count(), 0);
    }

    #[test]
    fn sublist_subscription_guard_id_is_unique() {
        let sl = sublist();
        let g1 = sl.subscribe(&SubjectPattern::new("a"), None);
        let g2 = sl.subscribe(&SubjectPattern::new("b"), None);
        let g3 = sl.subscribe(&SubjectPattern::new("c"), None);

        assert_ne!(g1.id(), g2.id());
        assert_ne!(g2.id(), g3.id());
        assert_ne!(g1.id(), g3.id());
    }

    #[test]
    fn sublist_count_tracks_subscribe_and_unsubscribe() {
        let sl = sublist();
        assert_eq!(sl.count(), 0);

        let g1 = sl.subscribe(&SubjectPattern::new("a"), None);
        assert_eq!(sl.count(), 1);

        let g2 = sl.subscribe(&SubjectPattern::new("b"), None);
        assert_eq!(sl.count(), 2);

        drop(g1);
        assert_eq!(sl.count(), 1);

        drop(g2);
        assert_eq!(sl.count(), 0);
    }

    fn sharded_sublist() -> ShardedSublist {
        ShardedSublist::with_prefix_depth(8, 1)
    }

    fn distinct_sharded_subjects(index: &ShardedSublist) -> (Subject, Subject) {
        let first = Subject::new("alpha.events");
        let first_shard = index.shard_index_for_subject(&first);

        for candidate in [
            "beta.events",
            "gamma.events",
            "delta.events",
            "epsilon.events",
            "zeta.events",
            "eta.events",
        ] {
            let subject = Subject::new(candidate);
            if index.shard_index_for_subject(&subject) != first_shard {
                return (first, subject);
            }
        }

        panic!("expected at least two subjects to map to distinct shards");
    }

    #[test]
    fn sharded_sublist_assigns_literal_prefixes_deterministically() {
        let index = sharded_sublist();
        let pattern = SubjectPattern::new("tenant.orders.created");

        let shard1 = index
            .shard_index_for_pattern(&pattern)
            .expect("literal prefix should map to a concrete shard");
        let shard2 = index
            .shard_index_for_pattern(&pattern)
            .expect("literal prefix should map deterministically");

        assert_eq!(shard1, shard2);
        assert_eq!(
            index.shard_index_for_subject(&Subject::new("tenant.orders.created")),
            shard1
        );
        assert!(
            index
                .shard_index_for_pattern(&SubjectPattern::new("*.orders"))
                .is_none()
        );
    }

    #[test]
    fn sharded_sublist_uses_fallback_for_wildcard_prefixes() {
        let index = sharded_sublist();
        let pattern = SubjectPattern::new("*.orders");

        let generation_before = index.fallback_generation();
        let guard = index.subscribe(&pattern, None);
        let generation_after = index.fallback_generation();

        assert!(guard.shard_index().is_none());
        assert!(generation_after > generation_before);
        assert_eq!(index.lookup(&Subject::new("tenant.orders")).total(), 1);
    }

    #[test]
    fn sharded_sublist_mutation_bumps_only_target_shard() {
        let index = sharded_sublist();
        let (subject_a, subject_b) = distinct_sharded_subjects(&index);
        let pattern_a = SubjectPattern::from(&subject_a);
        let pattern_b = SubjectPattern::from(&subject_b);
        let shard_a = index
            .shard_index_for_pattern(&pattern_a)
            .expect("literal pattern should map to a shard");
        let shard_b = index
            .shard_index_for_pattern(&pattern_b)
            .expect("literal pattern should map to a shard");
        assert_ne!(shard_a, shard_b);

        let before_a = index.shard_generation(shard_a).expect("shard exists");
        let before_b = index.shard_generation(shard_b).expect("shard exists");
        let _guard_a = index.subscribe(&pattern_a, None);
        let after_a = index.shard_generation(shard_a).expect("shard exists");
        let after_b = index.shard_generation(shard_b).expect("shard exists");

        assert!(after_a > before_a);
        assert_eq!(after_b, before_b);
    }

    #[test]
    fn sharded_sublist_cross_shard_cache_isolation_preserves_hot_shard() {
        let index = sharded_sublist();
        let (subject_a, subject_b) = distinct_sharded_subjects(&index);
        let pattern_a = SubjectPattern::from(&subject_a);
        let pattern_b = SubjectPattern::from(&subject_b);
        let shard_a = index.shard_index_for_subject(&subject_a);
        let shard_b = index.shard_index_for_subject(&subject_b);
        assert_ne!(shard_a, shard_b);

        let _guard_a = index.subscribe(&pattern_a, None);
        let initial = index.lookup(&subject_a);
        assert_eq!(initial.total(), 1);

        let generation_a_before = index.shard_generation(shard_a).expect("shard exists");
        let _guard_b = index.subscribe(&pattern_b, None);
        let generation_a_after = index.shard_generation(shard_a).expect("shard exists");

        assert_eq!(generation_a_after, generation_a_before);
        assert_eq!(index.lookup(&subject_a).total(), 1);
    }

    #[test]
    fn sharded_sublist_distribution_stays_within_reasonable_skew() {
        let index = sharded_sublist();
        let mut counts = vec![0usize; index.shard_count()];

        for tenant in 0..256 {
            let subject = Subject::new(format!("tenant{tenant}.events").as_str());
            let shard = index.shard_index_for_subject(&subject);
            counts[shard] += 1;
        }

        let average = 256 / index.shard_count();
        let worst = counts.into_iter().max().expect("shards exist");
        assert!(
            worst <= average * 2,
            "expected bounded shard skew, saw {worst}"
        );
    }

    // -----------------------------------------------------------------------
    // SubjectRegistry tests
    // -----------------------------------------------------------------------

    fn event_entry(pattern: &str) -> RegistryEntry {
        RegistryEntry {
            pattern: SubjectPattern::new(pattern),
            family: RegistryFamily::Event,
            description: String::new(),
        }
    }

    fn command_entry(pattern: &str) -> RegistryEntry {
        RegistryEntry {
            pattern: SubjectPattern::new(pattern),
            family: RegistryFamily::Command,
            description: String::new(),
        }
    }

    fn control_entry(pattern: &str) -> RegistryEntry {
        RegistryEntry {
            pattern: SubjectPattern::new(pattern),
            family: RegistryFamily::Control,
            description: String::new(),
        }
    }

    fn capture_entry(pattern: &str) -> RegistryEntry {
        RegistryEntry {
            pattern: SubjectPattern::new(pattern),
            family: RegistryFamily::CaptureSelector,
            description: String::new(),
        }
    }

    #[test]
    fn registry_register_and_lookup() {
        let reg = SubjectRegistry::new();
        reg.register(event_entry("orders.created"))
            .expect("register");

        let result = reg.lookup(&Subject::new("orders.created"));
        assert!(result.is_some());
        assert_eq!(result.unwrap().family, RegistryFamily::Event);
    }

    #[test]
    fn registry_lookup_returns_none_for_unmatched() {
        let reg = SubjectRegistry::new();
        reg.register(event_entry("orders.created"))
            .expect("register");

        assert!(reg.lookup(&Subject::new("payments.created")).is_none());
    }

    #[test]
    fn registry_rejects_ambiguous_overlapping_patterns() {
        let reg = SubjectRegistry::new();
        reg.register(event_entry("events.*.created"))
            .expect("register first pattern");

        let err = reg
            .register(event_entry("events.user.*"))
            .expect_err("ambiguous overlap should be rejected");

        assert!(matches!(
            err,
            SubjectRegistryError::ConflictingPattern { .. }
        ));
    }

    #[test]
    fn registry_allows_non_overlapping_patterns() {
        let reg = SubjectRegistry::new();
        reg.register(event_entry("orders.created"))
            .expect("register orders");
        reg.register(event_entry("payments.created"))
            .expect("register payments");

        assert_eq!(reg.count(), 2);
    }

    #[test]
    fn registry_deregister_removes_entry() {
        let reg = SubjectRegistry::new();
        reg.register(event_entry("orders.created"))
            .expect("register");

        let removed = reg.deregister("orders.created").expect("deregister");
        assert_eq!(removed.family, RegistryFamily::Event);
        assert_eq!(reg.count(), 0);
        assert!(reg.lookup(&Subject::new("orders.created")).is_none());
    }

    #[test]
    fn registry_deregister_not_found() {
        let reg = SubjectRegistry::new();
        let err = reg.deregister("nonexistent").expect_err("should not find");
        assert!(matches!(err, SubjectRegistryError::NotFound { .. }));
    }

    #[test]
    fn registry_list_by_family() {
        let reg = SubjectRegistry::new();
        reg.register(event_entry("events.user.created"))
            .expect("event1");
        reg.register(event_entry("events.user.deleted"))
            .expect("event2");
        reg.register(command_entry("commands.user.create"))
            .expect("command1");
        reg.register(control_entry("$SYS.health.ping"))
            .expect("control1");

        let events = reg.list_by_family(RegistryFamily::Event);
        assert_eq!(events.len(), 2);

        let commands = reg.list_by_family(RegistryFamily::Command);
        assert_eq!(commands.len(), 1);

        let controls = reg.list_by_family(RegistryFamily::Control);
        assert_eq!(controls.len(), 1);

        let replies = reg.list_by_family(RegistryFamily::Reply);
        assert_eq!(replies.len(), 0);
    }

    #[test]
    fn registry_lookup_returns_most_specific_match() {
        let reg = SubjectRegistry::new();
        reg.register(event_entry("events.>"))
            .expect("broad wildcard should register");
        reg.register(event_entry("events.user.created"))
            .expect("specific");

        let result = reg
            .lookup(&Subject::new("events.user.created"))
            .expect("found");
        assert_eq!(result.pattern.as_str(), "events.user.created");
    }

    #[test]
    fn registry_rejects_control_entries_outside_system_namespace() {
        let reg = SubjectRegistry::new();
        let err = reg
            .register(control_entry("events.user.created"))
            .expect_err("control entry outside sys namespace should fail");

        assert!(matches!(err, SubjectRegistryError::InvalidEntry { .. }));
    }

    #[test]
    fn registry_rejects_capture_selectors_without_wildcards() {
        let reg = SubjectRegistry::new();
        let err = reg
            .register(capture_entry("events.user.created"))
            .expect_err("capture selector must include a wildcard");

        assert!(matches!(err, SubjectRegistryError::InvalidEntry { .. }));
    }

    #[test]
    fn registry_accepts_capture_selectors_with_wildcards() {
        let reg = SubjectRegistry::new();
        reg.register(capture_entry("events.user.*"))
            .expect("capture selector with wildcard should register");

        let result = reg
            .lookup(&Subject::new("events.user.created"))
            .expect("capture selector should match");
        assert_eq!(result.family, RegistryFamily::CaptureSelector);
    }

    #[test]
    fn registry_wildcard_lookup_matches() {
        let reg = SubjectRegistry::new();
        reg.register(event_entry("events.>")).expect("wildcard");

        let result = reg
            .lookup(&Subject::new("events.user.created"))
            .expect("found");
        assert_eq!(result.pattern.as_str(), "events.>");
        assert_eq!(result.family, RegistryFamily::Event);
    }

    #[test]
    fn registry_deregister_then_reregister() {
        let reg = SubjectRegistry::new();
        reg.register(event_entry("orders.created"))
            .expect("register");
        reg.deregister("orders.created").expect("deregister");

        // After deregistration, can re-register the same pattern.
        reg.register(command_entry("orders.created"))
            .expect("re-register as command");

        let result = reg.lookup(&Subject::new("orders.created")).expect("found");
        assert_eq!(result.family, RegistryFamily::Command);
    }

    #[test]
    fn registry_concurrent_read_access() {
        use std::thread;

        let reg = Arc::new(SubjectRegistry::new());
        reg.register(event_entry("orders.created"))
            .expect("register");

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let reg_clone = Arc::clone(&reg);
                thread::spawn(move || {
                    for _ in 0..100 {
                        let result = reg_clone.lookup(&Subject::new("orders.created"));
                        assert!(result.is_some());
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("thread panicked");
        }
    }
}
