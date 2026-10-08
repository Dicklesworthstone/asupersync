//! A keyed set of streams polled as one.
//!
//! [`StreamMap`] merges streams that are added and removed by key while it is
//! being polled, and yields each item with the key of the stream it came
//! from. A server that forwards several subscriptions down one connection
//! keeps one entry per subscription: subscribe inserts, unsubscribe removes,
//! and every item arrives labelled with its subscription.

use super::Stream;
use std::borrow::Borrow;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Streams indexed by key, merged into one stream of `(key, item)` pairs.
///
/// Each poll starts at the entry after the one that last produced an item, so
/// a busy stream cannot starve the others. A stream that ends is removed.
/// When the map is empty, polling returns `Ready(None)`; streams inserted
/// afterwards are polled by later calls.
///
/// Lookups compare keys linearly: the map is meant for tens or hundreds of
/// streams, like the subscriptions of one connection.
///
/// ```
/// use asupersync::runtime::RuntimeBuilder;
/// use asupersync::stream::{StreamExt, StreamMap, iter};
///
/// let runtime = RuntimeBuilder::current_thread().build().unwrap();
/// runtime.block_on(async {
///     let mut map = StreamMap::new();
///     map.insert("odd", iter(vec![1, 3]));
///     map.insert("even", iter(vec![2, 4]));
///
///     let mut seen = Vec::new();
///     while let Some((key, value)) = map.next().await {
///         seen.push((key, value));
///     }
///     seen.sort();
///     assert_eq!(seen, [("even", 2), ("even", 4), ("odd", 1), ("odd", 3)]);
///     assert!(map.is_empty());
/// });
/// ```
#[must_use = "streams do nothing unless polled"]
pub struct StreamMap<K, V> {
    entries: Vec<(K, V)>,
    /// Where the next poll starts.
    cursor: usize,
}

impl<K, V> StreamMap<K, V> {
    /// An empty map.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            cursor: 0,
        }
    }

    /// An empty map with room for `capacity` streams.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            cursor: 0,
        }
    }

    /// Adds `stream` under `key`, returning the stream it replaces.
    pub fn insert(&mut self, key: K, stream: V) -> Option<V>
    where
        K: Eq,
    {
        if let Some((_, existing)) = self.entries.iter_mut().find(|(k, _)| *k == key) {
            return Some(std::mem::replace(existing, stream));
        }
        self.entries.push((key, stream));
        None
    }

    /// Removes and returns the stream under `key`.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let index = self.entries.iter().position(|(k, _)| k.borrow() == key)?;
        Some(self.remove_at(index).1)
    }

    /// Whether a stream is stored under `key`.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        self.entries.iter().any(|(k, _)| k.borrow() == key)
    }

    /// The stream under `key`.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        self.entries
            .iter()
            .find(|(k, _)| k.borrow() == key)
            .map(|(_, stream)| stream)
    }

    /// The stream under `key`, mutably.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        self.entries
            .iter_mut()
            .find(|(k, _)| k.borrow() == key)
            .map(|(_, stream)| stream)
    }

    /// The number of streams.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map holds no streams.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes every stream.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.cursor = 0;
    }

    /// The keys and streams, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &(K, V)> {
        self.entries.iter()
    }

    /// The keys and streams, mutably, in no particular order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut (K, V)> {
        self.entries.iter_mut()
    }

    /// The keys, in no particular order.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.entries.iter().map(|(key, _)| key)
    }

    /// The streams, in no particular order.
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, stream)| stream)
    }

    /// The streams, mutably, in no particular order.
    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.entries.iter_mut().map(|(_, stream)| stream)
    }

    fn remove_at(&mut self, index: usize) -> (K, V) {
        let removed = self.entries.swap_remove(index);
        if self.cursor >= self.entries.len() {
            self.cursor = 0;
        }
        removed
    }
}

impl<K, V> StreamMap<K, V>
where
    K: Clone,
    V: Stream + Unpin,
{
    /// Polls the streams for the next item, yielding it with its stream's key.
    pub fn poll_next_entry(&mut self, cx: &mut Context<'_>) -> Poll<Option<(K, V::Item)>> {
        let len = self.entries.len();
        let start = if len == 0 { 0 } else { self.cursor % len };
        // Ended streams are removed after the scan, so removing one cannot
        // move an unpolled entry behind the scan position.
        let mut ended = Vec::new();
        let mut produced = None;
        for offset in 0..len {
            let index = (start + offset) % len;
            let (key, stream) = &mut self.entries[index];
            match Pin::new(stream).poll_next(cx) {
                Poll::Ready(Some(item)) => {
                    produced = Some((key.clone(), item));
                    self.cursor = index + 1;
                    break;
                }
                Poll::Ready(None) => ended.push(index),
                Poll::Pending => {}
            }
        }
        // Highest index first: each `swap_remove` then moves in an entry that
        // is not itself waiting to be removed.
        ended.sort_unstable();
        for index in ended.into_iter().rev() {
            self.remove_at(index);
        }
        match produced {
            Some(entry) => Poll::Ready(Some(entry)),
            None if self.entries.is_empty() => Poll::Ready(None),
            None => Poll::Pending,
        }
    }
}

impl<K, V> Default for StreamMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> Unpin for StreamMap<K, V> {}

impl<K, V> Stream for StreamMap<K, V>
where
    K: Clone,
    V: Stream + Unpin,
{
    type Item = (K, V::Item);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().poll_next_entry(cx)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let mut upper = Some(0_usize);
        for (_, stream) in &self.entries {
            upper = upper
                .zip(stream.size_hint().1)
                .and_then(|(a, b)| a.checked_add(b));
        }
        (0, upper)
    }
}

impl<K: std::fmt::Debug, V> std::fmt::Debug for StreamMap<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamMap")
            .field("keys", &self.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl<K: Eq, V> FromIterator<(K, V)> for StreamMap<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let mut map = Self::new();
        for (key, stream) in iter {
            map.insert(key, stream);
        }
        map
    }
}

impl<K: Eq, V> Extend<(K, V)> for StreamMap<K, V> {
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        for (key, stream) in iter {
            self.insert(key, stream);
        }
    }
}
