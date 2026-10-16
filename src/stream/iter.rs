//! Convert iterators into streams.
//!
//! This module provides the [`iter`] function to convert any `IntoIterator`
//! into a `Stream`.

use super::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A stream that yields items from an iterator.
///
/// Created by the [`iter`] function.
#[derive(Debug)]
pub struct Iter<I> {
    iter: I,
}

impl<I> Iter<I> {
    /// Creates a new `Iter` stream from an iterator.
    #[inline]
    pub(crate) fn new(iter: I) -> Self {
        Self { iter }
    }
}

impl<I> Unpin for Iter<I> {}

impl<I: Iterator> Stream for Iter<I> {
    type Item = I::Item;

    #[inline]
    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.iter.next())
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

/// Convert an iterator into a stream.
///
/// The resulting stream will yield items synchronously (always returning
/// `Poll::Ready`), making it useful for testing and for converting
/// synchronous data sources.
///
/// # Examples
///
/// ```
/// use asupersync::stream::{iter, StreamExt};
///
/// let stream = iter(vec![1, 2, 3]);
/// // stream.next().await returns Some(1), Some(2), Some(3), None
/// ```
#[inline]
pub fn iter<I>(i: I) -> Iter<I::IntoIter>
where
    I: IntoIterator,
{
    Iter::new(i.into_iter())
}

#[cfg(test)]
#[path = "iter_inline_tests.rs"]
mod tests;
