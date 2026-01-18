//! Async line iterator for files.

use crate::fs::buf_reader::BufReader;
use crate::io::AsyncRead;
use crate::stream::Stream;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Iterator over the lines of an instance of `BufReader`.
#[derive(Debug)]
pub struct Lines<R> {
    pub(crate) inner: crate::io::Lines<BufReader<R>>,
}

impl<R: AsyncRead + Unpin> Stream for Lines<R> {
    type Item = io::Result<String>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}
