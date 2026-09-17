//! File publication followed by durable receipt persistence before final Proof.
use super::ledger::Claim;
use asupersync::io::AsyncWrite;
use asupersync::net::atp::sdk::native_auth::live::LiveStreamReceipt;
use asupersync::net::atp::sdk::native_auth::live::commit::LiveStreamCommitSink;
use asupersync::net::atp::sdk::native_auth::live::commit::file::LiveFileSink;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

type Persist = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
type Terminal = Result<(), (io::ErrorKind, Option<i32>)>;

/// None preserves the original file-sink behavior; Some adds the durable barrier.
pub(super) struct LedgerSink {
    file: LiveFileSink,
    claim: Option<Claim>,
    receipt: Option<LiveStreamReceipt>,
    published: bool,
    persist: Option<Persist>,
    terminal: Option<Terminal>,
}

impl LedgerSink {
    pub fn new(file: LiveFileSink, claim: Option<Claim>) -> Self {
        Self {
            file,
            claim,
            receipt: None,
            published: false,
            persist: None,
            terminal: None,
        }
    }
}

impl AsyncWrite for LedgerSink {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.file).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().file).poll_shutdown(cx)
    }
}

impl LiveStreamCommitSink for LedgerSink {
    fn poll_commit(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        receipt: &LiveStreamReceipt,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.receipt.as_ref().is_some_and(|old| old != receipt) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ledger sink receipt changed",
            )));
        }
        if let Some(terminal) = this.terminal {
            return Poll::Ready(terminal.map_err(|(kind, raw)| {
                raw.map_or_else(|| io::Error::from(kind), io::Error::from_raw_os_error)
            }));
        }
        this.receipt.get_or_insert_with(|| receipt.clone());
        if !this.published {
            let result = ready!(Pin::new(&mut this.file).poll_commit(cx, receipt));
            if let Err(error) = result {
                this.terminal = Some(Err((error.kind(), error.raw_os_error())));
                return Poll::Ready(Err(error));
            }
            this.published = true;
        }
        if let Some(claim) = &this.claim {
            if this.persist.is_none() {
                let claim = claim.clone();
                let receipt = receipt.clone();
                this.persist = Some(Box::pin(async move { claim.commit(receipt).await }));
            }
            let result = ready!(
                this.persist
                    .as_mut()
                    .expect("receipt persistence")
                    .as_mut()
                    .poll(cx)
            );
            this.persist = None;
            this.terminal = Some(
                result
                    .as_ref()
                    .copied()
                    .map_err(|error| (error.kind(), error.raw_os_error())),
            );
            return Poll::Ready(result);
        }
        this.terminal = Some(Ok(()));
        Poll::Ready(Ok(()))
    }
}
