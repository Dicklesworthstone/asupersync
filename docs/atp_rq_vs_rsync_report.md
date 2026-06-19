# ATP-RQ vs tuned rsync: honest final report

Status: LAND.2 final campaign report.

Evidence source: `docs/atp_rq_beat_rsync_ledger.md`, specifically F-POS-5 and
E-RESYNC-13 through E-RESYNC-19. Scope is the 5 MB ATP-RQ delta re-sync
campaign. Rows are byte-identical only unless called out as invalid. The
headline metric is bytes on the wire.

## Executive verdict

ATP-RQ does not beat tuned rsync over every connection or every edit shape.
That claim is false and must not be used.

ATP-RQ does have one proven, durable bytes-on-wire win: mid-file insert/shift
re-sync. After the byte-precise sub-chunk delta path landed, ATP-RQ sends only
the localized shifted-region literals plus compact delta metadata, while tuned
rsync resends roughly half of the 5 MB file. The gated campaign result is
11.1x to 15.1x fewer bytes on the wire than tuned rsync, with byte-identical
output.

ATP-RQ is also robust: after the repair fallback fix, it converges
byte-identically in the tested lossy cells, including 10% loss and high-BDP
settings. That is a correctness and convergence win. It is not a bytes win.

ATP-RQ still loses to tuned rsync on append edits, spread/random edits,
lossy-link byte counts, and memory at this 5 MB scale. The dominant remaining
cost is RaptorQ/FEC/protocol overhead on top of otherwise competitive delta
payload bytes.

## Where ATP-RQ wins

| Scenario | ATP-RQ wire | tuned rsync wire | Result |
|---|---:|---:|---|
| 5 MB mid-file insert, 4-rep gated run | 182-248 KB | about 2.75 MB | ATP-RQ wins 11.1x-15.1x |
| Earlier 5 MB insert after adaptive FEC | 199 KB | 2.75 MB | ATP-RQ wins about 14x |
| First valid insert win | 395 KB | 2.75 MB | ATP-RQ wins about 7x |

This is an algorithmic delta win, not a transport-speed claim. Content-defined
chunking keeps most shifted content aligned and limits retransmission to the
localized changed region. Tuned rsync's fixed-block rolling checksum is much
less favorable on mid-file insert/shift edits and sends roughly half the file.

The safe claim is: ATP-RQ beats tuned rsync by 11.1x-15.1x on byte-identical
5 MB mid-file insert/shift re-sync campaign cells.

The unsafe claim is: ATP-RQ beats rsync over any connection. The campaign did
not prove that. In particular, a lossy insert run where the sidecar negotiation
fell back to a full-object send is not a valid delta win row.

## Where ATP-RQ is robust

After the FEC fallback repair fix, ATP-RQ converged instead of failing closed in
the lossy campaign cells:

| Regime | Change | ATP-RQ correctness | Bytes result |
|---|---|---|---|
| 2% loss / 80 ms / 50 Mbit | append | byte-identical | loses badly on bytes |
| 5% loss / 80 ms / 50 Mbit | append and 1% spread | byte-identical | loses on bytes |
| 10% loss / 120 ms / 20 Mbit | append and 1% spread | byte-identical | loses on bytes |
| 200 ms / 1 Gbit high-BDP | append and 1% spread | byte-identical | loses on bytes |

This is still important. ATP-RQ now demonstrates sound convergence behavior
under loss, and fail-closed behavior remains the right posture when the transfer
cannot be completed safely. But "converges under loss" must not be rewritten as
"beats rsync under loss."

## Where ATP-RQ loses

Append remains rsync's best case. ATP-RQ's append payload is already in the
right range, roughly 83-85 KB versus rsync's roughly 96 KB, but fixed
sidecar, RaptorQ, FEC, and protocol overhead push total wire bytes above rsync.

| Scenario | ATP-RQ wire | tuned rsync wire | Result |
|---|---:|---:|---|
| Clean/good append, favorable single rep | 128.8 KB | 96.1 KB | ATP-RQ loses 1.34x |
| Clean/good append, later 3-rep band | 145-158 KB | about 96 KB | ATP-RQ loses about 1.5x |
| 2% loss append | 988 KB | 96.3 KB | ATP-RQ loses 10.25x |
| 5% loss append | 267.9 KB | 96.4 KB | ATP-RQ loses 2.78x |
| 10% loss append | 139.5 KB | 96.5 KB | ATP-RQ loses 1.45x |
| High-BDP append | 176.4 KB | 98.2 KB | ATP-RQ loses 1.80x |

Spread/random edits also lose. In those cells, most chunks become dirty, so
content-defined chunking has little structure to exploit and ATP-RQ pays FEC
tax on near-full-object traffic. The 10% loss 1% spread row sent 10.31 MB with
ATP-RQ versus 5.53 MB with rsync, a 1.87x loss.

Memory also loses at this scale. The measured 5 MB rows put ATP-RQ around
24-25 MB peak RSS and tuned rsync around 8.4-8.6 MB peak RSS, so ATP-RQ uses
about 3x more memory for the tested 5 MB transfers.

## Why the scorecard looks this way

Insert/shift wins because ATP-RQ's content-defined chunking and sub-chunk
literals localize the changed region. The link does not create that win; the
delta representation does.

Append loses because rsync is already close to ideal for tail-only edits.
ATP-RQ can make the payload competitive, but the remaining per-transfer
sidecar/FEC/symbol overhead is large enough to lose the wire-byte comparison.

Lossy links did not become a bytes win at 5 MB because rsync's TCP path did
not stall in the tested regimes. ATP-RQ's rateless repair makes the transfer
converge, but it also adds repair and protocol bytes. At this file size, the
FEC tax is larger than any transport advantage.

Spread edits lose because the edit shape destroys most reuse. When nearly every
chunk is dirty, ATP-RQ behaves much closer to a full-object transfer and then
adds FEC overhead.

## Remaining work before broader claims

The strongest remaining byte-reduction lever is per-block FEC repair. The
ledger identifies a current failure mode where repair is effectively per-entry,
so a lossy repair round can re-spray blocks that the receiver already has.
Repairing only the still-needed blocks is the best direct path to reducing the
lossy-byte explosion.

The second major lever is replacing or hardening the interactive receiver
sidecar. A Slepian-Wolf syndrome path could remove sidecar bytes and avoid the
loss-sensitive sidecar negotiation that caused a lossy insert cell to fall back
to full-object send. That work still needs real decode integration and test
evidence before it can support any campaign claim.

Large high-BDP files remain an unproven hypothesis, not a claim. At 5 MB, rsync
did not stall even at 10% loss or 200 ms high-BDP. Prior larger-file evidence
also suggests ATP-RQ may become decode-bound, so any larger-file transport win
must be measured rather than assumed.

Memory must be tracked as a first-class metric. The current campaign shows an
ATP-RQ memory loss, not a memory win.

## Final claim language

Use this:

> ATP-RQ beats tuned rsync by 11.1x-15.1x on byte-identical 5 MB mid-file
> insert/shift re-sync cells, thanks to content-defined chunking and
> byte-precise sub-chunk delta literals.

Also safe:

> ATP-RQ converges byte-identically in the tested lossy 5 MB cells, including
> 10% loss, but those rows still lose to rsync on bytes.

Do not use these:

> ATP-RQ beats rsync over any connection.

> ATP-RQ beats rsync on append.

> ATP-RQ beats rsync on lossy-byte counts.

> ATP-RQ uses less memory than rsync.
