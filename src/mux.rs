//! The minimal mux carried by one bridge link: OPEN / DATA / CLOSE / WINDOW.
//!
//! Only the proxy opens streams — one per mobile connection — so stream ids
//! need no odd/even split and the bridge never allocates.

use std::future::Future;
use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::timeout;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::noise::{NoiseDecoder, NoiseEncoder};
use crate::wire::{
    FRAME_HEAD, KIND_CLOSE, KIND_DATA, KIND_OPEN, KIND_WINDOW, MAX_PAYLOAD, WINDOW,
};

/// Silence longer than this ends the session; the bridge pings every 30s.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Frames a stream may hold before dispatch would block.
///
/// The real bound on a stream is its byte window, which the bridge may not
/// exceed; this is sized for the worst case of many small frames inside one
/// window rather than for `WINDOW / MAX_PAYLOAD`. Overflow therefore means a
/// peer that ignored its credit, and it now costs that one stream — see the
/// `Full` arm of `read_loop` — instead of the whole link.
const INBOX_FRAMES: usize = 1024;
/// Frames the writer coalesces into one buffer before flushing. One `/api`
/// call is several small frames; packing them costs one syscall, not six.
const WRITE_BATCH: usize = 32;

type LinkReader = FramedRead<OwnedReadHalf, NoiseDecoder>;
type LinkWriter = FramedWrite<OwnedWriteHalf, NoiseEncoder>;

pub struct Frame {
    pub id: u32,
    pub kind: u8,
    pub payload: Bytes,
}

impl Frame {
    fn control(id: u32, kind: u8) -> Self {
        Self { id, kind, payload: Bytes::new() }
    }
}

struct StreamState {
    inbox: mpsc::Sender<Bytes>,
    /// Credit we still hold for sending to the bridge.
    credit: Arc<Semaphore>,
    /// One slot of this bridge's stream budget, held for the stream's life.
    /// Reserving here rather than checking before insertion is what makes the
    /// per-bridge ceiling exact under concurrency.
    _budget: OwnedSemaphorePermit,
}

/// One live bridge link and every stream riding it.
pub struct MuxSession {
    out: mpsc::Sender<Frame>,
    streams: DashMap<u32, StreamState>,
    next_id: AtomicU32,
    /// This bridge's stream ceiling, as a permit pool.
    budget: Arc<Semaphore>,
    /// Both tasks carrying this link, so a session displaced by a duplicate
    /// registration can be torn down from outside. Set once, right after
    /// `start` spawns them.
    tasks: OnceLock<(AbortHandle, AbortHandle)>,
    /// Invoked when the *peer* announces a new stream. Production registers
    /// nothing — only the proxy opens streams. A bridge (and therefore the
    /// loopback harness that stands in for one) needs this to react to them.
    on_open: OnceLock<Arc<dyn Fn(StreamTx, StreamRx) + Send + Sync>>,
}

impl MuxSession {
    /// Take over an authenticated bridge link; the handle resolves when it dies.
    /// @param max_streams - concurrent stream ceiling for this link.
    pub fn start(
        reader: LinkReader,
        mut writer: LinkWriter,
        max_streams: usize,
    ) -> (Arc<Self>, JoinHandle<()>) {
        let (out, mut outbox) = mpsc::channel::<Frame>(256);
        let session = Arc::new(Self {
            out,
            streams: DashMap::new(),
            next_id: AtomicU32::new(1),
            budget: Arc::new(Semaphore::new(max_streams.max(1))),
            tasks: OnceLock::new(),
            on_open: OnceLock::new(),
        });

        let writer_task = tokio::spawn(async move {
            let mut batch = Vec::with_capacity(WRITE_BATCH);
            while outbox.recv_many(&mut batch, WRITE_BATCH).await > 0 {
                // feed buffers; the single flush is the only syscall.
                for frame in batch.drain(..) {
                    if writer.feed(frame).await.is_err() {
                        return;
                    }
                }
                if writer.flush().await.is_err() {
                    return;
                }
            }
        });

        let writer_abort = writer_task.abort_handle();
        let writer_abort_on_death = writer_abort.clone();

        let reading = session.clone();
        let handle = tokio::spawn(async move {
            let _ = reading.read_loop(reader).await;
            // Closing the credit gate wakes senders parked on a dead link.
            reading.streams.retain(|_, state| {
                state.credit.close();
                false
            });
            writer_abort_on_death.abort();
        });
        // Both halves are abortable from outside, so a session displaced by a
        // duplicate registration can be torn down by whoever displaced it.
        let _ = session.tasks.set((handle.abort_handle(), writer_abort));
        (session, handle)
    }

    /// Streams currently riding this link.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Handle streams the peer opens, until the link dies.
    ///
    /// Only a stream announced by the peer over the wire fires the handler;
    /// `try_open_stream` (the proxy's own side) never does, because the proxy
    /// both opens and serves those itself.
    pub fn on_open<F>(&self, handler: F)
    where
        F: Fn(StreamTx, StreamRx) + Send + Sync + 'static,
    {
        let _ = self.on_open.set(Arc::new(handler));
    }

    /// Tear this link down unconditionally.
    ///
    /// Used when a duplicate registration takes over its routing key: the
    /// displaced link is no longer addressable, so leaving it open would keep
    /// a socket whose keepalives still flow but which no phone can ever reach.
    /// Closing the credit gate first wakes senders parked on stream windows;
    /// aborting both tasks then closes the socket, which is what tells the
    /// other end to reconnect.
    pub fn shutdown(&self) {
        self.streams.retain(|_, state| {
            state.credit.close();
            false
        });
        if let Some((reader, writer)) = self.tasks.get() {
            reader.abort();
            writer.abort();
        }
    }

    /// Open one stream for an incoming mobile connection, if the bridge has
    /// budget left.
    ///
    /// The slot is taken before anything is inserted or sent, so the ceiling
    /// holds no matter how many clients arrive at once; a plain length check
    /// followed by a separate insert would let concurrent callers overshoot.
    /// @returns the stream halves, or `None` once this bridge is full.
    pub async fn try_open_stream(self: &Arc<Self>) -> Option<(StreamTx, StreamRx)> {
        let budget = self.budget.clone().try_acquire_owned().ok()?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (inbox, rx) = mpsc::channel::<Bytes>(INBOX_FRAMES);
        let credit = Arc::new(Semaphore::new(WINDOW as usize));
        self.streams.insert(id, StreamState { inbox, credit: credit.clone(), _budget: budget });
        if self.send(Frame::control(id, KIND_OPEN)).await.is_err() {
            // The link died between reserving and announcing: release the slot
            // rather than leaking it for the life of the process.
            self.streams.remove(&id);
            return None;
        }
        Some((StreamTx { id, session: self.clone(), credit }, StreamRx { rx }))
    }

    async fn send(&self, frame: Frame) -> Result<()> {
        self.out
            .send(frame)
            .await
            .map_err(|_| Error::new(ErrorKind::BrokenPipe, "bridge link closed"))
    }

    async fn read_loop(self: &Arc<Self>, mut reader: LinkReader) -> Result<()> {
        loop {
            let frame = timeout(IDLE_TIMEOUT, reader.next())
                .await
                .map_err(|_| Error::new(ErrorKind::TimedOut, "bridge idle"))?;
            let Some(mut frame) = frame.transpose()? else { return Ok(()) };
            if frame.len() < FRAME_HEAD {
                return Err(Error::new(ErrorKind::InvalidData, "short frame"));
            }
            let id = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
            let kind = frame[4];
            // Slice, not copy: the payload shares the decrypted buffer.
            frame.advance(FRAME_HEAD);
            let body = frame;

            // streamId 0 is the keepalive channel: echo it so the bridge can
            // tell a live link from a half-open one.
            if id == 0 {
                self.send(Frame::control(0, KIND_DATA)).await?;
                continue;
            }
            match kind {
                // The peer opened a stream: materialise its halves and hand
                // them to whoever is serving as the far end.
                KIND_OPEN => {
                    let (inbox, rx) = mpsc::channel::<Bytes>(INBOX_FRAMES);
                    let credit = Arc::new(Semaphore::new(WINDOW as usize));
                    let _budget = match self.budget.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        // Over budget: refuse the stream rather than exceed the
                        // link's ceiling.
                        Err(_) => {
                            self.send(Frame::control(id, KIND_CLOSE)).await?;
                            continue;
                        }
                    };
                    self.streams.insert(id, StreamState { inbox, credit: credit.clone(), _budget });
                    if let Some(handler) = self.on_open.get() {
                        handler(
                            StreamTx { id, session: Arc::clone(self), credit },
                            StreamRx { rx },
                        );
                    }
                }
                KIND_DATA => {
                    let inbox = self.streams.get(&id).map(|s| s.inbox.clone());
                    if let Some(inbox) = inbox {
                        match inbox.try_send(body) {
                            Ok(()) => {}
                            // The mobile side hung up while this was in flight:
                            // its stream is gone, but the link serves everyone
                            // else and must survive it.
                            Err(mpsc::error::TrySendError::Closed(_)) => {}
                            // Full means the bridge wrote past the window it
                            // was granted. That is a broken peer, but only on
                            // this stream: hanging up the whole link would let
                            // one bad stream take every phone on this bridge
                            // down with it.
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                if let Some((_, state)) = self.streams.remove(&id) {
                                    state.credit.close();
                                }
                                self.send(Frame::control(id, KIND_CLOSE)).await?;
                            }
                        }
                    }
                }
                KIND_WINDOW if body.len() == 4 => {
                    let grant = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    if let Some(state) = self.streams.get(&id) {
                        state.credit.add_permits(grant as usize);
                    }
                }
                KIND_CLOSE => {
                    if let Some((_, state)) = self.streams.remove(&id) {
                        state.credit.close();
                    }
                }
                _ => {}
            }
        }
    }
}

fn broken() -> Error {
    Error::new(ErrorKind::BrokenPipe, "bridge link closed")
}

/// Send half of one mux stream.
pub struct StreamTx {
    id: u32,
    session: Arc<MuxSession>,
    credit: Arc<Semaphore>,
}

impl StreamTx {
    /// Send bytes, blocking while the peer's receive window is full.
    pub async fn send(&self, mut data: Bytes) -> Result<()> {
        while !data.is_empty() {
            let take = data.len().min(MAX_PAYLOAD);
            let permits = self
                .credit
                .acquire_many(take as u32)
                .await
                .map_err(|_| broken())?;
            permits.forget();
            self.session
                .send(Frame { id: self.id, kind: KIND_DATA, payload: data.split_to(take) })
                .await?;
        }
        Ok(())
    }

    /// Return receive credit after the bytes have left for the mobile client.
    pub async fn grant(&self, bytes: u32) -> Result<()> {
        self.session
            .send(Frame {
                id: self.id,
                kind: KIND_WINDOW,
                payload: Bytes::copy_from_slice(&bytes.to_be_bytes()),
            })
            .await
    }

    /// Close the stream on both ends.
    pub async fn close(&self) {
        self.session.streams.remove(&self.id);
        let _ = self.session.send(Frame::control(self.id, KIND_CLOSE)).await;
    }
}

/// Receive half of one mux stream.
pub struct StreamRx {
    rx: mpsc::Receiver<Bytes>,
}

impl StreamRx {
    /// Next chunk from the bridge, or None once the stream ends.
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.recv().await
    }
}

impl MuxSession {
    /// Remove one stream and tell the bridge it is gone, without awaiting.
    ///
    /// Used by Drop: an HTTP connection ending must release its bridge slot at
    /// once, and the drop path cannot await the outbox.
    pub fn close_stream(&self, id: u32) {
        if let Some((_, state)) = self.streams.remove(&id) {
            state.credit.close();
        }
        let _ = self.out.try_send(Frame::control(id, KIND_CLOSE));
    }
}

/// Bytes queued for the bridge before a flush is forced.
///
/// This is a latency bound, not a memory bound: the real bound is the stream's
/// 256 KiB credit window. hyper writes a whole head in one call and bodies in
/// whatever chunks it has, so buffering a few KiB here turns a request into one
/// mux frame instead of a dozen.
const WRITE_COALESCE: usize = 32 * 1024;

/// Return receive credit once half the window is owed, instead of one frame
/// per read. Halves the control traffic while leaving the peer half a window
/// to keep writing into.
const GRANT_THRESHOLD: u32 = WINDOW / 2;

/// One mux stream exposed as a byte stream, so it can carry plain HTTP/1.1.
///
/// This is what replaces the phone's Noise socket: the proxy opens a stream,
/// performs the Noise_IK handshake over it, and then hands the *plaintext* side
/// to hyper. Reads pull decrypted payloads out of the stream; writes are
/// coalesced and sealed by StreamTx, whose credit window provides the
/// back-pressure all the way back to the tunnel.
pub struct MuxStreamIo {
    tx: Arc<StreamTx>,
    rx: StreamRx,
    /// The tail of a received frame not yet handed to the reader.
    inbox: Option<Bytes>,
    /// Bytes written but not yet sent.
    out: BytesMut,
    /// A single in-flight StreamTx::send, so a full window parks the writer
    /// instead of buffering without bound.
    pending: Option<Pin<Box<dyn Future<Output = Result<()>> + Send>>>,
    /// Receive credit earned by reading, not yet handed back to the peer.
    ///
    /// The peer may send exactly one window before it must be replenished, so
    /// a stream that never returns credit stalls once a window has crossed.
    /// The reader cannot await the outbox, so credit accumulates here and is
    /// offered opportunistically; the writer task drains the channel, so a
    /// momentarily full outbox simply leaves it for the next read.
    credit_due: u32,
}

impl MuxStreamIo {
    /// Wrap one opened stream as an AsyncRead + AsyncWrite transport.
    pub fn new(tx: StreamTx, rx: StreamRx) -> Self {
        Self {
            tx: Arc::new(tx),
            rx,
            inbox: None,
            out: BytesMut::with_capacity(WRITE_COALESCE),
            pending: None,
            credit_due: 0,
        }
    }

    /// Hand back receive credit once half a window is owed.
    fn return_credit(&mut self) {
        if self.credit_due < GRANT_THRESHOLD {
            return;
        }
        self.flush_credit();
    }

    /// Hand back all receive credit owed, even below the threshold.
    ///
    /// Called when the stream ends, so the peer is never left short of the
    /// final bytes it sent.
    fn flush_credit(&mut self) {
        if self.credit_due == 0 {
            return;
        }
        let grant = Frame {
            id: self.tx.id,
            kind: KIND_WINDOW,
            payload: Bytes::copy_from_slice(&self.credit_due.to_be_bytes()),
        };
        if self.tx.session.out.try_send(grant).is_ok() {
            self.credit_due = 0;
        }
    }
}

impl AsyncRead for MuxStreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        // Drain the frame already in hand before asking the stream for more:
        // a bridge may pack several HTTP bytes into one mux frame.
        let take;
        if let Some(chunk) = self.inbox.as_mut() {
            let n = chunk.len().min(buf.remaining());
            buf.put_slice(&chunk[..n]);
            chunk.advance(n);
            if chunk.is_empty() {
                self.inbox = None;
            }
            take = n;
        } else {
            let next = self.rx.rx.poll_recv(cx);
            match next {
                Poll::Ready(Some(chunk)) => {
                    let n = chunk.len().min(buf.remaining());
                    buf.put_slice(&chunk[..n]);
                    if n < chunk.len() {
                        let mut rest = chunk;
                        rest.advance(n);
                        self.inbox = Some(rest);
                    }
                    take = n;
                }
                // None is a clean end of stream: the bridge closed this stream.
                Poll::Ready(None) => {
                    self.flush_credit();
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        // What the reader has taken is what the peer may send again.
        self.credit_due += take as u32;
        self.return_credit();
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MuxStreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize>> {
        // A pending send owns the buffer; apply back-pressure until it drains.
        if self.pending.is_some() {
            return Poll::Pending;
        }
        self.out.extend_from_slice(data);
        if self.out.len() >= WRITE_COALESCE {
            let tx = self.tx.clone();
            let frame = self.out.split().freeze();
            self.pending = Some(Box::pin(async move { tx.send(frame).await }));
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if let Some(mut fut) = self.pending.take() {
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    self.pending = Some(fut);
                    return Poll::Pending;
                }
            }
        }
        if self.out.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let tx = self.tx.clone();
        let frame = self.out.split().freeze();
        self.pending = Some(Box::pin(async move { tx.send(frame).await }));
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.flush_credit();
                self.tx.session.close_stream(self.tx.id);
                Poll::Ready(result)
            }
        }
    }
}

impl Drop for MuxStreamIo {
    fn drop(&mut self) {
        // Whatever ended the HTTP connection — a finished keep-alive, a client
        // hanging up, an error — the bridge slot must go back now, after any
        // credit still owed to the peer.
        self.flush_credit();
        self.tx.session.close_stream(self.tx.id);
    }
}
