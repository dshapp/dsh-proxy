//! The minimal mux carried by one bridge link: OPEN / DATA / CLOSE / WINDOW.
//!
//! Only the proxy opens streams — one per mobile connection — so stream ids
//! need no odd/even split and the bridge never allocates.

use std::io::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::noise::{NoiseDecoder, NoiseEncoder};
use crate::wire::{FRAME_HEAD, KIND_CLOSE, KIND_DATA, KIND_OPEN, KIND_WINDOW, MAX_PAYLOAD, WINDOW};

/// Silence longer than this ends the session; the bridge pings every 30s.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Frames a stream may hold before dispatch would block. The window bounds
/// bytes, not frame count, so this is sized for small frames rather than for
/// `WINDOW / MAX_PAYLOAD`.
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
}

/// One live bridge link and every stream riding it.
pub struct MuxSession {
    out: mpsc::Sender<Frame>,
    streams: DashMap<u32, StreamState>,
    next_id: AtomicU32,
}

impl MuxSession {
    /// Take over an authenticated bridge link; the handle resolves when it dies.
    pub fn start(reader: LinkReader, mut writer: LinkWriter) -> (Arc<Self>, JoinHandle<()>) {
        let (out, mut outbox) = mpsc::channel::<Frame>(256);
        let session = Arc::new(Self {
            out,
            streams: DashMap::new(),
            next_id: AtomicU32::new(1),
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

        let reading = session.clone();
        let handle = tokio::spawn(async move {
            let _ = reading.read_loop(reader).await;
            // Closing the credit gate wakes senders parked on a dead link.
            reading.streams.retain(|_, state| {
                state.credit.close();
                false
            });
            writer_task.abort();
        });
        (session, handle)
    }

    /// Streams currently riding this link.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Open one stream for an incoming mobile connection.
    pub async fn open_stream(self: &Arc<Self>) -> Result<(StreamTx, StreamRx)> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (inbox, rx) = mpsc::channel::<Bytes>(INBOX_FRAMES);
        let credit = Arc::new(Semaphore::new(WINDOW as usize));
        self.streams.insert(id, StreamState { inbox, credit: credit.clone() });
        self.send(Frame::control(id, KIND_OPEN)).await?;
        Ok((StreamTx { id, session: self.clone(), credit }, StreamRx { rx }))
    }

    async fn send(&self, frame: Frame) -> Result<()> {
        self.out
            .send(frame)
            .await
            .map_err(|_| Error::new(ErrorKind::BrokenPipe, "bridge link closed"))
    }

    async fn read_loop(&self, mut reader: LinkReader) -> Result<()> {
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
                            // was granted, which is a broken peer.
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                return Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "receive window exceeded",
                                ));
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
