//! The minimal mux carried by one bridge link: OPEN / DATA / CLOSE / WINDOW.
//!
//! Only the proxy opens streams — one per mobile connection — so stream ids
//! need no odd/even split and the bridge never allocates.

use std::collections::HashMap;
use std::io::{Error, ErrorKind, Result};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::noise::NoiseTransport;
use crate::wire::{
    FRAME_HEAD, KIND_CLOSE, KIND_DATA, KIND_OPEN, KIND_WINDOW, MAX_PAYLOAD, WINDOW,
};

/// Silence longer than this ends the session; the bridge pings every 30s.
const IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Frames a stream may hold before dispatch would block. The window bounds
/// bytes, not frame count, so this is sized for small frames rather than for
/// `WINDOW / MAX_PAYLOAD`.
const INBOX_FRAMES: usize = 1024;

struct Frame {
    id: u32,
    kind: u8,
    payload: Vec<u8>,
}

impl Frame {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAME_HEAD + self.payload.len());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.push(self.kind);
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.push(0);
        out.extend_from_slice(&self.payload);
        out
    }
}

struct StreamState {
    inbox: mpsc::Sender<Vec<u8>>,
    /// Credit we still hold for sending to the bridge.
    credit: Arc<Semaphore>,
}

/// One live bridge link and every stream riding it.
pub struct MuxSession {
    out: mpsc::Sender<Frame>,
    streams: Mutex<HashMap<u32, StreamState>>,
    next_id: AtomicU32,
}

impl MuxSession {
    /// Take over an authenticated bridge socket; the handle resolves when the link dies.
    pub fn start(socket: TcpStream, transport: NoiseTransport) -> (Arc<Self>, JoinHandle<()>) {
        let (reader, mut writer) = socket.into_split();
        let (out, mut outbox) = mpsc::channel::<Frame>(256);
        let session = Arc::new(Self {
            out,
            streams: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
        });
        let transport = Arc::new(transport);

        let write_transport = transport.clone();
        let writer_task = tokio::spawn(async move {
            while let Some(frame) = outbox.recv().await {
                let Ok(sealed) = write_transport.encrypt(&frame.encode()) else { break };
                let mut buf = Vec::with_capacity(sealed.len() + 2);
                buf.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
                buf.extend_from_slice(&sealed);
                if writer.write_all(&buf).await.is_err() {
                    break;
                }
            }
        });

        let reading = session.clone();
        let handle = tokio::spawn(async move {
            let _ = reading.read_loop(reader, transport).await;
            if let Ok(mut streams) = reading.streams.lock() {
                // Closing the credit gate wakes senders parked on a dead link.
                for (_, state) in streams.drain() {
                    state.credit.close();
                }
            }
            writer_task.abort();
        });
        (session, handle)
    }

    /// Streams currently riding this link.
    pub fn stream_count(&self) -> usize {
        self.streams.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Open one stream for an incoming mobile connection.
    pub async fn open_stream(self: &Arc<Self>) -> Result<(StreamTx, StreamRx)> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (inbox, rx) = mpsc::channel::<Vec<u8>>(INBOX_FRAMES);
        let credit = Arc::new(Semaphore::new(WINDOW as usize));
        self.streams
            .lock()
            .map_err(|_| Error::new(ErrorKind::Other, "poisoned"))?
            .insert(id, StreamState { inbox, credit: credit.clone() });
        self.send(Frame { id, kind: KIND_OPEN, payload: Vec::new() }).await?;
        let tx = StreamTx { id, session: self.clone(), credit };
        Ok((tx, StreamRx { rx }))
    }

    async fn send(&self, frame: Frame) -> Result<()> {
        self.out
            .send(frame)
            .await
            .map_err(|_| Error::new(ErrorKind::BrokenPipe, "bridge link closed"))
    }

    async fn read_loop(
        &self,
        mut reader: tokio::net::tcp::OwnedReadHalf,
        transport: Arc<NoiseTransport>,
    ) -> Result<()> {
        loop {
            let mut len = [0u8; 2];
            timeout(IDLE_TIMEOUT, reader.read_exact(&mut len))
                .await
                .map_err(|_| Error::new(ErrorKind::TimedOut, "bridge idle"))??;
            let mut sealed = vec![0u8; u16::from_be_bytes(len) as usize];
            reader.read_exact(&mut sealed).await?;
            let frame = transport.decrypt(&sealed)?;
            if frame.len() < FRAME_HEAD {
                return Err(Error::new(ErrorKind::InvalidData, "short frame"));
            }
            let id = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
            let kind = frame[4];
            let body = &frame[FRAME_HEAD..];
            // streamId 0 is the keepalive channel: echo it so the bridge can
            // tell a live link from a half-open one.
            if id == 0 {
                self.send(Frame { id: 0, kind: KIND_DATA, payload: Vec::new() }).await?;
                continue;
            }
            match kind {
                KIND_DATA => {
                    let inbox = {
                        let streams = self.streams.lock().map_err(|_| broken())?;
                        streams.get(&id).map(|s| s.inbox.clone())
                    };
                    if let Some(inbox) = inbox {
                        match inbox.try_send(body.to_vec()) {
                            Ok(()) => {}
                            // The mobile side hung up while this was in flight:
                            // its stream is gone, but the link serves everyone
                            // else and must survive it.
                            Err(mpsc::error::TrySendError::Closed(_)) => {}
                            // Full means the bridge wrote past the window it
                            // was granted, which is a broken peer.
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                return Err(Error::new(ErrorKind::InvalidData, "receive window exceeded"));
                            }
                        }
                    }
                }
                KIND_WINDOW => {
                    if body.len() == 4 {
                        let grant = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                        let streams = self.streams.lock().map_err(|_| broken())?;
                        if let Some(state) = streams.get(&id) {
                            state.credit.add_permits(grant as usize);
                        }
                    }
                }
                KIND_CLOSE => {
                    if let Some(state) = self.streams.lock().map_err(|_| broken())?.remove(&id) {
                        state.credit.close();
                    }
                }
                _ => {}
            }
        }
    }
}

fn broken() -> Error {
    Error::new(ErrorKind::Other, "poisoned")
}

/// Send half of one mux stream.
pub struct StreamTx {
    id: u32,
    session: Arc<MuxSession>,
    credit: Arc<Semaphore>,
}

impl StreamTx {
    /// Send bytes, blocking while the peer's receive window is full.
    pub async fn send(&self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let take = data.len().min(MAX_PAYLOAD);
            let permits = self
                .credit
                .acquire_many(take as u32)
                .await
                .map_err(|_| broken())?;
            permits.forget();
            self.session
                .send(Frame { id: self.id, kind: KIND_DATA, payload: data[..take].to_vec() })
                .await?;
            data = &data[take..];
        }
        Ok(())
    }

    /// Return receive credit after the bytes have left for the mobile client.
    pub async fn grant(&self, bytes: u32) -> Result<()> {
        self.session
            .send(Frame { id: self.id, kind: KIND_WINDOW, payload: bytes.to_be_bytes().to_vec() })
            .await
    }

    /// Close the stream on both ends.
    pub async fn close(&self) {
        self.session.streams.lock().map(|mut s| s.remove(&self.id)).ok();
        let _ = self
            .session
            .send(Frame { id: self.id, kind: KIND_CLOSE, payload: Vec::new() })
            .await;
    }
}

/// Receive half of one mux stream.
pub struct StreamRx {
    rx: mpsc::Receiver<Vec<u8>>,
}

impl StreamRx {
    /// Next chunk from the bridge, or None once the stream ends.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}
