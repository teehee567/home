use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Result, anyhow, bail};
use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use rustc_hash::FxHashMap;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::modules::ModuleId;
use crate::traits::{FramedReceiver, FramedSender, SplittableStream};
use crate::transport::frame::{Frame, FrameKind};

pub type PeerId = u64;

const OUTBOUND_CAP: usize = 256;
const EVENT_BUF: usize = 64;
const PENDING_INIT_CAP: usize = 32;
const EVENTS_INIT_CAP: usize = 8;
const PEERS_INIT_CAP: usize = 32;

#[trait_variant::make(Send)]
pub trait Dispatcher: Send + Sync + 'static {
    async fn dispatch(&self, peer: PeerId, frame: Frame) -> Option<Frame>;
}

type OutboundTx = mpsc::Sender<Bytes>;
type OutboundRx = mpsc::Receiver<Bytes>;
type PendingMap = Arc<Mutex<FxHashMap<u64, oneshot::Sender<Frame>>>>;
type EventMap = Arc<RwLock<FxHashMap<ModuleId, broadcast::Sender<Vec<u8>>>>>;

pub struct Peer {
    id: PeerId,
    outbound: OutboundTx,
    next_id: AtomicU64,
    pending: PendingMap,
    events: EventMap,
    _reader_task: JoinHandle<()>,
    _writer_task: JoinHandle<()>,
}

#[inline]
fn encode(frame: &Frame) -> Result<Bytes> {
    Ok(Bytes::from(postcard::to_allocvec(frame)?))
}

impl Peer {
    pub fn spawn<S, D, F>(id: PeerId, stream: S, dispatcher: Arc<D>, on_close: F) -> Arc<Self>
    where
        S: SplittableStream + 'static,
        D: Dispatcher,
        F: FnOnce() + Send + 'static,
    {
        let (reader, writer) = stream.split();
        let (tx, rx) = mpsc::channel::<Bytes>(OUTBOUND_CAP);
        let pending: PendingMap = Arc::new(Mutex::new(FxHashMap::with_capacity_and_hasher(
            PENDING_INIT_CAP,
            Default::default(),
        )));
        let events: EventMap = Arc::new(RwLock::new(FxHashMap::with_capacity_and_hasher(
            EVENTS_INIT_CAP,
            Default::default(),
        )));

        let writer_task = tokio::spawn(writer_loop(writer, rx));
        let reader_task = tokio::spawn(reader_loop(
            id,
            reader,
            dispatcher,
            tx.clone(),
            pending.clone(),
            events.clone(),
            on_close,
        ));

        Arc::new(Self {
            id,
            outbound: tx,
            next_id: AtomicU64::new(1),
            pending,
            events,
            _reader_task: reader_task,
            _writer_task: writer_task,
        })
    }

    pub fn connect<S, D>(stream: S, dispatcher: Arc<D>) -> Arc<Self>
    where
        S: SplittableStream + 'static,
        D: Dispatcher,
    {
        Self::spawn(0, stream, dispatcher, || {})
    }

    pub fn id(&self) -> PeerId {
        self.id
    }

    pub fn try_send_bytes(&self, bytes: Bytes) -> Result<()> {
        self.outbound
            .try_send(bytes)
            .map_err(|e| anyhow!("peer {} outbound: {}", self.id, e))
    }

    pub async fn send_event(&self, route: ModuleId, payload: Vec<u8>) -> Result<()> {
        let frame = Frame {
            kind: FrameKind::Event,
            route,
            request_id: 0,
            payload,
        };
        let bytes = encode(&frame)?;

        self.outbound.send(bytes).await.map_err(|_| anyhow!("peer {} outbound closed", self.id))
    }

    pub async fn request(&self, route: ModuleId, payload: Vec<u8>) -> Result<Vec<u8>> {
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let frame = Frame {
            kind: FrameKind::Request,
            route,
            request_id,
            payload,
        };
        let bytes = encode(&frame)?;

        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(request_id, tx);

        if self.outbound.send(bytes).await.is_err() {
            self.pending.lock().remove(&request_id);
            bail!("peer {} closed", self.id);
        }

        let response = rx.await.map_err(|_| anyhow!("response dropped"))?;
        match response.kind {
            FrameKind::Response => Ok(response.payload),
            FrameKind::Error => {
                let msg: String = postcard::from_bytes(&response.payload)
                    .unwrap_or_else(|_| "remote error".into());
                bail!(msg);
            }
            _ => bail!("unexpected frame kind on response"),
        }
    }

    pub fn subscribe(&self, route: ModuleId) -> broadcast::Receiver<Vec<u8>> {
        if let Some(s) = self.events.read().get(&route) {
            return s.subscribe();
        }
        self.events
            .write()
            .entry(route)
            .or_insert_with(|| broadcast::channel::<Vec<u8>>(EVENT_BUF).0)
            .subscribe()
    }
}

// yeets over wire
async fn writer_loop<W: FramedSender>(mut writer: W, mut rx: OutboundRx) {
    while let Some(bytes) = rx.recv().await {
        if writer.send(&bytes).await.is_err() {
            break;
        }
    }
}

// handles receiving data, yeets to dispatcher
async fn reader_loop<R, D, F>(
    peer_id: PeerId,
    mut reader: R,
    dispatcher: Arc<D>,
    outbound: OutboundTx,
    pending: PendingMap,
    events: EventMap,
    on_close: F,
) where
    R: FramedReceiver,
    D: Dispatcher,
    F: FnOnce(),
{
    loop {
        let bytes = match reader.receive().await {
            Ok(b) => b,
            Err(_) => break,
        };
        let frame: Frame = match postcard::from_bytes(&bytes) {
            Ok(f) => f,
            Err(_) => continue,
        };
        match frame.kind {
            FrameKind::Request => {
                let d = dispatcher.clone();
                let out = outbound.clone();
                tokio::spawn(async move {
                    if let Some(resp) = d.dispatch(peer_id, frame).await {
                        if let Ok(bytes) = encode(&resp) {
                            let _ = out.send(bytes).await;
                        }
                    }
                });
            }
            FrameKind::Response | FrameKind::Error => {
                let tx = pending.lock().remove(&frame.request_id);
                if let Some(tx) = tx {
                    let _ = tx.send(frame);
                }
            }
            FrameKind::Event => {
                let sender = events.read().get(&frame.route).cloned();
                if let Some(s) = sender {
                    let _ = s.send(frame.payload);
                }
            }
        }
    }
    let waiters: Vec<oneshot::Sender<Frame>> =
        pending.lock().drain().map(|(_, s)| s).collect();
    drop(waiters);
    on_close();
}

// mainly for server side, allows for a pool of clients to be broadcast to,
// otherwise the api is just using hte peer stuff.
pub struct PeerPool<D: Dispatcher> {
    peers: RwLock<FxHashMap<PeerId, Arc<Peer>>>,
    dispatcher: Arc<D>,
}

impl<D: Dispatcher> PeerPool<D> {
    pub fn new(dispatcher: Arc<D>) -> Arc<Self> {
        Arc::new(Self {
            peers: RwLock::new(FxHashMap::with_capacity_and_hasher(
                PEERS_INIT_CAP,
                Default::default(),
            )),
            dispatcher,
        })
    }

    pub fn attach<S>(self: &Arc<Self>, peer_id: PeerId, stream: S) -> Arc<Peer>
    where
        S: SplittableStream + 'static,
    {
        let pool = self.clone();
        let peer = Peer::spawn(peer_id, stream, self.dispatcher.clone(), move || {
            pool.peers.write().remove(&peer_id);
        });
        self.peers.write().insert(peer_id, peer.clone());
        peer
    }

    pub fn detach(&self, peer_id: PeerId) -> Option<Arc<Peer>> {
        self.peers.write().remove(&peer_id)
    }

    pub fn get(&self, peer_id: PeerId) -> Option<Arc<Peer>> {
        self.peers.read().get(&peer_id).cloned()
    }

    pub fn broadcast_event(&self, route: ModuleId, payload: Vec<u8>) {
        let bytes = match encode(&Frame {
            kind: FrameKind::Event,
            route,
            request_id: 0,
            payload,
        }) {
            Ok(b) => b,
            Err(_) => return,
        };
        let peers: Vec<Arc<Peer>> = {
            let guard = self.peers.read();
            let mut v = Vec::with_capacity(guard.len());
            v.extend(guard.values().cloned());
            v
        };
        for p in peers {
            let _ = p.try_send_bytes(bytes.clone());
        }
    }

    pub fn peer_ids(&self) -> Vec<PeerId> {
        self.peers.read().keys().copied().collect()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.read().len()
    }
}
