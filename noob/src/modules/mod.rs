#[cfg(windows)]
pub mod genshin;
pub mod app_watcher;
pub mod sys_info;
mod registry;

pub use registry::{ModuleId, Modules};

use std::future::Future;

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::transport::frame::{Frame, FrameKind, error_frame};

const REQUEST_CAP: usize = 128;
const EVENT_CAP: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("{0}")]
    Other(String),
}

// no sync so data doesnt have to be shared
pub trait Module: Send + Sized + 'static {
    const NAME: &str;

    type Request: Serialize + DeserializeOwned + Send + 'static;
    type Response: Serialize + DeserializeOwned + Send + 'static;
    type Event: Clone + Send + Serialize + DeserializeOwned + 'static;

    fn new() -> Self;

    fn run(self, ctx: Context<Self>) -> impl Future<Output = ()> + Send;
}

pub trait Routed {
    const ID: ModuleId;
}

pub struct Request<M: Module> {
    pub payload: M::Request,
    reply: oneshot::Sender<Result<M::Response, ModuleError>>,
}

impl<M: Module> Request<M> {
    pub fn reply(self, result: Result<M::Response, ModuleError>) {
        let _ = self.reply.send(result);
    }
}

/// inside run, queue + event publisher
pub struct Context<M: Module> {
    rx: mpsc::Receiver<Request<M>>,
    events: broadcast::Sender<M::Event>,
}

impl<M: Module> Context<M> {
    pub async fn recv(&mut self) -> Option<Request<M>> {
        self.rx.recv().await
    }

    pub fn publish(&self, event: M::Event) {
        let _ = self.events.send(event);
    }
}

/// handle to a module
pub struct Handle<M: Module> {
    tx: mpsc::Sender<Request<M>>,
    events: broadcast::Sender<M::Event>,
}

impl<M: Module> Clone for Handle<M> {
    fn clone(&self) -> Self {
        Self { tx: self.tx.clone(), events: self.events.clone() }
    }
}

impl<M: Module> Handle<M> {
    pub async fn request(&self, payload: M::Request) -> Result<M::Response, ModuleError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Request { payload, reply })
            .await
            .map_err(|_| ModuleError::Other("module stopped".into()))?;
        rx.await.map_err(|_| ModuleError::Other("module stopped".into()))?
    }

    pub fn subscribe(&self) -> broadcast::Receiver<M::Event> {
        self.events.subscribe()
    }
}

// create a module
pub fn spawn<M: Module>() -> Handle<M> {
    let (tx, rx) = mpsc::channel(REQUEST_CAP);
    let (events, _) = broadcast::channel(EVENT_CAP);
    let ctx = Context { rx, events: events.clone() };
    tokio::spawn(M::new().run(ctx));
    Handle { tx, events }
}

/// dispatch to module and receive
pub async fn dispatch_to<M: Module>(handle: &Handle<M>, frame: Frame) -> Frame {
    let payload: M::Request = match postcard::from_bytes(&frame.payload) {
        Ok(p) => p,
        Err(e) => return error_frame(&frame, e.to_string()),
    };
    match handle.request(payload).await {
        Ok(resp) => match postcard::to_allocvec(&resp) {
            Ok(payload) => Frame {
                kind: FrameKind::Response,
                route: frame.route,
                request_id: frame.request_id,
                payload,
            },
            Err(e) => error_frame(&frame, e.to_string()),
        },
        Err(e) => error_frame(&frame, e.to_string()),
    }
}

/// ```ignore
/// register_modules! {
///     pub enum ModuleId;
///     pub struct Modules;
///
///     Settings => settings::SettingsModule,
///     #[cfg(windows)] Genshin => genshin::GenshinModule,
/// }
/// ```
#[macro_export]
macro_rules! register_modules {
    (
        $(#[$emeta:meta])* $evis:vis enum $route:ident;
        $(#[$smeta:meta])* $svis:vis struct $modules:ident;
        $(
            $(#[cfg($cfg:meta)])? $variant:ident => $ty:ty
        ),* $(,)?
    ) => {
        $(#[$emeta])*
        #[derive(
            ::core::clone::Clone, ::core::marker::Copy, ::core::fmt::Debug,
            ::core::cmp::PartialEq, ::core::cmp::Eq, ::core::hash::Hash,
            ::serde::Serialize, ::serde::Deserialize,
        )]
        $evis enum $route {
            $( $variant, )*
        }

        $(#[$smeta])*
        #[allow(non_snake_case)]
        $svis struct $modules {
            $( #[cfg(all($($cfg,)?))] pub $variant: $crate::modules::Handle<$ty>, )*
        }

        $(
            #[cfg(all($($cfg,)?))]
            impl $crate::modules::Routed for $ty {
                const ID: $route = $route::$variant;
            }
        )*

        impl $modules {
            pub fn spawn() -> Self {
                Self {
                    $( #[cfg(all($($cfg,)?))] $variant: $crate::modules::spawn::<$ty>(), )*
                }
            }

            pub fn broadcast_events(
                &self,
                pool: ::std::sync::Arc<$crate::transport::conn_manager::PeerPool<Self>>,
            ) {
                $(
                    #[cfg(all($($cfg,)?))]
                    {
                        let mut sub = self.$variant.subscribe();
                        let pool = pool.clone();
                        ::tokio::spawn(async move {
                            loop {
                                match sub.recv().await {
                                    ::core::result::Result::Ok(ev) => {
                                        if let ::core::result::Result::Ok(bytes) =
                                            ::postcard::to_allocvec(&ev)
                                        {
                                            pool.broadcast_event($route::$variant, bytes);
                                        }
                                    }
                                    ::core::result::Result::Err(
                                        ::tokio::sync::broadcast::error::RecvError::Lagged(_),
                                    ) => continue,
                                    ::core::result::Result::Err(_) => break,
                                }
                            }
                        });
                    }
                )*
            }
        }

        impl $crate::transport::conn_manager::Dispatcher for $modules {
            #[allow(unused_variables)]
            async fn dispatch(
                &self,
                _peer: $crate::transport::conn_manager::PeerId,
                frame: $crate::transport::frame::Frame,
            ) -> ::core::option::Option<$crate::transport::frame::Frame> {
                match frame.route {
                    $(
                        #[cfg(all($($cfg,)?))]
                        $route::$variant => ::core::option::Option::Some(
                            $crate::modules::dispatch_to(&self.$variant, frame).await
                        ),
                        #[cfg(not(all($($cfg,)?)))]
                        $route::$variant => ::core::option::Option::Some(
                            $crate::transport::frame::error_frame(
                                &frame,
                                ::std::string::String::from(
                                    "module unsupported on this platform",
                                ),
                            )
                        ),
                    )*
                }
            }
        }
    };
}