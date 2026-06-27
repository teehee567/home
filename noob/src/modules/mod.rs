#[cfg(windows)]
pub mod genshin;
pub mod app_watcher;
pub mod metrics;
mod registry;

pub use registry::{ModuleId, Modules};

use std::future::Future;

use sea_orm::sea_query::TableCreateStatement;
use sea_orm::{ConnectionTrait, Schema};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::storage::NodeDeps;
use crate::transport::frame::{Frame, FrameKind, error_frame};

const REQUEST_CAP: usize = 128;
const EVENT_CAP: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("storage error: {0}")]
    Storage(#[from] sea_orm::DbErr),

    #[error("{0}")]
    Other(String),
}

// no sync so data doesnt have to be shared
pub trait Module: Send + Sized + 'static {
    const NAME: &str;

    type Request: Serialize + DeserializeOwned + Send + 'static;
    type Response: Serialize + DeserializeOwned + Send + 'static;
    type Event: Clone + Send + Serialize + DeserializeOwned + 'static;

    /// tables this module needs created; default = none
    fn tables(_schema: &Schema) -> Vec<TableCreateStatement> {
        Vec::new()
    }

    /// load state fail aborts startup
    fn new(deps: &NodeDeps) -> impl Future<Output = Result<Self, ModuleError>> + Send;

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
pub async fn spawn<M: Module>(deps: &NodeDeps) -> Result<Handle<M>, ModuleError> {
    let db = deps.db();
    let backend = db.get_database_backend();
    let schema = Schema::new(backend);
    // if tables doesnt exist then create
    for mut stmt in M::tables(&schema) {
        stmt.if_not_exists();
        db.execute(backend.build(&stmt)).await?;
    }

    let (tx, rx) = mpsc::channel(REQUEST_CAP);
    let (events, _) = broadcast::channel(EVENT_CAP);
    let ctx = Context { rx, events: events.clone() };
    let module = M::new(deps).await?;
    tokio::spawn(module.run(ctx));
    Ok(Handle { tx, events })
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
///     device {
///         Settings => settings::SettingsModule,
///     }
///     desktop {
///         #[cfg(windows)] Genshin => genshin::GenshinModule,
///     }
///     authority {
///         FileStore => file_store::FileStoreModule,
///     }
/// }
/// ```
#[macro_export]
macro_rules! register_modules {
    (
        $(#[$emeta:meta])* $evis:vis enum $route:ident;
        $(#[$smeta:meta])* $svis:vis struct $modules:ident;
        device { $( $(#[cfg($dcfg:meta)])? $dvar:ident => $dty:ty ),* $(,)? }
        desktop { $( $(#[cfg($kcfg:meta)])? $kvar:ident => $kty:ty ),* $(,)? }
        authority { $( $(#[cfg($acfg:meta)])? $avar:ident => $aty:ty ),* $(,)? }
    ) => {
        $crate::register_modules! {
            @flat
            $(#[$emeta])* $evis enum $route;
            $(#[$smeta])* $svis struct $modules;
            $( $(#[cfg($dcfg)])? $dvar => $dty, )*
            $( $(#[cfg($kcfg)])? $kvar => $kty, )*
            $( $(#[cfg($acfg)])? $avar => $aty, )*
        }

        impl $route {
            /// Per-device routes — hosted by every node.
            $evis const DEVICE: &[$route] = &[ $( $route::$dvar, )* ];
            /// Desktop routes — hosted only by interactive user machines.
            $evis const DESKTOP: &[$route] = &[ $( $route::$kvar, )* ];
            /// Authority routes — hosted only by the always-on node.
            $evis const AUTHORITY: &[$route] = &[ $( $route::$avar, )* ];
        }

        impl $modules {
            /// Spawn what an interactive user machine hosts (device + desktop).
            $svis async fn spawn_desktop(
                deps: &$crate::storage::NodeDeps,
            ) -> ::core::result::Result<Self, $crate::modules::ModuleError> {
                Self::spawn_groups(&[$route::DEVICE, $route::DESKTOP], deps).await
            }

            /// Spawn what the always-on node hosts (device + authority).
            $svis async fn spawn_server(
                deps: &$crate::storage::NodeDeps,
            ) -> ::core::result::Result<Self, $crate::modules::ModuleError> {
                Self::spawn_groups(&[$route::DEVICE, $route::AUTHORITY], deps).await
            }
        }
    };
    (
        @flat
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
            $( #[cfg(all($($cfg,)?))] pub $variant: ::core::option::Option<$crate::modules::Handle<$ty>>, )*
        }

        $(
            #[cfg(all($($cfg,)?))]
            impl $crate::modules::Routed for $ty {
                const ID: $route = $route::$variant;
            }
        )*

        impl $modules {
            /// spawn hosted modules only
            #[allow(non_snake_case)]
            pub async fn spawn_groups(
                hosted: &[&[$route]],
                deps: &$crate::storage::NodeDeps,
            ) -> ::core::result::Result<Self, $crate::modules::ModuleError> {
                $(
                    #[cfg(all($($cfg,)?))]
                    let $variant = if hosted.iter().any(|g| g.contains(&$route::$variant)) {
                        ::core::option::Option::Some($crate::modules::spawn::<$ty>(deps).await?)
                    } else {
                        ::core::option::Option::None
                    };
                )*
                ::core::result::Result::Ok(Self {
                    $(
                        #[cfg(all($($cfg,)?))]
                        $variant,
                    )*
                })
            }

            pub fn broadcast_events(
                &self,
                pool: ::std::sync::Arc<$crate::transport::conn_manager::PeerPool<Self>>,
            ) {
                $(
                    #[cfg(all($($cfg,)?))]
                    if let ::core::option::Option::Some(handle) = &self.$variant {
                        let mut sub = handle.subscribe();
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
                            match &self.$variant {
                                ::core::option::Option::Some(handle) => {
                                    $crate::modules::dispatch_to(handle, frame).await
                                }
                                ::core::option::Option::None => {
                                    $crate::transport::frame::error_frame(
                                        &frame,
                                        ::std::string::String::from(
                                            "module not hosted on this node",
                                        ),
                                    )
                                }
                            }
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