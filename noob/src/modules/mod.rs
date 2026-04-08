pub mod genshin;

// base for modules
use serde::{Deserialize, Serialize};

pub type ModuleId = u16;

pub trait Module: Send + Sync + 'static {
    const ID: ModuleId;
    const NAME: &str;

    type Request: Serialize + for<'de> Deserialize<'de> + Send;
    type Response: Serialize + for<'de> Deserialize<'de> + Send;

    fn handle(&self, req: Self::Request) -> Result<Self::Response, ModuleError>;
}

pub trait BroadcastModule: Module {
    type Broadcast: Serialize + for<'de> Deserialize<'de> + Send + Clone;
}

#[derive(Debug, thiserror::Error)]
pub enum ModuleError {
    #[error("module not found: {0}")]
    NotFound(ModuleId),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("{0}")]
    Other(String),
}
