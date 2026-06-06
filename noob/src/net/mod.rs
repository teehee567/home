pub mod node;
pub mod remote;

pub use node::Node;
pub use remote::{RemoteEvents, RemoteHandle};

use crate::transport::conn_manager::{Dispatcher, PeerId};
use crate::transport::frame::Frame;

pub const STREAM_ID: u16 = 1;

pub struct NoDispatch;

impl Dispatcher for NoDispatch {
    async fn dispatch(&self, _peer: PeerId, _frame: Frame) -> Option<Frame> {
        None
    }
}