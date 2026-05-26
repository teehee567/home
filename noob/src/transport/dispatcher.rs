use crate::transport::{conn_manager::{Dispatcher, PeerId}, frame::Frame};



pub struct ServerDispatcher {

}

impl Dispatcher for ServerDispatcher {
    async fn dispatch(&self, peer: PeerId, frame: Frame) -> Option<Frame> {

        return None
    }
}