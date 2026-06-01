use crate::modules::ModuleId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum FrameKind {
    Request,
    Response,
    Event,
    Error,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Frame {
    pub kind: FrameKind,
    pub route: ModuleId,
    pub request_id: u64,
    pub payload: Vec<u8>,
}

pub fn error_frame(frame: &Frame, msg: String) -> Frame {
    Frame {
        kind: FrameKind::Error,
        route: frame.route,
        request_id: frame.request_id,
        payload: postcard::to_allocvec(&msg).unwrap_or_default(),
    }
}