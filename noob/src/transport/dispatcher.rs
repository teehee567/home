use crate::modules::Module;
use crate::transport::frame::{Frame, FrameKind, error_frame};

pub fn run_module<M: Module>(module: &M, frame: Frame) -> Frame {
    let req: M::Request = match postcard::from_bytes(&frame.payload) {
        Ok(req) => req,
        Err(e) => return error_frame(&frame, e.to_string()),
    };
    match module.handle(req) {
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


// Dispatch over module
#[macro_export]
macro_rules! dispatch_modules {
    ($(#[$meta:meta])* $vis:vis struct $name:ident {
        $($field:ident : $ty:ty),* $(,)?
    }) => {
        $(#[$meta])*
        $vis struct $name {
            $(pub $field: $ty,)*
        }

        impl $crate::transport::conn_manager::Dispatcher for $name {
            async fn dispatch(
                &self,
                _peer: $crate::transport::conn_manager::PeerId,
                frame: $crate::transport::frame::Frame,
            ) -> ::core::option::Option<$crate::transport::frame::Frame> {
                $(
                    if frame.route == <$ty as $crate::modules::Module>::ID {
                        return ::core::option::Option::Some(
                            $crate::transport::dispatcher::run_module(&self.$field, frame)
                        );
                    }
                )*
                ::core::option::Option::None
            }
        }
    };
}