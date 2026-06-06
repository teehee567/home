//! Networking glue: a symmetric `Node` over the `CoreStream` transport.
//!
//! Every node hosts a `Modules` dispatcher and a `PeerPool`; "server" and "client"
//! are roles (listen vs dial), not types. See `docs/networking-plan.md`.

pub mod remote;
