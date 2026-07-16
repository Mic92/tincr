//! Per-message-type parse/format. One module per `protocol_*.c` file.
//!
//! Each message type is a struct with `parse` and `format` methods.
//! Handlers in the daemon do `Msg::parse(line)?` then mutate state; the
//! mutation is *not* here, only the wire grammar.
//!
//! ## The `nonce` field
//!
//! `ADD_SUBNET`, `DEL_SUBNET`, `ADD_EDGE`, `DEL_EDGE`, `KEY_CHANGED` all
//! have a random hex second field. It's a dedup nonce: forwarded
//! messages are deduplicated by full string compare, and the nonce
//! ensures two identical-payload messages from different paths don't
//! collapse. We parse-but-skip it; the daemon supplies a fresh one
//! when formatting.

pub mod edge;
pub mod key;
pub mod misc;
pub mod subnet;

pub use edge::{AddEdge, DelEdge};
pub use key::{AnsKey, KeyChanged, ReqKey, ReqKeyExt};
pub use misc::{MtuInfo, SptpsPacket, TcpPacket, UdpInfo};
pub use subnet::SubnetMsg;
