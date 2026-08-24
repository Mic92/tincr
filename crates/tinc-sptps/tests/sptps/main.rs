//! Rust↔Rust SPTPS tests. The C differential tests live in `vs_c.rs`.

#[path = "../common/mod.rs"]
mod common;

mod aead;
mod fastpath;
mod framing;
mod hybrid;
mod hybrid_confirm;
mod nonce_limit;
mod rekey;
mod replay_window;
mod small_order;
mod stream_reassembly;
