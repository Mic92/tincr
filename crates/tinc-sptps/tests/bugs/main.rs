//! Regressions for error-path defects found during testing-strategy review.

#[path = "../common/mod.rs"]
pub mod common;

mod adversarial_framing;
mod c_interop;
mod confirm_state_send;
mod fastpath_replay_window;
mod hybrid_stream;
mod open_data_into_err_buffer;
mod send_record_oversized;
mod seqno_wrap_nonce_reuse;
