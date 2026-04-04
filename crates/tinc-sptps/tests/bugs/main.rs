//! Regressions for error-path defects found during testing-strategy review.

#[path = "../common/mod.rs"]
mod common;

mod fastpath_replay_window;
mod open_data_into_err_buffer;
mod send_record_oversized;
