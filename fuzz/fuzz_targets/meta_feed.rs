#![no_main]
//! Meta-connection stream framing after the SPTPS handshake.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| tincd::fuzz::meta_feed(data));
