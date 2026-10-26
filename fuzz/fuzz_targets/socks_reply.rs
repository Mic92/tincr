#![no_main]
//! SOCKS4/5 proxy reply parsing. Must never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| tincd::fuzz::socks_reply(data));
