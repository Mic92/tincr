#![no_main]
//! `mss::clamp` on an ethernet frame (MTU in the first two bytes). Must never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| tincd::fuzz::mss_clamp(data));
