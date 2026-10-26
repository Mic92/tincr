#![no_main]
//! `GroBucket::offer` on a packet stream, flushed output fed to `tso_split`. Must never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| tinc_device::fuzz::gro(data));
