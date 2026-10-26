#![no_main]
//! `tso_split` on `[vnet_hdr][IP]`. Must never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| tinc_device::fuzz::tso(data));
