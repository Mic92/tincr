#![no_main]
//! router/switch routing and ICMP/ARP/NDP/fragment reply builders. Must never panic.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| tincd::fuzz::route_frame(data));
