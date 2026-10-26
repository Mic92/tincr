//! Entry points for `fuzz/` (cargo-fuzz): arbitrary bytes into the
//! TSO splitter and the GRO coalescer. The only property is "does not
//! panic". Compiled with the `fuzzing` feature and in tests.

use crate::{DeviceArena, GroBucket, GroVerdict, GsoType, VNET_HDR_LEN, VirtioNetHdr, tso_split};

/// Same scratch shape as the daemon's device path.
const SEGMENTS: usize = 64;

/// `[vnet_hdr(10)][IP super-segment]`, as the TUN device delivers it.
pub fn tso(data: &[u8]) {
    let Some(hdr) = VirtioNetHdr::decode(data) else {
        return;
    };
    let pkt = data.get(VNET_HDR_LEN..).unwrap_or_default();
    split(&hdr, pkt);
}

fn split(hdr: &VirtioNetHdr, pkt: &[u8]) {
    let Some(gso_type) = hdr.gso() else {
        return;
    };
    if matches!(gso_type, GsoType::None) {
        return;
    }
    let mut out = vec![0u8; SEGMENTS * DeviceArena::STRIDE];
    let mut lens = [0usize; SEGMENTS];
    let _ = tso_split(pkt, hdr, gso_type, &mut out, DeviceArena::STRIDE, &mut lens);
}

/// A stream of IP packets, each prefixed by a little-endian `u16`
/// length, offered to one `GroBucket` the way the daemon does. Every
/// flushed super-segment is fed back through `tso_split`, which must
/// accept whatever GRO built.
pub fn gro(mut data: &[u8]) {
    let mut bucket = GroBucket::new();
    while let [a, b, rest @ ..] = data {
        let len = usize::from(u16::from_le_bytes([*a, *b])).min(rest.len());
        let (ip, tail) = rest.split_at(len);
        data = tail;
        if matches!(bucket.offer(ip), GroVerdict::FlushFirst) {
            flush(&mut bucket);
            let _ = bucket.offer(ip);
        }
    }
    flush(&mut bucket);
}

fn flush(bucket: &mut GroBucket) {
    if let Some(frame) = bucket.flush() {
        let frame = frame.to_vec();
        tso(&frame);
    }
}

#[cfg(test)]
mod tests {
    use super::{gro, tso};

    #[test]
    fn smoke() {
        for data in [&[][..], &[0; 64], &[0xff; 1600]] {
            tso(data);
            gro(data);
        }
    }
}
