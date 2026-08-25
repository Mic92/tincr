//! Worker → control-thread punt channel for slow-path packets.
//! Bounded, drop-on-full (UDP semantics), free-list so the steady
//! state allocates nothing. Mutex over lock-free: punts are the slow
//! path by construction, and this keeps the module safe code only.
//! The worker kicks an eventfd after pushing; control drains on wake.

#![cfg_attr(not(test), expect(dead_code))]
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Mutex;

/// Max punted frame: MTU-sized UDP payload. Supers are never punted whole.
pub(crate) const PUNT_SLOT: usize = 2048;

/// 256 × 2KB = 512KB worst case per worker; beyond that dropping
/// beats queueing more behind an already-lagging control thread.
const PUNT_CAP: usize = 256;

pub(crate) struct PuntPkt {
    pub buf: Box<[u8; PUNT_SLOT]>,
    pub len: u16,
    /// `Some` = UDP datagram from this source; `None` = TUN frame.
    pub src: Option<SocketAddr>,
}

pub(crate) struct PuntQueue {
    q: Mutex<Inner>,
}

struct Inner {
    full: VecDeque<PuntPkt>,
    #[expect(clippy::vec_box)] // boxes move in/out of PuntPkt without a 2KB copy
    free: Vec<Box<[u8; PUNT_SLOT]>>,
    dropped: u64,
}

impl PuntQueue {
    pub(crate) fn new() -> Self {
        Self {
            q: Mutex::new(Inner {
                full: VecDeque::with_capacity(PUNT_CAP),
                free: Vec::new(),
                dropped: 0,
            }),
        }
    }

    /// `false` = ring full, packet dropped.
    pub(crate) fn push(&self, pkt: &[u8], src: Option<SocketAddr>) -> bool {
        debug_assert!(pkt.len() <= PUNT_SLOT);
        let mut q = self.q.lock().expect("punt lock");
        if q.full.len() >= PUNT_CAP {
            q.dropped += 1;
            return false;
        }
        let mut buf = q.free.pop().unwrap_or_else(|| Box::new([0u8; PUNT_SLOT]));
        buf[..pkt.len()].copy_from_slice(pkt);
        #[expect(clippy::cast_possible_truncation)] // ≤ PUNT_SLOT
        q.full.push_back(PuntPkt {
            buf,
            len: pkt.len() as u16,
            src,
        });
        true
    }

    /// Caller returns the buffer via [`recycle`] after processing.
    pub(crate) fn pop(&self) -> Option<PuntPkt> {
        self.q.lock().expect("punt lock").full.pop_front()
    }

    pub(crate) fn recycle(&self, buf: Box<[u8; PUNT_SLOT]>) {
        let mut q = self.q.lock().expect("punt lock");
        if q.free.len() < PUNT_CAP {
            q.free.push(buf);
        }
    }

    pub(crate) fn dropped(&self) -> u64 {
        self.q.lock().expect("punt lock").dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "10.0.0.1:655".parse().unwrap()
    }

    #[test]
    fn push_pop_roundtrip() {
        let q = PuntQueue::new();
        assert!(q.push(b"hello", Some(addr())));
        let p = q.pop().unwrap();
        assert_eq!(&p.buf[..usize::from(p.len)], b"hello");
        assert_eq!(p.src, Some(addr()));
        q.recycle(p.buf);
        assert!(q.pop().is_none());
    }

    #[test]
    fn drops_when_full_and_counts() {
        let q = PuntQueue::new();
        for _ in 0..PUNT_CAP {
            assert!(q.push(b"x", None));
        }
        assert!(!q.push(b"x", None));
        assert_eq!(q.dropped(), 1);
    }

    #[test]
    fn freelist_reuses_buffers() {
        let q = PuntQueue::new();
        assert!(q.push(b"a", Some(addr())));
        let p = q.pop().unwrap();
        let ptr = std::ptr::from_ref(&*p.buf) as usize;
        q.recycle(p.buf);
        assert!(q.push(b"b", Some(addr())));
        let p2 = q.pop().unwrap();
        assert_eq!(std::ptr::from_ref(&*p2.buf) as usize, ptr);
    }
}
