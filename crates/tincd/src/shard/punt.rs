//! Worker → control-thread punt channel for slow-path packets.
//! Bounded, drop-on-full (UDP semantics), free-list so the steady
//! state allocates nothing. Mutex over lock-free: punts are the slow
//! path by construction, and this keeps the module safe code only.
//! The worker kicks an eventfd after pushing; control drains on wake.

#![allow(dead_code)] // see worker.rs
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
    pub src: SocketAddr,
    /// Listener slot index for the reply path.
    pub sock: u8,
}

pub(crate) struct PuntQueue {
    q: Mutex<Inner>,
}

struct Inner {
    full: VecDeque<PuntPkt>,
    #[allow(clippy::vec_box)] // boxes move in/out of PuntPkt without a 2KB copy
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
    pub(crate) fn push(&self, pkt: &[u8], src: SocketAddr, sock: u8) -> bool {
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
            sock,
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
        assert!(q.push(b"hello", addr(), 3));
        let p = q.pop().unwrap();
        assert_eq!(&p.buf[..usize::from(p.len)], b"hello");
        assert_eq!(p.sock, 3);
        assert_eq!(p.src, addr());
        q.recycle(p.buf);
        assert!(q.pop().is_none());
    }

    #[test]
    fn drops_when_full_and_counts() {
        let q = PuntQueue::new();
        for _ in 0..PUNT_CAP {
            assert!(q.push(b"x", addr(), 0));
        }
        assert!(!q.push(b"x", addr(), 0));
        assert_eq!(q.dropped(), 1);
    }

    #[test]
    fn freelist_reuses_buffers() {
        let q = PuntQueue::new();
        assert!(q.push(b"a", addr(), 0));
        let p = q.pop().unwrap();
        let ptr = std::ptr::from_ref(&*p.buf) as usize;
        q.recycle(p.buf);
        assert!(q.push(b"b", addr(), 0));
        let p2 = q.pop().unwrap();
        assert_eq!(std::ptr::from_ref(&*p2.buf) as usize, ptr);
    }
}
