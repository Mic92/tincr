//! 6-byte SHA-512-prefix node identity (`node.c:125-132`, `net.h:61-63`).
//!
//! Every UDP packet on the wire is `[dst_id:6][src_id:6][sptps...]`
//! (`net.h:92-93` `SRCID`/`DSTID` macros, `DEFAULT_PACKET_OFFSET=12`).
//! The receiver does a HashMap lookup on the 6-byte source ID
//! (`net_packet.c:617-633` `lookup_node_id`) to find which peer's
//! SPTPS state to feed the ciphertext to. On miss it falls back to
//! `try_mac` — trial-decrypt against every node — which is the slow
//! path the ID prefix exists to avoid.
//!
//! The ID is `SHA-512(name)[:6]`. C `node_add` (`node.c:126-128`):
//! `sha512(n->name, strlen(n->name), buf); memcpy(&n->id, buf, 6)`.
//! No NUL byte. Names are ASCII (`net_setup.c` validates `[A-Za-z0-9_]`)
//! but the hash doesn't care; we hash `str::as_bytes()`.
//!
//! ## Why a side table, not a `graph::Node` field
//!
//! C stores `node_id_t id` inline in `node_t` and keys a second splay
//! tree on it (`node_id_tree`, `node.c:60`). `tinc-graph::Node` is the
//! pure-BFS slot — no daemon-layer baggage. So we keep the bidi map
//! here: `NodeId6 → NodeId` for the UDP receive path, `NodeId →
//! NodeId6` for the send path (we need our own ID to write into
//! `SRCID`). Same data, two indices, like the C's two trees.

#![forbid(unsafe_code)]

use std::fmt;

use crate::inthash::IntHashMap;

use sha2::{Digest, Sha512};
use tinc_graph::NodeId;

/// `node_id_t` (`net.h:61-63`): `struct { uint8_t x[6]; }`.
///
/// `Copy` because the C passes it by value all over `net_packet.c`.
/// `Hash`/`Eq` because it's a HashMap key (the C uses `memcmp` via
/// `node_id_compare`, `node.c:63-65`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId6([u8; 6]);

impl NodeId6 {
    /// `net_packet.c:1014`: `node_id_t nullid = {0}`. Six zero bytes
    /// is the "no source ID" marker on the relay path: when `to !=
    /// myself` we forward, and the forwarded packet's SRCID stays
    /// null so the final hop's `lookup_node_id` falls through to
    /// `try_mac`. (Relay nodes don't have the endpoint's SPTPS key
    /// anyway, so the ID lookup would be useless to them.)
    pub const NULL: Self = Self([0; 6]);

    /// `node.c:126-128`. SHA-512 of `name` bytes (no NUL), keep the
    /// first 6.
    ///
    /// `strlen` in the C means UTF-8 bytes here, not chars — but
    /// node names are validated ASCII upstream so the distinction
    /// is moot. We hash `as_bytes()` to match `strlen` exactly.
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        let digest = Sha512::digest(name.as_bytes());
        let mut id = [0u8; 6];
        id.copy_from_slice(&digest[..6]);
        Self(id)
    }

    #[must_use]
    pub fn is_null(&self) -> bool {
        self.0 == [0; 6]
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Construct from raw wire bytes. The UDP receive path slices 6
    /// bytes out of the packet buffer at `SRCID`/`DSTID` offsets;
    /// this is the typed wrapper for that slice.
    #[must_use]
    pub fn from_bytes(b: [u8; 6]) -> Self {
        Self(b)
    }
}

/// `node.c:204-208` `dump_nodes` format: `snprintf(id + 2*c, 3,
/// "%02x", n->id.x[c])` for `c` in `0..6`. Lowercase, no separators,
/// 12 chars. Chunk-5 `dump_nodes` currently writes the literal
/// `"000000000000"`; this is the real value to slot in there.
impl fmt::Display for NodeId6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for NodeId6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId6({self})")
    }
}

/// `node_id_tree` (`node.c:60`). C uses a splay tree keyed on
/// `memcmp` of the 6 bytes; we use a HashMap. The reverse index
/// (`by_node`) replaces the C's inline `n->id` field — `graph::Node`
/// doesn't carry it, so we keep a side table.
///
/// ## Collisions
///
/// 48 bits, SHA-512 is uniform. Birthday bound is ~16M nodes before
/// 50% collision probability. The C does NOT handle this:
/// `splay_insert` returns NULL on duplicate key, `node.c:131` ignores
/// the return. A second node with the same ID just doesn't get
/// indexed, so UDP packets from it fall through to `try_mac`.
///
/// We diverge slightly: insert-overwrites + WARN. Either way a real
/// collision means a misconfigured (or hostile) network; the WARN is
/// the operator-visible breadcrumb the C lacks.
#[derive(Default)]
pub struct NodeId6Table {
    // IntHashMap: NodeId6 is 48 bits of SHA-512 output (already
    // uniform; no DoS-resistant hash needed) and NodeId is a dense
    // u32 slab index. Per-packet UDP recv path hits `by_id` once
    // (`handle_incoming_vpn_packet`), send path hits `by_node` twice
    // (`send_sptps_data_relay` for src+dst id6). At 1.5 Mpps,
    // SipHash-on-6-bytes was material; see `inthash.rs`.
    by_id: IntHashMap<NodeId6, NodeId>,
    by_node: IntHashMap<NodeId, NodeId6>,
}

impl NodeId6Table {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// `node_add` (`node.c:125-131`). Computes the ID from `name` and
    /// indexes both directions. Called alongside `lookup_or_add_node`
    /// — every node the daemon learns about (from `ADD_EDGE`, from
    /// config, from invite) gets an entry here.
    ///
    /// On collision (different `NodeId`, same `NodeId6`): overwrites
    /// and logs WARN. The C silently drops; we make it loud. The old
    /// `by_node` entry for the displaced node is left dangling — its
    /// `id_of()` still returns the (now-reassigned) ID. That's fine:
    /// `id_of` is for the send path, and we'll still write a valid ID
    /// into outgoing packets. The receive path is what's ambiguous,
    /// and that ambiguity is inherent to a 48-bit hash, not our bug.
    pub fn add(&mut self, name: &str, node: NodeId) {
        let id6 = NodeId6::from_name(name);
        self.insert_raw(id6, node, name);
    }

    /// Direct insert without hashing `name`. Exposed for the
    /// collision test (which needs to force a duplicate `NodeId6`
    /// without finding a SHA-512 collision). The daemon never calls
    /// this — `add` is the only entry point in production.
    pub(crate) fn insert_raw(&mut self, id6: NodeId6, node: NodeId, name: &str) {
        if let Some(&prev) = self.by_id.get(&id6)
            && prev != node
        {
            log::warn!(
                target: "tincd",
                "node_id collision: {name} → {id6} already maps to {prev:?}, overwriting"
            );
        }
        self.by_id.insert(id6, node);
        self.by_node.insert(node, id6);
    }

    /// `lookup_node_id` (`node.c:157-160`). The UDP fast path:
    /// `net_packet.c:617-633` reads 6 bytes at `SRCID(pkt)`, calls
    /// this, gets the graph slot. `None` → fall back to `try_mac`.
    #[must_use]
    pub fn lookup(&self, id6: NodeId6) -> Option<NodeId> {
        self.by_id.get(&id6).copied()
    }

    /// Reverse lookup: which 6-byte ID does this graph slot have?
    /// The send path needs this to write `SRCID` into outgoing
    /// packets (`net_packet.c` writes `myself->id`). C reads
    /// `n->id` inline; we look it up here.
    #[must_use]
    pub fn id_of(&self, node: NodeId) -> Option<NodeId6> {
        self.by_node.get(&node).copied()
    }

    /// `node_del` (`node.c:144-145`): `splay_delete(&node_id_tree,
    /// n)`. Called when a node leaves the mesh. We remove both
    /// directions.
    ///
    /// If a collision had displaced this node from `by_id`, the
    /// `by_id.remove` is a no-op on the wrong key — but we look up
    /// via `by_node` first, so we remove the right `by_id` entry
    /// (which may now belong to the *colliding* node). That's a
    /// second-order collision mess; in practice, with <16M nodes,
    /// this code path is dead.
    pub fn remove(&mut self, node: NodeId) {
        if let Some(id6) = self.by_node.remove(&node) {
            // Only remove from by_id if it still points to us.
            // Guards against the collision-displacement case: if
            // another node overwrote our by_id slot, don't yank
            // *their* entry.
            if self.by_id.get(&id6) == Some(&node) {
                self.by_id.remove(&id6);
            }
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_node.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_node.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ─── KAT: NodeId6::from_name vs C sha512 ─────────────────────

    /// Vectors from `kat/gen_node_id.c`, which links the actual
    /// `src/ed25519/sha512.c` (LibTomCrypt) and emits `buf[0..6]`
    /// hex. Regenerate: `nix build .#kat-node-id`.
    ///
    /// The empty-string case (`cf83e1357eef`) is the well-known
    /// SHA-512("") prefix — sanity anchor independent of tinc.
    #[test]
    fn from_name_kat() {
        #[rustfmt::skip]
        let cases: &[(&str, &str)] = &[
            ("alice",                                    "408b27d3097e"),
            ("bob",                                      "0416a26ba554"),
            ("",                                         "cf83e1357eef"),
            ("long_name_with_underscores_and_digits123", "3de528e9ad98"),
        ];
        for (name, want_hex) in cases {
            let got = NodeId6::from_name(name);
            assert_eq!(
                got.to_string(),
                *want_hex,
                "from_name({name:?}) = {got} want {want_hex}"
            );
        }
    }

    #[test]
    fn null_is_zero_is_null() {
        assert_eq!(NodeId6::NULL.as_bytes(), &[0u8; 6]);
        assert!(NodeId6::NULL.is_null());
        assert!(!NodeId6::from_name("alice").is_null());
        assert_eq!(NodeId6::from_bytes([0; 6]), NodeId6::NULL);
    }

    /// `node.c:204-208`: the `dump_nodes` snprintf loop. `%02x`
    /// lowercase, 6 iterations, no separators → 12 chars exactly.
    /// The KAT above already checks the *value*; this checks the
    /// *format invariants* independently.
    #[test]
    fn display_is_12_hex_lowercase() {
        let id = NodeId6::from_name("alice");
        let s = id.to_string();
        assert_eq!(s.len(), 12);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
        // And NULL specifically: the chunk-5 dump_nodes placeholder.
        assert_eq!(NodeId6::NULL.to_string(), "000000000000");
    }

    // ─── NodeId6Table ────────────────────────────────────────────

    #[test]
    fn table_roundtrip() {
        let mut t = NodeId6Table::new();
        assert!(t.is_empty());

        let alice = NodeId(1);
        let bob = NodeId(2);
        t.add("alice", alice);
        t.add("bob", bob);
        assert_eq!(t.len(), 2);

        // Forward: id6 → NodeId. The UDP receive path.
        let alice_id6 = NodeId6::from_name("alice");
        assert_eq!(t.lookup(alice_id6), Some(alice));
        assert_eq!(t.lookup(NodeId6::from_name("bob")), Some(bob));
        assert_eq!(t.lookup(NodeId6::from_name("carol")), None);

        // Reverse: NodeId → id6. The send path (write SRCID).
        assert_eq!(t.id_of(alice), Some(alice_id6));
        assert_eq!(t.id_of(NodeId(99)), None);

        // Remove clears both directions.
        t.remove(alice);
        assert_eq!(t.lookup(alice_id6), None);
        assert_eq!(t.id_of(alice), None);
        assert_eq!(t.len(), 1);

        // Removing an unknown node is a no-op (C splay_delete same).
        t.remove(NodeId(99));
        assert_eq!(t.len(), 1);
    }

    /// Two distinct graph slots, manually mapped to the SAME 6-byte
    /// ID via `insert_raw` (we're not finding a real SHA-512
    /// collision in a unit test). Second insert overwrites; both
    /// `by_node` entries persist; removing the displaced node does
    /// NOT yank the survivor's `by_id` entry.
    ///
    /// We don't capture the WARN log here — `log` crate test capture
    /// needs `testing_logger` or similar, not in our dev-deps. The
    /// overwrite *behavior* is what we assert; the WARN is best-
    /// effort operator UX.
    #[test]
    fn table_collision_overwrites() {
        let mut t = NodeId6Table::new();
        let id6 = NodeId6::from_bytes([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]);
        let n1 = NodeId(1);
        let n2 = NodeId(2);

        t.insert_raw(id6, n1, "first");
        assert_eq!(t.lookup(id6), Some(n1));

        // Collision: same id6, different NodeId. Logs WARN, overwrites.
        t.insert_raw(id6, n2, "second");
        assert_eq!(t.lookup(id6), Some(n2), "by_id overwritten");

        // by_node still has BOTH entries — id_of works for both.
        // (The displaced node can still send; it just can't be
        // looked up on receive. That's the C's behavior too: n->id
        // is set, but node_id_tree only indexes one of them.)
        assert_eq!(t.id_of(n1), Some(id6));
        assert_eq!(t.id_of(n2), Some(id6));

        // Removing the displaced node: must NOT yank n2's by_id slot.
        t.remove(n1);
        assert_eq!(t.lookup(id6), Some(n2), "survivor's by_id intact");
        assert_eq!(t.id_of(n1), None);
    }
}
