//! Slotmap key newtypes shared across `conn.rs`, `outgoing.rs`,
//! `daemon.rs`. Hoisted so `Connection` can hold a typed
//! `Option<OutgoingId>` without a `daemon`/`outgoing` dep cycle.

use slotmap::new_key_type;

new_key_type! {
    /// Connection handle. Generational: stale id → `conns.get(id) == None`.
    pub struct ConnId;

    /// `outgoing_t*`. Slotmap key for `Daemon.outgoings`. Carried
    /// in `TimerWhat::RetryOutgoing(OutgoingId)` and on
    /// `Connection.outgoing` so `terminate` knows to retry.
    pub struct OutgoingId;
}
