//! `variables[]` — `tincctl.c:1680-1758`. The static metadata table
//! about config keys: which file they belong in, whether they repeat,
//! whether they're obsolete, whether they're safe to accept from an
//! untrusted invitation.
//!
//! ## Why this lives in `tinc-conf` not `tinc-tools`
//!
//! Four consumers in C:
//!
//! | Consumer | Uses |
//! |---|---|
//! | `fsck.c:157` | linear scan; warn on obsolete, server-var-in-host, host-var-in-server, non-multiple-appearing-twice |
//! | `tincctl.c:1858` (`cmd_config` set/get) | lookup; reject set on obsolete, reject `node.var` if `!HOST`, reject bare `var` if `!SERVER`, downgrade `add` → `set` if `!MULTIPLE` |
//! | `invitation.c:879` | lookup; reject `!SAFE` keys from invitation payload (defense: invitation comes from a peer you don't yet trust) |
//! | `tincctl.c:3100` (tab-complete) | prefix scan over names |
//!
//! Three of four are `tinc-tools` commands (4a/5b). One is the daemon
//! (invitation handling, Phase 5). The table is *about* config keys,
//! which is `tinc-conf`'s domain. Putting it here means both binaries
//! reach it without `tinc-tools` ← `tincd` or vice versa.
//!
//! ## Why not generate this from C
//!
//! It's static data — 74 entries, never changes except when adding a
//! config key (rare; daemon work). The C source IS the spec. Hand-
//! transcription is one-shot work, and the test at the bottom counts
//! entries and spot-checks flags so transcription drift gets caught.
//! Generating it would mean either parsing C (fragile) or building +
//! introspecting the C binary (a whole nix derivation for 74 lines).
//!
//! ## Flags as `u8` newtype, not `bitflags!`
//!
//! Five flags. `u8` holds eight. The methods we need are `contains`,
//! `union` (in the table only, via `|`), `iter` over flag bits (for
//! tests). Hand-rolling those is ~20 LOC; `bitflags` is a dep + a
//! macro for the same. The newtype keeps the bare `u8` from leaking —
//! callers can't `flags & 1` and forget which bit is which.
//!
//! ## Lookup
//!
//! C does linear scan + `strcasecmp` everywhere. 74 entries, called
//! once-per-config-line at fsck time or once-per-set-command. We do
//! the same: linear scan, `eq_ignore_ascii_case` (not folded — the
//! query strings come from parsed config, which already preserves
//! case for error messages). Returns `Option<&'static Var>` so the
//! canonical-case `name` is available — `cmd_config` uses it to
//! normalize `port` → `Port` in the file it writes (`tincctl.c:1864`).
//!
//! Tab-complete needs prefix scan; that's just `.iter()` on the
//! slice. Expose `VARS` directly for that.
//!
//! ## The table is NOT in canonical order
//!
//! C has it in two blocks: server-only first (alpha-ish), then the
//! `VAR_HOST` ones. **`MTUInfoInterval` and `UDPInfoInterval` break
//! alpha** in the server block (they're after `UDPDiscoveryTimeout`).
//! We preserve the C order. fsck's duplicate-count uses `count[i]`
//! indexed by table position — the *index* is stable across C and
//! Rust if and only if the order matches. fsck doesn't compare its
//! `count` array to a C-produced one (it's local), so divergence
//! wouldn't break anything observable. But: free invariant, costs
//! nothing, and "the table matches the C table" is easier to reason
//! about than "the table is the C table sorted."
//!
//! ## `DISABLE_LEGACY` doesn't gate anything here
//!
//! Checked: no `#ifdef DISABLE_LEGACY` in the table. `Cipher`,
//! `Digest`, `MACLength` (legacy crypto knobs) are all present
//! unconditionally. The daemon ignores them under nolegacy; fsck
//! still validates them as "this is a known key, it's not obsolete,
//! it's HOST-allowed." That's correct: a config file with `Cipher =
//! aes-256-cbc` is *valid syntax* even on a daemon that ignores it.

#![allow(clippy::doc_markdown)]

/// Bitflags for config-key metadata. `tincctl.h:36-40`.
///
/// `u8` newtype — see module doc for why not `bitflags!`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VarFlags(u8);

impl VarFlags {
    /// `VAR_SERVER = 1`. Allowed in `tinc.conf`. Almost everything
    /// has this; the few exceptions (`Address`, `Ed25519PublicKey`,
    /// `Port`, `PublicKey`, `Subnet`, `Weight`) are HOST-only because
    /// they describe a *peer*, not the daemon's own behavior. `Port`
    /// is the surprising one — your own port goes in `hosts/YOU`, not
    /// `tinc.conf`. The daemon reads its *own* host file at startup
    /// (`read_host_config(myself->name)`, `conf_net.c`).
    pub const SERVER: Self = Self(1);

    /// `VAR_HOST = 2`. Allowed in `hosts/*` files. The dual-tagged
    /// keys (`SERVER | HOST`) are settable as either daemon-wide
    /// default in `tinc.conf` or per-peer override in `hosts/NAME`.
    /// `Compression`, `ClampMSS`, `TCPOnly` etc — knobs you might
    /// want different per peer.
    pub const HOST: Self = Self(2);

    /// `VAR_MULTIPLE = 4`. May appear more than once. `Subnet`,
    /// `ConnectTo`, `Address` (a peer can have several). Everything
    /// else is single-valued; the parser silently keeps the *first*
    /// occurrence (`Config::lookup().next()`). fsck warns when a
    /// non-MULTIPLE key appears twice — it's the only place that
    /// surfaces the silent-first-wins behavior. `cmd_config add`
    /// downgrades to `set` for non-MULTIPLE keys (`tincctl.c:1915`)
    /// — adding a second `Port` would silently shadow itself.
    pub const MULTIPLE: Self = Self(4);

    /// `VAR_OBSOLETE = 8`. Deprecated. fsck warns; `cmd_config set`
    /// warns + asks for confirmation. Four keys: `GraphDumpFile`
    /// (replaced by `tinc dump graph`), `PrivateKey`/`PublicKey`/
    /// `PublicKeyFile` (the old RSA-inline-in-config-file scheme).
    pub const OBSOLETE: Self = Self(8);

    /// `VAR_SAFE = 16`. Safe to accept from an invitation payload.
    /// Invitations are how you join a network: a peer you don't yet
    /// trust sends you a config blob. Letting that blob set `Device`
    /// or `ScriptsInterpreter` would be a remote-exec vector. SAFE
    /// is the allowlist — `Subnet`, `ConnectTo`, address-family/mode
    /// stuff. Anything that picks a file path or a binary is NOT
    /// safe. (`invitation.c:912`.)
    pub const SAFE: Self = Self(16);

    /// `flags.contains(VarFlags::SERVER)`. The C does `type &
    /// VAR_SERVER` everywhere; this is the type-safe spelling.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// `|` for table construction. `const` so the table is a `static`
    /// literal.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl core::ops::BitOr for VarFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl core::fmt::Debug for VarFlags {
    /// `SERVER|HOST|SAFE` form, not raw `u8`. For test failure
    /// messages — `assert_eq!(v.flags, ...)` prints something
    /// readable.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let names: &[_] = &[
            (Self::SERVER, "SERVER"),
            (Self::HOST, "HOST"),
            (Self::MULTIPLE, "MULTIPLE"),
            (Self::OBSOLETE, "OBSOLETE"),
            (Self::SAFE, "SAFE"),
        ];
        let mut first = true;
        for &(flag, name) in names {
            if self.contains(flag) {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        if first {
            // No flags set. Doesn't happen in the real table (every
            // entry has at least SERVER or HOST), but Debug should
            // be total.
            f.write_str("(none)")?;
        }
        Ok(())
    }
}

/// One row in the table. `var_t` (`tincctl.h:42-45`).
#[derive(Debug, Clone, Copy)]
pub struct Var {
    /// Canonical case. `Port`, not `port`. `cmd_config set port 655`
    /// writes `Port = 655` — the table is the canonicalization source
    /// (`tincctl.c:1864`: `variable = (char *)variables[i].name`).
    pub name: &'static str,
    pub flags: VarFlags,
}

// The table. Transcribed line-for-line from tincctl.c:1680-1758.
// C order preserved (see module doc). The {NULL, 0} sentinel is just
// the slice end.
//
// Spelling out the macro: `S` = SERVER, `H` = HOST, `M` = MULTIPLE,
// `O` = OBSOLETE, `F` (saFe) = SAFE. Single-letter consts to keep
// each row on one line — diff against the C is line-aligned that way.

#[allow(non_upper_case_globals)] // single-letter, scoped to this block
const S: VarFlags = VarFlags::SERVER;
#[allow(non_upper_case_globals)]
const H: VarFlags = VarFlags::HOST;
#[allow(non_upper_case_globals)]
const M: VarFlags = VarFlags::MULTIPLE;
#[allow(non_upper_case_globals)]
const O: VarFlags = VarFlags::OBSOLETE;
#[allow(non_upper_case_globals)]
const F: VarFlags = VarFlags::SAFE;

/// Shorthand. `v("Port", H)` reads better than `Var { name: "Port",
/// flags: H }` × 74. The C uses brace-init; this is the closest Rust
/// gets without a proc-macro.
const fn v(name: &'static str, flags: VarFlags) -> Var {
    Var { name, flags }
}

/// `variables[]`. The full table, C order. Public so tab-complete can
/// `.iter()` it.
///
/// **74 entries.** Asserted at the bottom — if you add one, bump the
/// assert. If the assert fires *without* you adding one, you have a
/// transcription error.
pub static VARS: &[Var] = &[
    // ─── Server configuration (tincctl.c:1681 comment) ──────────────
    v("AddressFamily", S.union(F)),
    v("AutoConnect", S.union(F)),
    v("BindToAddress", S.union(M)),
    v("BindToInterface", S),
    v("Broadcast", S.union(F)),
    v("BroadcastSubnet", S.union(M).union(F)),
    v("ConnectTo", S.union(M).union(F)),
    v("DecrementTTL", S.union(F)),
    v("Device", S),
    v("DeviceStandby", S),
    v("DeviceType", S),
    v("DirectOnly", S.union(F)),
    v("Ed25519PrivateKeyFile", S),
    v("ExperimentalProtocol", S),
    v("Forwarding", S),
    v("FWMark", S),
    v("GraphDumpFile", S.union(O)),
    v("Hostnames", S),
    v("IffOneQueue", S),
    v("Interface", S),
    v("InvitationExpire", S),
    v("KeyExpire", S.union(F)),
    v("ListenAddress", S.union(M)),
    v("LocalDiscovery", S.union(F)),
    v("LogLevel", S),
    v("MACExpire", S.union(F)),
    v("MaxConnectionBurst", S.union(F)),
    v("MaxOutputBufferSize", S.union(F)),
    v("MaxTimeout", S.union(F)),
    v("Mode", S.union(F)),
    v("Name", S),
    v("PingInterval", S.union(F)),
    v("PingTimeout", S.union(F)),
    v("PriorityInheritance", S),
    v("PrivateKey", S.union(O)),
    v("PrivateKeyFile", S),
    v("ProcessPriority", S),
    v("Proxy", S),
    v("ReplayWindow", S.union(F)),
    v("Sandbox", S),
    v("ScriptsExtension", S),
    v("ScriptsInterpreter", S),
    v("StrictSubnets", S.union(F)),
    v("TunnelServer", S.union(F)),
    v("UDPDiscovery", S.union(F)),
    v("UDPDiscoveryKeepaliveInterval", S.union(F)),
    v("UDPDiscoveryInterval", S.union(F)),
    v("UDPDiscoveryTimeout", S.union(F)),
    // ─── Alpha break in C: these two come after UDPDiscovery* ──────
    // tincctl.c:1731-1732. Preserved.
    v("MTUInfoInterval", S.union(F)),
    v("UDPInfoInterval", S.union(F)),
    v("UDPRcvBuf", S),
    v("UDPSndBuf", S),
    v("UPnP", S),
    v("UPnPDiscoverWait", S),
    v("UPnPRefreshPeriod", S),
    v("VDEGroup", S),
    v("VDEPort", S),
    // ─── Host configuration (tincctl.c:1740 comment) ────────────────
    v("Address", H.union(M)),
    v("Cipher", S.union(H)),
    v("ClampMSS", S.union(H).union(F)),
    v("Compression", S.union(H).union(F)),
    v("Digest", S.union(H)),
    v("Ed25519PublicKey", H),
    v("Ed25519PublicKeyFile", S.union(H)),
    v("IndirectData", S.union(H).union(F)),
    v("MACLength", S.union(H)),
    v("PMTU", S.union(H)),
    v("PMTUDiscovery", S.union(H)),
    v("Port", H),
    v("PublicKey", H.union(O)),
    v("PublicKeyFile", S.union(H).union(O)),
    v("Subnet", H.union(M).union(F)),
    v("TCPOnly", S.union(H).union(F)),
    v("Weight", H.union(F)),
];

/// Transcription tripwire. C has 74 entries (`grep '{"' | wc -l` on
/// `tincctl.c:1681-1758`). If this fires, count again.
const _: () = assert!(VARS.len() == 74);

/// Look up by name, case-insensitive. C does this inline everywhere
/// (`for(i=0; variables[i].name; i++) if(!strcasecmp(...))`). We
/// give it a name.
///
/// Returns `Option<&'static Var>` — the `&'static` matters for
/// `cmd_config`'s canonicalization: `lookup("port").unwrap().name`
/// gives `"Port"` with `'static` lifetime, no clone needed.
///
/// `None` for unknown keys. fsck *skips* unknowns (`var_type == 0` →
/// `continue`, `fsck.c:164`) — this is intentional: a typo'd key
/// doesn't crash, it's just inert (and the actual `Config::lookup`
/// finds nothing, so the daemon ignores it). Surfacing "unknown key"
/// as a warning is a feature request, not a port — the C doesn't.
#[must_use]
pub fn lookup(name: &str) -> Option<&'static Var> {
    VARS.iter().find(|v| v.name.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spot-check transcription. Not exhaustive — exhaustive would be
    /// reading the C, which is what we just did. These cover one entry
    /// per flag-combination shape, plus the alpha-break boundary.
    #[test]
    fn spot_check() {
        // Pure SERVER.
        let v = lookup("Device").unwrap();
        assert_eq!(v.name, "Device");
        assert_eq!(v.flags, S);

        // SERVER | SAFE — most common combo.
        assert_eq!(lookup("Mode").unwrap().flags, S | F);

        // SERVER | MULTIPLE.
        assert_eq!(lookup("BindToAddress").unwrap().flags, S | M);

        // SERVER | MULTIPLE | SAFE.
        assert_eq!(lookup("ConnectTo").unwrap().flags, S | M | F);

        // SERVER | OBSOLETE.
        assert_eq!(lookup("GraphDumpFile").unwrap().flags, S | O);

        // Pure HOST.
        assert_eq!(lookup("Port").unwrap().flags, H);

        // HOST | MULTIPLE.
        assert_eq!(lookup("Address").unwrap().flags, H | M);

        // HOST | MULTIPLE | SAFE — Subnet, the most-set key in
        // practice.
        assert_eq!(lookup("Subnet").unwrap().flags, H | M | F);

        // SERVER | HOST — dual-tagged.
        assert_eq!(lookup("Cipher").unwrap().flags, S | H);

        // SERVER | HOST | SAFE.
        assert_eq!(lookup("Compression").unwrap().flags, S | H | F);

        // SERVER | HOST | OBSOLETE.
        assert_eq!(lookup("PublicKeyFile").unwrap().flags, S | H | O);

        // The alpha-break boundary (tincctl.c:1731). MTUInfoInterval
        // is at index 48 in the C array (zero-indexed). Verify our
        // index matches — proves order preservation, not just content.
        assert_eq!(VARS[48].name, "MTUInfoInterval");
        assert_eq!(VARS[49].name, "UDPInfoInterval");
    }

    /// Case-insensitive lookup. C uses `strcasecmp`.
    #[test]
    fn lookup_case_insensitive() {
        // Canonical case → finds it.
        assert_eq!(lookup("Port").unwrap().name, "Port");
        // Lower → still finds it. `name` is the *canonical* case,
        // not the query case — that's the canonicalization.
        assert_eq!(lookup("port").unwrap().name, "Port");
        // Upper.
        assert_eq!(lookup("PORT").unwrap().name, "Port");
        // Mixed.
        assert_eq!(lookup("ed25519publickey").unwrap().name, "Ed25519PublicKey");
    }

    /// Unknown keys. Including the easy-to-typo ones.
    #[test]
    fn lookup_unknown() {
        assert!(lookup("NotARealKey").is_none());
        assert!(lookup("").is_none());
        // `Subnets` (plural) is not a key. `Subnet` is.
        assert!(lookup("Subnets").is_none());
    }

    /// Every entry has at least SERVER or HOST. Nothing in the table
    /// is "neither" — that would be a key valid nowhere, which is
    /// nonsense. (OBSOLETE entries still have SERVER or HOST: they're
    /// obsolete *but were once valid somewhere*.)
    #[test]
    fn every_entry_is_server_or_host() {
        for v in VARS {
            assert!(
                v.flags.contains(VarFlags::SERVER) || v.flags.contains(VarFlags::HOST),
                "{} has neither SERVER nor HOST",
                v.name
            );
        }
    }

    /// No duplicate names. The C doesn't check this (linear scan
    /// finds the first; a duplicate would be silently shadowed). We
    /// check at test time.
    #[test]
    fn no_duplicate_names() {
        // Folded set. n=74, O(n²) is 5476 comparisons, instant.
        for (i, a) in VARS.iter().enumerate() {
            for b in &VARS[i + 1..] {
                assert!(
                    !a.name.eq_ignore_ascii_case(b.name),
                    "duplicate: {} / {}",
                    a.name,
                    b.name
                );
            }
        }
    }

    /// Flag predicates spelled out. The Debug impl is the readable
    /// form; test it once so a future Debug rewrite doesn't silently
    /// regress test-failure messages.
    #[test]
    fn flags_debug() {
        assert_eq!(format!("{:?}", S | H | F), "SERVER|HOST|SAFE");
        assert_eq!(format!("{S:?}"), "SERVER");
        assert_eq!(format!("{:?}", VarFlags(0)), "(none)");
    }

    /// `contains` semantics. `S | H` contains `S`, contains `H`,
    /// contains `S | H`, does NOT contain `M`. Obvious, but `&==` vs
    /// `&!=0` is a one-character bug that this would catch.
    #[test]
    fn flags_contains() {
        let f = S | H;
        assert!(f.contains(S));
        assert!(f.contains(H));
        assert!(f.contains(S | H));
        assert!(!f.contains(M));
        // The subtle one: `contains(S | M)` on `S | H` is FALSE. Both
        // bits required, only one present. C `(type & (S|M)) == (S|M)`
        // semantics. (C consumers actually test one bit at a time so
        // this case never comes up there; but `contains` should be
        // correct anyway.)
        assert!(!f.contains(S | M));
    }

    /// SAFE invariant: nothing SAFE is also OBSOLETE. SAFE means
    /// "accept from untrusted peer"; OBSOLETE means "warn on use."
    /// Accepting-then-warning is incoherent. The C doesn't have a
    /// SAFE+OBSOLETE entry (checked); pin it.
    #[test]
    fn safe_not_obsolete() {
        for v in VARS {
            assert!(
                !(v.flags.contains(F) && v.flags.contains(O)),
                "{} is both SAFE and OBSOLETE",
                v.name
            );
        }
    }

    /// SAFE invariant: nothing SAFE picks a file path or binary.
    /// This is the *purpose* of SAFE (see module doc). The keys that
    /// pick paths (`Device`, `*KeyFile`, `ScriptsInterpreter`,
    /// `Proxy`) are NOT safe. We can't statically know which keys are
    /// path-ish, but we can spot-check the obvious ones.
    #[test]
    fn unsafe_paths_not_safe() {
        for name in [
            "Device",
            "PrivateKeyFile",
            "Ed25519PrivateKeyFile",
            "ScriptsInterpreter",
            "ScriptsExtension",
            "Proxy",
        ] {
            let v = lookup(name).unwrap();
            assert!(
                !v.flags.contains(F),
                "{name} is SAFE but picks a path/binary"
            );
        }
    }
}
