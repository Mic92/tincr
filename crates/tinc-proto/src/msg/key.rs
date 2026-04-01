//! `protocol_key.c`: `KEY_CHANGED`, `REQ_KEY`, `ANS_KEY`.
//!
//! ## The `REQ_KEY` extension hole
//!
//! `REQ_KEY` is the most overloaded message. The wire form:
//!
//! - Legacy: `%d %s %s` — just from/to.
//! - Extended: `%d %s %s %d [%s]` — fourth field is a sub-request type
//!   (`REQ_KEY`/`REQ_PUBKEY`/`ANS_PUBKEY`/`SPTPS_PACKET`), fifth is
//!   sub-type-specific (a base64 SPTPS record, or a base64 pubkey).
//!
//! `req_key_h` parses with `< 2` (not `!= 2`), so the third `%d` is
//! optional and defaults to 0 (the C local `int reqno = 0`). When
//! `reqno != 0`, control passes to `req_key_ext_h` which does *another*
//! `sscanf` skipping four fields to grab the payload.
//!
//! We model this as `ReqKey { from, to, ext: Option<ReqKeyExt> }` where
//! `ReqKeyExt` is the (sub-type, optional-payload) pair. The Rust
//! daemon dispatches on `ext` instead of re-scanning.
//!
//! ## `KEY_CHANGED` doesn't `check_id`
//!
//! `key_changed_h` parses the name but doesn't call `check_id` on it —
//! just `lookup_node(name)`, which fails harmlessly if the name is
//! garbage. We don't add a check the C doesn't have.

use crate::addr::AddrStr;
use crate::tok::{ParseError, Tok};
use crate::{Request, check_id};

// ────────────────────────────────────────────────────────────────────
// KEY_CHANGED

/// Body of `KEY_CHANGED`. Flooded broadcast: a node has rekeyed,
/// everyone should drop their cached session key for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChanged {
    /// Node that changed its key. *Not* `check_id`-validated — see
    /// module doc.
    pub node: String,
}

impl KeyChanged {
    /// `key_changed_h`: `sscanf("%*d %*x %s", name)`. No `check_id`.
    ///
    /// # Errors
    /// Too few tokens.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(line);
        t.skip()?; // %*d
        t.skip()?; // %*x — dedup nonce
        let node = t.s()?;
        Ok(Self {
            node: node.to_string(),
        })
    }

    /// `send_key_changed`: `send_request("%d %x %s", KEY_CHANGED, prng(...), myself->name)`.
    #[must_use]
    pub fn format(&self, nonce: u32) -> String {
        format!("{} {nonce:x} {}", Request::KeyChanged, self.node)
    }
}

// ────────────────────────────────────────────────────────────────────
// REQ_KEY

/// Extended `REQ_KEY` sub-request. The fourth field, when present.
///
/// The C re-uses `request_t` enum values for the sub-type — `reqno ==
/// REQ_KEY` means "SPTPS handshake initiation", `reqno == REQ_PUBKEY`
/// means "send me your pubkey", etc. We keep the wire `i32` plus the
/// optional payload string; the daemon switches on the int.
///
/// Why not an enum here? `req_key_ext_h` has a `default:` case that
/// logs and continues. Unknown `reqno` is *not* a parse error; it's a
/// "log and ignore". An enum would force us to either reject (wrong) or
/// add a `Unknown(i32)` variant (which is just `i32` with extra steps).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReqKeyExt {
    /// `reqno` — re-uses `request_t` values. `REQ_KEY`=15 (SPTPS init),
    /// `REQ_PUBKEY`=19, `ANS_PUBKEY`=20, `SPTPS_PACKET`=21.
    pub reqno: i32,
    /// `buf`/`pubkey` from `req_key_ext_h`. Base64-encoded (tinc's
    /// LSB-first variant). Decoding is the daemon's job — at this layer
    /// it's an opaque token.
    ///
    /// `REQ_PUBKEY` (19) has no payload; the others do. We don't
    /// enforce that pairing here — `req_key_ext_h` does
    /// `if(sscanf(...) == 1)` per sub-type, so the C also treats
    /// payload presence as soft.
    pub payload: Option<String>,
}

/// Body of `REQ_KEY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReqKey {
    pub from: String,
    pub to: String,
    /// `None` for legacy (3-token) form. `Some` for extended (4+ token).
    pub ext: Option<ReqKeyExt>,
}

impl ReqKey {
    /// `req_key_h` + `req_key_ext_h` parse, fused.
    ///
    /// `sscanf("%*d %s %s %d", from, to, &reqno)` with `< 2` — so `reqno`
    /// is optional, defaults to the C local's 0. We use `Option` instead
    /// of 0-as-sentinel: cleaner, and 0 is `Request::Id` which would be
    /// a confusing accidental collision.
    ///
    /// Then if `reqno` was present, peel off one more optional `%s`
    /// (the `req_key_ext_h` `sscanf("%*d %*s %*s %*d %s", buf)`).
    ///
    /// # Errors
    /// Too few tokens (< 2 names) or bad name.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(line);
        t.skip()?;

        let from = t.s()?;
        let to = t.s()?;
        if !check_id(from) || !check_id(to) {
            return Err(ParseError);
        }

        let ext = match t.d_opt()? {
            None => None,
            Some(reqno) => Some(ReqKeyExt {
                reqno,
                payload: t.s_opt()?.map(str::to_string),
            }),
        };

        Ok(Self {
            from: from.to_string(),
            to: to.to_string(),
            ext,
        })
    }

    /// `send_req_key` and friends. There are *four* `send_request` call
    /// sites in `protocol_key.c` for `REQ_KEY`:
    ///
    /// - `"%d %s %s"` — legacy
    /// - `"%d %s %s %d"` — extended, no payload (e.g. `REQ_PUBKEY`)
    /// - `"%d %s %s %d %s"` — extended with payload
    /// - `"%s"` — forwarding (the daemon re-emits the input verbatim;
    ///   not our concern)
    ///
    /// We pick the format string from `ext`.
    #[must_use]
    pub fn format(&self) -> String {
        let head = format!("{} {} {}", Request::ReqKey, self.from, self.to);
        match &self.ext {
            None => head,
            Some(ReqKeyExt {
                reqno,
                payload: None,
            }) => format!("{head} {reqno}"),
            Some(ReqKeyExt {
                reqno,
                payload: Some(p),
            }) => format!("{head} {reqno} {p}"),
        }
    }
}

// ────────────────────────────────────────────────────────────────────
// ANS_KEY

/// Body of `ANS_KEY`. The session-key reply. Seven mandatory fields,
/// two optional (reflexive UDP addr/port — appended by relays, not the
/// origin; see `protocol_key.c:477`).
///
/// `key` is hex-encoded session key for legacy, or unused for SPTPS
/// (the SPTPS path goes through `REQ_KEY` extension instead). We don't
/// hex-decode here — opaque token, daemon's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnsKey {
    pub from: String,
    pub to: String,
    pub key: String,
    /// `cipher_get_nid()`. OpenSSL NID. 0 = no cipher.
    pub cipher: i32,
    /// `digest_get_nid()`. 0 = no MAC.
    pub digest: i32,
    /// `digest_length()`. `%lu` — `unsigned long`, hence `u64`. Always
    /// tiny in practice but we honor the printf width.
    pub maclen: u64,
    /// Compression level, `0..=11` (zlib levels + LZO). `%d` signed.
    pub compression: i32,
    /// Reflexive UDP address. Relays splice this on (`"%s %s %s"` —
    /// original line + addr + port). Origin doesn't send it.
    pub udp_addr: Option<(AddrStr, AddrStr)>,
}

impl AnsKey {
    /// `ans_key_h`: `sscanf("%*d %s %s %s %d %d %lu %d %s %s")`, `< 7`.
    ///
    /// 7 mandatory + 2 optional. Unlike `ADD_EDGE`, the C *doesn't*
    /// reject 8 (one optional present, one not) — `sscanf` returning 8
    /// satisfies `< 7 → false`, and the handler only checks
    /// `!*address` (zero-init buffer) to decide whether to use the
    /// addr. Port is used unconditionally if addr is non-empty. So
    /// receiving exactly addr-but-no-port would be a NULL deref in the
    /// C... except `sscanf` reads `%s` greedily and there's nothing
    /// after, so it can't actually happen on a well-formed line.
    ///
    /// We treat the pair as atomic anyway (both or neither). If a peer
    /// somehow sends 8 fields, the C is in UB territory; we reject
    /// cleanly.
    ///
    /// # Errors
    /// Fewer than 7 fields, bad name, malformed int, or exactly one
    /// trailing addr/port token.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let mut t = Tok::new(line);
        t.skip()?;

        let from = t.s()?;
        let to = t.s()?;
        if !check_id(from) || !check_id(to) {
            return Err(ParseError);
        }
        let key = t.s()?;
        let cipher = t.d()?;
        let digest = t.d()?;
        let maclen = t.lu()?;
        let compression = t.d()?;

        let udp_addr = match (t.s_opt()?, t.s_opt()?) {
            (None, None) => None,
            (Some(a), Some(p)) => Some((AddrStr::new(a)?, AddrStr::new(p)?)),
            _ => return Err(ParseError),
        };

        Ok(Self {
            from: from.to_string(),
            to: to.to_string(),
            key: key.to_string(),
            cipher,
            digest,
            maclen,
            compression,
            udp_addr,
        })
    }

    /// `send_ans_key`: `send_request("%d %s %s %s %d %d %lu %d", ANS_KEY, ...)`.
    ///
    /// The 7-field form. Relays append addr/port by re-emitting
    /// `"%s %s %s"` with the original line as the first `%s` —
    /// `format_with_addr` covers that.
    #[must_use]
    pub fn format(&self) -> String {
        let head = format!(
            "{} {} {} {} {} {} {} {}",
            Request::AnsKey,
            self.from,
            self.to,
            self.key,
            self.cipher,
            self.digest,
            self.maclen,
            self.compression,
        );
        match &self.udp_addr {
            None => head,
            // Relay-appended form. The C does this by re-printf-ing the
            // entire input line (`"%s %s %s", request, addr, port`); the
            // result is identical.
            Some((a, p)) => format!("{head} {a} {p}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_changed() {
        let line = "14 abc alice";
        let m = KeyChanged::parse(line).unwrap();
        assert_eq!(m.node, "alice");
        assert_eq!(m.format(0xabc), line);

        // No check_id: garbage name parses (C does lookup_node, fails
        // softly).
        assert_eq!(KeyChanged::parse("14 0 ba!d").unwrap().node, "ba!d");
    }

    #[test]
    fn req_key_legacy() {
        let line = "15 alice bob";
        let m = ReqKey::parse(line).unwrap();
        assert_eq!(m.from, "alice");
        assert_eq!(m.to, "bob");
        assert!(m.ext.is_none());
        assert_eq!(m.format(), line);
    }

    #[test]
    fn req_key_ext_no_payload() {
        // REQ_PUBKEY = 19. `send_request("%d %s %s %d", REQ_KEY, ..., REQ_PUBKEY)`
        let line = "15 alice bob 19";
        let m = ReqKey::parse(line).unwrap();
        let ext = m.ext.as_ref().unwrap();
        assert_eq!(ext.reqno, 19);
        assert!(ext.payload.is_none());
        assert_eq!(m.format(), line);
    }

    #[test]
    fn req_key_ext_with_payload() {
        // SPTPS init: `send_request("%d %s %s %d %s", REQ_KEY, ..., REQ_KEY, buf)`
        // buf is tinc-base64 of an SPTPS KEX record.
        let line = "15 alice bob 15 SGVsbG8gV29ybGQ"; // dummy b64
        let m = ReqKey::parse(line).unwrap();
        let ext = m.ext.as_ref().unwrap();
        assert_eq!(ext.reqno, 15);
        assert_eq!(ext.payload.as_deref(), Some("SGVsbG8gV29ybGQ"));
        assert_eq!(m.format(), line);
    }

    #[test]
    fn req_key_unknown_reqno() {
        // req_key_ext_h has a `default:` that logs and returns true.
        // Unknown reqno is *not* a parse error.
        let m = ReqKey::parse("15 a b 999").unwrap();
        assert_eq!(m.ext.as_ref().unwrap().reqno, 999);
    }

    #[test]
    fn ans_key() {
        // Typical legacy: aes-256-cbc (NID 427), sha256 (NID 672),
        // maclen 32, no compression.
        let line = "16 alice bob deadbeef0011 427 672 32 0";
        let m = AnsKey::parse(line).unwrap();
        assert_eq!(m.key, "deadbeef0011");
        assert_eq!(m.cipher, 427);
        assert_eq!(m.maclen, 32);
        assert!(m.udp_addr.is_none());
        assert_eq!(m.format(), line);
    }

    #[test]
    fn ans_key_with_relay_addr() {
        let line = "16 a b ff 0 0 0 0 10.0.0.1 655";
        let m = AnsKey::parse(line).unwrap();
        let (a, p) = m.udp_addr.as_ref().unwrap();
        assert_eq!(a.as_str(), "10.0.0.1");
        assert_eq!(p.as_str(), "655");
        assert_eq!(m.format(), line);
    }

    #[test]
    fn ans_key_eight_fields_rejected() {
        // C is in UB-ish territory here (uses port without checking it
        // was set). We reject.
        assert!(AnsKey::parse("16 a b ff 0 0 0 0 10.0.0.1").is_err());
    }
}
