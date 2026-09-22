//! SPTPS parameter capability signalling (tincr extension).
//!
//! SPTPS `kex`/`aead` are configured per host file with no wire
//! negotiation: `docs/PROTOCOL.md` used to promise that a mismatch
//! "logs `BadKex` and retries" — in reality the responder's
//! [`Sptps`](tinc_sptps::Sptps) rejects the initiator's KEX length /
//! SIG length as `BadKex`/`BadSig`, the connection tears down, and
//! the retry re-sends the same mismatched pair forever. Against a
//! tinc-pre peer (which doesn't understand `x25519-mlkem768` at all)
//! a node configured for the hybrid KEX therefore never forms a
//! tunnel.
//!
//! The extension rides two messages that both sides see *before*
//! [`Sptps::start`] is called for the relevant direction:
//!
//! - `ID <name> <maj>.<min> <cap>` — an extra token on the ID line.
//!   A C responder parses with a fixed `sscanf` pattern and leaves
//!   the token in the buffer after the newline match, which the
//!   handlers never inspect: unknown tokens are silently tolerated.
//! - `REQ_KEY <from> <to> 4 <b64> <cap>` — a token after the payload.
//!   C relays forward the original request line verbatim
//!   (`send_request(c, "%s", request)`), so the stamp survives
//!   multi-hop paths, and the receiver's `sscanf` likewise ignores it.
//!
//! `cap` is a two-character token, one lowercase hex digit per axis
//! (kex, aead). Digit `0` means "the compiled default"; each other
//! digit names one enum variant (see [`digit`]/[`from_digit`]). Hex
//! so the encoding survives the enums growing past nine entries. An
//! unknown digit is treated as *absent* by both parsers so that an
//! older reader — or one facing a future encoding it doesn't know —
//! degrades to the default pair instead of picking wrong parameters.
//!
//! Adoption rules (see `docs/PROTOCOL.md`):
//!
//! - A `REQ_KEY` **initiator** stamps its own intended pair.
//! - A **responder** that receives a stamp adopts it for that tunnel;
//!   an absent stamp means "peer predates the extension / is a C
//!   node", and the responder keeps its configured pair (legacy
//!   behaviour: both ends were required to agree out of band).
//! - An ID-line **reply** echoes the initiator's stamp back iff it
//!   parsed it. A silent reply means "this peer did not understand
//!   the token", which is how an initiator learns the responder is
//!   C-compatible and must be sent classical/default parameters.

use tinc_sptps::{SptpsAead, SptpsKex};

/// The SPTPS parameter pair one side intends to use, encoded as the
/// two-character wire token. `DEFAULT` is what a C node (or an
/// extension-unaware tincr) uses: the compiled defaults
/// (`x25519` + `chacha20-poly1305`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cap {
    pub kex: SptpsKex,
    pub aead: SptpsAead,
}

impl Cap {
    /// The pair every implementation agrees on without the extension.
    pub(crate) const DEFAULT: Self = Self {
        kex: SptpsKex::X25519,
        aead: SptpsAead::ChaCha20Poly1305,
    };

    /// The pair a peer with these settings would put on the wire.
    #[must_use]
    pub(crate) const fn new(kex: SptpsKex, aead: SptpsAead) -> Self {
        Self { kex, aead }
    }

    /// Render as `"<kex><aead>"`, e.g. `"11"` for the
    /// hybrid-KEX + AES-256-GCM pair a post-quantum rollout sets.
    #[must_use]
    pub(crate) fn token(self) -> String {
        let mut buf = [0u8; 2];
        buf[0] = hex_digit(self.kex.discriminator().into());
        buf[1] = hex_digit(self.aead.discriminant().into());
        // hex digits are ASCII.
        String::from_utf8(buf.to_vec()).expect("ascii")
    }

    /// Parse a token. Anything that isn't two lowercase hex digits
    /// naming known variants is `None` — callers treat `None` as
    /// "extension not understood" and fall back to [`Cap::DEFAULT`]
    /// or their own config, never to a half-parsed pair.
    #[must_use]
    pub(crate) fn parse(token: &str) -> Option<Self> {
        let bytes = token.as_bytes();
        if bytes.len() != 2 {
            return None;
        }
        // to_digit yields 0..=15, so the narrowing is lossless; try_from
        // states that instead of silently truncating.
        let kex = (bytes[0] as char)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
            .and_then(SptpsKex::from_discriminant)?;
        let aead = (bytes[1] as char)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
            .and_then(SptpsAead::from_discriminant)?;
        Some(Self { kex, aead })
    }
}

fn hex_digit(d: u32) -> u8 {
    char::from_digit(d, 16).expect("digit < 16") as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_all_pairs() {
        for kex in [SptpsKex::X25519, SptpsKex::X25519MlKem768] {
            for aead in [SptpsAead::ChaCha20Poly1305, SptpsAead::Aes256Gcm] {
                let cap = Cap::new(kex, aead);
                assert_eq!(Cap::parse(&cap.token()), Some(cap), "{}", cap.token());
            }
        }
    }

    #[test]
    fn defaults_encode_as_zeroes() {
        // A C node never sends a token; a node configured with the
        // defaults stamps "00", which must decode to the same pair a
        // C node would silently use.
        assert_eq!(Cap::DEFAULT.token(), "00");
        assert_eq!(Cap::parse("00"), Some(Cap::DEFAULT));
        assert_eq!(
            Cap::new(SptpsKex::X25519MlKem768, SptpsAead::Aes256Gcm).token(),
            "11"
        );
    }

    #[test]
    fn unknown_tokens_parse_as_absent() {
        // Out-of-range indices, upper-case (never emitted), and
        // non-tokens all mean "not understood".
        for bad in ["", "0", "xyz", "22", "11 ", "1g", "ff", "-0", "1D"] {
            assert_eq!(Cap::parse(bad), None, "{bad:?}");
        }
    }
}
