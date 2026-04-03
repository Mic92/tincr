//! `read_pem` / `write_pem` from `ecdsa.c` / `ecdsagen.c`.
//!
//! Not RFC 7468 PEM. The armor lines look the same (`-----BEGIN
//! <TYPE>-----` / `-----END <TYPE>-----`) but the body is
//! `b64encode_tinc` — LSB-first packing, no `=` padding. A standard
//! PEM decoder will produce the *wrong bytes* when given a tinc key
//! file. The base64 codec is in `tinc-crypto::b64` and KAT-locked
//! against the C; here we handle the framing.
//!
//! ## Layout
//!
//! `write_pem` (`ecdsagen.c:50-68`) chunks at 48 raw bytes per line
//! → 64 base64 chars. So a 96-byte private key blob is two lines.
//! `read_pem` (`ecdsa.c:71-128`) accepts any line length — it just
//! decodes line-by-line and concatenates.
//!
//! ## The struct overlap trick
//!
//! `ecdsa_read_pem_private_key` calls `read_pem(fp, "ED25519 PRIVATE
//! KEY", ecdsa->private, sizeof(*ecdsa))` — writing 96 bytes starting
//! at the `private` field, which spills over into `public`. This works
//! because `struct ecdsa` is `{ uint8_t private[64]; uint8_t
//! public[32]; }` packed, no padding. The on-disk private key blob is
//! therefore `private[64] || public[32]` — exactly what
//! `tinc_crypto::sign::SigningKey::{from,to}_blob` expects.

use std::io::{self, BufRead, BufReader, Read, Write};
use tinc_crypto::b64;
use zeroize::Zeroizing;

/// `read_pem` errors. The C sets `errno` (`EINVAL` or `ENOENT`) and
/// logs; we typed-enum it. `NotFound` maps to the C `ENOENT` case
/// where the BEGIN marker is absent — distinct from "found but
/// malformed" because callers (`read_ecdsa_public_key` in
/// `net_setup.c`) check `errno == ENOENT` to fall through to the
/// `Ed25519PublicKey =` config-variable path.
#[derive(Debug)]
pub enum PemError {
    /// `-----BEGIN <type>-----` never found. C: `errno = ENOENT`.
    NotFound,
    /// Found the block but `b64decode_tinc` rejected a line.
    /// C: `"Invalid base64 data in PEM file"`, `errno = EINVAL`.
    BadBase64,
    /// Decoded total ≠ expected. C distinguishes "too much" (line
    /// overflows remaining `size`) from "too little" (`size != 0` at
    /// END). We collapse — both mean the file is corrupt.
    Size { got: usize, want: usize },
    /// `fgets` failure mid-read. C silently breaks the loop on this
    /// (it doesn't distinguish EOF from error after the fgets — it
    /// just falls through to the `if(size)` check). We surface it.
    Io(io::Error),
}

impl std::fmt::Display for PemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PemError::NotFound => write!(f, "PEM block not found"),
            PemError::BadBase64 => write!(f, "invalid base64 data in PEM file"),
            PemError::Size { got, want } => {
                write!(f, "PEM body decodes to {got} bytes, expected {want}")
            }
            PemError::Io(e) => write!(f, "I/O error reading PEM: {e}"),
        }
    }
}

impl std::error::Error for PemError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PemError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// `read_pem`. Finds the first `-----BEGIN <type>-----` block, decodes
/// the body, requires the result to be exactly `expected_len` bytes.
///
/// The `type` match is `strncmp` (prefix) — so a file with `-----BEGIN
/// ED25519 PRIVATE KEY EXTRA STUFF-----` is accepted by a search for
/// `ED25519 PRIVATE KEY`. Unlikely to matter (tinc only ever writes
/// the exact strings) but preserved for fidelity.
///
/// Result is wrapped in `Zeroizing` because private keys flow through
/// here. The C `memzero`s its buffers on the error path (`ecdsa.c:
/// 121-126`); `Zeroizing` does it on *every* drop.
///
/// # Errors
/// See [`PemError`]. Notably, `NotFound` is the common no-key-in-file
/// case; the caller may want to fall through to another source.
pub fn read_pem(
    r: impl Read,
    ty: &str,
    expected_len: usize,
) -> Result<Zeroizing<Vec<u8>>, PemError> {
    // Everything decoded touches this buffer. Preallocate to avoid
    // reallocs that would scatter copies of partial key material
    // across the heap. (`Zeroizing<Vec>` only zeroes the *final*
    // allocation.) The size check rejects overflow before we'd grow.
    let mut out = Zeroizing::new(Vec::with_capacity(expected_len));
    let mut in_block = false;
    // `Zeroizing<String>` for the line buffer too — base64-of-key is
    // not the key but it's a deterministic transform of one.
    let mut line = Zeroizing::new(String::new());
    let mut br = BufReader::new(r);

    // Manual `read_line` loop instead of `.lines()` so the line buffer
    // is a single owned `String` we can zeroize, instead of a fresh
    // allocation per line that drops without zeroing.
    loop {
        line.clear();
        let n = br.read_line(&mut line).map_err(PemError::Io)?;
        if n == 0 {
            break; // EOF
        }
        // C `strcspn(line, "\r\n")` for the body lines, `strncmp` for
        // the markers. Stripping CR/LF up front handles both.
        let trimmed = line.trim_end_matches(['\r', '\n']);

        if !in_block {
            // C: `strncmp(line, "-----BEGIN ", 11)` then
            //    `strncmp(line + 11, type, typelen)`.
            // The second is *prefix*, not exact — see fn doc.
            if let Some(rest) = trimmed.strip_prefix("-----BEGIN ") {
                if rest.starts_with(ty) {
                    in_block = true;
                }
            }
            continue;
        }

        // C: `strncmp(line, "-----END ", 9)`. Doesn't check the type
        // matches BEGIN — first END of *any* type closes the block.
        // tinc only writes matched pairs so it never matters.
        if trimmed.starts_with("-----END ") {
            // Exited cleanly. Size check below.
            return finish(out, expected_len);
        }

        // Body line. C `b64decode_tinc(line, line, linelen)` decodes
        // in place; we can't (immutable `&str`). The decoder returns
        // 0 on bad input *or* on empty input — C `if(!len)` treats
        // both as error, but a blank line inside a PEM block is also
        // not something tinc writes. Preserve.
        let decoded = b64::decode(trimmed).ok_or(PemError::BadBase64)?;
        if decoded.is_empty() {
            return Err(PemError::BadBase64);
        }

        // C `if(len > size)` — overflow check before memcpy. `size` is
        // the remaining capacity, decremented per line. We check
        // total-so-far instead; same outcome, simpler bookkeeping.
        if out.len() + decoded.len() > expected_len {
            return Err(PemError::Size {
                got: out.len() + decoded.len(),
                want: expected_len,
            });
        }
        out.extend_from_slice(&decoded);
        // `decoded` itself is a plain `Vec` — it's a fresh allocation
        // from `b64::decode`. Zeroize it before drop. Can't make
        // `b64::decode` return `Zeroizing` without it leaking into
        // the public API of `tinc-crypto`; it's only ever key-
        // adjacent here, so wipe locally.
        let mut decoded = decoded;
        zeroize::Zeroize::zeroize(&mut decoded);
    }

    // EOF without END. C falls through to the same `if(size)` check.
    // If `in_block` is still false, we never found BEGIN — that's
    // `NotFound`, not `Size`.
    if !in_block {
        return Err(PemError::NotFound);
    }
    finish(out, expected_len)
}

fn finish(out: Zeroizing<Vec<u8>>, want: usize) -> Result<Zeroizing<Vec<u8>>, PemError> {
    if out.len() == want {
        Ok(out)
    } else {
        Err(PemError::Size {
            got: out.len(),
            want,
        })
    }
}

/// `write_pem`. 48 raw bytes per line → 64 base64 chars, standard
/// `+/` alphabet (`b64encode_tinc` not `b64encode_tinc_urlsafe`).
///
/// Output is the exact byte sequence `ecdsagen.c:write_pem` produces,
/// modulo libc `fprintf` buffering (which doesn't affect bytes-on-disk).
///
/// # Errors
/// I/O on the writer.
pub fn write_pem(mut w: impl Write, ty: &str, body: &[u8]) -> io::Result<()> {
    writeln!(w, "-----BEGIN {ty}-----")?;
    for chunk in body.chunks(48) {
        // `b64::encode` returns `String`, freshly allocated.
        // Key material → zeroize before drop.
        let line = Zeroizing::new(b64::encode(chunk));
        writeln!(w, "{}", &*line)?;
    }
    writeln!(w, "-----END {ty}-----")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip at the canonical sizes. 32 bytes (public, one line),
    /// 96 bytes (private, two lines), and 48 bytes (exactly one full
    /// line, the boundary case).
    #[test]
    fn roundtrip_sizes() {
        for &len in &[32, 48, 96, 1, 47, 49, 100] {
            #[allow(clippy::cast_possible_truncation)] // test data, len <= 100
            let blob: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut buf = Vec::new();
            write_pem(&mut buf, "TEST", &blob).unwrap();
            let back = read_pem(&buf[..], "TEST", len).unwrap();
            assert_eq!(&*back, &blob[..], "len={len}");
        }
    }

    /// `write_pem` chunks at 48. A 96-byte body is exactly two lines.
    #[test]
    fn write_chunking() {
        let blob = [0u8; 96];
        let mut buf = Vec::new();
        write_pem(&mut buf, "X", &blob).unwrap();
        let s = String::from_utf8(buf).unwrap();
        let lines: Vec<_> = s.lines().collect();
        // BEGIN, body, body, END.
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0], "-----BEGIN X-----");
        assert_eq!(lines[3], "-----END X-----");
        // 48 bytes → 64 chars each.
        assert_eq!(lines[1].len(), 64);
        assert_eq!(lines[2].len(), 64);
        // 48 zero bytes encode to 64 'A's under tinc's LSB packing
        // (every 6-bit window is 0 → alphabet[0] = 'A'). Same as RFC
        // here because zero bytes are bit-order-invariant.
        assert_eq!(lines[1], "A".repeat(64));
    }

    /// 49 bytes: one full 64-char line, one short trailing line.
    #[test]
    fn write_chunking_uneven() {
        let blob = [0u8; 49];
        let mut buf = Vec::new();
        write_pem(&mut buf, "X", &blob).unwrap();
        let lines: Vec<_> = std::str::from_utf8(&buf).unwrap().lines().collect();
        assert_eq!(lines.len(), 4); // BEGIN, 64-char, 2-char, END
        assert_eq!(lines[1].len(), 64);
        // 1 byte → 2 chars (no padding). `b64encode_tinc([0x00])` = "AA".
        assert_eq!(lines[2], "AA");
    }

    /// `read_pem` accepts arbitrary line lengths — chunking is a write
    /// concern only. C decodes line-by-line, doesn't check line length.
    #[test]
    fn read_ignores_chunking() {
        let blob: Vec<u8> = (0..96u8).collect();
        let body = b64::encode(&blob);
        // One giant line.
        let pem = format!("-----BEGIN X-----\n{body}\n-----END X-----\n");
        let back = read_pem(pem.as_bytes(), "X", 96).unwrap();
        assert_eq!(&*back, &blob[..]);
    }

    /// CRLF input. The C `strcspn(line, "\r\n")` handles it; so do we.
    #[test]
    fn read_crlf() {
        let blob: Vec<u8> = (0..32u8).collect();
        let body = b64::encode(&blob);
        let pem = format!("-----BEGIN X-----\r\n{body}\r\n-----END X-----\r\n");
        let back = read_pem(pem.as_bytes(), "X", 32).unwrap();
        assert_eq!(&*back, &blob[..]);
    }

    /// Type match is prefix (`strncmp(line+11, type, typelen)`).
    #[test]
    fn read_type_prefix() {
        let pem = "-----BEGIN FOO BAR EXTRA-----\nAA\n-----END FOO-----\n";
        // Searching for "FOO" matches "FOO BAR EXTRA".
        assert!(read_pem(pem.as_bytes(), "FOO", 1).is_ok());
        assert!(read_pem(pem.as_bytes(), "FOO BAR", 1).is_ok());
        // But "FOOZ" doesn't prefix-match "FOO BAR EXTRA".
        assert!(matches!(
            read_pem(pem.as_bytes(), "FOOZ", 1),
            Err(PemError::NotFound)
        ));
    }

    /// END type isn't checked — first END of any type closes.
    #[test]
    fn read_end_type_unchecked() {
        let pem = "-----BEGIN FOO-----\nAA\n-----END SOMETHING ELSE-----\n";
        let back = read_pem(pem.as_bytes(), "FOO", 1).unwrap();
        assert_eq!(&*back, &[0u8]);
    }

    #[test]
    fn read_not_found() {
        assert!(matches!(
            read_pem(&b""[..], "X", 1),
            Err(PemError::NotFound)
        ));
        assert!(matches!(
            read_pem(&b"just some text\n"[..], "X", 1),
            Err(PemError::NotFound)
        ));
        // Wrong type.
        let pem = "-----BEGIN BAR-----\nAA\n-----END BAR-----\n";
        assert!(matches!(
            read_pem(pem.as_bytes(), "FOO", 1),
            Err(PemError::NotFound)
        ));
    }

    /// Size mismatch: too little. C `if(size)` after the loop.
    #[test]
    fn read_size_short() {
        let pem = "-----BEGIN X-----\nAA\n-----END X-----\n"; // 1 byte
        assert!(matches!(
            read_pem(pem.as_bytes(), "X", 32),
            Err(PemError::Size { got: 1, want: 32 })
        ));
    }

    /// Size mismatch: too much. C `if(len > size)` mid-loop.
    #[test]
    fn read_size_long() {
        let blob = [0u8; 100];
        let mut buf = Vec::new();
        write_pem(&mut buf, "X", &blob).unwrap();
        // Ask for 50, file has 100.
        assert!(matches!(
            read_pem(&buf[..], "X", 50),
            Err(PemError::Size { want: 50, .. })
        ));
    }

    /// Empty body line inside the block. C `if(!len)` rejects.
    #[test]
    fn read_empty_body_line() {
        let pem = "-----BEGIN X-----\nAA\n\nAA\n-----END X-----\n";
        assert!(matches!(
            read_pem(pem.as_bytes(), "X", 2),
            Err(PemError::BadBase64)
        ));
    }

    /// Garbage in body. `b64::decode` rejects.
    #[test]
    fn read_bad_b64() {
        let pem = "-----BEGIN X-----\n!!!!\n-----END X-----\n";
        assert!(matches!(
            read_pem(pem.as_bytes(), "X", 3),
            Err(PemError::BadBase64)
        ));
    }

    /// Stuff before BEGIN is skipped. The same file can have config
    /// lines and a key — `parse_file` reads the config, `read_pem`
    /// reads the key, both from the same `hosts/foo`.
    #[test]
    fn read_skips_preamble() {
        let pem = "\
Address = 1.2.3.4
Port = 655
-----BEGIN X-----
AA
-----END X-----
";
        let back = read_pem(pem.as_bytes(), "X", 1).unwrap();
        assert_eq!(&*back, &[0u8]);
    }

    /// Full integration: a `SigningKey` → PEM → `SigningKey`. This is
    /// the actual on-disk format. The body is `private[64] || public[32]`
    /// per the struct-overlap trick (see module doc).
    #[test]
    fn signing_key_roundtrip() {
        use tinc_crypto::sign::SigningKey;

        let sk = SigningKey::from_seed(&[7u8; 32]);
        let blob = sk.to_blob();

        let mut pem = Vec::new();
        write_pem(&mut pem, "ED25519 PRIVATE KEY", &blob).unwrap();

        let back = read_pem(&pem[..], "ED25519 PRIVATE KEY", 96).unwrap();
        let mut blob2 = [0u8; 96];
        blob2.copy_from_slice(&back);
        let sk2 = SigningKey::from_blob(&blob2);

        // Same key signs the same message to the same signature.
        let msg = b"hello";
        assert_eq!(sk.sign(msg), sk2.sign(msg));
    }

    /// And the public-key-only file: 32 bytes, one body line of 43
    /// chars (32 bytes → 32*4/3 rounded up = 43).
    #[test]
    fn public_key_file_shape() {
        use tinc_crypto::sign::SigningKey;

        let sk = SigningKey::from_seed(&[7u8; 32]);
        let pk = sk.public_key();

        let mut pem = Vec::new();
        write_pem(&mut pem, "ED25519 PUBLIC KEY", pk).unwrap();

        let lines: Vec<_> = std::str::from_utf8(&pem).unwrap().lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1].len(), 43);

        let back = read_pem(&pem[..], "ED25519 PUBLIC KEY", 32).unwrap();
        assert_eq!(&back[..], pk);
    }
}
