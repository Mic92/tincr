//! `conf.c` + the PEM-ish key file format from `ecdsa.c`.
//!
//! ## What's here, what's not
//!
//! `conf.c` is a `key = value` line format with three layers:
//!
//!   1. **`parse_config_line`** — single-line tokenizer. Surprisingly
//!      fiddly: trailing whitespace stripped, separator is *zero or
//!      more* `[\t ]` then *optional* `=` then more `[\t ]`. So
//!      `"Port=655"`, `"Port 655"`, `"Port \t = \t 655"` all parse
//!      identically. Upstream's `tincctl` writes `Key = Value` but old
//!      hand-written configs use the bare-space form.
//!
//!   2. **`read_config_file`** — line loop, skips `#` comments and
//!      blanks, *and* skips PEM-armored blocks (`-----BEGIN`..`END`).
//!      That last bit is why a `hosts/foo` file can have both the
//!      `Address = 1.2.3.4` lines *and* the public key glued on the
//!      end — the parser steps over the PEM armor.
//!
//!   3. **Config tree + lookup** — a splay tree keyed by
//!      `(strcasecmp(var), cmdline-before-file, line, file)`. The
//!      ordering matters because `lookup_config`/`lookup_config_next`
//!      walk a contiguous same-variable run in that order. Net effect:
//!      `tincd -o Port=656` overrides `Port = 655` in `tinc.conf`,
//!      and multi-valued keys (`Subnet`, `ConnectTo`) iterate in
//!      cmdline-then-file-line order.
//!
//! Layers 1+2 are pure string handling — ported here byte-for-byte.
//! Layer 3's *ordering* is preserved (it's protocol-adjacent: a peer's
//! `hosts/foo` is read into a config tree, and `Subnet` iteration
//! order affects which routes win on conflict). The *splay tree* is
//! replaced with a `Vec` + stable sort — config files are tens of
//! lines; `O(n)` lookup is invisible next to the `fopen`.
//!
//! ## What's deferred
//!
//!  - `get_config_address` → `str2addrinfo` → `getaddrinfo`. Phase 5.
//!  - `get_config_subnet` → `str2net` already lives in `tinc-proto`.
//!    Daemon glues those together; not this crate's job.
//!  - `read_server_config`'s `conf.d/*.conf` scan and `cmdline_conf`
//!    merge — daemon startup, Phase 5. The pieces (`parse_file` +
//!    `Config::merge`) are here.
//!  - `names.c` (`confbase`, `pidfilename`, etc.) — Phase 5 with the
//!    `directories` crate. Nothing in *this* crate hardcodes paths.
//!  - `append_config_file` — `tincctl` territory, not the daemon.
//!
//! ## PEM
//!
//! Not RFC 7468 PEM. tinc's keys are wrapped in `-----BEGIN`/`END`
//! armor, but the body is `b64encode_tinc` (LSB-first packing — see
//! `tinc-crypto::b64`), not RFC 4648. `write_pem` chunks at 48 raw
//! bytes per line (→ 64 chars). `read_pem` accepts any line length but
//! requires the decoded total to match the expected size *exactly*.
//!
//! The base64 codec is already KAT-locked in `tinc-crypto`; here we
//! test the framing.

#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
// `as` casts on file/line numbers — small, monotone, never wrapping.
#![allow(clippy::cast_possible_truncation)]

pub mod parse;
pub mod pem;

pub use parse::{parse_file, parse_line, Config, Entry, ParseError, Source};
pub use pem::{read_pem, write_pem, PemError};
