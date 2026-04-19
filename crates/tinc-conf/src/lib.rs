//! Tinc's `key = value` config format and its PEM-ish key file framing.
//!
//! Lines are tokenized with a forgiving separator (any mix of spaces,
//! tabs and an optional `=`), `#` comments and blanks are skipped, and
//! PEM-armored blocks are stepped over so a `hosts/foo` file can hold
//! both `Address =` lines and a trailing public key. Parsed entries
//! land in a `Vec` ordered by `(case-insensitive name,
//! cmdline-before-file, line, file)`, which is the order lookups walk:
//! `-o` overrides beat file entries and multi-valued keys like `Subnet`
//! or `ConnectTo` iterate in a stable, predictable sequence. The PEM
//! reader/writer handles tinc's `BEGIN`/`END` armor around the
//! crate-local base64 codec used for stored keys. The PEM framing is
//! tinc-flavoured rather than RFC 7468: the armor lines look standard
//! but the body uses `tinc-crypto`'s LSB-first base64 chunked at 48
//! raw bytes per line, and the reader requires the decoded length to
//! match the expected size exactly.

#![forbid(unsafe_code)]

pub mod name;
pub mod parse;
pub mod pem;
pub mod vars;

pub use parse::{
    Config, Entry, ParseError, ReadError, Source, parse_file, parse_line, read_server_config,
    split_kv,
};
pub use pem::{PemError, read_pem, write_pem};
pub use vars::{VARS, Var, VarFlags, lookup as lookup_var};
