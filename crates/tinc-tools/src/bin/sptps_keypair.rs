//! `sptps_keypair PRIVATE PUBLIC` — generate an Ed25519 keypair, write
//! both halves to disk in tinc's PEM-ish format.
//!
//! Port of `src/sptps_keypair.c` (140 LOC, of which ~100 is `getopt`
//! boilerplate). The actual work is `generate` → `write_pem` × 2.
//!
//! No `clap` — two positional args and a `--help`. The C uses
//! `getopt_long` for a single `--help` option, which is a lot of
//! ceremony for not much. Hand-roll.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use tinc_tools::keypair;

fn usage(prog: &str) {
    eprintln!("Usage: {prog} [--help] private_key_file public_key_file");
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().collect();
    let prog = args.remove(0);

    if args.iter().any(|a| a == "--help" || a == "-h") {
        usage(&prog);
        return ExitCode::SUCCESS;
    }

    if args.len() != 2 {
        eprintln!("Wrong number of arguments.");
        usage(&prog);
        return ExitCode::FAILURE;
    }

    let private = PathBuf::from(&args[0]);
    let public = PathBuf::from(&args[1]);

    let sk = keypair::generate();

    if let Err(e) = keypair::write_pair(&sk, &private, &public) {
        eprintln!("Could not write key pair: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
