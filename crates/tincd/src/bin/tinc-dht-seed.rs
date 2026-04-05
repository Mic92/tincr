//! Standalone Mainline DHT swarm + resolver. For sealed-network tests
//! where `router.bittorrent.com:6881` is unreachable.
//!
//! ```sh
//! tinc-dht-seed 6881 10 relay   # 10-node swarm, runs until SIGTERM
//! tinc-dht-seed --resolve v2TC3R...aSru relay:6881   # one-shot read
//! ```
//!
//! N=10 (not 1): one seed is K=1, the put never iterates. mainline's
//! own tests use 10 as the convergence floor.
//!
//! `SELF_HOST` (the third arg): seeds bootstrap to each other via
//! `SELF_HOST:BASE` instead of `127.0.0.1:BASE`. With loopback,
//! seeds' routing tables hold loopback addrs, so referrals to a
//! remote client say `127.0.0.1:port` — the client dials *its own*
//! loopback, every tid times out, the query never drains. Found
//! empirically (NixOS test hung 60s with loopback, passed with
//! `relay`). The seeds dialing themselves via their public NIC is a
//! hairpin; Linux handles it.
//!
//! `PUBKEY` is tinc's b64 (LSB-first bit packing, NOT standard).
//! `base64 -d` gives 32 different bytes → wrong key → false negative.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use mainline::Dht;

fn usage() {
    eprintln!("Usage:");
    eprintln!("  tinc-dht-seed BASE_PORT [COUNT [SELF_HOST]]");
    eprintln!("      Run COUNT seed nodes on BASE_PORT..BASE_PORT+COUNT.");
    eprintln!("      COUNT defaults to 1. Runs until killed.");
    eprintln!("      SELF_HOST: externally-reachable address for inter-seed");
    eprintln!("      bootstrap (so referrals to remote clients are followable).");
    eprintln!("      Default 127.0.0.1 — fine if clients are on the same host.");
    eprintln!("  tinc-dht-seed --resolve TINC_B64_PUBKEY BOOTSTRAP_HOST:PORT");
    eprintln!("      One-shot: get_mutable for PUBKEY, print value, exit.");
    eprintln!("      Exits 1 if no record found (publish didn't land).");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        usage();
        return ExitCode::SUCCESS;
    }

    if args.first().is_some_and(|a| a == "--resolve") {
        return resolve_mode(&args[1..]);
    }

    seed_mode(&args)
}

/// One-shot resolve. Exits 1 on miss (publish didn't land, or
/// signature didn't verify — mainline rejects bad sigs before the
/// iterator yields, indistinguishable from not-found here).
fn resolve_mode(args: &[String]) -> ExitCode {
    let [b64, bootstrap] = args else {
        eprintln!("tinc-dht-seed --resolve: need PUBKEY BOOTSTRAP");
        usage();
        return ExitCode::FAILURE;
    };

    let Some(decoded) = tinc_crypto::b64::decode(b64) else {
        eprintln!("tinc-dht-seed: pubkey is not valid tinc b64");
        return ExitCode::FAILURE;
    };
    let Ok(public): Result<[u8; 32], _> = decoded.try_into() else {
        eprintln!(
            "tinc-dht-seed: pubkey decoded to {} bytes, want 32",
            b64.len()
        );
        return ExitCode::FAILURE;
    };

    let Ok(dht) = Dht::builder()
        .bootstrap(std::slice::from_ref(bootstrap))
        .build()
    else {
        eprintln!("tinc-dht-seed: bind failed");
        return ExitCode::FAILURE;
    };
    // Without this, get_mutable races the bootstrap find_node.
    dht.bootstrapped();

    // b"tinc" = Discovery::SALT. Hardcoded: re-exporting would link
    // the whole daemon (discovery.rs → SigningKey → dalek hazmat).
    let Some(item) = dht.get_mutable(&public, Some(b"tinc"), None).next() else {
        eprintln!("tinc-dht-seed: no record for pubkey (publish not landed?)");
        return ExitCode::FAILURE;
    };
    println!("{}", String::from_utf8_lossy(item.value()));
    ExitCode::SUCCESS
}

/// N-node swarm. Node 0 starts with no bootstrap (it's the root);
/// nodes 1..N bootstrap to `<SELF_HOST>:BASE`. They build a routing
/// table by querying each other; remote clients dial all N directly
/// AND follow referrals to `<SELF_HOST>:port` for the rest.
fn seed_mode(args: &[String]) -> ExitCode {
    let Some(base) = args.first().and_then(|s| s.parse::<u16>().ok()) else {
        eprintln!("tinc-dht-seed: invalid or missing BASE_PORT");
        usage();
        return ExitCode::FAILURE;
    };
    let count: u16 = match args.get(1) {
        None => 1,
        Some(s) => match s.parse() {
            Ok(n) if n >= 1 => n,
            _ => {
                eprintln!("tinc-dht-seed: COUNT must be >= 1");
                return ExitCode::FAILURE;
            }
        },
    };
    // See module doc for why this must NOT be 127.0.0.1 when remote.
    let self_host = args.get(2).map_or("127.0.0.1", String::as_str);

    // Node 0: no_bootstrap (root). Without it the builder defaults
    // to mainline's public seeds → 30s of DNS timeouts in a sealed
    // VM. Nodes 1..N bootstrap to SELF_HOST:base; root records them
    // at the recvfrom source (also SELF_HOST: hairpin), so referrals
    // to remote clients are followable.
    let root_bootstrap = format!("{self_host}:{base}");
    let mut nodes = Vec::with_capacity(count.into());

    for i in 0..count {
        let port = base + i;
        let mut builder = Dht::builder();
        builder.server_mode().port(port);
        if i == 0 {
            builder.no_bootstrap();
        } else {
            builder.bootstrap(std::slice::from_ref(&root_bootstrap));
        }
        match builder.build() {
            Ok(d) => nodes.push(d),
            Err(e) => {
                eprintln!("tinc-dht-seed: bind 0.0.0.0:{port} failed: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    // NixOS test waits for the last port's line (any earlier bind
    // error returns FAILURE before printing).
    for d in &nodes {
        let addr = d.info().local_addr();
        println!("tinc-dht-seed listening on 0.0.0.0:{}", addr.port());
    }

    // Each Dht runs on its own thread; main just keeps them alive.
    // SIGTERM → process exit → kernel reaps the sockets.
    loop {
        std::thread::park();
    }
}
