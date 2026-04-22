//! Routing-table persistence (`dht_nodes` file). Warm-start hint only —
//! lets a restart skip the DNS-seed round-trip. Never load-bearing.

use std::net::SocketAddrV4;
use std::path::Path;

/// Cap on routing-table addrs written to `dht_nodes`. Transmission's
/// `dht.dat` keeps the full table (~hundreds); 100 is plenty to skip
/// the DNS-seed round-trip on restart and small enough to not care
/// about atomic-rename.
const MAX_PERSISTED_NODES: usize = 100;

/// Read the persisted routing-table file (one `ip:port` per line, same
/// shape as the addrcache). Missing / unreadable / unparseable → empty
/// + debug log; the file is a warm-start hint, never load-bearing.
#[must_use]
pub fn load_persisted_nodes(path: &Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .lines()
            .map(str::trim)
            // Reject anything that doesn't parse as a v4 sockaddr:
            // mainline's `to_socket_address` would skip it anyway, and
            // this keeps a corrupted file from feeding garbage to DNS.
            .filter(|l| l.parse::<SocketAddrV4>().is_ok())
            .take(MAX_PERSISTED_NODES)
            .map(String::from)
            .collect(),
        Err(e) => {
            log::debug!(target: "tincd::discovery",
                        "dht_nodes load {}: {e} (cold bootstrap)", path.display());
            Vec::new()
        }
    }
}

/// Write up to [`MAX_PERSISTED_NODES`] routing-table addrs, one per
/// line. Best-effort; caller logs on `Err`.
///
/// # Errors
/// Propagates `create_dir_all` / `write` failures (read-only state dir,
/// disk full). The caller treats this as non-fatal.
pub fn save_persisted_nodes(path: &Path, nodes: &[String]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut buf = String::new();
    for n in nodes.iter().take(MAX_PERSISTED_NODES) {
        buf.push_str(n);
        buf.push('\n');
    }
    std::fs::write(path, buf)
}
