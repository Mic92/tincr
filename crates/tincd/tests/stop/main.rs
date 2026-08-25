//! Single real `tincd` driven over its control socket and signals.

use std::path::Path;

#[path = "../common/mod.rs"]
#[macro_use]
mod common;

mod cli_flags;
mod control;
mod lifecycle;
mod peer;

use common::Node;

/// `testnode`: dummy device, no peers, not yet started.
pub(crate) fn testnode(dir: &Path) -> Node {
    let node = Node::new(dir, "testnode", 0x42);
    node.write_config_multi(&[], &[]);
    node
}
