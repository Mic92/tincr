//! Shared test tempdir helper.
//!
//! Wraps `tempfile::TempDir` so paths are unique per call and removed on
//! drop. Earlier helpers keyed on `ThreadId`, which collided with stale
//! root-owned dirs left by sudo runs. The newtype adds `Deref<Target=Path>`
//! so call sites can keep `dir.join(..)` / `f(&dir)` without `.path()`.

use std::ops::Deref;
use std::path::Path;

/// RAII temp directory: unique per call, removed on drop.
pub(crate) struct TmpDir(tempfile::TempDir);

impl TmpDir {
    /// Fresh temp dir; `tag` is a debug prefix only.
    pub(crate) fn new(tag: &str) -> Self {
        Self(
            tempfile::Builder::new()
                .prefix(&format!("tincd-test-{tag}-"))
                .tempdir()
                .expect("create tempdir"),
        )
    }

    pub(crate) fn path(&self) -> &Path {
        self.0.path()
    }
}

impl Deref for TmpDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        self.0.path()
    }
}

impl AsRef<Path> for TmpDir {
    fn as_ref(&self) -> &Path {
        self.0.path()
    }
}

/// Shorthand for `TmpDir::new`.
pub(crate) fn tmpdir(tag: &str) -> TmpDir {
    TmpDir::new(tag)
}
