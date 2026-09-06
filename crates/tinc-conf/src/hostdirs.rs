//! `hosts/` plus an optional `HostsOverlayDirectory`.
//!
//! On managed systems `hosts/` is deployed read-only from a registry.
//! Accepted invitations are written to the overlay instead, so a deploy
//! never clobbers them. Lookups try `hosts/` first and fall back to the
//! overlay, which means the registry copy wins once a node lands there.

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::Config;
use crate::name::check_id;

#[derive(Debug, Clone)]
pub struct HostDirs {
    primary: PathBuf,
    overlay: Option<PathBuf>,
}

impl HostDirs {
    #[must_use]
    pub fn new(confbase: &Path, overlay: Option<PathBuf>) -> Self {
        let primary = confbase.join("hosts");
        // An overlay that is `hosts/` itself would list every node twice.
        let overlay = overlay.filter(|o| !o.components().eq(primary.components()));
        Self { primary, overlay }
    }

    /// Reads `HostsOverlayDirectory` from the merged config. A relative
    /// path is taken against confbase.
    #[must_use]
    pub fn from_config(confbase: &Path, config: &Config) -> Self {
        let overlay = config
            .lookup("HostsOverlayDirectory")
            .next()
            .map(|e| confbase.join(e.get_str()));
        Self::new(confbase, overlay)
    }

    /// Path to read `name` from. Prefers `hosts/`, then the overlay. When
    /// neither has it, returns the `hosts/` path so error messages point
    /// there.
    #[must_use]
    pub fn file(&self, name: &str) -> PathBuf {
        let p = self.primary.join(name);
        if present(&p) {
            return p;
        }
        match &self.overlay {
            Some(o) if present(&o.join(name)) => o.join(name),
            _ => p,
        }
    }

    /// Any directory entry for `name` in either dir, dangling symlinks
    /// included. This is the guard before creating a host file.
    #[must_use]
    pub fn exists(&self, name: &str) -> bool {
        present(&self.primary.join(name))
            || self
                .overlay
                .as_ref()
                .is_some_and(|o| present(&o.join(name)))
    }

    /// Where new host files are created.
    #[must_use]
    pub fn write_path(&self, name: &str) -> PathBuf {
        self.overlay.as_ref().unwrap_or(&self.primary).join(name)
    }

    #[must_use]
    pub fn primary(&self) -> &Path {
        &self.primary
    }

    #[must_use]
    pub fn overlay(&self) -> Option<&Path> {
        self.overlay.as_deref()
    }

    /// Valid node names across both dirs, sorted, deduplicated.
    ///
    /// # Errors
    /// Either dir is unreadable. A missing overlay is fine, it is created
    /// on first write.
    pub fn names(&self) -> io::Result<Vec<String>> {
        let mut names = BTreeSet::new();
        collect(&self.primary, &mut names)?;
        if let Some(o) = &self.overlay {
            match collect(o, &mut names) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
                _ => {}
            }
        }
        Ok(names.into_iter().collect())
    }
}

/// `Path::exists` follows symlinks, so a dangling one would read as free.
fn present(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok()
}

fn collect(dir: &Path, into: &mut BTreeSet<String>) -> io::Result<()> {
    for ent in fs::read_dir(dir)?.flatten() {
        if let Some(n) = ent.file_name().to_str()
            && check_id(n)
        {
            into.insert(n.to_owned());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    /// A dangling symlink in `hosts/` still occupies the name. Falling
    /// through to the overlay would let an invitee claim it.
    #[test]
    fn dangling_symlink_occupies_name() {
        let tmp = tempfile::tempdir().unwrap();
        let ov = tmp.path().join("ov");
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();
        fs::create_dir_all(&ov).unwrap();
        symlink("/nonexistent", tmp.path().join("hosts/bob")).unwrap();
        fs::write(ov.join("bob"), "").unwrap();
        let d = HostDirs::new(tmp.path(), Some(ov));
        assert!(d.exists("bob"));
        assert_eq!(d.file("bob"), tmp.path().join("hosts/bob"));
        assert!(!d.exists("carol"));
    }

    /// A missing overlay is normal before the first join. An unreadable one
    /// hides nodes and must surface.
    #[test]
    fn names_overlay_missing_vs_unreadable() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();
        let d = HostDirs::new(tmp.path(), Some(tmp.path().join("nope")));
        assert!(d.names().unwrap().is_empty());
        let file = tmp.path().join("file");
        fs::write(&file, "").unwrap();
        let d = HostDirs::new(tmp.path(), Some(file));
        assert!(d.names().is_err());
    }
    /// Pointing the overlay at `hosts/` itself is a no-op, not a second
    /// scan of the same directory.
    #[test]
    fn overlay_equal_to_primary_is_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        for v in ["hosts", "hosts/", "./hosts"] {
            let f = tmp.path().join("tinc.conf");
            fs::write(&f, format!("HostsOverlayDirectory = {v}\n")).unwrap();
            let d = HostDirs::from_config(tmp.path(), &Config::read(&f).unwrap());
            assert!(d.overlay().is_none(), "{v}");
        }
    }

    #[test]
    fn primary_shadows_overlay() {
        let tmp = tempfile::tempdir().unwrap();
        let ov = tmp.path().join("hosts.local");
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();
        fs::create_dir_all(&ov).unwrap();
        let d = HostDirs::new(tmp.path(), Some(ov.clone()));

        fs::write(ov.join("bob"), "").unwrap();
        assert_eq!(d.file("bob"), ov.join("bob"));
        fs::write(tmp.path().join("hosts/bob"), "").unwrap();
        assert_eq!(d.file("bob"), tmp.path().join("hosts/bob"));

        assert_eq!(d.file("nobody"), tmp.path().join("hosts/nobody"));
        assert_eq!(d.write_path("carol"), ov.join("carol"));

        fs::write(ov.join("alice"), "").unwrap();
        fs::write(ov.join("README.txt"), "").unwrap();
        assert_eq!(d.names().unwrap(), ["alice", "bob"]);
    }

    #[test]
    fn no_overlay_is_plain_hosts() {
        let tmp = tempfile::tempdir().unwrap();
        let d = HostDirs::new(tmp.path(), None);
        assert_eq!(d.write_path("x"), tmp.path().join("hosts/x"));
        assert!(d.names().is_err());
    }
}
