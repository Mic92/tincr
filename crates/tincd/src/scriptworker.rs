//! Off-loop FIFO executor for hook scripts and small disk writes:
//! keeps `waitpid()`/`fsync()` off the event loop without losing the
//! `host-up → subnet-up` ordering a per-job `spawn()` would race.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;

use crate::script::{self, ScriptEnv, ScriptResult};

/// Bounded so a hung script can't make a flapping mesh eat RAM.
/// Sized for ~200 nodes × (host-up + per-node + subnet-up).
const QUEUE_CAP: usize = 1024;

pub(crate) enum Job {
    /// One `script::execute` call. `name` is relative to `confbase`
    /// (e.g. `"host-up"`, `"hosts/bob-up"`).
    Script {
        confbase: PathBuf,
        name: String,
        env: ScriptEnv,
        interpreter: Option<String>,
    },
    /// Atomic write-then-rename; keeps addrcache fsync+rename tail
    /// latency off the event loop.
    WriteFile { path: PathBuf, bytes: Vec<u8> },
}

/// FIFO worker. Thread spawns lazily on first `submit` so it
/// inherits the post-`sandbox::enter` Landlock domain. `Drop` joins
/// so shutdown drains queued `host-down`/`subnet-down`.
#[derive(Default)]
pub(crate) struct ScriptWorker {
    inner: Mutex<Option<(SyncSender<Job>, JoinHandle<()>)>>,
    full_warned: AtomicBool,
}

impl ScriptWorker {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Enqueue. On a full queue the job is **dropped** + warned once
    /// — better a missed `subnet-up` than a frozen data plane.
    ///
    /// # Panics
    /// If the OS refuses to spawn the worker thread on first call.
    pub(crate) fn submit(&self, job: Job) {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (tx, _) = guard.get_or_insert_with(|| {
            let (tx, rx) = sync_channel(QUEUE_CAP);
            let handle = std::thread::Builder::new()
                .name("tinc-script".into())
                .spawn(move || run(&rx))
                .expect("spawn script worker thread");
            (tx, handle)
        });
        if let Err(TrySendError::Full(_)) = tx.try_send(job)
            && !self.full_warned.swap(true, Ordering::Relaxed)
        {
            log::warn!(target: "tincd",
                "script worker queue full ({QUEUE_CAP}); dropping hook invocations");
        }
    }
}

impl Drop for ScriptWorker {
    fn drop(&mut self) {
        // Hang up the sender so `rx.recv()` returns Err and the
        // worker exits after draining what's already queued.
        if let Some((tx, h)) = self.inner.get_mut().ok().and_then(Option::take) {
            drop(tx);
            let _ = h.join();
        }
    }
}

fn run(rx: &Receiver<Job>) {
    while let Ok(job) = rx.recv() {
        match job {
            Job::Script {
                confbase,
                name,
                env,
                interpreter,
            } => {
                log_script(
                    &name,
                    script::execute(&confbase, &name, &env, interpreter.as_deref()),
                );
            }
            Job::WriteFile { path, bytes } => {
                if let Err(e) = crate::addrcache::write_atomic(&path, &bytes) {
                    log::debug!(target: "tincd::conn",
                        "address cache save failed: {e}");
                }
            }
        }
    }
}

/// Same shape as `Daemon::log_script`; duplicated because the worker
/// has no `Daemon`.
fn log_script(name: &str, r: std::io::Result<ScriptResult>) {
    match r {
        Ok(ScriptResult::NotFound | ScriptResult::Ok) => {}
        Ok(ScriptResult::Sandboxed) => {
            log::debug!(target: "tincd", "Script {name}: skipped (Sandbox=high)");
        }
        Ok(ScriptResult::Failed(st)) => {
            log::error!(target: "tincd", "Script {name} exited with status: {st}");
        }
        Err(e) => {
            log::error!(target: "tincd", "Script {name} spawn failed: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::PermissionsExt;

    /// FIFO ordering + Drop drains: the property user scripts rely on.
    #[test]
    fn fifo_and_drain_on_drop() {
        let dir = std::env::temp_dir().join(format!(
            "tincd-scriptworker-{:?}",
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out");
        let s = dir.join("hook");
        std::fs::write(
            &s,
            format!("#!/bin/sh\nprintf '%s' \"$N\" >> '{}'\n", out.display()),
        )
        .unwrap();
        std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o755)).unwrap();

        let w = ScriptWorker::new();
        for i in 0..5 {
            let mut env = ScriptEnv::base(None, "x", None, None, None);
            env.add("N", i.to_string());
            w.submit(Job::Script {
                confbase: dir.clone(),
                name: "hook".into(),
                env,
                interpreter: None,
            });
        }
        drop(w); // joins → all 5 done in order
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "01234");
    }
}
