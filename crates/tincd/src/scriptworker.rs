//! Off-loop FIFO executor for hook scripts and small disk writes:
//! keeps `waitpid()`/`fsync()` off the event loop without losing the
//! `host-up → subnet-up` ordering a per-job `spawn()` would race.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;

use crate::addrcache;
use crate::script::{self, ScriptEnv, ScriptResult};
use std::io;
use std::thread::Builder;

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
    /// Signalled once every earlier job has run.
    Barrier(SyncSender<()>),
}

/// FIFO worker. Jobs queue until [`Self::start`], which runs after
/// `sandbox::enter` so the thread inherits the Landlock domain. `Drop`
/// joins so shutdown drains queued `host-down`/`subnet-down`.
pub(crate) struct ScriptWorker {
    tx: Option<SyncSender<Job>>,
    pending: Option<Receiver<Job>>,
    join: Option<JoinHandle<()>>,
    full_warned: AtomicBool,
}

impl ScriptWorker {
    #[must_use]
    pub(crate) fn new() -> Self {
        let (tx, rx) = sync_channel(QUEUE_CAP);
        Self {
            tx: Some(tx),
            pending: Some(rx),
            join: None,
            full_warned: AtomicBool::new(false),
        }
    }

    /// # Panics
    /// If the OS refuses to spawn the worker thread.
    pub(crate) fn start(&mut self) {
        let Some(rx) = self.pending.take() else {
            return;
        };
        #[expect(
            clippy::expect_used,
            reason = "thread spawn failure is fatal (resource exhaustion)"
        )]
        let handle = Builder::new()
            .name("tinc-script".into())
            .spawn(move || run(&rx))
            .expect("spawn script worker thread");
        self.join = Some(handle);
    }

    /// Enqueue. On a full queue the job is **dropped** + warned once
    /// — better a missed `subnet-up` than a frozen data plane.
    pub(crate) fn submit(&self, job: Job) {
        let Some(tx) = &self.tx else {
            return;
        };
        if let Err(TrySendError::Full(_)) = tx.try_send(job)
            && !self.full_warned.swap(true, Ordering::Relaxed)
        {
            log::warn!(target: "tincd",
                "script worker queue full ({QUEUE_CAP}); dropping hook invocations");
        }
    }
}

impl ScriptWorker {
    /// Block until every job queued so far has run, so a synchronous
    /// `tinc-down` cannot overtake a queued `host-down`.
    pub(crate) fn flush(&self) {
        let (Some(tx), Some(_)) = (&self.tx, &self.join) else {
            return;
        };
        let (done_tx, done_rx) = sync_channel(1);
        if tx.send(Job::Barrier(done_tx)).is_ok() {
            let _ = done_rx.recv();
        }
    }
}

impl Drop for ScriptWorker {
    fn drop(&mut self) {
        // Hang up the sender so `rx.recv()` returns Err and the
        // worker exits after draining what's already queued.
        drop(self.tx.take());
        if let Some(h) = self.join.take() {
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
            Job::Barrier(done) => {
                let _ = done.send(());
            }
            Job::WriteFile { path, bytes } => {
                if let Err(e) = addrcache::write_atomic(&path, &bytes) {
                    log::debug!(target: "tincd::conn",
                        "address cache save failed: {e}");
                }
            }
        }
    }
}

/// Same shape as `Daemon::log_script`; duplicated because the worker
/// has no `Daemon`.
fn log_script(name: &str, r: io::Result<ScriptResult>) {
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

    use crate::testutil;
    use std::fs;
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    /// FIFO ordering + Drop drains: the property user scripts rely on.
    #[test]
    fn fifo_and_drain_on_drop() {
        let dir = testutil::tmpdir("scriptworker");
        let out = dir.join("out");
        let s = dir.join("hook");
        fs::write(
            &s,
            format!("#!/bin/sh\nprintf '%s' \"$N\" >> '{}'\n", out.display()),
        )
        .unwrap();
        fs::set_permissions(&s, Permissions::from_mode(0o755)).unwrap();

        let mut w = ScriptWorker::new();
        for i in 0..5 {
            let mut env = ScriptEnv::base(None, "x", None, None, None);
            env.add("N", i.to_string());
            w.submit(Job::Script {
                confbase: dir.to_path_buf(),
                name: "hook".into(),
                env,
                interpreter: None,
            });
        }
        w.start(); // jobs queued before start run too
        drop(w); // joins → all 5 done in order
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "01234");
    }
}
