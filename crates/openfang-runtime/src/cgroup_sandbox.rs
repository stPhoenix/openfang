//! Linux cgroup v2 sandbox — per-agent `pids.max` enforcement.
//!
//! ## Why
//! `RLIMIT_NPROC` on Linux limits processes by **real UID**, not per-process
//! tree. The openfang tokio daemon's own threads count as tasks against the
//! same UID, so a per-child setrlimit cap (default 256) trivially blows up
//! once the daemon plus user-shared procs plus a yt-dlp + ffmpeg pipeline are
//! running. Cgroup v2's `pids.max` is per-cgroup, so an agent's subprocess
//! tree is bounded independently of what else the daemon UID is doing.
//!
//! ## Design
//! 1. At daemon startup, `init(&policy)` detects our cgroup via
//!    `/proc/self/cgroup`. If we're not at the cgroup root, we move ourselves
//!    into a `supervisor/` subgroup so the parent cgroup has no internal
//!    processes (cgroup v2 forbids enabling subtree controllers on a cgroup
//!    that contains processes, except the root). We then enable the `pids`
//!    controller in the parent's `cgroup.subtree_control`. Returns a
//!    `CgroupSession` carrying the agent-parent path.
//! 2. Per agent spawn, `CgroupSession::create_agent(uuid, &policy)` mkdir's
//!    `agent-<uuid>/`, writes `pids.max`, and opens `cgroup.procs` O_WRONLY
//!    | O_CLOEXEC. The fd is wrapped in `Arc<OwnedFd>` so `pre_exec` closures
//!    in different concurrent `tool_shell_exec` calls share it safely.
//! 3. In each `pre_exec`, `write_self_pid_async_signal_safe(fd)` writes the
//!    child's pid to the cgroup before exec. Async-signal-safe: stack
//!    itoa + single `libc::write`, no allocation, no locks, no std::fs.
//!
//! ## Fallback
//! If `init` or `create_agent` fails (cgroup v2 not mounted, no delegation,
//! container with read-only cgroupfs), callers receive `None` and fall back
//! to the existing `setrlimit(RLIMIT_NPROC)` floor.

use openfang_types::config::CgroupPolicy;

/// The cgroup.procs file descriptor handed to `pre_exec` closures.
///
/// Linux: `Arc<OwnedFd>`. Other platforms: zero-sized inert handle that is
/// never constructed (callers always pass `None`). This lets cross-platform
/// signatures use `Option<CgroupProcsFd>` without per-OS cfg pollution.
#[cfg(target_os = "linux")]
pub type CgroupProcsFd = std::sync::Arc<std::os::fd::OwnedFd>;

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone)]
pub struct CgroupProcsFd;

// ──────────────────────────────────────────────────────────────────────────
// Linux implementation
// ──────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;
    use std::fs;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    pub(super) const CGROUP_ROOT: &str = "/sys/fs/cgroup";
    pub(super) const SUPERVISOR_LEAF: &str = "supervisor";

    #[derive(Debug, thiserror::Error)]
    pub enum CgroupError {
        #[error("cgroup v2 not mounted at {0}")]
        NotMounted(&'static str),
        #[error("self cgroup detection failed: {0}")]
        SelfDetectFailed(String),
        #[error("controller '{0}' not available in parent cgroup {1:?}")]
        ControllerUnavailable(String, PathBuf),
        #[error("no write permission on {0:?}: {1}")]
        NoWritePermission(PathBuf, std::io::Error),
        #[error("disk full creating cgroup at {0:?}")]
        NoSpace(PathBuf),
        #[error("cgroup_policy.enabled is false")]
        Disabled,
        #[error("io error on {0:?}: {1}")]
        Io(PathBuf, std::io::Error),
    }

    impl CgroupError {
        pub(super) fn classify(path: &Path, e: std::io::Error) -> Self {
            use std::io::ErrorKind;
            match (e.kind(), e.raw_os_error()) {
                (ErrorKind::PermissionDenied, _) => {
                    Self::NoWritePermission(path.to_path_buf(), e)
                }
                (_, Some(libc::ENOSPC)) => Self::NoSpace(path.to_path_buf()),
                _ => Self::Io(path.to_path_buf(), e),
            }
        }
    }

    /// Parsed `/proc/self/cgroup` v2 line.
    pub fn detect_self_cgroup() -> Result<PathBuf, CgroupError> {
        let raw = fs::read_to_string("/proc/self/cgroup")
            .map_err(|e| CgroupError::SelfDetectFailed(format!("read /proc/self/cgroup: {e}")))?;
        parse_self_cgroup(&raw)
    }

    pub(super) fn parse_self_cgroup(content: &str) -> Result<PathBuf, CgroupError> {
        for line in content.lines() {
            // cgroup v2 unified hierarchy line: "0::<path>"
            if let Some(suffix) = line.strip_prefix("0::") {
                let path = if suffix == "/" {
                    PathBuf::from(CGROUP_ROOT)
                } else {
                    PathBuf::from(CGROUP_ROOT).join(suffix.trim_start_matches('/'))
                };
                return Ok(path);
            }
        }
        Err(CgroupError::SelfDetectFailed(
            "no '0::' line in /proc/self/cgroup (cgroup v2 unified hierarchy required)".into(),
        ))
    }

    #[derive(Debug)]
    pub struct ProbeReport {
        pub own_cgroup: PathBuf,
        pub pids_available: bool,
        pub pids_in_subtree: bool,
    }

    pub fn probe() -> Result<ProbeReport, CgroupError> {
        let root_ctrl = Path::new(CGROUP_ROOT).join("cgroup.controllers");
        if !root_ctrl.exists() {
            return Err(CgroupError::NotMounted(CGROUP_ROOT));
        }
        let own = detect_self_cgroup()?;
        let own_ctrl = own.join("cgroup.controllers");
        let controllers =
            fs::read_to_string(&own_ctrl).map_err(|e| CgroupError::classify(&own_ctrl, e))?;
        let pids_available = controllers.split_whitespace().any(|c| c == "pids");

        let subtree = own.join("cgroup.subtree_control");
        let pids_in_subtree = fs::read_to_string(&subtree)
            .map(|s| s.split_whitespace().any(|c| c == "pids"))
            .unwrap_or(false);
        Ok(ProbeReport {
            own_cgroup: own,
            pids_available,
            pids_in_subtree,
        })
    }

    /// One-time daemon-startup setup. See module docs for the supervisor move.
    pub fn init(policy: &CgroupPolicy) -> Result<CgroupSession, CgroupError> {
        if !policy.enabled {
            return Err(CgroupError::Disabled);
        }
        let own = if policy.parent_path.is_empty() {
            detect_self_cgroup()?
        } else {
            PathBuf::from(&policy.parent_path)
        };

        // Verify pids controller is available in our parent.
        let ctrl_path = own.join("cgroup.controllers");
        let controllers = fs::read_to_string(&ctrl_path)
            .map_err(|e| CgroupError::classify(&ctrl_path, e))?;
        if !controllers.split_whitespace().any(|c| c == "pids") {
            return Err(CgroupError::ControllerUnavailable("pids".into(), own));
        }

        let is_root = own.as_path() == Path::new(CGROUP_ROOT);
        let subtree_path = own.join("cgroup.subtree_control");
        let current_subtree = fs::read_to_string(&subtree_path)
            .map_err(|e| CgroupError::classify(&subtree_path, e))?;
        let pids_enabled = current_subtree.split_whitespace().any(|c| c == "pids");

        if !pids_enabled {
            if !is_root {
                // Move the daemon process into a supervisor leaf so our own
                // cgroup has no internal processes — required by cgroup v2
                // before we can enable subtree controllers.
                let supervisor = own.join(SUPERVISOR_LEAF);
                fs::create_dir_all(&supervisor)
                    .map_err(|e| CgroupError::classify(&supervisor, e))?;
                let sup_procs = supervisor.join("cgroup.procs");
                let pid_str = format!("{}\n", unsafe { libc::getpid() });
                fs::write(&sup_procs, pid_str.as_bytes())
                    .map_err(|e| CgroupError::classify(&sup_procs, e))?;
            }
            fs::write(&subtree_path, "+pids")
                .map_err(|e| CgroupError::classify(&subtree_path, e))?;
        }

        Ok(CgroupSession { agent_parent: own })
    }

    /// Per-daemon handle: parent directory where agent cgroups are created.
    #[derive(Debug, Clone)]
    pub struct CgroupSession {
        pub agent_parent: PathBuf,
    }

    impl CgroupSession {
        pub fn create_agent(
            &self,
            agent_id: uuid::Uuid,
            policy: &CgroupPolicy,
        ) -> Result<SessionCgroup, CgroupError> {
            let dir = self.agent_parent.join(format!("agent-{agent_id}"));
            fs::create_dir_all(&dir).map_err(|e| CgroupError::classify(&dir, e))?;

            let max_path = dir.join("pids.max");
            let max_str = format!("{}\n", policy.max_processes);
            fs::write(&max_path, max_str.as_bytes())
                .map_err(|e| CgroupError::classify(&max_path, e))?;

            let procs_path = dir.join("cgroup.procs");
            let path_cstr = std::ffi::CString::new(procs_path.as_os_str().as_encoded_bytes())
                .map_err(|_| {
                    CgroupError::Io(
                        procs_path.clone(),
                        std::io::Error::other("path contains NUL"),
                    )
                })?;
            let fd =
                unsafe { libc::open(path_cstr.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                let err = std::io::Error::last_os_error();
                return Err(CgroupError::classify(&procs_path, err));
            }
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            Ok(SessionCgroup {
                dir,
                procs_fd: Arc::new(owned),
            })
        }
    }

    /// Per-agent cgroup. Holds the cgroup directory path and an `Arc<OwnedFd>`
    /// to `cgroup.procs`. The fd is shared across all concurrent
    /// `tool_shell_exec` calls for the agent; cgroupfs serializes writes.
    #[derive(Debug)]
    pub struct SessionCgroup {
        pub dir: PathBuf,
        procs_fd: Arc<OwnedFd>,
    }

    impl SessionCgroup {
        pub fn procs_fd(&self) -> Arc<OwnedFd> {
            Arc::clone(&self.procs_fd)
        }

        pub fn destroy(self) -> Result<(), CgroupError> {
            // Drop the fd reference held by this handle. Other Arc clones
            // (in flight pre_exec captures) keep the fd open until they
            // complete, then the cgroup becomes removable.
            drop(self.procs_fd);
            match fs::remove_dir(&self.dir) {
                Ok(()) => Ok(()),
                Err(e) => {
                    tracing::warn!(
                        path = %self.dir.display(),
                        error = %e,
                        "cgroup rmdir failed (likely procs still alive); leaked"
                    );
                    Err(CgroupError::Io(self.dir.clone(), e))
                }
            }
        }
    }

    /// **Async-signal-safe.** Safe to call from a `pre_exec` closure.
    /// Writes `getpid()` followed by '\n' to `procs_fd`. No allocation, no
    /// locks, no std::fs — only `libc::getpid` and `libc::write`.
    pub fn write_self_pid_async_signal_safe(
        procs_fd: std::os::fd::RawFd,
    ) -> Result<(), std::io::Error> {
        let pid = unsafe { libc::getpid() };
        let mut buf = [0u8; 12];
        let len = format_pid_into(pid, &mut buf);
        let start = buf.len() - len;
        let written = unsafe {
            libc::write(
                procs_fd,
                buf.as_ptr().add(start) as *const _,
                len,
            )
        };
        if written < 0 {
            Err(std::io::Error::last_os_error())
        } else if (written as usize) != len {
            Err(std::io::Error::other("short write to cgroup.procs"))
        } else {
            Ok(())
        }
    }

    /// Manual itoa: writes `<pid>\n` into the *end* of `buf`. Returns the
    /// number of bytes written. Async-signal-safe.
    pub(super) fn format_pid_into(pid: libc::pid_t, buf: &mut [u8; 12]) -> usize {
        let mut n = if pid < 0 { 0u32 } else { pid as u32 };
        let mut idx = buf.len() - 1;
        buf[idx] = b'\n';
        let end = idx;
        if n == 0 {
            idx -= 1;
            buf[idx] = b'0';
        } else {
            while n > 0 {
                idx -= 1;
                buf[idx] = b'0' + (n % 10) as u8;
                n /= 10;
            }
        }
        end - idx + 1
    }
}

#[cfg(target_os = "linux")]
pub use linux_impl::*;

// ──────────────────────────────────────────────────────────────────────────
// Non-Linux stubs
// ──────────────────────────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
mod stub_impl {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    pub enum CgroupError {
        #[error("cgroup sandbox is Linux-only")]
        Unsupported,
    }

    #[derive(Debug, Clone)]
    pub struct CgroupSession;

    #[derive(Debug)]
    pub struct SessionCgroup;

    pub fn init(_policy: &CgroupPolicy) -> Result<CgroupSession, CgroupError> {
        Err(CgroupError::Unsupported)
    }

    impl CgroupSession {
        pub fn create_agent(
            &self,
            _agent_id: uuid::Uuid,
            _policy: &CgroupPolicy,
        ) -> Result<SessionCgroup, CgroupError> {
            Err(CgroupError::Unsupported)
        }
    }

    impl SessionCgroup {
        pub fn procs_fd(&self) -> CgroupProcsFd {
            CgroupProcsFd
        }
        pub fn destroy(self) -> Result<(), CgroupError> {
            Ok(())
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub use stub_impl::*;

// ──────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::linux_impl::*;
    use std::path::PathBuf;

    #[test]
    fn parse_self_cgroup_root() {
        let p = parse_self_cgroup("0::/\n").unwrap();
        assert_eq!(p, PathBuf::from(CGROUP_ROOT));
    }

    #[test]
    fn parse_self_cgroup_nested() {
        let p = parse_self_cgroup("0::/system.slice/openfang.service\n").unwrap();
        assert_eq!(
            p,
            PathBuf::from("/sys/fs/cgroup/system.slice/openfang.service")
        );
    }

    #[test]
    fn parse_self_cgroup_v1_only_errs() {
        let r = parse_self_cgroup("12:cpu,cpuacct:/foo\n11:memory:/bar\n");
        assert!(r.is_err());
    }

    #[test]
    fn parse_self_cgroup_mixed_v1_and_v2() {
        // Hybrid system: v1 lines + a single v2 line. Pick the v2 line.
        let r = parse_self_cgroup("12:cpu,cpuacct:/foo\n0::/user.slice/u.service\n").unwrap();
        assert_eq!(
            r,
            PathBuf::from("/sys/fs/cgroup/user.slice/u.service")
        );
    }

    #[test]
    fn format_pid_basic() {
        let mut buf = [0u8; 12];
        let n = format_pid_into(12345, &mut buf);
        assert_eq!(&buf[buf.len() - n..], b"12345\n");
    }

    #[test]
    fn format_pid_single_digit() {
        let mut buf = [0u8; 12];
        let n = format_pid_into(7, &mut buf);
        assert_eq!(&buf[buf.len() - n..], b"7\n");
    }

    #[test]
    fn format_pid_zero() {
        let mut buf = [0u8; 12];
        let n = format_pid_into(0, &mut buf);
        assert_eq!(&buf[buf.len() - n..], b"0\n");
    }

    #[test]
    fn format_pid_max_u32() {
        let mut buf = [0u8; 12];
        let n = format_pid_into(i32::MAX, &mut buf);
        assert_eq!(&buf[buf.len() - n..], b"2147483647\n");
    }
}
