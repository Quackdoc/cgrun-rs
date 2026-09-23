use anyhow::{Context, Result, bail};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, fork};
use std::ffi::CString;
use std::path::Path;

fn enotsup_hint(cgroup: &Path) -> String {
    format!(
        "move to {}: Operation not supported — delegation not properly enabled (parent {} must be writable, have controllers in cgroup.controllers and +controllers in cgroup.subtree_control, and satisfy no-internal-process: no tasks in the parent when it has children)",
        cgroup.display(),
        cgroup.parent().unwrap_or(cgroup).display()
    )
}

pub fn spawn_in_cgroup(
    mount: &Path,
    rel: &str,
    cgroup: &Path,
    cmd: &[String],
    use_priv: bool,
) -> Result<i32> {
    if cmd.is_empty() {
        bail!("no command");
    }

    let cstrs: Vec<CString> = cmd
        .iter()
        .map(|s| CString::new(s.as_str()).with_context(|| format!("argument contains NUL: {s:?}")))
        .collect::<Result<Vec<_>>>()?;

    // CLOEXEC so the pipe never leaks into the execed child on any path.
    let (read_fd, write_fd) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).context("pipe")?;

    match unsafe { fork().context("fork")? } {
        ForkResult::Parent { child } => {
            drop(read_fd);

            if let Err(e) = crate::cgroup::write_cgroup_procs(cgroup, child.as_raw()) {
                let escalated = use_priv
                    && !crate::privilege::is_root()
                    && crate::privilege::is_permission_error(&e)
                    && crate::privilege::escalate_move_to_cgroup(mount, rel, child.as_raw())
                        .is_ok();
                if !escalated {
                    let _ = nix::sys::signal::kill(child, nix::sys::signal::SIGKILL);
                    drop(write_fd);
                    let _ = waitpid(child, None);
                    if crate::cgroup::is_enotsup(&e) {
                        return Err(e).context(enotsup_hint(cgroup));
                    }
                    return Err(e).context(format!("move to {}", cgroup.display()));
                }
            }

            // Wake child after it is in the cgroup
            let _ = nix::unistd::write(&write_fd, b"x");
            drop(write_fd);

            loop {
                match waitpid(child, None) {
                    Ok(WaitStatus::Exited(_, code)) => return Ok(code),
                    Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(128 + sig as i32),
                    Ok(_) => continue,
                    Err(e) => bail!("waitpid: {e}"),
                }
            }
        }
        ForkResult::Child => {
            drop(write_fd);
            let mut buf = [0u8; 1];
            // Block until parent places us in the target cgroup. Any
            // short read / EOF / error means the parent died before the
            // migrate — never exec outside the cgroup, exit instead.
            match nix::unistd::read(&read_fd, &mut buf) {
                Ok(1) => {}
                _ => std::process::exit(125),
            }
            drop(read_fd);

            let err = nix::unistd::execvp(&cstrs[0], &cstrs).unwrap_err();
            eprintln!("exec: {err}");
            std::process::exit(127);
        }
    }
}
