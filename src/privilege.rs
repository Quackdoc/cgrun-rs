use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

fn find_in_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p = dir.join(name);
        if p.is_file() && nix::unistd::access(&p, nix::unistd::AccessFlags::X_OK).is_ok() {
            return Some(p);
        }
    }
    None
}

pub fn escalate_with_args(args: &[String]) -> Result<()> {
    let exe = std::env::current_exe()
        .context("current_exe")?
        .to_string_lossy()
        .to_string();
    let bin = find_in_path("pkexec").context("pkexec not found in PATH (install polkit)")?;
    let mut cmd = Command::new(&bin);
    cmd.arg(&exe);
    cmd.args(args);
    let st = cmd
        .status()
        .with_context(|| format!("spawn {}", bin.display()))?;
    if st.success() {
        Ok(())
    } else {
        bail!(
            "pkexec failed ({st}): run `pkexec {} setup` once to delegate {}",
            exe,
            crate::BASE,
        )
    }
}

pub fn is_permission_error(e: &anyhow::Error) -> bool {
    for cause in e.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::PermissionDenied {
                return true;
            }
            if matches!(
                io.raw_os_error(),
                Some(x) if x == nix::errno::Errno::EACCES as i32 || x == nix::errno::Errno::EPERM as i32
            ) {
                return true;
            }
        }
    }
    false
}

/// Errors that mean "not delegated to you": permission denied, or the
/// parent cannot take controllers (EBUSY, e.g. it already runs processes).
pub fn is_delegation_error(e: &anyhow::Error) -> bool {
    if is_permission_error(e) {
        return true;
    }
    for cause in e.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if io.kind() == std::io::ErrorKind::ResourceBusy {
                return true;
            }
            if io.raw_os_error() == Some(nix::errno::Errno::EBUSY as i32) {
                return true;
            }
        }
    }
    false
}

const DELEGATED_FILES: &[&str] = &[
    "cgroup.procs",
    "cgroup.subtree_control",
    "cgroup.threads",
    "dmem.low",
    "dmem.max",
    "memory.max",
    "memory.high",
    "memory.low",
    "memory.min",
    "cpu.weight",
    "cpu.weight.nice",
    "cpu.max",
    "cgroup.kill",
    "cgroup.freeze",
    "cgroup.type",
    "cgroup.events",
];

fn chown_delegate(path: &Path, uid: u32, gid: u32) {
    let uid = nix::unistd::Uid::from_raw(uid);
    let gid = nix::unistd::Gid::from_raw(gid);

    for file in DELEGATED_FILES {
        let p = path.join(file);
        if p.exists() {
            let _ = nix::unistd::chown(&p, Some(uid), Some(gid));
        }
    }
    let _ = nix::unistd::chown(path, Some(uid), Some(gid));

    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perm = meta.permissions();
        perm.set_mode(0o775);
        let _ = std::fs::set_permissions(path, perm);
    }
}

fn try_enable_all(source: &Path, target: &Path) {
    const MANAGED: &[&str] = &["dmem", "memory", "cpu"];
    if let Ok(ctrls) = crate::cgroup::read_controllers(source) {
        let refs: Vec<&str> = ctrls
            .iter()
            .map(|s| s.as_str())
            .filter(|c| MANAGED.contains(c))
            .collect();
        let _ = crate::cgroup::enable_controllers(target, &refs);
    }
}

pub fn validate_rel(rel: &str) -> Result<()> {
    if rel.trim().is_empty() {
        bail!("invalid cgroup path ''");
    }
    if rel.starts_with('/') {
        bail!("invalid cgroup path '{rel}': must be relative");
    }
    let p = Path::new(rel);
    for comp in p.components() {
        use std::path::Component;
        match comp {
            Component::Normal(_) => {}
            _ => bail!("invalid cgroup path '{rel}'"),
        }
    }
    Ok(())
}

pub fn validate_base(base: &str) -> Result<()> {
    validate_rel(base)
}

fn checked_path(mount: &Path, rel: &str) -> Result<PathBuf> {
    validate_rel(rel)?;
    let full = crate::cgroup::full_cgroup_path(mount, rel);
    if !crate::cgroup::is_under_mount(mount, &full) {
        bail!("invalid cgroup path '{rel}': escapes the cgroup mount");
    }
    Ok(full)
}

pub fn privileged_setup(mount: &Path, base: &str, uid: u32, gid: u32) -> Result<()> {
    let full_path = checked_path(mount, base)?;
    let existed = full_path.exists();
    let full = crate::cgroup::create_cgroup_dir(mount, base)?;
    try_enable_all(mount, mount);
    if !existed {
        chown_delegate(&full, uid, gid);
    }
    Ok(())
}

pub fn privileged_create_cgroup(mount: &Path, rel: &str, uid: u32, gid: u32) -> Result<()> {
    let leaf_path = checked_path(mount, rel)?;
    let existed = leaf_path.exists();
    try_enable_all(mount, mount);

    if let Some(parent) = Path::new(rel).parent().and_then(|p| p.to_str())
        && !parent.is_empty()
    {
        let parent_path = crate::cgroup::full_cgroup_path(mount, parent);
        if !parent_path.exists() {
            privileged_create_cgroup(mount, parent, uid, gid)?;
        }
        try_enable_all(mount, &parent_path);
    }

    let full = crate::cgroup::create_cgroup_dir(mount, rel)?;
    if !existed {
        chown_delegate(&full, uid, gid);
    }
    Ok(())
}

pub fn privileged_clean_tree(mount: &Path, base: &str, owner_uid: u32) -> Result<()> {
    validate_base(base)?;
    let mut failed = Vec::new();
    let mut skipped = 0usize;
    for p in crate::cgroup::find_cgrun_cgroups(mount, &[base, crate::ROOT_BASE]) {
        // Never delete another user's cgroups on their behalf
        if owner_uid != 0 && dir_owner(&p) != Some(owner_uid) {
            skipped += 1;
            continue;
        }
        if let Err(e) = crate::signal_cgroup(mount, base, &p, nix::sys::signal::SIGKILL) {
            failed.push(format!("{}: {e:#}", p.display()));
        }
    }
    if !failed.is_empty() {
        bail!("could not remove: {}", failed.join(", "))
    }
    if skipped > 0 {
        eprintln!("skipped {skipped} cgroup(s) owned by other users");
    }
    Ok(())
}

fn dir_owner(p: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| m.uid())
}

pub fn privileged_move(mount: &Path, rel: &str, pid: i32) -> Result<()> {
    let full = checked_path(mount, rel)?;
    crate::cgroup::write_cgroup_procs(&full, pid)?;
    Ok(())
}

pub fn escalate_move_to_cgroup(_mount: &Path, rel: &str, pid: i32) -> Result<()> {
    validate_rel(rel)?;
    escalate_with_args(&[
        "privileged".into(),
        "--move".into(),
        rel.into(),
        "--move-pid".into(),
        pid.to_string(),
    ])
}

pub fn invoking_ids() -> (u32, u32) {
    if !is_root() {
        return (
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw(),
        );
    }
    let uid = std::env::var("PKEXEC_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| std::env::var("SUDO_UID").ok().and_then(|s| s.parse().ok()))
        .unwrap_or_else(|| nix::unistd::getuid().as_raw());

    let gid = std::env::var("PKEXEC_GID")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| std::env::var("SUDO_GID").ok().and_then(|s| s.parse().ok()))
        .unwrap_or_else(|| nix::unistd::getgid().as_raw());

    (uid, gid)
}
