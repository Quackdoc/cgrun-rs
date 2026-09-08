use anyhow::{Context, Result, bail};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

pub fn find_cgroup2_mount() -> Result<PathBuf> {
    if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return Ok(PathBuf::from("/sys/fs/cgroup"));
    }
    let data = fs::read_to_string("/proc/self/mountinfo").context("read /proc/self/mountinfo")?;
    for line in data.lines() {
        if let Some((pre, post)) = line.split_once(" - ")
            && post.split_whitespace().next() == Some("cgroup2")
            && let Some(mp) = pre.split_whitespace().nth(4)
        {
            return Ok(PathBuf::from(mp));
        }
    }
    bail!("cgroup2 mount not found")
}

pub fn current_cgroup_rel() -> Result<String> {
    let data =
        fs::read_to_string("/proc/self/cgroup").context("failed to read /proc/self/cgroup")?;
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let p = rest
                .trim()
                .split(" (deleted)")
                .next()
                .unwrap_or(rest)
                .trim();
            return Ok(p.trim_matches('/').to_string());
        }
    }
    bail!("no cgroup v2 entry");
}

pub fn full_cgroup_path(mount: &Path, rel: &str) -> PathBuf {
    let rel = rel.trim_start_matches('/');
    if rel.is_empty() {
        mount.to_path_buf()
    } else {
        mount.join(rel)
    }
}

pub fn read_controllers(p: &Path) -> Result<Vec<String>> {
    let data = fs::read_to_string(p.join("cgroup.controllers"))
        .with_context(|| format!("read {}", p.display()))?;
    Ok(data.split_whitespace().map(|s| s.to_string()).collect())
}

pub fn read_subtree_control(p: &Path) -> Result<String> {
    match fs::read_to_string(p.join("cgroup.subtree_control")) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).context(format!("read {}/cgroup.subtree_control", p.display())),
    }
}

pub fn enable_controllers(p: &Path, ctrls: &[&str]) -> Result<()> {
    let cur = read_subtree_control(p).unwrap_or_default();
    let enabled: Vec<&str> = cur.split_whitespace().collect();
    let need: Vec<String> = ctrls
        .iter()
        .filter(|c| !enabled.contains(*c))
        .map(|c| format!("+{c}"))
        .collect();
    if need.is_empty() {
        return Ok(());
    }

    fs::write(p.join("cgroup.subtree_control"), need.join(" "))
        .with_context(|| format!("write {}/cgroup.subtree_control", p.display()))?;
    Ok(())
}

pub fn create_cgroup_dir(mount: &Path, rel: &str) -> Result<PathBuf> {
    let full = full_cgroup_path(mount, rel);
    fs::create_dir_all(&full).with_context(|| format!("mkdir {}", full.display()))?;
    // Ensure cgroup is not left in invalid threaded topology
    // (e.g. domain invalid under domain threaded parent)
    let _ = ensure_valid_type(&full);
    Ok(full)
}

pub fn ensure_valid_type(path: &Path) -> Result<()> {
    let ty_path = path.join("cgroup.type");
    if let Ok(data) = fs::read_to_string(&ty_path)
        && data.contains("invalid")
    {
        // Parent is threaded domain, child domain is invalid — make child threaded
        let _ = fs::write(&ty_path, "threaded");
        // Verify it became valid
        if let Ok(new_data) = fs::read_to_string(&ty_path)
            && new_data.contains("invalid")
        {
            bail!(
                "cgroup type still invalid after fix: {}: {}",
                path.display(),
                new_data.trim()
            );
        }
    }
    Ok(())
}

pub fn remove_cgroup_with_retry(path: &Path) -> Result<()> {
    const MAX_ATTEMPTS: usize = 50;
    const INITIAL_DELAY: Duration = Duration::from_millis(10);
    const MAX_DELAY: Duration = Duration::from_secs(1);

    let mut delay = INITIAL_DELAY;
    for attempt in 1..=MAX_ATTEMPTS {
        match fs::remove_dir(path) {
            Ok(()) => return Ok(()),
            Err(_) if !path.exists() => return Ok(()),
            Err(e) => {
                // EBUSY: processes still attached.
                // ENOTEMPTY: child cgroups still present
                let raw = e.raw_os_error();
                let busy = raw == Some(nix::errno::Errno::EBUSY as i32)
                    || e.kind() == std::io::ErrorKind::ResourceBusy;
                let not_empty = raw == Some(nix::errno::Errno::ENOTEMPTY as i32)
                    || e.kind() == std::io::ErrorKind::DirectoryNotEmpty;
                if busy || not_empty {
                    if attempt == MAX_ATTEMPTS {
                        return Err(e).context(format!("cgroup busy: {}", path.display()));
                    }
                    thread::sleep(delay);
                    delay = (delay * 2).min(MAX_DELAY);
                } else {
                    return Err(e).context(format!("rmdir {}", path.display()));
                }
            }
        }
    }
    Ok(())
}

pub fn write_cgroup_procs(cgroup: &Path, pid: i32) -> Result<()> {
    fs::write(cgroup.join("cgroup.procs"), format!("{pid}\n"))
        .with_context(|| format!("write {}/cgroup.procs", cgroup.display()))?;
    Ok(())
}

pub fn is_cgroup_dir(p: &Path) -> bool {
    p.join("cgroup.procs").exists()
}

pub fn members(cgroup: &Path) -> Result<Vec<i32>> {
    let data = fs::read_to_string(cgroup.join("cgroup.procs"))
        .with_context(|| format!("read {}/cgroup.procs", cgroup.display()))?;
    Ok(data
        .lines()
        .filter_map(|l| l.trim().parse::<i32>().ok())
        .collect())
}

fn is_not_found(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
    })
}

/// Pids in a cgroup. A missing cgroup.procs means the cgroup is already
/// Any other read failure errors instead of silently killing nothing.
fn tree_pids(cgroup: &Path) -> Result<Vec<i32>> {
    match members(cgroup) {
        Ok(p) => Ok(p),
        Err(e) if is_not_found(&e) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// True when `p` is the mount itself or lives below it (lexical check).
pub fn is_under_mount(mount: &Path, p: &Path) -> bool {
    p == mount || p.strip_prefix(mount).is_ok()
}

pub fn kill_tree(cgroup: &Path) -> Result<()> {
    let kill = cgroup.join("cgroup.kill");
    if kill.exists() {
        fs::write(&kill, "1").with_context(|| format!("write {}", kill.display()))?;
        return Ok(());
    }
    for pid in tree_pids(cgroup)? {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), nix::sys::signal::SIGKILL);
    }
    Ok(())
}

pub fn signal_tree(mount: &Path, cgroup: &Path, sig: nix::sys::signal::Signal) -> Result<()> {
    for pid in tree_pids(cgroup)? {
        // Narrow the PID-reuse race: verify the target is still a member
        // of this tree before signaling.
        if !pid_in_tree(mount, cgroup, pid) {
            continue;
        }
        match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), sig) {
            Ok(()) => {}
            Err(nix::errno::Errno::ESRCH) => {}
            Err(e) => bail!("kill {}: {e}", pid),
        }
    }
    Ok(())
}

/// check still in cgroup via /proc/<pid>/cgroup.
fn pid_in_tree(mount: &Path, target: &Path, pid: i32) -> bool {
    let data = match fs::read_to_string(format!("/proc/{pid}/cgroup")) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let target_rel = target
        .strip_prefix(mount)
        .map(|r| r.to_string_lossy().to_string())
        .unwrap_or_default();
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let proc_rel = rest.trim().trim_matches('/').to_string();
            if target_rel.is_empty() {
                return true;
            }
            if proc_rel == target_rel || proc_rel.starts_with(&format!("{target_rel}/")) {
                return true;
            }
        }
    }
    false
}

pub fn freeze(mount: &Path, cgroup: &Path) -> Result<()> {
    let p = cgroup.join("cgroup.freeze");
    if p.exists() {
        fs::write(&p, "1").with_context(|| format!("write {}", p.display()))?;
    } else {
        signal_tree(mount, cgroup, nix::sys::signal::SIGSTOP)?;
    }
    Ok(())
}

pub fn thaw(mount: &Path, cgroup: &Path) -> Result<()> {
    let p = cgroup.join("cgroup.freeze");
    if p.exists() {
        fs::write(&p, "0").with_context(|| format!("write {}", p.display()))?;
    } else {
        signal_tree(mount, cgroup, nix::sys::signal::SIGCONT)?;
    }
    Ok(())
}

/// Find all cgroups created by cgrun. Returned deepest-first so removal
/// never tries a parent before its children. Unreadable subtrees are
/// skipped.
pub fn find_cgrun_cgroups(mount: &Path, bases: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk_cgrun(mount, mount, bases, &mut out, 0);
    out.sort_by(|a, b| {
        b.components()
            .count()
            .cmp(&a.components().count())
            .then_with(|| a.cmp(b))
    });
    out
}

const MAX_WALK_DEPTH: usize = 128;

fn walk_cgrun(mount: &Path, dir: &Path, bases: &[&str], out: &mut Vec<PathBuf>, depth: usize) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for e in entries.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }
        let p = e.path();
        let Ok(rel) = p
            .strip_prefix(mount)
            .map(|r| r.to_string_lossy().to_string())
        else {
            continue;
        };
        let name = e.file_name().to_string_lossy().to_string();
        let under_base = under_any_base(&rel, bases);
        // Scattered leaves must look like our transient scopes
        // (`cgrun-<pid>-<rand>.scope`); a bare `cgrun-*` prefix alone could
        // collide with unrelated dirs.
        if (under_base || is_transient_leaf_name(&name)) && is_cgroup_dir(&p) {
            out.push(p.clone());
        }
        walk_cgrun(mount, &p, bases, out, depth + 1);
    }
}

/// True when `rel` (mount-relative) is `base` itself or lives below it,
/// for any of the given bases.
pub(crate) fn under_any_base(rel: &str, bases: &[&str]) -> bool {
    bases.iter().any(|b| {
        let b = b.trim_matches('/');
        !b.is_empty() && (rel == b || rel.starts_with(&format!("{b}/")))
    })
}

/// `cgrun-<pid>-<rand:04x>.scope`, the transient leaf shape from `cmd_run`.
pub fn is_transient_leaf_name(name: &str) -> bool {
    name.strip_prefix("cgrun-")
        .and_then(|r| r.strip_suffix(".scope"))
        .and_then(|r| r.split_once('-'))
        .is_some_and(|(pid, rnd)| {
            !pid.is_empty()
                && pid.bytes().all(|b| b.is_ascii_digit())
                && rnd.len() == 4
                && rnd.bytes().all(|b| b.is_ascii_hexdigit())
        })
}
