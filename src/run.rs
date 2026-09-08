use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use usage::Args;

#[derive(Args)]
pub struct RunArgs {
    /// Make cgroup persistent with given name (transient is default)
    #[usage(long)]
    persistent: Option<String>,
    /// dmem low limit: protect SIZE (or REGION:SIZE) from VRAM eviction to GTT
    #[usage(long, value_name = "SPEC")]
    vram_low: Vec<String>,
    /// dmem max limit: hard cap SIZE (or REGION:SIZE) per VRAM region
    #[usage(long, value_name = "SPEC")]
    vram_max: Vec<String>,
    /// memory hard limit (system RAM): SIZE or max -> memory.max
    #[usage(long, value_name = "SIZE")]
    memory_max: Option<String>,
    /// memory throttle boundary (system RAM): SIZE or max -> memory.high
    #[usage(long, value_name = "SIZE")]
    memory_high: Option<String>,
    /// memory protection (system RAM): SIZE or max -> memory.low
    #[usage(long, value_name = "SIZE")]
    memory_low: Option<String>,
    /// memory min protection (system RAM): SIZE or max -> memory.min
    #[usage(long, value_name = "SIZE")]
    memory_min: Option<String>,
    /// CPU weight 1..10000 (proportional)
    #[usage(long)]
    cpu_weight: Option<u32>,
    /// CPU weight nice -20..19 (alternative to --cpu-weight)
    #[usage(long = "cpu-weight-nice", value_name = "NICE")]
    cpu_weight_nice: Option<i32>,
    /// Grace period for SIGTERM -> SIGKILL on exit (seconds, 0 = immediate kill)
    #[usage(long, default = "2")]
    grace: u64,
    /// Run under /sys/fs/cgroup/cgrun via pkexec (system-wide, needs polkit)
    #[usage(long = "priv")]
    priv_: bool,
    /// Command to run
    #[usage(arg)]
    cmd: Vec<String>,
}

impl RunArgs {
    fn needs_dmem(&self) -> bool {
        !self.vram_low.is_empty() || !self.vram_max.is_empty()
    }
    fn needs_memory(&self) -> bool {
        self.memory_max.is_some()
            || self.memory_high.is_some()
            || self.memory_low.is_some()
            || self.memory_min.is_some()
    }
    fn needs_cpu(&self) -> bool {
        self.cpu_weight.is_some() || self.cpu_weight_nice.is_some()
    }
}

pub fn cmd_run(r: RunArgs) -> Result<()> {
    let mount = crate::cgroup::find_cgroup2_mount()?;
    let cap = check_requirements(&r, &mount)?;
    let (name, is_persistent) = leaf_name(r.persistent.as_deref())?;
    let rel = leaf_rel(r.priv_, crate::privilege::is_root(), &name);
    let cgroup = ensure_exists(
        &mount,
        &rel,
        r.needs_dmem(),
        r.needs_memory(),
        r.needs_cpu(),
        r.priv_,
    )?;
    apply_limits(&cgroup, &r, &cap)?;
    eprintln!(
        "running in {} (persistent={})",
        cgroup.display(),
        is_persistent
    );
    let code = crate::exec::spawn_in_cgroup(&mount, &rel, &cgroup, &r.cmd, r.priv_)?;
    if !is_persistent {
        graceful_kill(&mount, &cgroup, r.grace);
        let _ = crate::cgroup::remove_cgroup_with_retry(&cgroup);
    }
    std::process::exit(code);
}

// No slashes, no `..`, no shell metacharacters, no whitespace.
fn validate_persistent_name(name: &str) -> Result<()> {
    match name {
        n if n.len() > 128 => bail!("invalid --persistent NAME (max 128 chars)"),
        n if n.trim().is_empty() || n == "." || n == ".." => bail!("invalid --persistent NAME"),
        n if !n
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_')) =>
        {
            bail!("invalid --persistent NAME '{name}': use [A-Za-z0-9._-] only")
        }
        _ => Ok(()),
    }
}

fn check_requirements(r: &RunArgs, mount: &Path) -> Result<std::collections::HashMap<String, u64>> {
    if r.cmd.is_empty() {
        bail!("no command provided (use -- <cmd>)");
    }
    if r.cpu_weight.is_some() && r.cpu_weight_nice.is_some() {
        bail!("use only one of --cpu-weight or --cpu-weight-nice");
    }
    let controllers = crate::cgroup::read_controllers(mount).unwrap_or_default();
    let has_cpu = controllers.contains(&"cpu".to_string());
    let has_memory = crate::control::memory_available(&controllers);

    let cap = crate::control::read_dmem_capacity(mount).unwrap_or_default();
    let has_dmem = !cap.is_empty();

    if r.needs_dmem() && !has_dmem {
        bail!(
            "dmem not available: /sys/fs/cgroup/dmem.capacity is empty or missing (no regions / driver support)"
        );
    }
    if r.needs_cpu() && !has_cpu {
        bail!("cpu controller not available");
    }
    if r.needs_memory() && !has_memory {
        bail!("memory controller not available");
    }
    Ok(cap)
}

// Leaf name: persistent NAME or a transient cgrun-<pid>-<rand>.scope.
// Returns (name, is_persistent).
fn leaf_name(persistent: Option<&str>) -> Result<(String, bool)> {
    if let Some(name) = persistent {
        validate_persistent_name(name)?;
        Ok((name.to_string(), true))
    } else {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let rnd = (nanos ^ pid) & 0xffff;
        Ok((format!("cgrun-{pid}-{rnd:04x}.scope"), false))
    }
}

// - --priv: always under the system /sys/fs/cgroup/cgrun (via pkexec).
// - root without --priv: always under /sys/fs/cgroup/cgrun-root.
// - regular: always within the current scope (never escalates).
pub(crate) fn leaf_rel(priv_: bool, is_root: bool, name: &str) -> String {
    if priv_ {
        return format!("{}/{}", crate::BASE, name);
    }
    if is_root {
        return format!("{}/{}", crate::ROOT_BASE, name);
    }
    // Strip a trailing `.scope` so we never nest under a leaf scope.
    let cur_raw = crate::cgroup::current_cgroup_rel().unwrap_or_default();
    let mut cur = cur_raw.trim_matches('/').to_string();
    if cur.ends_with(".scope") {
        cur = Path::new(&cur)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .trim_matches('/')
            .to_string();
    }
    // cgroup.type is fixed to threaded when parent is domain threaded
    // via create_cgroup_dir -> ensure_valid_type so a populated parent can host the leaf.
    if cur.is_empty() {
        name.to_string()
    } else {
        format!("{cur}/{name}")
    }
}

fn apply_limits(
    cgroup: &Path,
    r: &RunArgs,
    cap: &std::collections::HashMap<String, u64>,
) -> Result<()> {
    if !r.vram_low.is_empty() {
        crate::control::apply_dmem_limits(cgroup, "dmem.low", &r.vram_low, cap)?;
        eprintln!("dmem.low configured for {}", cgroup.display());
    }
    if !r.vram_max.is_empty() {
        crate::control::apply_dmem_limits(cgroup, "dmem.max", &r.vram_max, cap)?;
        eprintln!("dmem.max configured for {}", cgroup.display());
    }
    if r.needs_memory() {
        if let Some(v) = r.memory_max.as_deref() {
            crate::control::set_memory_max(cgroup, v)
                .with_context(|| format!("write {}/memory.max", cgroup.display()))?;
            eprintln!("memory.max={v} set for {}", cgroup.display());
        }
        if let Some(v) = r.memory_high.as_deref() {
            crate::control::set_memory_high(cgroup, v)
                .with_context(|| format!("write {}/memory.high", cgroup.display()))?;
            eprintln!("memory.high={v} set for {}", cgroup.display());
        }
        if let Some(v) = r.memory_low.as_deref() {
            crate::control::set_memory_low(cgroup, v)
                .with_context(|| format!("write {}/memory.low", cgroup.display()))?;
            eprintln!("memory.low={v} set for {}", cgroup.display());
        }
        if let Some(v) = r.memory_min.as_deref() {
            crate::control::set_memory_min(cgroup, v)
                .with_context(|| format!("write {}/memory.min", cgroup.display()))?;
            eprintln!("memory.min={v} set for {}", cgroup.display());
        }
    }
    if r.needs_cpu() {
        if let Some(w) = r.cpu_weight {
            crate::control::set_cpu_weight(cgroup, w)
                .with_context(|| format!("write {}/cpu.weight", cgroup.display()))?;
            eprintln!("cpu.weight={} set for {}", w, cgroup.display());
        }
        if let Some(n) = r.cpu_weight_nice {
            crate::control::set_cpu_weight_nice(cgroup, n)
                .with_context(|| format!("write {}/cpu.weight.nice", cgroup.display()))?;
            eprintln!("cpu.weight.nice={} set for {}", n, cgroup.display());
        }
    }
    Ok(())
}

fn ensure_exists(
    mount: &Path,
    rel: &str,
    needs_dmem: bool,
    needs_memory: bool,
    needs_cpu: bool,
    use_priv: bool,
) -> Result<PathBuf> {
    crate::privilege::validate_rel(rel)
        .map_err(|_| anyhow::anyhow!("invalid cgroup path '{rel}'"))?;
    let full = crate::cgroup::full_cgroup_path(mount, rel);
    if !crate::cgroup::is_under_mount(mount, &full) {
        bail!("invalid cgroup path '{rel}'");
    }
    if full.exists() {
        return Ok(full);
    }

    // Privileged mode owns the cgrun/ tree: escalate once to create it
    if use_priv && !crate::privilege::is_root() {
        let (uid, gid) = crate::privilege::invoking_ids();
        crate::privilege::escalate_with_args(&[
            "privileged".into(),
            "--create".into(),
            rel.into(),
            "--owner-uid".into(),
            uid.to_string(),
            "--owner-gid".into(),
            gid.to_string(),
        ])
        .with_context(|| {
            format!(
                "permission denied on {}: run `pkexec {} setup` once",
                mount.display(),
                std::env::current_exe().unwrap_or_default().display()
            )
        })?;
        if !full.exists() {
            bail!("pkexec succeeded but {} still missing", full.display());
        }
        return Ok(full);
    }

    // Regular mode stays within the current scope and never escalates:
    let try_create = || -> Result<PathBuf> {
        if needs_dmem {
            crate::control::ensure_control_hierarchy(mount, rel, &["dmem"])?;
        }
        if needs_memory {
            crate::control::ensure_control_hierarchy(mount, rel, &["memory"])?;
        }
        if needs_cpu {
            crate::control::ensure_control_hierarchy(mount, rel, &["cpu"])?;
        }
        crate::cgroup::create_cgroup_dir(mount, rel)
    };

    match try_create() {
        Ok(p) => Ok(p),
        Err(e) if crate::privilege::is_delegation_error(&e) => Err(delegation_error(&full, e)),
        Err(e) => Err(e).context(format!("mkdir {} failed", full.display())),
    }
}

// Context for delegation failures in regular (within-scope) operation.
fn delegation_error(full: &Path, e: anyhow::Error) -> anyhow::Error {
    e.context(format!(
        "cannot create cgroup {}: Check delegation permissions or run with --priv",
        full.display()
    ))
}

fn graceful_kill(mount: &Path, cgroup: &Path, grace: u64) {
    if grace == 0 {
        let _ = crate::cgroup::kill_tree(cgroup);
        return;
    }
    let _ = crate::cgroup::signal_tree(mount, cgroup, nix::sys::signal::SIGTERM);
    let start = std::time::Instant::now();
    while start.elapsed().as_secs() < grace {
        match crate::cgroup::members(cgroup) {
            Ok(v) if v.is_empty() => return,
            Ok(_) => {}
            Err(_) => {}
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = crate::cgroup::kill_tree(cgroup);
}
