mod cgroup;
mod control;
mod exec;
mod privilege;
mod run;

use anyhow::{Context, Result, bail, ensure};
use std::path::{Path, PathBuf};
use usage::{Args, Cli, Subcommands};

#[derive(Cli)]
#[usage(
    bin = "cgrun",
    version,
    about = "daemonless cgroupv2 runner with dmem, memory and cpu control"
)]
struct CliArgs {
    #[usage(subcommand)]
    command: Commands,
}

#[derive(Subcommands)]
enum Commands {
    /// Create and delegate base cgroup
    Setup(Setup),
    /// Run a command in a dedicated cgroup (transient by default)
    Run(run::RunArgs),
    /// Clean up all cgroups created by cgrun
    Clean(Clean),
    /// Signal whole tree in a cgroup, removing it if cgrun-created
    Kill(Kill),
    /// Freeze (suspend) whole tree via cgroup.freeze
    Freeze(Freeze),
    /// Thaw (resume) whole tree
    Thaw(Thaw),
    /// List pids in a cgroup
    Ps(Ps),
    /// List cgroups created by cgrun (system base + transient leaves)
    List(List),
    /// Internal privileged helper
    #[usage(hide)]
    Privileged(Privileged),
}

#[derive(Args)]
struct Setup {
    /// Only check if setup is needed (exits 2 when setup is missing)
    #[usage(long)]
    check: bool,
    /// Base cgroup name
    #[usage(long, default = "cgrun")]
    base: String,
}

#[derive(Args)]
struct Clean {
    /// System base cgroup used by --priv (cleaned in full)
    #[usage(long, default = "cgrun")]
    base: String,
    /// Force without confirmation (dry run without it exits 2)
    #[usage(long)]
    force: bool,
}

#[derive(Args)]
struct Kill {
    /// Cgroup relative path (or absolute /sys/fs/cgroup/...)
    #[usage(arg, value_name = "CGROUP")]
    cgroup: String,
    /// Signal name or number (TERM, KILL, HUP, INT, 9, ...)
    #[usage(long, short = 's', default = "TERM")]
    signal: String,
}

#[derive(Args)]
struct Freeze {
    #[usage(arg, value_name = "CGROUP")]
    cgroup: String,
}

#[derive(Args)]
struct Thaw {
    #[usage(arg, value_name = "CGROUP")]
    cgroup: String,
}

#[derive(Args)]
struct Ps {
    #[usage(arg, value_name = "CGROUP")]
    cgroup: String,
}

#[derive(Args)]
struct List {
    /// System base cgroup used by --priv (listed in full)
    #[usage(long, default = "cgrun")]
    base: String,
}

#[derive(Args)]
struct Privileged {
    #[usage(long)]
    setup_base: Option<String>,
    #[usage(long)]
    create: Option<String>,
    #[usage(long)]
    clean: Option<String>,
    #[usage(long)]
    owner_uid: Option<u32>,
    #[usage(long)]
    owner_gid: Option<u32>,
    #[usage(long)]
    move_: Option<String>,
    #[usage(long)]
    move_pid: Option<i32>,
}

pub const BASE: &str = "cgrun";
pub const ROOT_BASE: &str = "cgrun-root";

fn main() {
    let cli = CliArgs::parse();
    let res = match cli.command {
        Commands::Setup(s) => cmd_setup(s.check, &s.base),
        Commands::Run(r) => run::cmd_run(r),
        Commands::Clean(c) => cmd_clean(&c.base, c.force),
        Commands::Privileged(p) => cmd_privileged(
            p.setup_base,
            p.create,
            p.clean,
            p.owner_uid,
            p.owner_gid,
            p.move_,
            p.move_pid,
        ),
        Commands::Kill(k) => cmd_kill(&k.cgroup, &k.signal),
        Commands::Freeze(f) => cmd_freeze(&f.cgroup, true),
        Commands::Thaw(t) => cmd_freeze(&t.cgroup, false),
        Commands::Ps(p) => cmd_ps(&p.cgroup),
        Commands::List(l) => cmd_list(&l.base),
    };
    if let Err(e) = res {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn cmd_setup(check: bool, base: &str) -> Result<()> {
    privilege::validate_base(base).map_err(|_| anyhow::anyhow!("invalid base '{base}'"))?;
    let mount = cgroup::find_cgroup2_mount()?;
    if check {
        let p = cgroup::full_cgroup_path(&mount, base);
        if !p.exists() {
            println!("setup needed: {} missing", p.display());
            std::process::exit(2);
        }
        println!("setup ok: {}", p.display());
        return Ok(());
    }
    let (uid, gid) = privilege::invoking_ids();
    if privilege::is_root() {
        privilege::privileged_setup(&mount, base, uid, gid)?;
        println!(
            "setup done: {}",
            cgroup::full_cgroup_path(&mount, base).display()
        );
        Ok(())
    } else {
        println!("escalating via pkexec...");
        privilege::escalate_with_args(&[
            "privileged".into(),
            "--setup-base".into(),
            base.into(),
            "--owner-uid".into(),
            uid.to_string(),
            "--owner-gid".into(),
            gid.to_string(),
        ])?;
        println!("setup done (escalated)");
        Ok(())
    }
}

fn cmd_privileged(
    setup_base: Option<String>,
    create: Option<String>,
    clean: Option<String>,
    uid: Option<u32>,
    gid: Option<u32>,
    move_rel: Option<String>,
    move_pid: Option<i32>,
) -> Result<()> {
    if !privilege::is_root() {
        bail!("privileged requires root");
    }
    let mount = cgroup::find_cgroup2_mount()?;
    // clean this shit up
    match (setup_base, create, clean, move_rel, move_pid) {
        (Some(b), None, None, None, None) => {
            let uid = uid.context("--setup-base requires --owner-uid")?;
            let gid = gid.context("--setup-base requires --owner-gid")?;
            privilege::privileged_setup(&mount, &b, uid, gid)
        }
        (None, Some(p), None, None, None) => {
            let uid = uid.context("--create requires --owner-uid")?;
            let gid = gid.context("--create requires --owner-gid")?;
            privilege::privileged_create_cgroup(&mount, &p, uid, gid)
        }
        (None, None, Some(b), None, None) => {
            let owner =
                uid.context("--clean requires --owner-uid (pass 0 as real root to clean all)")?;
            privilege::privileged_clean_tree(&mount, &b, owner)
        }
        (None, None, None, Some(rel), Some(pid)) => privilege::privileged_move(&mount, &rel, pid),
        (None, None, None, None, None) => bail!("privileged: no operation given"),
        (None, None, None, Some(_), None) => bail!("--move requires --move-pid"),
        (None, None, None, None, Some(_)) => bail!("--move-pid requires --move"),
        _ => bail!("privileged: pass exactly one of --setup-base, --create, --clean, --move"),
    }
}

fn resolve_cgroup(mount: &Path, input: &str) -> Result<PathBuf> {
    ensure!(!input.trim().is_empty(), "invalid cgroup path ''");
    let p = if input.starts_with('/') {
        PathBuf::from(input)
    } else {
        privilege::validate_rel(input)
            .map_err(|_| anyhow::anyhow!("invalid cgroup path '{input}'"))?;
        cgroup::full_cgroup_path(mount, input)
    };

    // Checks that we are actually cgroup to avoid path related issues
    ensure!(
        cgroup::is_under_mount(mount, &p),
        "invalid cgroup path '{input}': outside {}",
        mount.display()
    );
    ensure!(
        !p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir)),
        "invalid cgroup path '{input}'"
    );
    ensure!(cgroup::is_cgroup_dir(&p), "not a cgroup: {}", p.display());
    Ok(p)
}

fn parse_signal(s: &str) -> Result<nix::sys::signal::Signal> {
    let upper = s.to_ascii_uppercase();
    let name = upper.trim_start_matches("SIG");
    match name {
        "TERM" | "15" => Ok(nix::sys::signal::SIGTERM),
        "KILL" | "9" => Ok(nix::sys::signal::SIGKILL),
        "HUP" | "1" => Ok(nix::sys::signal::SIGHUP),
        "INT" | "2" => Ok(nix::sys::signal::SIGINT),
        "QUIT" | "3" => Ok(nix::sys::signal::SIGQUIT),
        "USR1" | "10" => Ok(nix::sys::signal::SIGUSR1),
        "USR2" | "12" => Ok(nix::sys::signal::SIGUSR2),
        _ => {
            if let Ok(n) = name.parse::<i32>()
                && let Ok(sig) = nix::sys::signal::Signal::try_from(n)
            {
                return Ok(sig);
            }
            bail!("unknown signal '{s}' (try TERM, KILL, HUP, INT, 9, 15)")
        }
    }
}

fn cmd_kill(cgroup_input: &str, sig_str: &str) -> Result<()> {
    let mount = cgroup::find_cgroup2_mount()?;
    let cgroup = resolve_cgroup(&mount, cgroup_input)?;
    if cgroup == mount {
        bail!("refusing to signal the cgroup root {}", mount.display());
    }
    if !cgroup.exists() {
        bail!("cgroup not found: {}", cgroup.display());
    }
    let sig = parse_signal(sig_str)?;
    if signal_cgroup(&mount, BASE, &cgroup, sig)? {
        println!("signaled {} with {sig:?} and removed it", cgroup.display());
    } else {
        println!(
            "signaled {} with {sig:?} (kept: not a cgrun cgroup)",
            cgroup.display()
        );
    }
    Ok(())
}

/// Shared signal path behind both `kill` and `clean`: signal the whole
/// tree, then remove the cgroup if it is cgrun-owned. Foreign cgroups are
/// only signaled, never deleted. Returns true when the cgroup was removed.
pub(crate) fn signal_cgroup(
    mount: &Path,
    base: &str,
    cgroup: &Path,
    sig: nix::sys::signal::Signal,
) -> Result<bool> {
    let owned = is_cgrun_target(mount, base, cgroup);
    let kill_res = if sig == nix::sys::signal::SIGKILL {
        cgroup::kill_tree(cgroup)
    } else {
        cgroup::signal_tree(mount, cgroup, sig)
    };
    match kill_res {
        Ok(()) => {}
        // Kernel refused the kill interfaces (EOPNOTSUPP) so rmdir
        Err(e) if cgroup::is_enotsup(&e) && owned => {}
        Err(e) => return Err(e),
    }
    if !owned {
        return Ok(false);
    }
    match cgroup::remove_cgroup_with_retry(cgroup) {
        Ok(()) => Ok(true),
        Err(e) if privilege::is_permission_error(&e) => Err(e).context(format!(
            "signaled {} with {sig:?}, but cannot remove it: permission denied (not yours?)",
            cgroup.display()
        )),
        Err(e) => {
            let remaining = match cgroup::members(cgroup) {
                Ok(m) => m.len().to_string(),
                Err(_) => "unknown".to_string(),
            };
            bail!(
                "signaled {} with {sig:?}, but {remaining} process(es) remain — cgroup not removed (use -s KILL to force): {e:#}",
                cgroup.display()
            );
        }
    }
}

fn is_cgrun_target(mount: &Path, base: &str, p: &Path) -> bool {
    let Ok(rel) = p.strip_prefix(mount) else {
        return false;
    };
    let rel = rel.to_string_lossy();
    if cgroup::under_any_base(&rel, &[base, ROOT_BASE]) {
        return true;
    }
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(cgroup::is_transient_leaf_name)
}

fn cmd_freeze(cgroup_input: &str, freeze: bool) -> Result<()> {
    let mount = cgroup::find_cgroup2_mount()?;
    let cgroup = resolve_cgroup(&mount, cgroup_input)?;
    if cgroup == mount {
        bail!("refusing to freeze the cgroup root {}", mount.display());
    }
    if !cgroup.exists() {
        bail!("cgroup not found: {}", cgroup.display());
    }
    if freeze {
        cgroup::freeze(&mount, &cgroup)?;
        println!("froze {}", cgroup.display());
    } else {
        cgroup::thaw(&mount, &cgroup)?;
        println!("thawed {}", cgroup.display());
    }
    Ok(())
}

fn cmd_ps(cgroup_input: &str) -> Result<()> {
    let mount = cgroup::find_cgroup2_mount()?;
    let cgroup = resolve_cgroup(&mount, cgroup_input)?;
    if !cgroup.exists() {
        bail!("cgroup not found: {}", cgroup.display());
    }
    let pids = cgroup::members(&cgroup).unwrap_or_default();
    if pids.is_empty() {
        println!("(empty) {}", cgroup.display());
    } else {
        println!("members of {} (whole tree):", cgroup.display());
        for pid in pids {
            println!("{pid}");
        }
    }
    Ok(())
}

struct CgroupRow {
    rel: String,
    kind: &'static str,
    pids: usize,
    controllers: Vec<String>,
}

fn rows_cgrun(mount: &Path, base: &str) -> Vec<CgroupRow> {
    let mut rows: Vec<CgroupRow> = cgroup::find_cgrun_cgroups(mount, &[base, ROOT_BASE])
        .iter()
        .map(|p| {
            let rel = p
                .strip_prefix(mount)
                .map(|r| r.to_string_lossy().to_string())
                .unwrap_or_else(|_| p.to_string_lossy().to_string());
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            CgroupRow {
                kind: if cgroup::is_transient_leaf_name(&name) {
                    "transient"
                } else {
                    "persistent"
                },
                pids: cgroup::members(p).unwrap_or_default().len(),
                controllers: cgroup::read_controllers(p).unwrap_or_default(),
                rel,
            }
        })
        .collect();
    rows.sort_by(|a, b| Path::new(&a.rel).cmp(Path::new(&b.rel)));
    rows
}

fn cmd_list(base: &str) -> Result<()> {
    privilege::validate_base(base).map_err(|_| anyhow::anyhow!("invalid base '{base}'"))?;
    let mount = cgroup::find_cgroup2_mount()?;
    // we own /sys/fs/cgroup/cgrun and /sys/fs/cgroup/cgrun-root,
    // so everything under them is ours by construction.
    // Transient `cgrun-*.scope` leaves are recognizable by shape anywhere.
    //
    // TODO: Custom-named regular-mode persistent cgroups leave no marker and can't be found.
    // Eventually we should add some kind of marker

    let rows = rows_cgrun(&mount, base);
    if rows.is_empty() {
        println!("(no cgrun cgroups)");
        return Ok(());
    }
    println!("{:<56} {:<10} {:>4}  CONTROLLERS", "CGROUP", "KIND", "PIDS");
    for r in rows {
        let ctrls = if r.controllers.is_empty() {
            "-".to_string()
        } else {
            r.controllers.join(" ")
        };
        println!("{:<56} {:<10} {:>4}  {}", r.rel, r.kind, r.pids, ctrls);
    }
    Ok(())
}

fn cmd_clean(base: &str, force: bool) -> Result<()> {
    privilege::validate_base(base).map_err(|_| anyhow::anyhow!("invalid base '{base}'"))?;
    let mount = cgroup::find_cgroup2_mount()?;
    // Deepest-first: children are always removed before their parents.
    let targets = cgroup::find_cgrun_cgroups(&mount, &[base, ROOT_BASE]);
    if targets.is_empty() {
        println!("nothing to do: no cgrun cgroups");
        return Ok(());
    }
    if !force {
        println!("will delete {} cgroup(s):", targets.len());
        for t in &targets {
            println!("  {}", t.display());
        }
        println!("run with --force to confirm");
        std::process::exit(2);
    }

    // Root cleans everything; unprivileged cleans what it owns and reports the rest.
    let failed: Vec<&PathBuf> = targets
        .iter()
        .filter_map(|t| {
            signal_cgroup(&mount, base, t, nix::sys::signal::SIGKILL)
                .map(|_| None)
                .unwrap_or_else(|e| Some((t, e)))
        })
        .map(|(t, e)| {
            eprintln!("{}: {e:#}", t.display());
            t
        })
        .collect();
    let cleaned = targets.len() - failed.len();
    if failed.is_empty() {
        println!("cleaned {} cgroup(s)", targets.len());
        return Ok(());
    }
    if cleaned > 0 {
        println!("cleaned {cleaned} cgroup(s)");
    }
    if privilege::is_root() {
        bail!(
            "could not remove {} cgroup(s) (see errors above)",
            failed.len()
        );
    }
    bail!(
        "could not remove {} cgroup(s) (permission denied = not yours; run as owner or root)",
        failed.len(),
    );
}

#[cfg(test)]
mod tests;
