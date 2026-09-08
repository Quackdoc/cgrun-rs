use super::*;
use super::control::*;
use std::collections::HashMap;

#[test]
fn transient_names() {
    assert!(cgroup::is_transient_leaf_name("cgrun-1234-ab12.scope"));
    assert!(cgroup::is_transient_leaf_name("cgrun-71217-70fb.scope"));
    assert!(!cgroup::is_transient_leaf_name("cgrun-1234-abc.scope")); // rnd must be 4 hex
    assert!(!cgroup::is_transient_leaf_name("cgrun-abc-ab12.scope")); // pid must be numeric
    assert!(!cgroup::is_transient_leaf_name("cgrun-1234-ab12")); // no .scope suffix
    assert!(!cgroup::is_transient_leaf_name("mygame"));
    assert!(!cgroup::is_transient_leaf_name("cgrun.slice"));
}

#[test]
fn signal_cgroup_removes_owned_keeps_foreign() {
    // Note: plain empty dirs — a fake cgroup.procs file would make
    // rmdir fail with ENOTEMPTY, unlike real cgroupfs dirs. Unique dir
    // per test run so parallel `cargo test` invocations don't collide.
    let root = std::env::temp_dir().join(format!(
        "cgrun-kill-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let owned = root.join("cgrun/cgrun-1-ab12.scope");
    std::fs::create_dir_all(&owned).unwrap();
    let foreign = root.join("other.scope");
    std::fs::create_dir_all(&foreign).unwrap();
    // Unrelated `cgrun-*` name that is NOT a transient scope must be kept.
    let lookalike = root.join("cgrun-backup");
    std::fs::create_dir_all(&lookalike).unwrap();

    assert!(signal_cgroup(&root, "cgrun", &owned, nix::sys::signal::SIGKILL).unwrap());
    assert!(!owned.exists());

    assert!(!signal_cgroup(&root, "cgrun", &foreign, nix::sys::signal::SIGTERM).unwrap());
    assert!(foreign.exists());
    assert!(!signal_cgroup(&root, "cgrun", &lookalike, nix::sys::signal::SIGTERM).unwrap());
    assert!(lookalike.exists());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn cgrun_target_scope() {
    let mount = Path::new("/sys/fs/cgroup");
    assert!(is_cgrun_target(mount, "cgrun", &mount.join("cgrun/mygame")));
    assert!(is_cgrun_target(mount, "cgrun", &mount.join("cgrun")));
    assert!(is_cgrun_target(
        mount,
        "cgrun",
        &mount.join("user.slice/cgrun-1-ab12.scope")
    ));
    assert!(!is_cgrun_target(
        mount,
        "cgrun",
        &mount.join("user.slice/app.scope")
    ));
    assert!(!is_cgrun_target(mount, "cgrun", &mount.join("cgrunevil")));
    assert!(!is_cgrun_target(mount, "cgrun", mount));
    assert!(!is_cgrun_target(
        mount,
        "cgrun",
        Path::new("/other/cgrun-1-ab12.scope")
    ));
    // Custom base is honored instead of the hardcoded default.
    assert!(is_cgrun_target(
        mount,
        "custom",
        &mount.join("custom/mygame")
    ));
    assert!(!is_cgrun_target(
        mount,
        "custom",
        &mount.join("cgrun/mygame")
    ));
    // Bare `cgrun-*` without transient shape is not a target.
    assert!(!is_cgrun_target(
        mount,
        "cgrun",
        &mount.join("cgrun-backup")
    ));
    // The root-run tree is always ours, whatever the configured base.
    assert!(is_cgrun_target(
        mount,
        "cgrun",
        &mount.join("cgrun-root/batch")
    ));
    assert!(is_cgrun_target(
        mount,
        "custom",
        &mount.join("cgrun-root/batch")
    ));
}

#[test]
fn leaf_rel_placement() {
    assert_eq!(run::leaf_rel(true, false, "x"), "cgrun/x");
    assert_eq!(run::leaf_rel(true, true, "x"), "cgrun/x");
    assert_eq!(run::leaf_rel(false, true, "x"), "cgrun-root/x");
    // Regular mode nests under the current scope; just check the leaf suffix.
    assert!(run::leaf_rel(false, false, "x").ends_with("/x") || run::leaf_rel(false, false, "x") == "x");
}

fn touch(dir: &std::path::Path, rel: &str, procs: &str) {
    let d = dir.join(rel);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("cgroup.procs"), procs).unwrap();
}

#[test]
fn walk_finds_base_tree_and_scattered_leaves() {
    let root = std::env::temp_dir().join(format!(
        "cgrun-list-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&root);
    // System base tree (priv mode): everything counts, even custom names.
    touch(&root, "cgrun/mygame", "100\n200\n");
    touch(&root, "cgrun/cgrun-9-00ff.scope", "300\n");
    // Root-run tree: always included alongside the configured base.
    touch(&root, "cgrun-root/batch", "600\n");
    // Scattered regular-mode transient leaf.
    touch(&root, "user.slice/cgrun-71217-70fb.scope", "400\n");
    // Noise: unrelated cgroups, plain dirs without cgroup.procs.
    touch(&root, "user.slice/app.scope", "500\n");
    std::fs::create_dir_all(root.join("user.slice/empty")).unwrap();

    // Deepest-first: children sort before their parents.
    let found = cgroup::find_cgrun_cgroups(&root, &["cgrun", crate::ROOT_BASE]);
    let rels: Vec<String> = found
        .iter()
        .map(|p| p.strip_prefix(&root).unwrap().to_string_lossy().to_string())
        .collect();
    assert_eq!(
        rels,
        [
            "cgrun/cgrun-9-00ff.scope",
            "cgrun/mygame",
            "cgrun-root/batch",
            "user.slice/cgrun-71217-70fb.scope",
        ]
    );

    let rows = rows_cgrun(&root, "cgrun");
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0].kind, "transient");
    assert_eq!(rows[1].kind, "persistent");
    assert_eq!(rows[1].pids, 2);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn sizes() {
    assert_eq!(parse_size("7G").unwrap(), Some(7 * 1024 * 1024 * 1024));
    assert_eq!(parse_size("max").unwrap(), None);
    assert_eq!(parse_size("512M").unwrap(), Some(512 * 1024 * 1024));
}

#[test]
fn expand_all() {
    let mut cap = HashMap::new();
    cap.insert("drm/0000:03:00.0/vram".into(), 8 * 1024 * 1024 * 1024);
    cap.insert("drm/0000:03:00.0/gtt".into(), 0);
    assert_eq!(expand_dmem_specs(&["4G".into()], &cap).unwrap().len(), 2);
}

#[test]
fn memory_limit_roundtrip() {
    let dir = std::env::temp_dir().join(format!(
        "cgrun-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    set_memory_limit(&dir, "memory.max", "512M").unwrap();
    let body = std::fs::read_to_string(dir.join("memory.max")).unwrap();
    assert_eq!(body.trim(), (512u64 * 1024 * 1024).to_string());
    set_memory_limit(&dir, "memory.max", "max").unwrap();
    let body = std::fs::read_to_string(dir.join("memory.max")).unwrap();
    assert_eq!(body.trim(), "max");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resolve_cgroup_rejects_plain_dirs() {
    let root = std::env::temp_dir().join(format!(
        "cgrun-resolve-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("plain")).unwrap();
    std::fs::create_dir_all(root.join("real.scope")).unwrap();
    std::fs::write(root.join("real.scope/cgroup.procs"), "").unwrap();

    assert!(resolve_cgroup(&root, "plain").is_err());
    assert!(resolve_cgroup(&root, "missing").is_err());
    assert!(resolve_cgroup(&root, "real.scope").is_ok());
    let _ = std::fs::remove_dir_all(&root);
}
