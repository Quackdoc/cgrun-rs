use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// ---------------------------------------------------------------------------
// Shared size parsing: "7G" / "512M" / "max" -> Some(bytes) / None
// Used by both dmem specs and memory limits. Keep single implementation so
// `memory` is never mistaken for `dmem` at the parse layer.
// ---------------------------------------------------------------------------

/// Suffix -> byte multiplier, matched case-insensitively.
const SIZE_MULTS: &[(&str, u64)] = &[
    ("", 1),
    ("b", 1),
    ("k", 1u64 << 10),
    ("kb", 1u64 << 10),
    ("kib", 1u64 << 10),
    ("m", 1u64 << 20),
    ("mb", 1u64 << 20),
    ("mib", 1u64 << 20),
    ("g", 1u64 << 30),
    ("gb", 1u64 << 30),
    ("gib", 1u64 << 30),
    ("t", 1u64 << 40),
    ("tb", 1u64 << 40),
    ("tib", 1u64 << 40),
];

/// "7G" / "512M" / "max" -> Some(bytes) / None
pub fn parse_size(s: &str) -> Result<Option<u64>> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("max") {
        return Ok(None);
    }
    if s.is_empty() {
        bail!("empty size");
    }
    let num_end = s
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(s.len());
    if num_end == 0 {
        bail!("invalid size '{s}'");
    }
    let n: u64 = s[..num_end]
        .parse()
        .with_context(|| format!("invalid size '{s}'"))?;
    let suffix = s[num_end..].trim();
    let mult = SIZE_MULTS
        .iter()
        .find_map(|(sfx, m)| sfx.eq_ignore_ascii_case(suffix).then_some(*m))
        .with_context(|| format!("unknown suffix '{suffix}' in '{s}'"))?;
    n.checked_mul(mult)
        .with_context(|| format!("size overflow in '{s}'"))
        .map(Some)
}

fn format_size(v: Option<u64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "max".to_string(),
    }
}

// dmem control section

/// Read total vram from /sys/fs/cgroup/dmem.capacity
pub fn read_dmem_capacity(mount: &Path) -> Result<HashMap<String, u64>> {
    let p = mount.join("dmem.capacity");
    let data = match fs::read_to_string(&p) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", p.display())),
    };

    let mut out = HashMap::new();
    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let region = it.next().context("missing region")?.to_string();
        let size: u64 = it.next().context("missing size")?.parse()?;
        out.insert(region, size);
    }
    Ok(out)
}

pub fn dmem_write_limit(cgroup: &Path, file: &str, region: &str, val: Option<u64>) -> Result<()> {
    let body = format!("{region} {}\n", format_size(val));
    fs::write(cgroup.join(file), body)
        .with_context(|| format!("write {}/{}", cgroup.display(), file))?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct DmemSpec {
    pub region: Option<String>,
    pub value: Option<u64>,
}

/// Parse one `--vram-low` / `--vram-max` SPEC: `"7G"` (all regions),
/// `"region 7G"`, or `"region:7G"` / `"region=max"`. A region must contain
/// `/`; bare sizes yield `region: None`. No space after `:` / `=`.
pub fn parse_dmem_spec(s: &str) -> Result<DmemSpec> {
    let s = s.trim();
    if s.is_empty() {
        bail!("empty spec");
    }

    // "region size" split by whitespace
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() == 2 && parts[0].contains('/') {
        return Ok(DmemSpec {
            region: Some(parts[0].into()),
            value: parse_size(parts[1])?,
        });
    }
    if parts.len() > 1 {
        bail!("invalid spec '{s}': use '<size>' or '<region>:<size>'");
    }

    // "region:size" or "region=size"
    for sep in [':', '='] {
        if let Some((left, right)) = s.split_once(sep) {
            let left = left.trim();
            let right = right.trim();
            if left.contains('/') {
                return Ok(DmemSpec {
                    region: Some(left.into()),
                    value: parse_size(right)?,
                });
            }
        }
    }

    match parse_size(s) {
        Ok(value) => Ok(DmemSpec {
            region: None,
            value,
        }),
        Err(_) => bail!("invalid spec '{s}': use '<size>' or '<region>:<size>'"),
    }
}

/// Resolve raw specs to concrete `(region, value)` pairs; bare sizes fan out
/// to every region in `cap`. Unknown regions bail.
pub fn expand_dmem_specs(
    specs: &[String],
    cap: &HashMap<String, u64>,
) -> Result<Vec<(String, Option<u64>)>> {
    if cap.is_empty() {
        bail!("no dmem regions (check dmem.capacity / driver)");
    }
    let mut out = Vec::new();
    for raw in specs {
        let sp = parse_dmem_spec(raw)?;
        if let Some(region) = sp.region {
            if !cap.contains_key(&region) {
                let available = cap.keys().cloned().collect::<Vec<_>>().join(", ");
                bail!("unknown region '{region}'; available: {available}");
            }
            out.push((region, sp.value));
        } else {
            for region in cap.keys() {
                out.push((region.clone(), sp.value));
            }
        }
    }
    Ok(out)
}

pub fn apply_dmem_limits(
    cgroup: &Path,
    file: &str,
    specs: &[String],
    cap: &HashMap<String, u64>,
) -> Result<()> {
    for (region, value) in expand_dmem_specs(specs, cap)? {
        dmem_write_limit(cgroup, file, &region, value)?;
    }
    Ok(())
}

// Memory control section
pub fn memory_available(controllers: &[String]) -> bool {
    controllers.iter().any(|c| c == "memory")
}

pub fn set_memory_limit(cgroup: &Path, file: &str, raw: &str) -> Result<()> {
    let val = parse_size(raw).with_context(|| {
        format!("invalid --{file} value '{raw}' (use SIZE like 512M/7G or max)")
    })?;
    fs::write(cgroup.join(file), format!("{}\n", format_size(val)))
        .with_context(|| format!("write {}/{}", cgroup.display(), file))?;
    Ok(())
}

pub fn set_memory_max(cgroup: &Path, raw: &str) -> Result<()> {
    set_memory_limit(cgroup, "memory.max", raw)
}

pub fn set_memory_high(cgroup: &Path, raw: &str) -> Result<()> {
    set_memory_limit(cgroup, "memory.high", raw)
}

pub fn set_memory_low(cgroup: &Path, raw: &str) -> Result<()> {
    set_memory_limit(cgroup, "memory.low", raw)
}

pub fn set_memory_min(cgroup: &Path, raw: &str) -> Result<()> {
    set_memory_limit(cgroup, "memory.min", raw)
}

// cpu control section

pub fn set_cpu_weight(cgroup: &Path, weight: u32) -> Result<()> {
    if !(1..=10000).contains(&weight) {
        bail!("cpu.weight must be 1..10000, got {weight}");
    }
    fs::write(cgroup.join("cpu.weight"), weight.to_string())
        .with_context(|| format!("write {}/cpu.weight", cgroup.display()))?;
    Ok(())
}

pub fn set_cpu_weight_nice(cgroup: &Path, nice: i32) -> Result<()> {
    if !(-20..=19).contains(&nice) {
        bail!("cpu.weight.nice must be -20..19, got {nice}");
    }
    fs::write(cgroup.join("cpu.weight.nice"), nice.to_string())
        .with_context(|| format!("write {}/cpu.weight.nice", cgroup.display()))?;
    Ok(())
}

// Control hierarchy delegation (top-down +controller enablement).

/// Ensure the requested controllers are delegated along the path so the
/// new leaf can actually use them. Controllers must be enabled top-down:
/// we walk every ancestor from the mount down to the direct parent and
/// enable at each level that already exists.
pub fn ensure_control_hierarchy(mount: &Path, rel: &str, controllers: &[&str]) -> Result<()> {
    // Root must be enabled first, then each ancestor in order.
    crate::cgroup::enable_controllers(mount, controllers)?;

    let parent = Path::new(rel)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("");
    if parent.is_empty() {
        return Ok(());
    }
    // Walk mount -> ... -> parent, enabling at each existing dir.
    let mut acc = Path::new("").to_path_buf();
    for comp in Path::new(parent).components() {
        use std::path::Component;
        match comp {
            Component::Normal(s) => acc.push(s),
            // Rel paths are pre-validated; skip anything exotic defensively.
            _ => bail!("invalid path component in '{rel}'"),
        }
        let dir = crate::cgroup::full_cgroup_path(mount, &acc.to_string_lossy());
        if dir.exists() {
            crate::cgroup::enable_controllers(&dir, controllers)?;
        }
    }
    Ok(())
}
