# cgrun-rs

Daemonless cgroup v2 runner with `dmem`, `memory` and `cpu` control.

Create isolated, delegatable cgroups with no daemon, with optional Ram and VRAM control [[1]](#references) and CPU weighting. Regular runs are rootless and never escalate; `--priv`, `setup` and `clean` escalate via `pkexec`.

## Features

- Transient cgroups (auto-cleaned) and named persistent cgroups
- `dmem` low limit: protect `N` bytes per region from eviction to GTT/system RAM (`dmem.low` — `--vram-low 7G` or `--vram-low drm/card0/vram:4G`) — keeps the working set resident in VRAM instead of spilling over PCIe on supported systems (i915 does not have the kernel support)
- CPU control: `cpu.weight` (`--cpu-weight 500`) or nice mapping (`--cpu-weight-nice -5`)
- Memory control: `memory.max/high/low/min` (`--memory-max 4G`, `--memory-high 6G`, ... or `max`)
- Daemonless — direct cgroupfs (`/sys/fs/cgroup`), no service required
- Graceful shutdown (`SIGTERM` → `SIGKILL` after `--grace`)
- Controls for existing cgroups: `ps`, `kill`, `freeze`/`thaw`

## Requirements

- Linux with cgroup v2 mounted at `/sys/fs/cgroup`
- Kernel with `dmem` controller for VRAM residency (`amdgpu`/`xe`, Linux 7.3+) — otherwise `memory`/`cpu` only
- `pkexec` (polkit) only for `--priv`, `setup` and `clean`

## Install

```sh
cargo build --release
./target/release/cgrun --help
```

## Quick Start

```sh
# Transient: runs in isolated cgroup, cleaned on exit
./target/release/cgrun run -- bash

# Keep 7G resident in VRAM (requires dmem, card auto configured)
./target/release/cgrun run --vram-low 7G -- ./game

# Per-region low limit
./target/release/cgrun run --vram-low drm/0000:03:00.0/vram:6G -- ./game

# Lower CPU weight
./target/release/cgrun run --cpu-weight 100 -- make -j$(nproc)
./target/release/cgrun run --cpu-weight-nice -5 -- make -j$(nproc)

# Persistent cgroup (kept after exit, under /sys/fs/cgroup/cgrun)
./target/release/cgrun run --persistent mygame --priv -- ./server
```

Transient leaves are named `cgrun-<pid>-<rand>.scope`. Regular runs always stay within your current cgroup (never nesting under a leaf `*.scope`) — e.g. `/sys/fs/cgroup/user.slice/user-1000.slice/cgrun-71217-70fb.scope`. With `--priv` everything lives under the system tree `/sys/fs/cgroup/cgrun/<name>`.

## Privilege Model

- **Regular (no `--priv`)**: always runs within your current scope. Never escalates — if the parent cgroup isn't delegated to you, the run fails with a delegation error. No auth prompt.
    May need a service to handle nested delegation for controls, for example: `dmemcg-booster` on `systemd` systems.
- **With `--priv`**: always runs under `/sys/fs/cgroup/cgrun`. Escalates via `pkexec` once to create and chown the leaf, then continues unprivileged.

```sh
# One-time run creation (creates and delegates cgroup without starting a process)
./target/release/cgrun setup
# Check only
./target/release/cgrun setup --check
# Custom base
./target/release/cgrun setup --base cgrun
```

`run --priv` creates its leaf under `/sys/fs/cgroup/cgrun` on demand (escalating via `pkexec`); `setup` is only needed if you want the base pre-created and delegated.

### Manual control delegation (without `pkexec` or service)
It is possible to do enable support for this manually to bypass the need for pkexec or a manual service.
**enable `+dmem` top-down — every ancestor that should pass the controller to its children must have it enabled**. 
A leaf only lists `dmem` in `cgroup.controllers` if all parents did.

As an example on systemd running will show `/sys/fs/cgroup/user.slice/user-1000.slice/cgrun-<stuff>.scope` 
You need to make sure every ancestor here supports dmem subtree_control. 
```sh
# Enable dmem down to the parent of your actual leaf.
# For cgrun's transient (e.g. /sys/fs/cgroup/user.slice/user-1000.slice/cgrun-71217-70fb.scope):
for p in \
  /sys/fs/cgroup \
  /sys/fs/cgroup/user.slice \
  /sys/fs/cgroup/user.slice/user-1000.slice; do
  echo "+dmem" | sudo tee "$p/cgroup.subtree_control"
done

# Verify
cgrun run -- bash
cat /sys/fs/cgroup/user.slice/user-1000.slice/cgrun-71217-70fb.scope/cgroup.controllers
cat /sys/fs/cgroup/user.slice/user-1000.slice/cgrun-71217-70fb.scope/dmem.low
# → should contain "dmem"
cat /sys/fs/cgroup/dmem.capacity  # should be non-empty (lists regions)

# For a deeper app leaf (e.g. Cosmic AppList), extend the same loop:
# .../user@1000.service and .../app.slice must also have +dmem:
# echo "+dmem" | sudo tee /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/cgroup.subtree_control
# echo "+dmem" | sudo tee /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/cgroup.subtree_control
# cat /sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/app-cosmic-*/cgroup.controllers
```

If any level is skipped, the child's `cgroup.controllers` will not contain `dmem` — that's the top-down delegation `cgrun` does internally (`control::ensure_control_hierarchy` at mount, then parent).

## Commands

```sh
cgrun run [--persistent NAME] [--vram-low SPEC]... [--vram-max SPEC]... [--memory-max SIZE] [--memory-high SIZE] [--memory-low SIZE] [--memory-min SIZE] [--cpu-weight W | --cpu-weight-nice N] [--grace SECS] [--priv] -- <cmd> [args...]
cgrun setup [--check] [--base cgrun]
cgrun clean [--base cgrun] --force  # remove all cgrun cgroups (base tree + transient leaves)
cgrun ps <cgroup>                          # list pids (whole subtree), abs or relative path
cgrun list [--base cgrun]                 # list cgrun cgroups (system base + transient leaves)
cgrun kill [-s SIGNAL] <cgroup>            # signal whole tree, then remove it if cgrun-created (TERM, KILL, HUP, INT, 9, 15, ...)
cgrun freeze <cgroup>                      # cgroup.freeze = 1
cgrun thaw <cgroup>                        # cgroup.freeze = 0
```

Exit code of `run` is the command's exit code (or `128+signal`).

## Listing

`cgrun list` scans `/sys/fs/cgroup` and shows every cgroup created by cgrun:
everything under the system base (`--base`, default `cgrun`) plus all
transient `cgrun-*.scope` leaves wherever they live, with kind, member pid
count and enabled controllers.

useful tidbitL You can list processes and their cgroups using `ps -e -o cgroup:50,pid,user,args:100 --sort=cgroup,args`

`cgrun kill [-s SIGNAL] <cgroup>` signals one cgroup and then removes it —
the single-cgroup equivalent of `clean`. Only cgrun-created targets (under
the system base or named `cgrun-*`) are removed; anything else is signaled
and kept. If processes survive the signal, the cgroup is kept and `kill`
fails with a hint (`use -s KILL to force`).

`cgrun clean --force` removes *all* cgrun cgroups at once (same discovery as
`list`, deepest-first, escalating via `pkexec` for anything you can't delete
yourself).

Note: custom-named *regular-mode* persistent cgroups live inside your own
scope under an arbitrary name and leave no marker, so `list` cannot find
them — use `--priv` (always under `/sys/fs/cgroup/cgrun/<name>`) for
persistent cgroups you want discoverable.

This is todo for fixing eventually.

## dmem — Keeping VRAM Resident

`--vram-low` sets `dmem.low` — While a cgroup's usage is below that boundary the kernel will try hard to keep its allocations resident in VRAM and instead evict/allocate from unprotected cgroups into `GTT` (system RAM accessed over PCIe). See References.

`SPEC` is `SIZE` or `REGION:SIZE`:

- `7G`, `512M`, `max`
- `drm/0000:03:00.0/vram:7G`, `drm/0000:03:00.0/vram=7G`, `drm/0000:03:00.0/vram 7G`
- Regions are read from `/sys/fs/cgroup/dmem.capacity`

Repeatable: `--vram-low 4G --vram-low drm/.../gtt:max`

If no `--vram-low`/`--vram-max` is given, `dmem.low`/`dmem.max` are left alone. Controllers are only enabled when you request them (`--vram-*`, `--memory-*`, `--cpu-*`).

## CPU Details

- `--cpu-weight 1..10000` writes `cpu.weight`
- `--cpu-weight-nice -20..19` writes `cpu.weight.nice` (mutually exclusive)

## Memory Details

- `--memory-max SIZE|max` writes `memory.max` (hard limit)
- `--memory-high SIZE|max` writes `memory.high` (throttle boundary)
- `--memory-low SIZE|max` writes `memory.low` (protection)
- `--memory-min SIZE|max` writes `memory.min` (min protection)

## Cleanup

```sh
# Remove all cgrun cgroups (requires confirmation)
./target/release/cgrun clean --force
# Single cgroup instead
./target/release/cgrun kill -s KILL <cgroup>
```

Transient cgroups are removed automatically on exit with a `2s` graceful period (`--grace 0` for immediate `SIGKILL`).


## Troubleshooting

- `dmem not available` — kernel/driver doesn't expose the `dmem` controller; use `memory`/`cpu` only or check `cat /sys/fs/cgroup/dmem.capacity`
- `cannot create cgroup ... is not delegated to you` — parent cgroup isn't writable by you; rerun with `--priv`
- `cgroup busy` on removal — process still attached; `cgrun kill -s KILL <cgroup>` or wait for `grace`

## References

[1] [Fixing AMDGPU's VRAM management for low-end GPUs — pixelcluster.dev](https://pixelcluster.dev/VRAM-Mgmt-fixed/) — why `dmem.low` is a *protection* limit that keeps the foreground game's VRAM from being spilled to GTT, and how the kernel patches + `dmemcg-booster`/`plasma-foreground-booster` tie together.

## TODO

- Track `flatten the pick` cgroup scheduling patches for gaming — Phoronix [Flatten The Pick v3](https://www.phoronix.com/news/Flatten-The-Pick-v3) (flat run-queue / `cgroup_mode` via dynamic weight, big min-FPS gains on older Intel + Polaris). Evaluate `cgroup_mode` handling once upstream.
- fix cleaning renamed cgroups

## License

MIT
