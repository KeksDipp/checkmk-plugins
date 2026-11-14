# Linux Update Tracker

Checkmk extension that shows **which** Linux packages have pending updates and for how long,
whether a reboot is pending and which package transactions failed. Works with APT, DNF, YUM and
Zypper. It is the Linux counterpart of the [Windows Update Tracker](../windows_update_tracker/).

| | |
|---|---|
| **Checkmk** | 2.5, 2.4 untested (all editions; Agent Bakery support for commercial editions) |
| **Agent** | Linux, bash 4+ |
| **License** | GPL-2.0 |

## Supported distributions

| Package manager | Distributions (tested) | Classification | Severity / publish date | History |
|---|---|---|---|---|
| APT | Debian 13, Ubuntu 24.04, Proxmox VE 9 (also Mint, Raspberry Pi OS …) | Security repository → *Security*, everything else *Other* | – | `/var/log/apt/history.log` |
| DNF 4 | Rocky 9, Alma 8 (also RHEL, Oracle, CentOS Stream 8/9) | from the advisories (`updateinfo`) | yes / advisory date or build date | `dnf history` |
| DNF 5 | Fedora 43 | from the advisories | yes / advisory date | `dnf history` |
| YUM | Amazon Linux 2 (also CentOS 7) | from the advisories | yes / – | `yum history` |
| Zypper | openSUSE Leap 16 (also SLES) | from the patches | yes / patch date | – |

Not supported: Arch, Alpine, Gentoo, NixOS and image-based systems (Fedora Atomic, MicroOS …).

## Services

### Linux Updates pending

Lists every package with a pending update and its age:

```
openssl (amd64) 3.5.1-1 -> 3.5.4-1~deb13u1 [trixie-security] (Security) - outdated since
  2026-11-10 06:12:00 (4 days), this version since 2026-11-13 06:12:00 (1 day)
  [outdated since, default] (!)
```

- Default: WARN after 2 days, CRIT after 7 days.
- **The age counts from when the package became outdated.** A newer version of the same package
  does not reset it – a package that is never updated always grows older. Alternatively the age
  can count from when the *current candidate version* showed up or from the *publish date* (DNF,
  Zypper).
- **Age rules** set other limits for certain packages (by classification, severity, package name
  or repository). The first matching rule wins.
- **Nothing is filtered by default.** Held packages (`apt-mark hold`), phased updates (Ubuntu),
  classifications, package names and repositories can be filtered. Filtered updates are listed in
  the details with the reason.
- WARN if the update search or the index refresh fails, or if the last successful search or the
  package index is older than 2 days (CRIT after 7 days). WARN if the plugin cannot write its
  state file (the ages would not be tracked).
- Optional levels for the number of pending updates.

### Linux Update reboot

Shows if a reboot is pending and since when. Default: WARN after 1 day, CRIT after 3 days.
Detected via `/run/reboot-required` (Debian/Ubuntu), a newer installed kernel than the running
one, core packages installed after the last boot (RPM systems: kernel, glibc, systemd, dbus,
firmware …, plus `/etc/dnf/plugins/needs-restarting.d/*.conf` and `/etc/zypp/needreboot`) and
`needrestart`. Inside containers (LXC, Docker …) the kernel is ignored.

Services still running old libraries are listed (`needrestart`, `dnf needs-restarting`,
`zypper ps` – if installed). By default they do not change the state.

### Linux Update failures

Shows failed and aborted package transactions of the last 30 days (default: WARN). A failure is
ignored when all its packages were handled by a later successful transaction or none of them
has a pending update anymore. A transaction still in progress is not counted. Also shows broken
packages (half-installed/half-configured in dpkg, problems from `dnf check`). Not available for
Zypper (its history does not record failures).

All rules are found under **Setup → Services → Service monitoring rules → Linux**, named
"… (Linux Update Tracker)".

## How it works

- The search only reads the **local package index** (`apt list --upgradable`,
  `dnf repoquery --upgrades -C`, `yum check-update -C`, `zypper --no-refresh list-updates`).
- Refreshing the index is configurable: **only if older than 12 h** (default), always, or never
  (if apt-daily, dnf-automatic or a cron job already does it). The age of the index is monitored.
- Nothing is ever installed or changed on the host.
- The plugin remembers since when each package is outdated, since when the candidate version is
  known and since when a reboot is pending in
  `/var/lib/check_mk_agent/linux_update_tracker.state`. The accuracy equals the plugin's run
  interval (default 4 h).

## Installation

### 1. Server side

Download `linux_update_tracker-<version>.mkp` from the
[Releases](https://github.com/KeksDipp/checkmk-plugins/releases) page and install it:

```bash
# as site user
mkp add linux_update_tracker-<version>.mkp
mkp enable linux_update_tracker <version>
omd restart apache
omd restart automation-helper   # otherwise a running site does not load the new plugin
```

or via *Setup → Extension packages* (commercial editions).

### 2a. Agent plugin – Agent Bakery (commercial editions)

Create a rule **Setup → Agents → Agent rules → Linux Update Tracker (Linux)**, set the interval
(default 4 h), the index refresh and the timeout per package manager call (default 600 s), then
bake and deploy the agents.

### 2b. Agent plugin – manual (all editions)

1. Copy `linux_update_tracker` to `/usr/lib/check_mk_agent/plugins/14400/` (the directory name
   is the run interval in seconds: every 4 hours, asynchronously) and make it executable:

   ```bash
   install -D -m 0755 linux_update_tracker /usr/lib/check_mk_agent/plugins/14400/linux_update_tracker
   ```

   Download it in Checkmk 2.5 under *Setup → Agents → Other operating systems* or take it from this
   repository / the release assets.
2. Optional: create `/etc/check_mk/linux_update_tracker.cfg`:

   ```ini
   REFRESH=auto            # auto | always | never
   REFRESH_MAX_AGE=43200   # auto: refresh if the index is older (seconds)
   CMD_TIMEOUT=600         # timeout per package manager call (seconds)
   LOCK_TIMEOUT=120        # wait for a package manager lock (seconds)
   ```

3. Run a service discovery for the host in Checkmk.

The first result appears after the first run has finished (usually seconds, with an index refresh
up to a few minutes). To test the plugin by hand, run it as root:

```bash
/usr/lib/check_mk_agent/plugins/14400/linux_update_tracker
```

## Notes

- Requires `bash`, `awk`, GNU `coreutils` (`timeout`, `date -f`) and the package manager itself.
  `flock` is used if available.
- It does not conflict with Checkmk's built-in `apt`, `yum` and `zypper` checks (different section and
  service names), but you usually only want one of them.
- APT has no advisory data, so APT updates are either *Security* (from a security suite) or
  *Other*.
- Agent output is JSON, one object per line, in section `<<<linux_update_tracker:sep(0)>>>`.

## License

GPL-2.0 – see [LICENSE](../../LICENSE).
