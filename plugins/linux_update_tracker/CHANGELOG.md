# Changelog – linux_update_tracker

## 1.0.0-beta.1 – 2026-11-15

- First release: services *Linux Updates pending*, *Linux Update reboot* and
  *Linux Update failures* for APT, DNF, DNF5, YUM and Zypper
- Per-package age rules (classification, severity, package, repository); age counts from when
  the package became outdated, from the candidate version or from the publish date
- Package index refresh: only if older than 12 h (default), always or never
- Agent Bakery rule *Linux Update Tracker (Linux)*
- Zypper: classification, severity and advisory are taken from the needed patches
  (verified on openSUSE Leap 16.0 with pending security patches)
- If several advisories cover one package, the worst classification/severity wins,
  on a tie the oldest advisory
- The agent no longer needs `xargs` or `find` (missing in minimal images); this also fixes the
  detection of phased updates on Ubuntu
- Phased updates (Ubuntu): only packages that apt really defers for this host count as phased
  (taken from an `apt-get -s dist-upgrade` simulation, not just from the rollout percentage)
- DNF5: the publish date of an advisory keeps its time of day (was cut to the date)
- YUM: failed/succeeded transactions list the updated packages (`Updated`/`Obsoleted` lines)
- Agent config: blanks around the key (`REFRESH = always`) are accepted
