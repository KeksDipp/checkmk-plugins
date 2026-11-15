# Changelog – linux_update_tracker

## 1.0.0-beta.1 – unreleased

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
