# Changelog – linux_update_tracker

## 1.0.0-beta.1 – unreleased

- First release: services *Linux Updates pending*, *Linux Update reboot* and
  *Linux Update failures* for APT, DNF, DNF5, YUM and Zypper
- Per-package age rules (classification, severity, package, repository); age counts from when
  the package became outdated, from the candidate version or from the publish date
- Package index refresh: only if older than 12 h (default), always or never
- Agent Bakery rule *Linux Update Tracker (Linux)*
- Known limitation: on Zypper the classification/severity from patches is not verified yet on a
  system with pending patches (tested systems had none)
