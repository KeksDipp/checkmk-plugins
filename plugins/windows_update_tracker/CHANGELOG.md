# Changelog – windows_update_tracker

## 1.0.0 – 2026-11-20

First stable release.

- Malformed agent output no longer crashes the checks. Invalid lines are skipped.
- Agent plugin 1.0.0: the state file is never read or written through a symlink or junction,
  and the temporary file gets a random name that is created exclusively.
- The checks stay compatible with the agent plugin of 1.0.0-beta.3; replacing the script on
  the hosts is recommended but not required.

## 1.0.0-beta.4 – 2026-11-13

- All filters in one list *Filtered updates*. Existing rules are migrated.
- The Defender platform update (KB4052623) is no longer filtered by default (can be selected)

## 1.0.0-beta.3 – 2026-11-13

- Optional updates (not auto-selected by Windows Update, e.g. most drivers) are ignored by
  default, new rule option *Optional updates*. Needs the new agent plugin.
- Details: one update per line, filtered updates with the reason

## 1.0.0-beta.2 – 2026-11-13

- Default age limits for pending updates: WARN after 2 days, CRIT after 7 days
  (was 14 / 30 days)

## 1.0.0-beta.1 – 2026-11-13

- First beta release
- Agent plugin `windows_update_tracker.ps1` (pending updates, first-seen tracking, pending reboot
  with timestamp, 30-day installation history)
- Services: *Windows Updates pending*, *Windows Update reboot*, *Windows Update failures*
- Age rules per classification / MSRC severity / title regex / KB number, age basis selectable
  (first seen or published)
- Filters for Definition Updates, Microsoft Defender, MSRT and custom patterns
- Metrics, graph and perfometers
- Agent Bakery plugin (Bakery API v1)
