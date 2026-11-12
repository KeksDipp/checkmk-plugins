# Changelog – windows_update_tracker

## 1.0.0 – unreleased

- Initial release
- Agent plugin `windows_update_tracker.ps1` (pending updates, first-seen tracking, pending reboot
  with timestamp, 30-day installation history)
- Services: *Windows Updates pending*, *Windows Update reboot*, *Windows Update failures*
- Age rules per classification / MSRC severity / title regex / KB number, age basis selectable
  (first seen or published)
- Filters for Definition Updates, Microsoft Defender, MSRT and custom patterns
- Metrics, graph and perfometers
- Agent Bakery plugin (Bakery API v1)
