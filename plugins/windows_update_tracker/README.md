# Windows Update Tracker

Checkmk extension that shows **which** Windows updates are pending, how long a reboot has been
pending and which installations failed.

| | |
|---|---|
| **Checkmk** | 2.5, 2.4 untested (all editions; Agent Bakery support for commercial editions) |
| **Agent** | Windows, Windows PowerShell 5.1 |
| **License** | GPL-2.0 |

## Services

### Windows Updates pending

Lists every pending update with its age:

```
KB5070001 - 2026-11 Cumulative Update for Windows 11 ... (Security Updates, Critical)
          - seen 10 days, published 12 days ago [published, Security 7/14] (!)
```

- Default: WARN after 2 days, CRIT after 7 days.
- **Age rules** set other limits for certain updates (by classification, severity, title or
  KB). The first matching rule wins. Age counts from *first seen on this host* or from the
  *Microsoft release date*.
- **Filtered by default:** definition updates (Defender signatures), MSRT and optional updates (not
  auto-selected by Windows Update, e.g. most drivers). Classifications, the Defender platform update
  and title/KB patterns can be added. Filtered updates are listed in the details with the reason.
- WARN if the update search fails or is older than 2 days (CRIT after 7 days).

### Windows Update reboot

Shows if a reboot is pending and since when. Default: WARN after 1 day, CRIT after 3 days.

### Windows Update failures

Shows failed installations of the last 30 days (default: WARN). Goes back to OK when the update
was installed later or is no longer offered (e.g. replaced by a newer update). Installations
still in progress are not counted.

All rules are found under **Setup → Services → Service monitoring rules → Windows**, named
"… (Windows Update Tracker)".

## How "first seen" works

Windows only knows when Microsoft released an update. So the plugin remembers when it first saw
each update (and since when a reboot is pending) in
`%ProgramData%\checkmk\agent\state\windows_update_tracker.json`. The accuracy equals the
plugin's run interval (default 4 h).

## Installation

### 1. Server side

Download `windows_update_tracker-<version>.mkp` from the
[Releases](https://github.com/KeksDipp/checkmk-plugins/releases) page and install it:

```bash
# as site user
mkp add windows_update_tracker-<version>.mkp
mkp enable windows_update_tracker <version>
omd restart apache
omd restart automation-helper   # otherwise a running site does not load the new plugin
```

or via *Setup → Extension packages* (commercial editions).

### 2a. Agent plugin – Agent Bakery (commercial editions)

Create a rule **Setup → Agents → Agent rules → Windows Update Tracker (Windows)**, set the
interval (default 4 h) and timeout (default 600 s), then bake and deploy the agents.

### 2b. Agent plugin – manual (all editions)

1. Copy `windows_update_tracker.ps1` to `C:\ProgramData\checkmk\agent\plugins\`.
   Download it in Checkmk 2.5 under *Setup → Agents → Other operating systems* (section
   "Windows_update_tracker (locally installed …)") or take it from this repository / the release
   assets. (*Windows files* only lists the files shipped with Checkmk itself, never locally
   installed ones – in 2.4 the file is only available from the repository.)
2. Make the plugin run **asynchronously** – a Windows Update search can take several minutes.
   Add to `C:\ProgramData\checkmk\agent\check_mk.user.yml`:

   ```yaml
   plugins:
     execution:
       - pattern: $CUSTOM_PLUGINS_PATH$\windows_update_tracker.ps1
         async: yes
         cache_age: 14400   # run every 4 hours
         timeout: 600
   ```

   If the file already contains a `plugins: execution:` list, add the entry **at the top, before
   the `*.*` wildcard entries** – the agent uses the first matching pattern, so an entry below
   `$CUSTOM_PLUGINS_PATH$\*.*` is silently ignored (the plugin then runs synchronously with a
   30 s timeout). Check the effective config with `check_mk_agent.exe showconfig plugins`.
3. Restart the agent: `net stop checkmkservice && net start checkmkservice`
4. Run a service discovery for the host in Checkmk.

The first result appears after the first search has finished (up to a few minutes).

To test the plugin by hand, run it in an elevated PowerShell:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\checkmk\agent\plugins\windows_update_tracker.ps1"
```

## Notes

- The plugin uses the update source configured on the host (Windows Update, Microsoft Update
  or WSUS). Hidden updates are not reported.
- It does not conflict with Checkmk's built-in `windows_updates` check (different section and
  service names), but you usually only want one of them.
- Agent output is plain ASCII JSON, one object per line, in section
  `<<<windows_update_tracker:sep(0)>>>`.

## License

GPL-2.0 – see [LICENSE](../../LICENSE).
