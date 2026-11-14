# Checkmk Plugins

A collection of open-source extensions for [Checkmk](https://checkmk.com/) – agent-based checks,
local checks, special agents, rulesets and graphing definitions – built for real-world homelab
and small-business monitoring.

## Plugins

| Plugin | Type | Description | Checkmk | Latest release |
|--------|------|-------------|---------|----------------|
| [windows_update_tracker](plugins/windows_update_tracker/) | Agent plugin + checks + bakery | Pending Windows updates with per-update age rules, pending reboot, failed installations, Defender filter | 2.5 (2.4 untested) | [1.0.0-beta.4](https://github.com/KeksDipp/checkmk-plugins/releases/tag/windows_update_tracker-v1.0.0-beta.4) |
| [linux_update_tracker](plugins/linux_update_tracker/) | Agent plugin + checks + bakery | Pending package updates (APT, DNF, YUM, Zypper) with per-package age rules, pending reboot, failed transactions | 2.5 (2.4 untested) | – |

Each plugin lives in its own directory under [`plugins/`](plugins/) with a dedicated README and
changelog.

## Compatibility

All plugins target the current plugin APIs (`cmk.agent_based.v2`, `cmk.rulesets.v1`,
`cmk.graphing.v1`, `cmk.server_side_calls.v1`) and are tested on **Checkmk 2.4** and/or
**Checkmk 2.5**. The supported versions are listed per plugin. Legacy (pre-2.3) APIs are not
supported.

## Installation

Download the `.mkp` file of the desired plugin from the
[Releases](https://github.com/KeksDipp/checkmk-plugins/releases) page.

**Via the GUI** (commercial editions):
*Setup → Extension packages → Upload package*, then enable it.

**Via the command line** (all editions, including Checkmk Community/Raw):

```bash
# as the site user
mkp add /path/to/<plugin>-<version>.mkp
mkp enable <plugin> <version>
cmk -R   # or: omd restart apache, depending on the plugin type
```

Some plugins additionally ship an agent plugin or local check that has to be deployed to the
monitored host – see the plugin's README for details.

## Repository layout

```
plugins/
└── <plugin-name>/
    ├── README.md
    ├── CHANGELOG.md
    └── local/                    # mirrors the layout of a Checkmk site ($OMD_ROOT/local)
        ├── lib/python3/cmk_addons/plugins/<plugin-name>/
        │   ├── agent_based/      # check plugins
        │   ├── rulesets/         # rule specs
        │   ├── graphing/         # metrics, graphs, perfometers
        │   └── server_side_calls/
        └── share/check_mk/agents/plugins/   # agent-side plugins (if any)
```

Because the directory structure matches `$OMD_ROOT/local`, a plugin can be copied (or symlinked)
straight into a test site during development.

## Releases & versioning

Plugins are versioned independently using [Semantic Versioning](https://semver.org/).
Releases are tagged as `<plugin-name>-v<version>` (e.g. `nic-watchdog-v1.0.0`) and the built
`.mkp` package is attached to the corresponding GitHub Release.

## Contributing

Issues and pull requests are welcome. Please run `ruff check .` and `ruff format .` before
submitting.

## License

This project is licensed under the [GNU General Public License v2.0](LICENSE), the same license
as Checkmk itself.

Copyright © 2026 Alexander Thomsen
