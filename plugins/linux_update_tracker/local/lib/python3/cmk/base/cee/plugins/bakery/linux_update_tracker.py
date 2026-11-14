#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Agent Bakery plugin for linux_update_tracker (commercial editions).

Bakery API v1 - stable on Checkmk 2.4 and 2.5 (deprecated in 3.0.0, removed in 3.1.0).
Configured via the agent rule "Linux Update Tracker (Linux)".
"""

from pathlib import Path
from typing import TypedDict

from .bakery_api.v1 import OS, FileGenerator, Plugin, PluginConfig, register


class LinuxUpdateTrackerConfig(TypedDict, total=False):
    deploy: bool
    interval: float
    refresh: tuple[str, float | None]
    timeout: int


def _config_lines(conf: LinuxUpdateTrackerConfig) -> list[str]:
    mode, max_age = conf.get("refresh", ("auto", 12 * 3600.0))
    if mode not in ("auto", "always", "never"):
        mode, max_age = "auto", 12 * 3600.0
    lines = [f"REFRESH={mode}"]
    if mode == "auto":
        lines.append(f"REFRESH_MAX_AGE={int(max_age or 12 * 3600)}")
    lines.append(f"CMD_TIMEOUT={int(conf.get('timeout', 600))}")
    return lines


def get_linux_update_tracker_files(conf: LinuxUpdateTrackerConfig) -> FileGenerator:
    if not conf.get("deploy", True):
        return
    yield Plugin(
        base_os=OS.LINUX,
        source=Path("linux_update_tracker"),
        interval=int(conf.get("interval", 4 * 3600)),
    )
    yield PluginConfig(
        base_os=OS.LINUX,
        lines=_config_lines(conf),
        target=Path("linux_update_tracker.cfg"),
        include_header=True,
    )


register.bakery_plugin(
    name="linux_update_tracker",
    files_function=get_linux_update_tracker_files,
)
