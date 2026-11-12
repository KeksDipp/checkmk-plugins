#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Agent Bakery plugin for windows_update_tracker (commercial editions).

Bakery API v1 - stable on Checkmk 2.4 and 2.5 (deprecated in 3.0.0, removed in 3.1.0).
Configured via the agent rule "Windows Update Tracker (Windows)".
"""

from pathlib import Path
from typing import TypedDict

from .bakery_api.v1 import OS, FileGenerator, Plugin, register


class WindowsUpdateTrackerConfig(TypedDict, total=False):
    deploy: bool
    interval: float
    timeout: int


def get_windows_update_tracker_files(conf: WindowsUpdateTrackerConfig) -> FileGenerator:
    if not conf.get("deploy", True):
        return
    yield Plugin(
        base_os=OS.WINDOWS,
        source=Path("windows_update_tracker.ps1"),
        interval=int(conf.get("interval", 4 * 3600)),
        asynchronous=True,
        timeout=int(conf.get("timeout", 600)),
    )


register.bakery_plugin(
    name="windows_update_tracker",
    files_function=get_windows_update_tracker_files,
)
