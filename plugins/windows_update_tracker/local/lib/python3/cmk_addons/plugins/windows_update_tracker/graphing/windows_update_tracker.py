#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Metrics, graphs and perfometers for windows_update_tracker."""

from cmk.graphing.v1 import Title
from cmk.graphing.v1.graphs import Graph
from cmk.graphing.v1.metrics import (
    Color,
    DecimalNotation,
    Metric,
    StrictPrecision,
    TimeNotation,
    Unit,
)
from cmk.graphing.v1.perfometers import Closed, FocusRange, Open, Perfometer

_COUNT = Unit(DecimalNotation(""), StrictPrecision(0))
_TIME = Unit(TimeNotation())

metric_windows_updates_pending = Metric(
    name="windows_updates_pending",
    title=Title("Pending Windows updates"),
    unit=_COUNT,
    color=Color.ORANGE,
)

metric_windows_updates_filtered = Metric(
    name="windows_updates_filtered",
    title=Title("Filtered Windows updates"),
    unit=_COUNT,
    color=Color.GRAY,
)

metric_windows_updates_oldest_age = Metric(
    name="windows_updates_oldest_age",
    title=Title("Age of oldest pending Windows update"),
    unit=_TIME,
    color=Color.PURPLE,
)

metric_windows_update_reboot_age = Metric(
    name="windows_update_reboot_age",
    title=Title("Windows reboot pending for"),
    unit=_TIME,
    color=Color.RED,
)

metric_windows_update_failures = Metric(
    name="windows_update_failures",
    title=Title("Failed Windows update installations"),
    unit=_COUNT,
    color=Color.DARK_RED,
)

graph_windows_updates_count = Graph(
    name="windows_updates_count",
    title=Title("Windows updates"),
    compound_lines=["windows_updates_pending", "windows_updates_filtered"],
)

perfometer_windows_updates_pending = Perfometer(
    name="windows_updates_pending",
    focus_range=FocusRange(Closed(0), Open(10)),
    segments=["windows_updates_pending"],
)

perfometer_windows_update_reboot_age = Perfometer(
    name="windows_update_reboot_age",
    focus_range=FocusRange(Closed(0), Open(3 * 86400)),
    segments=["windows_update_reboot_age"],
)

perfometer_windows_update_failures = Perfometer(
    name="windows_update_failures",
    focus_range=FocusRange(Closed(0), Open(5)),
    segments=["windows_update_failures"],
)
