#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Metrics, graphs and perfometers for linux_update_tracker."""

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

metric_linux_updates_pending = Metric(
    name="linux_updates_pending",
    title=Title("Pending Linux updates"),
    unit=_COUNT,
    color=Color.ORANGE,
)

metric_linux_updates_security = Metric(
    name="linux_updates_security",
    title=Title("Pending Linux security updates"),
    unit=_COUNT,
    color=Color.RED,
)

metric_linux_updates_filtered = Metric(
    name="linux_updates_filtered",
    title=Title("Filtered Linux updates"),
    unit=_COUNT,
    color=Color.GRAY,
)

metric_linux_updates_oldest_age = Metric(
    name="linux_updates_oldest_age",
    title=Title("Age of oldest pending Linux update"),
    unit=_TIME,
    color=Color.PURPLE,
)

metric_linux_update_reboot_age = Metric(
    name="linux_update_reboot_age",
    title=Title("Linux reboot pending for"),
    unit=_TIME,
    color=Color.RED,
)

metric_linux_update_failures = Metric(
    name="linux_update_failures",
    title=Title("Failed Linux package transactions"),
    unit=_COUNT,
    color=Color.DARK_RED,
)

metric_linux_update_broken = Metric(
    name="linux_update_broken",
    title=Title("Broken Linux packages"),
    unit=_COUNT,
    color=Color.DARK_ORANGE,
)

graph_linux_updates_count = Graph(
    name="linux_updates_count",
    title=Title("Linux updates"),
    compound_lines=["linux_updates_pending", "linux_updates_filtered"],
    simple_lines=["linux_updates_security"],
)

perfometer_linux_updates_pending = Perfometer(
    name="linux_updates_pending",
    focus_range=FocusRange(Closed(0), Open(20)),
    segments=["linux_updates_pending"],
)

perfometer_linux_update_reboot_age = Perfometer(
    name="linux_update_reboot_age",
    focus_range=FocusRange(Closed(0), Open(3 * 86400)),
    segments=["linux_update_reboot_age"],
)

perfometer_linux_update_failures = Perfometer(
    name="linux_update_failures",
    focus_range=FocusRange(Closed(0), Open(5)),
    segments=["linux_update_failures"],
)
