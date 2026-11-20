#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Metrics, graphs and perfometers for sophos_sfos."""

from cmk.graphing.v1 import Title
from cmk.graphing.v1.graphs import Graph, MinimalRange
from cmk.graphing.v1.metrics import Color, DecimalNotation, Metric, TimeNotation, Unit
from cmk.graphing.v1.perfometers import Closed, FocusRange, Open, Perfometer

UNIT_PERCENT = Unit(DecimalNotation("%"))
UNIT_COUNT = Unit(DecimalNotation(""))
UNIT_PER_SECOND = Unit(DecimalNotation("/s"))
UNIT_WATT = Unit(DecimalNotation("W"))

metric_sophos_sfos_mem_used_percent = Metric(
    name="sophos_sfos_mem_used_percent",
    title=Title("RAM usage"),
    unit=UNIT_PERCENT,
    color=Color.BLUE,
)

metric_sophos_sfos_swap_used_percent = Metric(
    name="sophos_sfos_swap_used_percent",
    title=Title("Swap usage"),
    unit=UNIT_PERCENT,
    color=Color.ORANGE,
)

metric_sophos_sfos_disk_used_percent = Metric(
    name="sophos_sfos_disk_used_percent",
    title=Title("Disk usage"),
    unit=UNIT_PERCENT,
    color=Color.GREEN,
)

metric_sophos_sfos_live_users = Metric(
    name="sophos_sfos_live_users",
    title=Title("Live users"),
    unit=UNIT_COUNT,
    color=Color.PURPLE,
)

metric_sophos_sfos_http_hits = Metric(
    name="sophos_sfos_http_hits",
    title=Title("HTTP hits"),
    unit=UNIT_PER_SECOND,
    color=Color.CYAN,
)

metric_sophos_sfos_ipsec_active_tunnels = Metric(
    name="sophos_sfos_ipsec_active_tunnels",
    title=Title("Active IPsec tunnels"),
    unit=UNIT_COUNT,
    color=Color.GREEN,
)

metric_sophos_sfos_license_remaining = Metric(
    name="sophos_sfos_license_remaining",
    title=Title("Time until next license expiry"),
    unit=Unit(TimeNotation()),
    color=Color.YELLOW,
)

metric_sophos_sfos_poe_power = Metric(
    name="sophos_sfos_poe_power",
    title=Title("PoE power draw"),
    unit=UNIT_WATT,
    color=Color.YELLOW,
)

graph_sophos_sfos_memory = Graph(
    name="sophos_sfos_memory",
    title=Title("Sophos Firewall memory"),
    simple_lines=["sophos_sfos_mem_used_percent", "sophos_sfos_swap_used_percent"],
    minimal_range=MinimalRange(0, 100),
)

perfometer_sophos_sfos_memory = Perfometer(
    name="sophos_sfos_memory",
    focus_range=FocusRange(Closed(0), Closed(100)),
    segments=["sophos_sfos_mem_used_percent"],
)

perfometer_sophos_sfos_disk = Perfometer(
    name="sophos_sfos_disk",
    focus_range=FocusRange(Closed(0), Closed(100)),
    segments=["sophos_sfos_disk_used_percent"],
)

perfometer_sophos_sfos_ipsec = Perfometer(
    name="sophos_sfos_ipsec",
    focus_range=FocusRange(Closed(0), Open(10)),
    segments=["sophos_sfos_ipsec_active_tunnels"],
)

perfometer_sophos_sfos_poe = Perfometer(
    name="sophos_sfos_poe",
    focus_range=FocusRange(Closed(0), Open(60)),
    segments=["sophos_sfos_poe_power"],
)

perfometer_sophos_sfos_live_users = Perfometer(
    name="sophos_sfos_live_users",
    focus_range=FocusRange(Closed(0), Open(100)),
    segments=["sophos_sfos_live_users"],
)
