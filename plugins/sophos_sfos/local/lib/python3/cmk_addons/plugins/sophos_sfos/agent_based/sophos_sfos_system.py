#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Device information and resource usage of Sophos Firewall OS.

Services:
  * Sophos System  - model, firmware, serial number, pattern versions, live users, HTTP hits
  * Sophos Memory  - RAM and swap usage as reported by SFOS (without cache/buffers)
  * Sophos Disk    - usage of the SFOS data partition

CPU utilization is not part of the SFOS MIB; the built-in check "CPU utilization"
(hr_cpu, HOST-RESOURCES-MIB) covers it.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cmk.agent_based.v2 import (
    Attributes,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    GetRateError,
    InventoryPlugin,
    InventoryResult,
    Metric,
    Result,
    Service,
    SimpleSNMPSection,
    State,
    StringTable,
    check_levels,
    get_rate,
    get_value_store,
    render,
)
from cmk_addons.plugins.sophos_sfos.lib import (
    DETECT_SFOS,
    SFOS_TREE,
    scalar_row,
    sfos_values,
    to_int,
)

MB = 1024 * 1024


@dataclass(frozen=True)
class SfosSystem:
    name: str
    model: str
    firmware: str
    serial: str
    webcat_version: str
    ips_version: str
    disk_capacity_mb: int | None
    disk_used_percent: int | None
    mem_capacity_mb: int | None
    mem_used_percent: int | None
    swap_capacity_mb: int | None
    swap_used_percent: int | None
    live_users: int | None
    http_hits: int | None


def parse_sophos_sfos_system(string_table: StringTable) -> SfosSystem | None:
    values = sfos_values(string_table)
    # sfosDeviceName, Type, FWVersion, AppKey (serial), WebcatVersion, IPSVersion
    info = scalar_row(values, "1", ("1.0", "2.0", "3.0", "4.0", "5.0", "6.0"))
    # disk capacity/%, memory capacity/%, swap capacity/%, live users, HTTP hits
    stats = scalar_row(
        values, "2", ("4.1.0", "4.2.0", "5.1.0", "5.2.0", "5.3.0", "5.4.0", "6.0", "7.0")
    )
    if info is None or stats is None:
        return None
    name, model, firmware, serial, webcat, ips = info
    disk_cap, disk_pct, mem_cap, mem_pct, swap_cap, swap_pct, users, http = stats
    return SfosSystem(
        name=name,
        model=model,
        firmware=firmware,
        serial=serial,
        webcat_version=webcat,
        ips_version=ips,
        disk_capacity_mb=to_int(disk_cap),
        disk_used_percent=to_int(disk_pct),
        mem_capacity_mb=to_int(mem_cap),
        mem_used_percent=to_int(mem_pct),
        swap_capacity_mb=to_int(swap_cap),
        swap_used_percent=to_int(swap_pct),
        live_users=to_int(users),
        http_hits=to_int(http),
    )


snmp_section_sophos_sfos_system = SimpleSNMPSection(
    name="sophos_sfos_system",
    detect=DETECT_SFOS,
    fetch=SFOS_TREE,
    parse_function=parse_sophos_sfos_system,
)


def _version(value: str) -> str:
    return value if value and value.lower() != "not available" else "not available"


# ---------------------------------------------------------------------------
# Sophos System
# ---------------------------------------------------------------------------


def discover_sophos_sfos_info(section: SfosSystem) -> DiscoveryResult:
    yield Service()


def check_sophos_sfos_info(section: SfosSystem) -> CheckResult:
    yield Result(
        state=State.OK,
        summary=f"Model: {section.model}, Firmware: {section.firmware}, Serial: {section.serial}",
    )
    yield Result(state=State.OK, notice=f"Device name: {section.name}")
    yield Result(state=State.OK, notice=f"IPS pattern version: {_version(section.ips_version)}")
    yield Result(
        state=State.OK,
        notice=f"Web category version: {_version(section.webcat_version)}",
    )

    if section.live_users is not None:
        yield Result(state=State.OK, summary=f"Live users: {section.live_users}")
        yield Metric("sophos_sfos_live_users", section.live_users)

    if section.http_hits is not None:
        try:
            rate = get_rate(
                get_value_store(), "http_hits", time.time(), section.http_hits, raise_overflow=True
            )
        except GetRateError:
            return
        yield Result(state=State.OK, notice=f"HTTP hits: {rate:.2f}/s")
        yield Metric("sophos_sfos_http_hits", rate)


check_plugin_sophos_sfos_info = CheckPlugin(
    name="sophos_sfos_info",
    sections=["sophos_sfos_system"],
    service_name="Sophos System",
    discovery_function=discover_sophos_sfos_info,
    check_function=check_sophos_sfos_info,
)


# ---------------------------------------------------------------------------
# Sophos Memory
# ---------------------------------------------------------------------------


def discover_sophos_sfos_memory(section: SfosSystem) -> DiscoveryResult:
    if section.mem_used_percent is not None:
        yield Service()


def _usage(
    label: str,
    percent: int,
    capacity_mb: int | None,
    levels: Any,
    metric: str,
) -> CheckResult:
    yield from check_levels(
        float(percent),
        levels_upper=levels,
        metric_name=metric,
        boundaries=(0.0, 100.0),
        render_func=render.percent,
        label=label,
    )
    if capacity_mb:
        used = capacity_mb * MB * percent / 100
        yield Result(
            state=State.OK,
            summary=f"{render.bytes(used)} of {render.bytes(capacity_mb * MB)}",
        )


def check_sophos_sfos_memory(params: Mapping[str, Any], section: SfosSystem) -> CheckResult:
    if section.mem_used_percent is None:
        return
    yield from _usage(
        "RAM",
        section.mem_used_percent,
        section.mem_capacity_mb,
        params.get("levels_mem"),
        "sophos_sfos_mem_used_percent",
    )
    if section.swap_used_percent is not None:
        yield from _usage(
            "Swap",
            section.swap_used_percent,
            section.swap_capacity_mb,
            params.get("levels_swap"),
            "sophos_sfos_swap_used_percent",
        )


check_plugin_sophos_sfos_memory = CheckPlugin(
    name="sophos_sfos_memory",
    sections=["sophos_sfos_system"],
    service_name="Sophos Memory",
    discovery_function=discover_sophos_sfos_memory,
    check_function=check_sophos_sfos_memory,
    check_default_parameters={
        "levels_mem": ("fixed", (80.0, 90.0)),
        "levels_swap": ("fixed", (50.0, 75.0)),
    },
    check_ruleset_name="sophos_sfos_memory",
)


# ---------------------------------------------------------------------------
# Sophos Disk
# ---------------------------------------------------------------------------


def discover_sophos_sfos_disk(section: SfosSystem) -> DiscoveryResult:
    if section.disk_used_percent is not None:
        yield Service()


def check_sophos_sfos_disk(params: Mapping[str, Any], section: SfosSystem) -> CheckResult:
    if section.disk_used_percent is None:
        return
    yield from _usage(
        "Used",
        section.disk_used_percent,
        section.disk_capacity_mb,
        params.get("levels"),
        "sophos_sfos_disk_used_percent",
    )


check_plugin_sophos_sfos_disk = CheckPlugin(
    name="sophos_sfos_disk",
    sections=["sophos_sfos_system"],
    service_name="Sophos Disk",
    discovery_function=discover_sophos_sfos_disk,
    check_function=check_sophos_sfos_disk,
    check_default_parameters={"levels": ("fixed", (80.0, 90.0))},
    check_ruleset_name="sophos_sfos_disk",
)


# ---------------------------------------------------------------------------
# HW/SW inventory
# ---------------------------------------------------------------------------


def inventory_sophos_sfos_system(section: SfosSystem) -> InventoryResult:
    yield Attributes(
        path=["hardware", "system"],
        inventory_attributes={
            "manufacturer": "Sophos",
            "model": section.model,
            "serial": section.serial,
        },
    )
    yield Attributes(
        path=["software", "os"],
        inventory_attributes={
            "vendor": "Sophos",
            "name": "Sophos Firewall OS",
            "version": section.firmware,
        },
    )
    if section.mem_capacity_mb:
        yield Attributes(
            path=["hardware", "memory"],
            inventory_attributes={"total_ram_usable": section.mem_capacity_mb * MB},
        )


inventory_plugin_sophos_sfos_system = InventoryPlugin(
    name="sophos_sfos_system",
    inventory_function=inventory_sophos_sfos_system,
)
