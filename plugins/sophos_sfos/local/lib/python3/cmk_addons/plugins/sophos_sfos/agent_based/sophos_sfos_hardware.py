#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Hardware sensors of Sophos Firewall OS (sfosXGHardware, SFOS 22.0 and later).

Services (each only if the device reports the values):
  * Temperature CPU / Temperature NPU - uses the built-in ruleset "Temperature"
  * Fan <n>                           - uses the built-in ruleset "FAN speed of hardware devices"
  * Power Supply <n>                  - up/down (larger appliances, e.g. XGS 2100 and up)
  * Sophos PoE                        - PoE ports: enabled, power draw against the port limit

Numeric values are only reliable from SFOS 22.0 GA build 411 on; older builds partly return
strings. Values that cannot be read as numbers are ignored.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from cmk.agent_based.v2 import (
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    SimpleSNMPSection,
    State,
    StringTable,
    check_levels,
    get_value_store,
)
from cmk.plugins.lib.temperature import TempParamType, check_temperature
from cmk_addons.plugins.sophos_sfos.lib import (
    DETECT_SFOS,
    SFOS_TREE,
    scalar_row,
    sfos_values,
    table_rows,
    to_int,
)

PSU_STATES = {1: "up", 2: "down"}
PSU_UP = 1
POE_ENABLED = 1


@dataclass(frozen=True)
class PoEPort:
    label: str
    enabled: bool
    limit_w: float | None
    usage_w: float | None
    voltage_v: float | None
    current_a: float | None


@dataclass
class SfosHardware:
    temperatures: dict[str, float] = field(default_factory=dict)
    fans: dict[str, int] = field(default_factory=dict)
    psus: dict[str, int] = field(default_factory=dict)
    poe: dict[str, PoEPort] = field(default_factory=dict)


def _temperature(raw: str) -> float | None:
    """SFOS reports tenths of a degree Celsius; strings with a decimal point are taken as is."""
    raw = raw.strip().rstrip("C").rstrip("°").strip()
    if not raw:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if "." in raw else value / 10.0


def _scaled(raw: str, factor: float) -> float | None:
    value = to_int(raw)
    return None if value is None else value / factor


def parse_sophos_sfos_hardware(string_table: StringTable) -> SfosHardware | None:
    values = sfos_values(string_table)
    temps = scalar_row(values, "9", ("1.0", "2.0"))  # NPU, CPU temperature
    fans = table_rows(values, "9.3.1", ("2",))  # fan speed (RPM)
    psus = table_rows(values, "9.4.1", ("2",))  # power supply status
    # PoE: label, enabled, limit (mW), usage (mW), voltage (mV), current (mA)
    poe = table_rows(values, "9.5.1", ("2", "3", "4", "5", "6", "7"))
    hw = SfosHardware()
    if temps:
        npu, cpu = temps
        for name, raw in (("CPU", cpu), ("NPU", npu)):
            if (value := _temperature(raw)) is not None and value > 0:
                hw.temperatures[name] = value
    for index, raw in fans:
        if (rpm := to_int(raw)) is not None:
            hw.fans[index] = rpm
    for index, raw in psus:
        if (state := to_int(raw)) is not None:
            hw.psus[index] = state
    for index, label, enabled, limit, usage, voltage, current in poe:
        name = label.strip() or index
        hw.poe[name] = PoEPort(
            label=name,
            enabled=to_int(enabled) == POE_ENABLED,
            limit_w=_scaled(limit, 1000.0),
            usage_w=_scaled(usage, 1000.0),
            voltage_v=_scaled(voltage, 1000.0),
            current_a=_scaled(current, 1000.0),
        )
    if not (hw.temperatures or hw.fans or hw.psus or hw.poe):
        return None
    return hw


snmp_section_sophos_sfos_hardware = SimpleSNMPSection(
    name="sophos_sfos_hardware",
    detect=DETECT_SFOS,
    fetch=SFOS_TREE,
    parse_function=parse_sophos_sfos_hardware,
)


# ---------------------------------------------------------------------------
# Temperature
# ---------------------------------------------------------------------------


def discover_sophos_sfos_temp(section: SfosHardware) -> DiscoveryResult:
    for name in section.temperatures:
        yield Service(item=name)


def check_sophos_sfos_temp(item: str, params: TempParamType, section: SfosHardware) -> CheckResult:
    if (value := section.temperatures.get(item)) is None:
        return
    yield from check_temperature(
        value,
        params,
        unique_name=f"sophos_sfos_temp_{item}",
        value_store=get_value_store(),
    )


check_plugin_sophos_sfos_temp = CheckPlugin(
    name="sophos_sfos_temp",
    sections=["sophos_sfos_hardware"],
    service_name="Temperature %s",
    discovery_function=discover_sophos_sfos_temp,
    check_function=check_sophos_sfos_temp,
    check_default_parameters={"levels": (75.0, 85.0)},
    check_ruleset_name="temperature",
)


# ---------------------------------------------------------------------------
# Fans
# ---------------------------------------------------------------------------


def _legacy_levels(levels: Any) -> Any:
    """The built-in ruleset hw_fans still produces plain (warn, crit) tuples."""
    if isinstance(levels, tuple) and len(levels) == 2 and not isinstance(levels[0], str):
        return ("fixed", (float(levels[0]), float(levels[1])))
    return levels


def discover_sophos_sfos_fan(section: SfosHardware) -> DiscoveryResult:
    for index in section.fans:
        yield Service(item=index)


def check_sophos_sfos_fan(
    item: str, params: Mapping[str, Any], section: SfosHardware
) -> CheckResult:
    if (rpm := section.fans.get(item)) is None:
        return
    yield from check_levels(
        rpm,
        levels_lower=_legacy_levels(params.get("lower")),
        levels_upper=_legacy_levels(params.get("upper")),
        metric_name="fan",
        render_func=lambda v: f"{int(v)} RPM",
        label="Speed",
    )


check_plugin_sophos_sfos_fan = CheckPlugin(
    name="sophos_sfos_fan",
    sections=["sophos_sfos_hardware"],
    service_name="Fan %s",
    discovery_function=discover_sophos_sfos_fan,
    check_function=check_sophos_sfos_fan,
    check_default_parameters={"lower": (2000, 1000)},
    check_ruleset_name="hw_fans",
)


# ---------------------------------------------------------------------------
# Power supplies
# ---------------------------------------------------------------------------


def discover_sophos_sfos_psu(section: SfosHardware) -> DiscoveryResult:
    for index in section.psus:
        yield Service(item=index)


def check_sophos_sfos_psu(item: str, section: SfosHardware) -> CheckResult:
    if (state := section.psus.get(item)) is None:
        return
    yield Result(
        state=State.OK if state == PSU_UP else State.CRIT,
        summary=f"Status: {PSU_STATES.get(state, f'unknown({state})')}",
    )


check_plugin_sophos_sfos_psu = CheckPlugin(
    name="sophos_sfos_psu",
    sections=["sophos_sfos_hardware"],
    service_name="Power Supply %s",
    discovery_function=discover_sophos_sfos_psu,
    check_function=check_sophos_sfos_psu,
)


# ---------------------------------------------------------------------------
# PoE
# ---------------------------------------------------------------------------


def discover_sophos_sfos_poe(section: SfosHardware) -> DiscoveryResult:
    if section.poe:
        yield Service()


def check_sophos_sfos_poe(section: SfosHardware) -> CheckResult:
    enabled = [p for p in section.poe.values() if p.enabled]
    total = sum(p.usage_w or 0.0 for p in enabled)
    yield Result(
        state=State.OK,
        summary=f"{len(enabled)} of {len(section.poe)} PoE ports enabled, {total:.1f} W in use",
    )
    yield Metric("sophos_sfos_poe_power", total)

    details = []
    for port in section.poe.values():
        if not port.enabled:
            details.append(f"Port {port.label}: disabled")
            continue
        text = f"Port {port.label}: {port.usage_w or 0.0:.1f} W"
        if port.limit_w:
            text += f" of {port.limit_w:.1f} W"
        if port.voltage_v and port.current_a is not None:
            text += f" ({port.voltage_v:.1f} V, {port.current_a * 1000:.0f} mA)"
        details.append(text)
        if port.limit_w and port.usage_w is not None and port.usage_w >= port.limit_w:
            yield Result(state=State.WARN, summary=f"Port {port.label} at its power limit")
    yield Result(state=State.OK, notice="\n".join(details))


check_plugin_sophos_sfos_poe = CheckPlugin(
    name="sophos_sfos_poe",
    sections=["sophos_sfos_hardware"],
    service_name="Sophos PoE",
    discovery_function=discover_sophos_sfos_poe,
    check_function=check_sophos_sfos_poe,
)
