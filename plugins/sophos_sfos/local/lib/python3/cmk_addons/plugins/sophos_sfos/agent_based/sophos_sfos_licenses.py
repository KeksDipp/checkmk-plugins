#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Subscription/license status of Sophos Firewall OS (sfosXGLicenseDetails).

Service:
  * Sophos Licenses - all license modules in one service. Modules that are subscribed or in
    evaluation at discovery are monitored; the worst module determines the state.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
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
    render,
)
from cmk_addons.plugins.sophos_sfos.lib import (
    DETECT_SFOS,
    SFOS_TREE,
    scalar_row,
    sfos_values,
    to_int,
)

# Order = OID index .5.<n>; key = identifier used in the ruleset (keep in sync)
LICENSE_KEYS = {
    "Base Firewall": "base_firewall",
    "Network Protection": "network_protection",
    "Web Protection": "web_protection",
    "Email Protection": "email_protection",
    "Web Server Protection": "webserver_protection",
    "Zero-Day Protection": "zeroday_protection",  # sfosSandstromLic (Sandstorm)
    "Enhanced Support": "enhanced_support",
    "Enhanced Plus Support": "enhanced_plus_support",
    "Central Orchestration": "central_orchestration",
}
LICENSE_MODULES = tuple(LICENSE_KEYS)

LICENSE_STATES = {
    0: "none",
    1: "evaluating",
    2: "not subscribed",
    3: "subscribed",
    4: "expired",
    5: "deactivated",
}
EVALUATING, SUBSCRIBED, EXPIRED, DEACTIVATED = 1, 3, 4, 5

# SFOS reports perpetual licenses (e.g. Base Firewall) with an expiry date far in the future.
PERPETUAL_YEAR = 2999


@dataclass(frozen=True)
class SfosLicense:
    status: int | None
    expiry_raw: str
    expiry: float | None  # epoch, None if not parseable
    perpetual: bool


Section = Mapping[str, SfosLicense]


def _parse_date(raw: str) -> datetime | None:
    raw = " ".join(raw.split())
    for fmt in ("%b %d %Y", "%d %b %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    return None


def parse_sophos_sfos_licenses(string_table: StringTable) -> Section | None:
    row = scalar_row(
        sfos_values(string_table),
        "5",
        (f"{n}.{col}.0" for n in range(1, len(LICENSE_MODULES) + 1) for col in (1, 2)),
    )
    if row is None:
        return None
    parsed = {}
    for idx, name in enumerate(LICENSE_MODULES):
        status = to_int(row[2 * idx]) if 2 * idx < len(row) else None
        expiry_raw = row[2 * idx + 1].strip() if 2 * idx + 1 < len(row) else ""
        if status is None and not expiry_raw:
            continue
        date = _parse_date(expiry_raw)
        parsed[name] = SfosLicense(
            status=status,
            expiry_raw=expiry_raw,
            # Licenses are valid through the given day
            expiry=date.timestamp() + 86400 if date and date.year < PERPETUAL_YEAR else None,
            perpetual=bool(date and date.year >= PERPETUAL_YEAR),
        )
    return parsed or None


snmp_section_sophos_sfos_licenses = SimpleSNMPSection(
    name="sophos_sfos_licenses",
    detect=DETECT_SFOS,
    fetch=SFOS_TREE,
    parse_function=parse_sophos_sfos_licenses,
)


def _status_name(value: int | None) -> str:
    if value is None:
        return "unknown"
    return LICENSE_STATES.get(value, f"unknown({value})")


def _lower_levels_state(value: float, levels: Any) -> State:
    if not isinstance(levels, tuple) or levels[0] != "fixed":
        return State.OK
    warn, crit = levels[1]
    if value < crit:
        return State.CRIT
    if value < warn:
        return State.WARN
    return State.OK


def _evaluate(
    lic: SfosLicense, params: Mapping[str, Any], now: float
) -> tuple[State, str, float | None]:
    """State, text and remaining seconds (None if not applicable) of one license module."""
    status = lic.status
    if status == SUBSCRIBED:
        state, text = State.OK, "subscribed"
    elif status == EVALUATING:
        state, text = State(params.get("state_evaluating", State.OK.value)), "evaluation"
    elif status == EXPIRED:
        state, text = State(params.get("state_expired", State.CRIT.value)), "expired"
    else:
        state = State(params.get("state_other", State.WARN.value))
        text = f"status {_status_name(status)}"

    if lic.perpetual:
        return state, f"{text}, no expiry date", None
    if lic.expiry is None:
        return state, f"{text}, expiry date {lic.expiry_raw}" if lic.expiry_raw else text, None

    remaining = lic.expiry - now
    expiry_date = render.date(lic.expiry - 86400)
    if remaining <= 0:
        if status != EXPIRED:
            # Status still claims a valid subscription, but the date has passed
            state = State.worst(state, State(params.get("state_expired", State.CRIT.value)))
            return state, f"{text}, expiry date {expiry_date} has passed", None
        return state, f"{text} on {expiry_date}", None

    state = State.worst(state, _lower_levels_state(remaining, params.get("levels_remaining")))
    return state, f"{text}, expires on {expiry_date} (in {render.timespan(remaining)})", remaining


def discover_sophos_sfos_licenses(section: Section) -> DiscoveryResult:
    modules = [name for name, lic in section.items() if lic.status in (SUBSCRIBED, EVALUATING)]
    if modules:
        yield Service(parameters={"discovered_modules": modules})


def check_sophos_sfos_licenses(params: Mapping[str, Any], section: Section) -> CheckResult:
    ignored = set(params.get("ignore", []))
    monitored = [
        name
        for name in params.get("discovered_modules", [])
        if LICENSE_KEYS.get(name, name) not in ignored
    ]
    now = time.time()

    problems = 0
    next_expiry: tuple[float, str] | None = None
    details = []
    for name in monitored:
        if (lic := section.get(name)) is None:
            state = State(params.get("state_other", State.WARN.value))
            yield Result(state=state, summary=f"{name}: not reported anymore")
            problems += 1
            continue
        state, text, remaining = _evaluate(lic, params, now)
        if state is State.OK:
            details.append(f"{name}: {text}")
        else:
            yield Result(state=state, summary=f"{name}: {text}")
            problems += 1
        if remaining is not None and (next_expiry is None or remaining < next_expiry[0]):
            next_expiry = (remaining, name)

    yield Result(
        state=State.OK,
        summary=f"{len(monitored) - problems} of {len(monitored)} licenses OK",
    )
    if next_expiry is not None:
        remaining, name = next_expiry
        yield Result(
            state=State.OK,
            summary=f"next expiry: {name} in {render.timespan(remaining)}",
        )
        yield Metric("sophos_sfos_license_remaining", remaining)

    for name, lic in section.items():
        if name not in monitored:
            reason = "ignored" if LICENSE_KEYS.get(name, name) in ignored else "not monitored"
            details.append(f"{name}: {_status_name(lic.status)} ({reason})")
    if details:
        yield Result(state=State.OK, notice="\n".join(details))


check_plugin_sophos_sfos_licenses = CheckPlugin(
    name="sophos_sfos_licenses",
    service_name="Sophos Licenses",
    discovery_function=discover_sophos_sfos_licenses,
    check_function=check_sophos_sfos_licenses,
    check_default_parameters={
        "levels_remaining": ("fixed", (30 * 86400.0, 14 * 86400.0)),
        "state_expired": State.CRIT.value,
        "state_evaluating": State.OK.value,
        "state_other": State.WARN.value,
        "ignore": [],
    },
    check_ruleset_name="sophos_sfos_licenses",
)
