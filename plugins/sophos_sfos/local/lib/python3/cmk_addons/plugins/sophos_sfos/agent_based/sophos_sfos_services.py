#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Status of the SFOS system services (sfosXGServiceStatus) in one service.

Service:
  * Sophos Services - every service that was running at discovery has to keep running
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from cmk.agent_based.v2 import (
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Result,
    Service,
    SimpleSNMPSection,
    State,
    StringTable,
)
from cmk_addons.plugins.sophos_sfos.lib import (
    DETECT_SFOS,
    SFOS_TREE,
    scalar_row,
    sfos_values,
    to_int,
)

# Order = OID index .3.<n>.0
SERVICE_NAMES = (
    "pop3",
    "imap4",
    "smtp",
    "ftp",
    "http",
    "antivirus",  # av
    "antispam",  # as
    "dns",
    "ha",
    "ips",
    "apache",
    "ntp",
    "tomcat",
    "sslvpn",
    "ipsec",
    "database",
    "network",
    "garner",
    "drouting",
    "sshd",
    "dgd",
)

SERVICE_STATES = {
    0: "untouched",
    1: "stopped",
    2: "initializing",
    3: "running",
    4: "exiting",
    5: "dead",
    6: "frozen",
    7: "unregistered",
}
RUNNING = 3

Section = Mapping[str, int]


def parse_sophos_sfos_services(string_table: StringTable) -> Section | None:
    row = scalar_row(
        sfos_values(string_table), "3", (f"{n}.0" for n in range(1, len(SERVICE_NAMES) + 1))
    )
    if row is None:
        return None
    parsed = {}
    for name, raw in zip(SERVICE_NAMES, row, strict=True):
        if (value := to_int(raw)) is not None:
            parsed[name] = value
    return parsed or None


snmp_section_sophos_sfos_services = SimpleSNMPSection(
    name="sophos_sfos_services",
    detect=DETECT_SFOS,
    fetch=SFOS_TREE,
    parse_function=parse_sophos_sfos_services,
)


def _state_name(value: int) -> str:
    return SERVICE_STATES.get(value, f"unknown({value})")


def discover_sophos_sfos_services(section: Section) -> DiscoveryResult:
    yield Service(
        parameters={"discovered_running": sorted(n for n, v in section.items() if v == RUNNING)}
    )


def check_sophos_sfos_services(params: Mapping[str, Any], section: Section) -> CheckResult:
    expected = set(params.get("discovered_running", [])) - set(params.get("ignore", []))
    state_not_running = State(params.get("state_not_running", State.CRIT.value))

    failed = []
    for name in sorted(expected):
        value = section.get(name)
        if value == RUNNING:
            continue
        failed.append(f"{name}: {_state_name(value) if value is not None else 'missing'}")
    if failed:
        yield Result(
            state=state_not_running,
            summary=f"Not running: {', '.join(failed)}",
        )

    running = sum(1 for v in section.values() if v == RUNNING)
    yield Result(state=State.OK, summary=f"{running} of {len(section)} services running")

    others = [
        f"{name}: {_state_name(value)}"
        for name, value in sorted(section.items())
        if value != RUNNING and name not in expected
    ]
    if others:
        yield Result(
            state=State.OK,
            notice=f"Not running (not monitored): {', '.join(others)}",
        )
    yield Result(
        state=State.OK,
        notice="\n".join(f"{name}: {_state_name(value)}" for name, value in section.items()),
    )


check_plugin_sophos_sfos_services = CheckPlugin(
    name="sophos_sfos_services",
    service_name="Sophos Services",
    discovery_function=discover_sophos_sfos_services,
    check_function=check_sophos_sfos_services,
    check_default_parameters={"state_not_running": State.CRIT.value, "ignore": []},
    check_ruleset_name="sophos_sfos_services",
)
