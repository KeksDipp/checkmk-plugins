#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""IPsec VPN connections of Sophos Firewall OS (sfosIPSecVpnTunnelTable).

Service:
  * Sophos IPsec <connection> - connection status, number of active tunnels (child SAs)

A connection that was deactivated by the administrator is reported separately from a
connection that is activated but down. Throughput is not part of the table: for route-based
VPNs (xfrm interfaces) use the interface check, policy-based VPNs have no counters via SNMP.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
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
    check_levels,
)
from cmk_addons.plugins.sophos_sfos.lib import (
    DETECT_SFOS,
    SFOS_TREE,
    clean_text,
    sfos_values,
    table_rows,
    to_int,
)

CONN_STATES = {0: "inactive", 1: "active", 2: "partially active"}
CONN_INACTIVE, CONN_ACTIVE, CONN_PARTIAL = 0, 1, 2
ACTIVATED = 1

CONN_TYPES = {1: "host-to-host", 2: "site-to-site", 3: "tunnel interface (route-based)"}


@dataclass(frozen=True)
class IPsecConnection:
    description: str
    policy: str
    mode: str
    conn_type: int | None
    local_gateway: str
    active_tunnels: int | None
    status: int | None
    activated: int | None


Section = Mapping[str, IPsecConnection]


# sfosIPSecVpnTunnelEntry columns
_IPSEC_COLUMNS = (
    "2",  # sfosIPSecVpnConnName
    "3",  # sfosIPSecVpnConnDes
    "4",  # sfosIPSecVpnPolicyUsed
    "5",  # sfosIPSecVpnConnMode
    "6",  # sfosIPSecVpnConnType
    "7",  # sfosIPSecVpnLocalgwPort
    "8",  # sfosIPSecVpnActiveTunnel
    "9",  # sfosIPSecVpnConnStatus
    "10",  # sfosIPSecVpnActivated
)


def parse_sophos_sfos_ipsec(string_table: StringTable) -> Section:
    parsed = {}
    rows = table_rows(sfos_values(string_table), "6.1.1.1.1", _IPSEC_COLUMNS)
    for _index, name, descr, policy, mode, ctype, gw, tunnels, status, activated in rows:
        if not (name := name.strip()):
            continue
        parsed[name] = IPsecConnection(
            description=clean_text(descr),
            policy=policy.strip(),
            mode=mode.strip(),
            conn_type=to_int(ctype),
            local_gateway=gw.strip(),
            active_tunnels=to_int(tunnels),
            status=to_int(status),
            activated=to_int(activated),
        )
    return parsed


snmp_section_sophos_sfos_ipsec = SimpleSNMPSection(
    name="sophos_sfos_ipsec",
    detect=DETECT_SFOS,
    fetch=SFOS_TREE,
    parse_function=parse_sophos_sfos_ipsec,
)


def discover_sophos_sfos_ipsec(section: Section) -> DiscoveryResult:
    for name in section:
        yield Service(item=name)


def check_sophos_sfos_ipsec(item: str, params: Mapping[str, Any], section: Section) -> CheckResult:
    if (conn := section.get(item)) is None:
        return

    if conn.activated is not None and conn.activated != ACTIVATED:
        yield Result(
            state=State(params.get("state_deactivated", State.OK.value)),
            summary="Deactivated by administrator",
        )
    elif conn.status == CONN_ACTIVE:
        yield Result(state=State.OK, summary="Connected")
    elif conn.status == CONN_PARTIAL:
        yield Result(
            state=State(params.get("state_partial", State.WARN.value)),
            summary="Partially connected (not all tunnels up)",
        )
    else:
        status = CONN_STATES.get(conn.status, "unknown") if conn.status is not None else "unknown"
        yield Result(
            state=State(params.get("state_down", State.CRIT.value)),
            summary=f"Not connected (status: {status})",
        )

    if conn.active_tunnels is not None:
        levels = params.get("levels_tunnels_lower")
        if conn.activated is not None and conn.activated != ACTIVATED:
            levels = None
        yield from check_levels(
            conn.active_tunnels,
            levels_lower=levels,
            metric_name="sophos_sfos_ipsec_active_tunnels",
            render_func=lambda v: str(int(v)),
            label="Active tunnels",
        )

    details = []
    if conn.description:
        details.append(f"Description: {conn.description}")
    if conn.conn_type is not None:
        details.append(f"Type: {CONN_TYPES.get(conn.conn_type, f'unknown({conn.conn_type})')}")
    if conn.mode:
        details.append(f"Mode: {conn.mode}")
    if conn.policy:
        details.append(f"Policy: {conn.policy}")
    if conn.local_gateway:
        details.append(f"Local gateway: {conn.local_gateway}")
    if details:
        yield Result(state=State.OK, notice="\n".join(details))


check_plugin_sophos_sfos_ipsec = CheckPlugin(
    name="sophos_sfos_ipsec",
    service_name="Sophos IPsec %s",
    discovery_function=discover_sophos_sfos_ipsec,
    check_function=check_sophos_sfos_ipsec,
    check_default_parameters={
        "state_deactivated": State.OK.value,
        "state_partial": State.WARN.value,
        "state_down": State.CRIT.value,
        "levels_tunnels_lower": ("no_levels", None),
    },
    check_ruleset_name="sophos_sfos_ipsec",
)
