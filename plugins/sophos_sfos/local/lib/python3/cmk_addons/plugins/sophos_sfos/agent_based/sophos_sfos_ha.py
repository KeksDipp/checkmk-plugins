#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""High availability (cluster) status of Sophos Firewall OS.

Service:
  * Sophos HA - HA state of both nodes, active node, failover detection

The device serial number (AppKey) and HA role found at discovery are stored in the service
parameters. If either changes, a failover has happened; the service reports it with a
configurable state until the service is rediscovered.
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
)
from cmk_addons.plugins.sophos_sfos.lib import (
    DETECT_SFOS,
    SFOS_TREE,
    scalar_row,
    sfos_values,
    to_int,
)

HA_ENABLED = 1

HA_STATES = {
    0: "not applicable",
    1: "auxiliary",
    2: "standalone",
    3: "primary",
    4: "faulty",
    5: "ready",
}
PRIMARY, AUXILIARY, FAULTY, READY = 3, 1, 4, 5

LOAD_BALANCING = {0: "not applicable", 1: "off", 2: "on"}


@dataclass(frozen=True)
class SfosHA:
    status: int | None
    own_appkey: str
    peer_appkey: str
    own_state: int | None
    peer_state: int | None
    mode: str
    load_balancing: int | None
    ha_port: str
    own_ha_ip: str
    peer_ha_ip: str
    aux_admin_port: str
    aux_admin_ip: str


_HA_OIDS = (
    "1.0",  # sfosHAStatus
    "2.0",  # sfosDeviceCurrentAppKey
    "3.0",  # sfosDevicePeerAppKey
    "4.0",  # sfosDeviceCurrentHAState
    "5.0",  # sfosDevicePeerHAState
    "6.0",  # sfosDeviceHAConfigMode
    "7.0",  # sfosDeviceLoadBalancing
    "8.0",  # sfosDeviceHAPort
    "9.0",  # sfosDeviceHACurrentIP
    "10.0",  # sfosDeviceHAPeerIP
    "11.1.0",  # sfosDeviceAuxAdminPort
    "11.2.0",  # sfosDeviceHAAuxAdminIP
)


def parse_sophos_sfos_ha(string_table: StringTable) -> SfosHA | None:
    if (row := scalar_row(sfos_values(string_table), "4", _HA_OIDS)) is None:
        return None
    return SfosHA(
        status=to_int(row[0]),
        own_appkey=row[1].strip(),
        peer_appkey=row[2].strip(),
        own_state=to_int(row[3]),
        peer_state=to_int(row[4]),
        mode=row[5].strip(),
        load_balancing=to_int(row[6]),
        ha_port=row[7].strip(),
        own_ha_ip=row[8].strip(),
        peer_ha_ip=row[9].strip(),
        aux_admin_port=row[10].strip(),
        aux_admin_ip=row[11].strip(),
    )


snmp_section_sophos_sfos_ha = SimpleSNMPSection(
    name="sophos_sfos_ha",
    detect=DETECT_SFOS,
    fetch=SFOS_TREE,
    parse_function=parse_sophos_sfos_ha,
)


def _ha_state(value: int | None) -> str:
    if value is None:
        return "unknown"
    return HA_STATES.get(value, f"unknown({value})")


def _node_state(value: int | None, params: Mapping[str, Any]) -> State:
    if value in (PRIMARY, AUXILIARY):
        return State.OK
    if value == READY:
        return State(params.get("state_ready", State.WARN.value))
    return State.CRIT


def discover_sophos_sfos_ha(section: SfosHA) -> DiscoveryResult:
    if section.status != HA_ENABLED:
        return
    yield Service(
        parameters={
            "discovered_appkey": section.own_appkey,
            "discovered_role": section.own_state,
        }
    )


def check_sophos_sfos_ha(params: Mapping[str, Any], section: SfosHA) -> CheckResult:
    if section.status != HA_ENABLED:
        yield Result(state=State.CRIT, summary="HA is disabled")
        return

    own, peer = section.own_state, section.peer_state

    # Active node: in Active-Passive the primary node carries the traffic.
    if own == PRIMARY:
        active = f"{section.own_appkey} (this device)"
    elif peer == PRIMARY:
        active = f"{section.peer_appkey} (peer)"
    else:
        active = None
    if active:
        yield Result(state=State.OK, summary=f"Active node: {active}")
    else:
        yield Result(state=State.CRIT, summary="No primary node")

    yield Result(state=_node_state(own, params), summary=f"This device: {_ha_state(own)}")
    yield Result(state=_node_state(peer, params), summary=f"Peer: {_ha_state(peer)}")
    if own == peer and own in (PRIMARY, AUXILIARY):
        yield Result(state=State.CRIT, summary=f"Both nodes report {_ha_state(own)}")

    if section.mode:
        yield Result(state=State.OK, summary=f"Mode: {section.mode}")

    state_failover = State(params.get("state_failover", State.WARN.value))
    discovered_appkey = params.get("discovered_appkey")
    discovered_role = params.get("discovered_role")
    if discovered_appkey and section.own_appkey and discovered_appkey != section.own_appkey:
        yield Result(
            state=state_failover,
            summary=(
                f"Failover: monitored address now answers from {section.own_appkey} "
                f"(was {discovered_appkey}), rediscover to acknowledge"
            ),
        )
    elif discovered_role is not None and own is not None and discovered_role != own:
        yield Result(
            state=state_failover,
            summary=(
                f"Failover: role changed from {_ha_state(discovered_role)} to {_ha_state(own)}, "
                "rediscover to acknowledge"
            ),
        )

    details = [
        f"Serial (this device): {section.own_appkey or '-'}",
        f"Serial (peer): {section.peer_appkey or '-'}",
        f"Load balancing: {LOAD_BALANCING.get(section.load_balancing or 0, '-')}",
        f"HA link: {section.ha_port or '-'} ({section.own_ha_ip or '-'} <-> "
        f"{section.peer_ha_ip or '-'})",
    ]
    if section.aux_admin_port or section.aux_admin_ip:
        details.append(
            f"Auxiliary admin access: {section.aux_admin_port or '-'} "
            f"{section.aux_admin_ip or ''}".rstrip()
        )
    yield Result(state=State.OK, notice="\n".join(details))


check_plugin_sophos_sfos_ha = CheckPlugin(
    name="sophos_sfos_ha",
    service_name="Sophos HA",
    discovery_function=discover_sophos_sfos_ha,
    check_function=check_sophos_sfos_ha,
    check_default_parameters={
        "state_failover": State.WARN.value,
        "state_ready": State.WARN.value,
    },
    check_ruleset_name="sophos_sfos_ha",
)
