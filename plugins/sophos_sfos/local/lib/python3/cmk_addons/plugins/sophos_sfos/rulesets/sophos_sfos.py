#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Check parameter rulesets for sophos_sfos."""

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    Integer,
    LevelDirection,
    MultipleChoice,
    MultipleChoiceElement,
    Percentage,
    ServiceState,
    SimpleLevels,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, HostCondition, Topic

DAY = 86400.0

# Keep in sync with agent_based/sophos_sfos_services.py
_SERVICES = (
    ("pop3", "POP3 proxy"),
    ("imap4", "IMAP4 proxy"),
    ("smtp", "SMTP proxy / mail"),
    ("ftp", "FTP proxy"),
    ("http", "Web proxy (HTTP)"),
    ("antivirus", "Anti-virus (av)"),
    ("antispam", "Anti-spam (as)"),
    ("dns", "DNS"),
    ("ha", "High availability"),
    ("ips", "IPS"),
    ("apache", "Web admin (Apache)"),
    ("ntp", "NTP"),
    ("tomcat", "Tomcat"),
    ("sslvpn", "SSL VPN"),
    ("ipsec", "IPsec VPN"),
    ("database", "Database"),
    ("network", "Network"),
    ("garner", "Logging (garner)"),
    ("drouting", "Dynamic routing"),
    ("sshd", "SSH daemon"),
    ("dgd", "Gateway monitoring (dgd)"),
)


# Keep in sync with LICENSE_KEYS in agent_based/sophos_sfos_licenses.py
_LICENSES = (
    ("base_firewall", "Base Firewall"),
    ("network_protection", "Network Protection"),
    ("web_protection", "Web Protection"),
    ("email_protection", "Email Protection"),
    ("webserver_protection", "Web Server Protection"),
    ("zeroday_protection", "Zero-Day Protection"),
    ("enhanced_support", "Enhanced Support"),
    ("enhanced_plus_support", "Enhanced Plus Support"),
    ("central_orchestration", "Central Orchestration"),
)


def _percent_levels(title: str, warn: float, crit: float) -> DictElement:
    return DictElement(
        parameter_form=SimpleLevels(
            title=Title(title),
            form_spec_template=Percentage(),
            level_direction=LevelDirection.UPPER,
            prefill_fixed_levels=DefaultValue((warn, crit)),
        ),
    )


def _state(title: str, help_text: str, default: ServiceState) -> DictElement:
    return DictElement(
        parameter_form=ServiceState(
            title=Title(title),
            help_text=Help(help_text),
            prefill=DefaultValue(default),
        ),
    )


# ---------------------------------------------------------------------------
# Memory / Disk
# ---------------------------------------------------------------------------


def _form_memory() -> Dictionary:
    return Dictionary(
        help_text=Help(
            "Memory usage as reported by Sophos Firewall OS (sfosMemoryPercentUsage). "
            "Unlike HOST-RESOURCES-MIB this value does not count cache and buffers."
        ),
        elements={
            "levels_mem": _percent_levels("Upper levels for RAM usage", 80.0, 90.0),
            "levels_swap": _percent_levels("Upper levels for swap usage", 50.0, 75.0),
        },
    )


rule_spec_sophos_sfos_memory = CheckParameters(
    name="sophos_sfos_memory",
    title=Title("Sophos Firewall memory"),
    topic=Topic.OPERATING_SYSTEM,
    parameter_form=_form_memory,
    condition=HostCondition(),
)


def _form_disk() -> Dictionary:
    return Dictionary(
        elements={"levels": _percent_levels("Upper levels for disk usage", 80.0, 90.0)},
    )


rule_spec_sophos_sfos_disk = CheckParameters(
    name="sophos_sfos_disk",
    title=Title("Sophos Firewall disk usage"),
    topic=Topic.STORAGE,
    parameter_form=_form_disk,
    condition=HostCondition(),
)


# ---------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------


def _form_services() -> Dictionary:
    return Dictionary(
        help_text=Help(
            "Every SFOS service that was running at service discovery has to keep running. "
            "Services that were not running at discovery are only listed. Rediscover the "
            "service after enabling or disabling features on the firewall."
        ),
        elements={
            "state_not_running": _state(
                "State if a monitored service is not running",
                "Applies to services that were running at discovery and are not ignored.",
                ServiceState.CRIT,
            ),
            "ignore": DictElement(
                parameter_form=MultipleChoice(
                    title=Title("Ignore these services"),
                    elements=[
                        MultipleChoiceElement(
                            name=name,
                            title=Title(title),
                        )
                        for name, title in _SERVICES
                    ],
                ),
            ),
        },
    )


rule_spec_sophos_sfos_services = CheckParameters(
    name="sophos_sfos_services",
    title=Title("Sophos Firewall services"),
    topic=Topic.APPLICATIONS,
    parameter_form=_form_services,
    condition=HostCondition(),
)


# ---------------------------------------------------------------------------
# HA
# ---------------------------------------------------------------------------


def _form_ha() -> Dictionary:
    return Dictionary(
        help_text=Help(
            "The serial number and HA role of the monitored address are stored at discovery. "
            "If they change, a failover has happened. Rediscover the service to acknowledge "
            "the new active node."
        ),
        elements={
            "state_failover": _state(
                "State after a failover",
                "State while the active node differs from the one found at discovery.",
                ServiceState.WARN,
            ),
            "state_ready": _state(
                "State if a node reports 'ready'",
                "'ready' is a transitional state, e.g. while a node joins the cluster. "
                "'faulty', 'standalone' and 'not applicable' are always critical.",
                ServiceState.WARN,
            ),
        },
    )


rule_spec_sophos_sfos_ha = CheckParameters(
    name="sophos_sfos_ha",
    title=Title("Sophos Firewall high availability"),
    topic=Topic.NETWORKING,
    parameter_form=_form_ha,
    condition=HostCondition(),
)


# ---------------------------------------------------------------------------
# Licenses
# ---------------------------------------------------------------------------


def _form_licenses() -> Dictionary:
    return Dictionary(
        elements={
            "levels_remaining": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Lower levels for the time until expiry"),
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[TimeMagnitude.DAY],
                    ),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=DefaultValue((30 * DAY, 14 * DAY)),
                ),
            ),
            "state_expired": _state(
                "State of an expired license",
                "Also used if the expiry date has passed while the status is still valid.",
                ServiceState.CRIT,
            ),
            "state_evaluating": _state(
                "State of an evaluation license",
                "The expiry levels apply in addition.",
                ServiceState.OK,
            ),
            "state_other": _state(
                "State if the license is no longer subscribed",
                "Status 'not subscribed', 'deactivated' or 'none' on a module that was "
                "subscribed at discovery.",
                ServiceState.WARN,
            ),
            "ignore": DictElement(
                parameter_form=MultipleChoice(
                    title=Title("Ignore these license modules"),
                    help_text=Help(
                        "Ignored modules are only listed in the details, e.g. a module you "
                        "let expire on purpose."
                    ),
                    elements=[
                        MultipleChoiceElement(name=name, title=Title(title))
                        for name, title in _LICENSES
                    ],
                ),
            ),
        },
    )


rule_spec_sophos_sfos_licenses = CheckParameters(
    name="sophos_sfos_licenses",
    title=Title("Sophos Firewall licenses"),
    topic=Topic.APPLICATIONS,
    parameter_form=_form_licenses,
    condition=HostCondition(),
)


# ---------------------------------------------------------------------------
# IPsec
# ---------------------------------------------------------------------------


def _form_ipsec() -> Dictionary:
    return Dictionary(
        elements={
            "state_down": _state(
                "State if an activated connection is down",
                "Connection status 'inactive' while the connection is activated.",
                ServiceState.CRIT,
            ),
            "state_partial": _state(
                "State if a connection is partially active",
                "Not all tunnels (child SAs) of the connection are up.",
                ServiceState.WARN,
            ),
            "state_deactivated": _state(
                "State if a connection is deactivated",
                "The administrator switched the connection off.",
                ServiceState.OK,
            ),
            "levels_tunnels_lower": DictElement(
                parameter_form=SimpleLevels(
                    title=Title("Lower levels for active tunnels"),
                    help_text=Help(
                        "Number of active tunnels (child SAs) of the connection, e.g. one per "
                        "local/remote network pair. Not applied to deactivated connections."
                    ),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=DefaultValue((1, 1)),
                ),
            ),
        },
    )


rule_spec_sophos_sfos_ipsec = CheckParameters(
    name="sophos_sfos_ipsec",
    title=Title("Sophos Firewall IPsec connections"),
    topic=Topic.NETWORKING,
    parameter_form=_form_ipsec,
    condition=HostAndItemCondition(item_title=Title("Connection name")),
)
