#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Rulesets for linux_update_tracker (check parameters + agent bakery)."""

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    DictElement,
    Dictionary,
    FixedValue,
    Integer,
    LevelDirection,
    List,
    MatchingScope,
    MultipleChoice,
    MultipleChoiceElement,
    RegularExpression,
    ServiceState,
    SimpleLevels,
    SingleChoice,
    SingleChoiceElement,
    String,
    TimeMagnitude,
    TimeSpan,
    validators,
)
from cmk.rulesets.v1.rule_specs import AgentConfig, CheckParameters, HostCondition, Topic

DAY = 86400.0

_CLASSIFICATIONS = [
    ("security", "Security updates"),
    ("bugfix", "Bugfix updates"),
    ("enhancement", "Enhancements / new packages"),
    ("other", "Other / unknown (APT: everything outside the security repository)"),
]

_SEVERITIES = [
    ("critical", "Critical"),
    ("important", "Important"),
    ("moderate", "Moderate"),
    ("low", "Low"),
    ("unspecified", "Not specified"),
]

_FILTERS = [
    ("held", "Held packages (apt-mark hold)"),
    ("phased", "Phased updates (Ubuntu, not offered to this host yet)"),
] + [(f"class_{n}", f"Classification: {t}") for n, t in _CLASSIFICATIONS]


def _regex_list(title: str, help_text: str) -> List:
    return List(
        title=Title(title),
        help_text=Help(help_text),
        element_template=RegularExpression(predefined_help_text=MatchingScope.INFIX),
        add_element_label=Label("Add pattern"),
    )


def _age_levels(title: str, warn_days: float, crit_days: float) -> SimpleLevels[float]:
    return SimpleLevels[float](
        title=Title(title),
        form_spec_template=TimeSpan(
            displayed_magnitudes=[TimeMagnitude.DAY, TimeMagnitude.HOUR],
        ),
        level_direction=LevelDirection.UPPER,
        prefill_fixed_levels=DefaultValue((warn_days * DAY, crit_days * DAY)),
    )


def _age_basis() -> SingleChoice:
    return SingleChoice(
        title=Title("Measure age from"),
        help_text=Help(
            "Outdated since: since the package first had an update on this host, newer versions "
            "do not reset it. This version since: since the current candidate version showed up. "
            "Published: release date of the advisory or build date of the package (DNF, Zypper); "
            "falls back to 'outdated since' if there is no date (APT, YUM)."
        ),
        elements=[
            SingleChoiceElement(name="first_seen", title=Title("Package outdated since")),
            SingleChoiceElement(name="version_seen", title=Title("Candidate version seen since")),
            SingleChoiceElement(name="published", title=Title("Published by the distribution")),
        ],
        prefill=DefaultValue("first_seen"),
    )


def _age_rule() -> Dictionary:
    return Dictionary(
        title=Title("Age rule"),
        help_text=Help("All selected criteria must match. No criteria = matches every package."),
        elements={
            "name": DictElement(
                parameter_form=String(
                    title=Title("Name"),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
                required=True,
            ),
            "classifications": DictElement(
                parameter_form=MultipleChoice(
                    title=Title("Classification is one of"),
                    elements=[
                        MultipleChoiceElement(name=n, title=Title(t)) for n, t in _CLASSIFICATIONS
                    ],
                    prefill=DefaultValue(["security"]),
                ),
            ),
            "severities": DictElement(
                parameter_form=MultipleChoice(
                    title=Title("Advisory severity is one of"),
                    help_text=Help("Only DNF, YUM and Zypper know severities."),
                    elements=[
                        MultipleChoiceElement(name=n, title=Title(t)) for n, t in _SEVERITIES
                    ],
                    prefill=DefaultValue(["critical", "important"]),
                ),
            ),
            "package_regex": DictElement(
                parameter_form=RegularExpression(
                    title=Title("Package name matches (regex)"),
                    predefined_help_text=MatchingScope.INFIX,
                ),
            ),
            "repo_regex": DictElement(
                parameter_form=RegularExpression(
                    title=Title("Repository matches (regex)"),
                    help_text=Help(
                        "APT: suites like 'trixie-security', DNF/YUM: repo id, Zypper: alias."
                    ),
                    predefined_help_text=MatchingScope.INFIX,
                ),
            ),
            "age_basis": DictElement(parameter_form=_age_basis(), required=True),
            "levels": DictElement(
                parameter_form=_age_levels("Max. age", 1, 3),
                required=True,
            ),
        },
    )


# ---------------------------------------------------------------------------
# Pending updates
# ---------------------------------------------------------------------------


def _form_pending() -> Dictionary:
    return Dictionary(
        title=Title("Linux Updates pending"),
        elements={
            "age_rules": DictElement(
                parameter_form=List(
                    title=Title("Age rules"),
                    help_text=Help(
                        "Own age limits for certain packages. Checked top to bottom, the first "
                        "matching rule wins. Everything else uses the default rule."
                    ),
                    element_template=_age_rule(),
                    add_element_label=Label("Add age rule"),
                ),
            ),
            "default_rule": DictElement(
                parameter_form=Dictionary(
                    title=Title("Default rule"),
                    elements={
                        "age_basis": DictElement(parameter_form=_age_basis(), required=True),
                        "levels": DictElement(
                            parameter_form=_age_levels("Max. age", 2, 7),
                            required=True,
                        ),
                    },
                ),
            ),
            "filters": DictElement(
                parameter_form=MultipleChoice(
                    title=Title("Filtered updates"),
                    help_text=Help(
                        "Selected updates are not counted and never change the state. They are "
                        "listed in the details under 'Filtered updates' with the reason."
                    ),
                    elements=[MultipleChoiceElement(name=n, title=Title(t)) for n, t in _FILTERS],
                    prefill=DefaultValue([]),
                ),
            ),
            "ignore_package_regexes": DictElement(
                parameter_form=_regex_list(
                    "Filtered updates by package name (regex)", "Not case-sensitive."
                ),
            ),
            "ignore_repo_regexes": DictElement(
                parameter_form=_regex_list(
                    "Filtered updates by repository (regex)",
                    "Not case-sensitive. APT: suites like 'trixie-backports', "
                    "DNF/YUM: repo id, Zypper: alias.",
                ),
            ),
            "levels_count": DictElement(
                parameter_form=SimpleLevels[int](
                    title=Title("Max. number of pending updates"),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue((20, 50)),
                ),
            ),
            "search_age": DictElement(
                parameter_form=_age_levels("Max. age of the last successful search", 2, 7),
            ),
            "index_age": DictElement(
                parameter_form=_age_levels(
                    "Max. age of the package index",
                    2,
                    7,
                ),
            ),
            "search_error_state": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if the update search fails"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "refresh_error_state": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if refreshing the package index fails"),
                    help_text=Help("Only when the agent plugin refreshes the index itself."),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        },
    )


rule_spec_linux_update_tracker_pending = CheckParameters(
    name="linux_update_tracker_pending",
    title=Title("Linux Updates pending (Linux Update Tracker)"),
    topic=Topic.LINUX,
    parameter_form=_form_pending,
    condition=HostCondition(),
)


# ---------------------------------------------------------------------------
# Pending reboot
# ---------------------------------------------------------------------------


def _form_reboot() -> Dictionary:
    return Dictionary(
        title=Title("Linux Update reboot"),
        elements={
            "levels": DictElement(
                parameter_form=SimpleLevels[float](
                    title=Title("Max. time a reboot may be pending"),
                    help_text=Help("'No levels' = never alert."),
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[
                            TimeMagnitude.DAY,
                            TimeMagnitude.HOUR,
                            TimeMagnitude.MINUTE,
                        ],
                    ),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue((1 * DAY, 3 * DAY)),
                ),
                required=True,
            ),
            "services_state": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if services need a restart"),
                    help_text=Help(
                        "Services still running old libraries (needrestart, "
                        "dnf needs-restarting, zypper ps)."
                    ),
                    prefill=DefaultValue(ServiceState.OK),
                ),
            ),
        },
    )


rule_spec_linux_update_tracker_reboot = CheckParameters(
    name="linux_update_tracker_reboot",
    title=Title("Linux Update reboot (Linux Update Tracker)"),
    topic=Topic.LINUX,
    parameter_form=_form_reboot,
    condition=HostCondition(),
)


# ---------------------------------------------------------------------------
# Failed transactions
# ---------------------------------------------------------------------------


def _form_failures() -> Dictionary:
    return Dictionary(
        title=Title("Linux Update failures"),
        elements={
            "state": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if a package transaction failed"),
                    help_text=Help("OK = only list failures, no alert."),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
            "lookback": DictElement(
                parameter_form=TimeSpan(
                    title=Title("Look back"),
                    help_text=Help("Max. 30 days."),
                    displayed_magnitudes=[TimeMagnitude.DAY, TimeMagnitude.HOUR],
                    prefill=DefaultValue(30 * DAY),
                    custom_validate=(validators.NumberInRange(min_value=3600, max_value=30 * DAY),),
                ),
            ),
            "ignore_if_succeeded_later": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Handled later"),
                    label=Label(
                        "Ignore if all its packages were handled by a later successful transaction"
                    ),
                    prefill=DefaultValue(True),
                ),
            ),
            "ignore_if_not_pending": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("No longer pending"),
                    label=Label("Ignore if none of its packages has a pending update"),
                    prefill=DefaultValue(True),
                ),
            ),
            "broken_state": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if packages are broken"),
                    help_text=Help(
                        "APT: half-installed or half-configured packages (dpkg). "
                        "DNF/YUM: problems reported by 'check'."
                    ),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        },
    )


rule_spec_linux_update_tracker_failures = CheckParameters(
    name="linux_update_tracker_failures",
    title=Title("Linux Update failures (Linux Update Tracker)"),
    topic=Topic.LINUX,
    parameter_form=_form_failures,
    condition=HostCondition(),
)


# ---------------------------------------------------------------------------
# Agent Bakery (commercial editions)
# ---------------------------------------------------------------------------


def _form_agent_config() -> Dictionary:
    return Dictionary(
        title=Title("Linux Update Tracker agent plugin"),
        help_text=Help(
            "Deploys the linux_update_tracker agent plugin. It runs asynchronously, the agent "
            "delivers the cached result in between."
        ),
        elements={
            "deploy": DictElement(
                parameter_form=BooleanChoice(
                    label=Label("Deploy the Linux Update Tracker plugin"),
                    prefill=DefaultValue(True),
                ),
                required=True,
            ),
            "interval": DictElement(
                parameter_form=TimeSpan(
                    title=Title("Execution interval"),
                    help_text=Help("How often to search for updates."),
                    displayed_magnitudes=[TimeMagnitude.HOUR, TimeMagnitude.MINUTE],
                    prefill=DefaultValue(4 * 3600.0),
                    custom_validate=(validators.NumberInRange(min_value=1800),),
                ),
                required=True,
            ),
            "refresh": DictElement(
                parameter_form=CascadingSingleChoice(
                    title=Title("Refresh the package index"),
                    help_text=Help(
                        "The search itself only reads the local package index. Without a refresh "
                        "the plugin only sees what another job (apt-daily, dnf-automatic, cron) "
                        "has fetched."
                    ),
                    elements=[
                        CascadingSingleChoiceElement(
                            name="auto",
                            title=Title("Only if the index is older than"),
                            parameter_form=TimeSpan(
                                displayed_magnitudes=[TimeMagnitude.DAY, TimeMagnitude.HOUR],
                                prefill=DefaultValue(12 * 3600.0),
                                custom_validate=(validators.NumberInRange(min_value=1800),),
                            ),
                        ),
                        CascadingSingleChoiceElement(
                            name="always",
                            title=Title("Always, before every search"),
                            parameter_form=FixedValue(value=None),
                        ),
                        CascadingSingleChoiceElement(
                            name="never",
                            title=Title("Never"),
                            parameter_form=FixedValue(value=None),
                        ),
                    ],
                    prefill=DefaultValue("auto"),
                ),
                required=True,
            ),
            "timeout": DictElement(
                parameter_form=Integer(
                    title=Title("Timeout per package manager call"),
                    label=Label("seconds"),
                    prefill=DefaultValue(600),
                    custom_validate=(validators.NumberInRange(min_value=60, max_value=3600),),
                ),
                required=True,
            ),
        },
    )


rule_spec_linux_update_tracker_bakery = AgentConfig(
    name="linux_update_tracker",
    title=Title("Linux Update Tracker (Linux)"),
    topic=Topic.LINUX,
    parameter_form=_form_agent_config,
)
