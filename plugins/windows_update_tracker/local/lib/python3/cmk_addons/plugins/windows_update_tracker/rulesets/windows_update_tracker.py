#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Rulesets for windows_update_tracker (check parameters + agent bakery)."""

from cmk.rulesets.v1 import Help, Label, Message, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    DefaultValue,
    DictElement,
    Dictionary,
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
    ("security", "Security Updates"),
    ("critical", "Critical Updates"),
    ("definition", "Definition Updates (e.g. Microsoft Defender)"),
    ("update_rollup", "Update Rollups"),
    ("update", "Updates"),
    ("feature_pack", "Feature Packs"),
    ("service_pack", "Service Packs"),
    ("upgrade", "Upgrades (feature updates)"),
    ("driver", "Drivers"),
    ("tool", "Tools"),
    ("other", "Other / unknown"),
]

_SEVERITIES = [
    ("critical", "Critical"),
    ("important", "Important"),
    ("moderate", "Moderate"),
    ("low", "Low"),
    ("unspecified", "Not specified"),
]


def _classification_choice(title: str, help_text: str, prefill: list[str]) -> MultipleChoice:
    return MultipleChoice(
        title=Title(title),
        help_text=Help(help_text) if help_text else None,
        elements=[MultipleChoiceElement(name=n, title=Title(t)) for n, t in _CLASSIFICATIONS],
        prefill=DefaultValue(prefill),
    )


def _filter_elements() -> dict[str, DictElement]:
    return {
        "ignore_defender": DictElement(
            parameter_form=BooleanChoice(
                title=Title("Microsoft Defender updates"),
                label=Label("Ignore Defender updates (KB2267602, KB4052623)"),
                prefill=DefaultValue(True),
            ),
        ),
        "ignore_msrt": DictElement(
            parameter_form=BooleanChoice(
                title=Title("Malicious Software Removal Tool"),
                label=Label("Ignore MSRT (KB890830)"),
                prefill=DefaultValue(True),
            ),
        ),
        "ignore_optional": DictElement(
            parameter_form=BooleanChoice(
                title=Title("Optional updates"),
                label=Label("Ignore optional updates (not auto-selected by Windows Update)"),
                help_text=Help(
                    "Optional updates (e.g. most drivers) are only installed when selected "
                    "manually under Windows Update > Advanced options > Optional updates."
                ),
                prefill=DefaultValue(True),
            ),
        ),
        "ignore_title_regexes": DictElement(
            parameter_form=List(
                title=Title("Ignore updates by title or KB (regex)"),
                help_text=Help("Not case-sensitive."),
                element_template=RegularExpression(predefined_help_text=MatchingScope.INFIX),
                add_element_label=Label("Add pattern"),
            ),
        ),
    }


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
            "First seen: since the update showed up on this host. "
            "Published: since Microsoft released it."
        ),
        elements=[
            SingleChoiceElement(name="first_seen", title=Title("First seen on this host")),
            SingleChoiceElement(name="published", title=Title("Published by Microsoft")),
        ],
        prefill=DefaultValue("first_seen"),
    )


def _age_rule() -> Dictionary:
    return Dictionary(
        title=Title("Age rule"),
        help_text=Help("All selected criteria must match. No criteria = matches every update."),
        elements={
            "name": DictElement(
                parameter_form=String(
                    title=Title("Name"),
                    custom_validate=(validators.LengthInRange(min_value=1),),
                ),
                required=True,
            ),
            "classifications": DictElement(
                parameter_form=_classification_choice(
                    "Classification is one of",
                    "",
                    ["security", "critical"],
                ),
            ),
            "severities": DictElement(
                parameter_form=MultipleChoice(
                    title=Title("MSRC severity is one of"),
                    elements=[
                        MultipleChoiceElement(name=n, title=Title(t)) for n, t in _SEVERITIES
                    ],
                    prefill=DefaultValue(["critical"]),
                ),
            ),
            "title_regex": DictElement(
                parameter_form=RegularExpression(
                    title=Title("Title matches (regex)"),
                    predefined_help_text=MatchingScope.INFIX,
                ),
            ),
            "kbs": DictElement(
                parameter_form=List(
                    title=Title("KB number is one of"),
                    element_template=String(
                        label=Label("KB"),
                        custom_validate=(
                            validators.MatchRegex(
                                regex=r"^(KB)?\d{5,8}$",
                                error_msg=Message("Enter a KB number like KB5034441"),
                            ),
                        ),
                    ),
                    add_element_label=Label("Add KB number"),
                ),
            ),
            "age_basis": DictElement(parameter_form=_age_basis(), required=True),
            "levels": DictElement(
                parameter_form=_age_levels("Max. age", 7, 14),
                required=True,
            ),
        },
    )


# ---------------------------------------------------------------------------
# Pending updates
# ---------------------------------------------------------------------------


def _form_pending() -> Dictionary:
    return Dictionary(
        title=Title("Windows Updates pending"),
        elements={
            "age_rules": DictElement(
                parameter_form=List(
                    title=Title("Age rules"),
                    help_text=Help(
                        "Own age limits for certain updates. Checked top to bottom, the first "
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
            "ignore_classifications": DictElement(
                parameter_form=_classification_choice(
                    "Ignore these classifications",
                    "Ignored updates are only listed in the details, they never alert.",
                    ["definition"],
                ),
            ),
            **_filter_elements(),
            "levels_count": DictElement(
                parameter_form=SimpleLevels[int](
                    title=Title("Max. number of pending updates"),
                    form_spec_template=Integer(),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue((5, 10)),
                ),
            ),
            "search_age": DictElement(
                parameter_form=_age_levels("Max. age of the last successful search", 2, 7),
            ),
            "search_error_state": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if the update search fails"),
                    prefill=DefaultValue(ServiceState.WARN),
                ),
            ),
        },
    )


rule_spec_windows_update_tracker_pending = CheckParameters(
    name="windows_update_tracker_pending",
    title=Title("Windows Updates pending (Windows Update Tracker)"),
    topic=Topic.WINDOWS,
    parameter_form=_form_pending,
    condition=HostCondition(),
)


# ---------------------------------------------------------------------------
# Pending reboot
# ---------------------------------------------------------------------------


def _form_reboot() -> Dictionary:
    return Dictionary(
        title=Title("Windows Update reboot"),
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
        },
    )


rule_spec_windows_update_tracker_reboot = CheckParameters(
    name="windows_update_tracker_reboot",
    title=Title("Windows Update reboot (Windows Update Tracker)"),
    topic=Topic.WINDOWS,
    parameter_form=_form_reboot,
    condition=HostCondition(),
)


# ---------------------------------------------------------------------------
# Failed installations
# ---------------------------------------------------------------------------


def _form_failures() -> Dictionary:
    return Dictionary(
        title=Title("Windows Update failures"),
        elements={
            "state": DictElement(
                parameter_form=ServiceState(
                    title=Title("State if an update failed"),
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
                    title=Title("Installed later"),
                    label=Label("Ignore if the update was installed successfully later"),
                    prefill=DefaultValue(True),
                ),
            ),
            "ignore_if_not_pending": DictElement(
                parameter_form=BooleanChoice(
                    title=Title("Replaced"),
                    label=Label("Ignore if the update is no longer offered (e.g. replaced)"),
                    prefill=DefaultValue(True),
                ),
            ),
        },
    )


rule_spec_windows_update_tracker_failures = CheckParameters(
    name="windows_update_tracker_failures",
    title=Title("Windows Update failures (Windows Update Tracker)"),
    topic=Topic.WINDOWS,
    parameter_form=_form_failures,
    condition=HostCondition(),
)


# ---------------------------------------------------------------------------
# Agent Bakery (commercial editions)
# ---------------------------------------------------------------------------


def _form_agent_config() -> Dictionary:
    return Dictionary(
        title=Title("Windows Update Tracker agent plugin"),
        help_text=Help("Deploys windows_update_tracker.ps1. It always runs in the background."),
        elements={
            "deploy": DictElement(
                parameter_form=BooleanChoice(
                    label=Label("Deploy the Windows Update Tracker plugin"),
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
            "timeout": DictElement(
                parameter_form=Integer(
                    title=Title("Timeout"),
                    label=Label("seconds"),
                    prefill=DefaultValue(600),
                    custom_validate=(validators.NumberInRange(min_value=60, max_value=3600),),
                ),
                required=True,
            ),
        },
    )


rule_spec_windows_update_tracker_bakery = AgentConfig(
    name="windows_update_tracker",
    title=Title("Windows Update Tracker (Windows)"),
    topic=Topic.WINDOWS,
    parameter_form=_form_agent_config,
)
