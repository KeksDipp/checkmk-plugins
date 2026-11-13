#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Check plugins for the windows_update_tracker agent section.

Services:
  * Windows Updates pending  - per-update age thresholds, filters, search freshness
  * Windows Update reboot    - pending reboot with age thresholds
  * Windows Update failures  - failed/aborted installations in a lookback window
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
    Result,
    Service,
    State,
    StringTable,
    check_levels,
    render,
)

DAY = 86400.0

CLASSIFICATION_TITLES = {
    "security": "Security Updates",
    "critical": "Critical Updates",
    "definition": "Definition Updates",
    "driver": "Drivers",
    "feature_pack": "Feature Packs",
    "service_pack": "Service Packs",
    "tool": "Tools",
    "update_rollup": "Update Rollups",
    "update": "Updates",
    "upgrade": "Upgrades",
    "other": "Other",
}

DEFENDER_REGEXES = [
    r"Security Intelligence",  # Defender definition updates
    r"\bKB2267602\b",
    r"\bKB4052623\b",  # Defender platform update
]
MSRT_REGEXES = [r"\bKB890830\b", r"Malicious Software Removal Tool"]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Update:
    id: str
    kb: tuple[str, ...]
    title: str
    classification: str
    severity: str
    published: int | None
    first_seen: int | None
    downloaded: bool = False

    @property
    def label(self) -> str:
        return ", ".join(self.kb) if self.kb else self.title[:60]

    @property
    def display(self) -> str:
        """KB number(s) and title, or only the title for updates without KB (e.g. drivers)."""
        return f"{', '.join(self.kb)} - {self.title}" if self.kb else self.title


@dataclass(frozen=True)
class HistoryEntry:
    id: str
    kb: tuple[str, ...]
    title: str
    classification: str
    date: int
    result: str
    hresult: str


@dataclass
class Section:
    meta: Mapping[str, Any] = field(default_factory=dict)
    pending: list[Update] = field(default_factory=list)
    reboot: Mapping[str, Any] | None = None
    history: list[HistoryEntry] = field(default_factory=list)


def _int_or_none(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _kb_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, list):
        return tuple(str(v) for v in value if v)
    return ()


def parse_windows_update_tracker(string_table: StringTable) -> Section | None:
    section = Section()
    found_meta = False
    for line in string_table:
        if not line or not line[0].strip():
            continue
        try:
            data = json.loads(line[0])
        except json.JSONDecodeError:
            continue
        kind = data.get("type")
        if kind == "meta":
            section.meta = data
            found_meta = True
        elif kind == "pending":
            section.pending.append(
                Update(
                    id=str(data.get("id", "")),
                    kb=_kb_tuple(data.get("kb")),
                    title=str(data.get("title", "")),
                    classification=str(data.get("classification") or "other"),
                    severity=str(data.get("severity") or ""),
                    published=_int_or_none(data.get("published")),
                    first_seen=_int_or_none(data.get("first_seen")),
                    downloaded=bool(data.get("downloaded")),
                )
            )
        elif kind == "reboot":
            section.reboot = data
        elif kind == "history":
            date = _int_or_none(data.get("date"))
            if date is None:
                continue
            section.history.append(
                HistoryEntry(
                    id=str(data.get("id", "")),
                    kb=_kb_tuple(data.get("kb")),
                    title=str(data.get("title", "")),
                    classification=str(data.get("classification") or "other"),
                    date=date,
                    result=str(data.get("result", "")),
                    hresult=str(data.get("hresult", "")),
                )
            )
    return section if found_meta else None


agent_section_windows_update_tracker = AgentSection(
    name="windows_update_tracker",
    parse_function=parse_windows_update_tracker,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_filtered(
    classification: str,
    title: str,
    kb: Sequence[str],
    ignore_classifications: Iterable[str],
    ignore_regexes: Iterable[str],
) -> bool:
    if classification in set(ignore_classifications):
        return True
    text = " ".join([title, *kb])
    return any(re.search(rx, text, re.IGNORECASE) for rx in ignore_regexes if rx)


def _ignore_patterns(params: Mapping[str, Any]) -> list[str]:
    patterns = list(params.get("ignore_title_regexes", []))
    if params.get("ignore_defender", True):
        patterns += DEFENDER_REGEXES
    if params.get("ignore_msrt", True):
        patterns += MSRT_REGEXES
    return patterns


def _normalize_kbs(kbs: Iterable[str]) -> set[str]:
    result = set()
    for kb in kbs:
        kb = kb.strip().upper()
        if not kb:
            continue
        result.add(kb if kb.startswith("KB") else f"KB{kb}")
    return result


def _rule_matches(rule: Mapping[str, Any], update: Update) -> bool:
    if (classes := rule.get("classifications")) and update.classification not in classes:
        return False
    if (sevs := rule.get("severities")) and (update.severity or "unspecified") not in sevs:
        return False
    if (rx := rule.get("title_regex")) and not re.search(rx, update.title, re.IGNORECASE):
        return False
    if kbs := rule.get("kbs"):
        if not _normalize_kbs(kbs) & {k.upper() for k in update.kb}:
            return False
    return True


def _evaluate_age(age: float | None, levels: object) -> State:
    if age is None or not isinstance(levels, tuple) or levels[0] != "fixed":
        return State.OK
    warn, crit = levels[1]
    if age >= crit:
        return State.CRIT
    if age >= warn:
        return State.WARN
    return State.OK


_STATE_MARK = {State.OK: "", State.WARN: " (!)", State.CRIT: " (!!)", State.UNKNOWN: " (?)"}


def _fmt_age(seconds: float | None) -> str:
    if seconds is None:
        return "n/a"
    if seconds >= DAY:  # whole days are enough for update ages
        days = int(seconds // DAY)
        return f"{days} day{'s' if days != 1 else ''}"
    return render.timespan(max(seconds, 0))


# ---------------------------------------------------------------------------
# Service 1: pending updates
# ---------------------------------------------------------------------------


def discover_windows_update_tracker(section: Section) -> DiscoveryResult:
    yield Service()


def check_windows_update_tracker(params: Mapping[str, Any], section: Section) -> CheckResult:
    now = time.time()
    meta = section.meta

    # --- search status / freshness -------------------------------------------------
    if not meta.get("search_ok"):
        err = meta.get("error") or "unknown error"
        hres = meta.get("hresult") or ""
        hres = f" ({hres})" if hres and hres not in err else ""
        yield Result(
            state=State(params.get("search_error_state", 1)),
            summary=f"Windows Update search failed: {err}{hres}",
        )
    if (last_success := _int_or_none(meta.get("last_success"))) is not None:
        yield from check_levels(
            now - last_success,
            levels_upper=params.get("search_age"),
            render_func=render.timespan,
            label="Last successful search",
            notice_only=True,
        )
    else:
        yield Result(
            state=State(params.get("search_error_state", 1)),
            summary="No successful Windows Update search yet",
        )

    # --- evaluate updates ----------------------------------------------------------
    ignore_cls = params.get("ignore_classifications", ["definition"])
    ignore_rx = _ignore_patterns(params)
    age_rules = params.get("age_rules", [])
    default_rule = params.get("default_rule", {})

    active: list[tuple[Update, State, str]] = []
    filtered: list[Update] = []
    oldest_age: float | None = None

    for upd in section.pending:
        if _is_filtered(upd.classification, upd.title, upd.kb, ignore_cls, ignore_rx):
            filtered.append(upd)
            continue
        rule = next((r for r in age_rules if _rule_matches(r, upd)), default_rule)
        basis = rule.get("age_basis", "first_seen")
        seen_age = now - upd.first_seen if upd.first_seen else None
        pub_age = now - upd.published if upd.published else None
        age = seen_age if basis == "first_seen" else pub_age
        state = _evaluate_age(age, rule.get("levels"))
        if seen_age is not None:
            oldest_age = seen_age if oldest_age is None else max(oldest_age, seen_age)

        cls_title = CLASSIFICATION_TITLES.get(upd.classification, upd.classification)
        sev = f", {upd.severity.capitalize()}" if upd.severity else ""
        rule_name = rule.get("name") or ("default" if rule is default_rule else "rule")
        line = (
            f"{upd.display} ({cls_title}{sev}) - "
            f"seen {_fmt_age(seen_age)}, published {_fmt_age(pub_age)} ago "
            f"[{'first seen' if basis == 'first_seen' else 'published'}, {rule_name}]"
            f"{_STATE_MARK[state]}"
        )
        active.append((upd, state, line))

    worst = State.worst(*(s for _u, s, _l in active)) if active else State.OK
    count = len(active)

    summary = f"{count} pending update{'s' if count != 1 else ''}"
    if filtered:
        summary += f" ({len(filtered)} filtered)"
    by_state = {st: [u.label for u, s, _l in active if s is st] for st in (State.CRIT, State.WARN)}
    details_parts = []
    if by_state[State.CRIT]:
        details_parts.append(f"CRIT: {', '.join(by_state[State.CRIT])}")
    if by_state[State.WARN]:
        details_parts.append(f"WARN: {', '.join(by_state[State.WARN])}")
    if details_parts:
        summary += " - " + "; ".join(details_parts)
    yield Result(state=worst, summary=summary)

    if count_levels := params.get("levels_count"):
        yield from check_levels(
            count,
            levels_upper=count_levels,
            metric_name="windows_updates_pending",
            render_func=lambda v: f"{int(v)}",
            label="Pending updates",
            notice_only=True,
        )
    else:
        yield Metric("windows_updates_pending", count)

    if oldest_age is not None:
        yield Result(state=State.OK, summary=f"Oldest: {_fmt_age(oldest_age)}")
    yield Metric("windows_updates_oldest_age", oldest_age or 0.0)
    yield Metric("windows_updates_filtered", len(filtered))

    for _u, _s, line in sorted(active, key=lambda t: t[1].value, reverse=True):
        yield Result(state=State.OK, notice=line)
    if filtered:
        yield Result(
            state=State.OK,
            notice="Filtered: " + "; ".join(u.display for u in filtered),
        )
    if source := meta.get("source"):
        yield Result(state=State.OK, notice=f"Update source: {source}")
    if (start_type := meta.get("wu_start_type")) == "Disabled":
        yield Result(state=State.WARN, summary="Windows Update service is disabled")
    elif start_type:
        yield Result(state=State.OK, notice=f"Windows Update service start type: {start_type}")


check_plugin_windows_update_tracker = CheckPlugin(
    name="windows_update_tracker",
    service_name="Windows Updates pending",
    sections=["windows_update_tracker"],
    discovery_function=discover_windows_update_tracker,
    check_function=check_windows_update_tracker,
    check_ruleset_name="windows_update_tracker_pending",
    check_default_parameters={
        "default_rule": {
            "age_basis": "first_seen",
            "levels": ("fixed", (14 * DAY, 30 * DAY)),
        },
        "age_rules": [],
        "ignore_classifications": ["definition"],
        "ignore_defender": True,
        "ignore_msrt": True,
        "ignore_title_regexes": [],
        "search_age": ("fixed", (2 * DAY, 7 * DAY)),
        "search_error_state": 1,
    },
)


# ---------------------------------------------------------------------------
# Service 2: pending reboot
# ---------------------------------------------------------------------------


def discover_windows_update_tracker_reboot(section: Section) -> DiscoveryResult:
    if section.reboot is not None:
        yield Service()


def check_windows_update_tracker_reboot(params: Mapping[str, Any], section: Section) -> CheckResult:
    reboot = section.reboot
    if reboot is None:
        yield Result(state=State.UNKNOWN, summary="No reboot information in agent output")
        return
    if not reboot.get("required"):
        yield Result(state=State.OK, summary="No reboot pending")
        yield Metric("windows_update_reboot_age", 0.0)
        return

    sources = ", ".join(reboot.get("sources") or []) or "unknown"
    since = _int_or_none(reboot.get("since"))
    if since is None:
        yield Result(state=State.OK, summary=f"Reboot pending (source: {sources})")
        return
    yield from check_levels(
        max(time.time() - since, 0.0),
        levels_upper=params.get("levels"),
        metric_name="windows_update_reboot_age",
        render_func=render.timespan,
        label="Reboot pending for",
    )
    yield Result(state=State.OK, notice=f"Detected via: {sources}")
    yield Result(state=State.OK, notice=f"Pending since: {render.datetime(since)}")


check_plugin_windows_update_tracker_reboot = CheckPlugin(
    name="windows_update_tracker_reboot",
    service_name="Windows Update reboot",
    sections=["windows_update_tracker"],
    discovery_function=discover_windows_update_tracker_reboot,
    check_function=check_windows_update_tracker_reboot,
    check_ruleset_name="windows_update_tracker_reboot",
    check_default_parameters={"levels": ("fixed", (1 * DAY, 3 * DAY))},
)


# ---------------------------------------------------------------------------
# Service 3: failed installations
# ---------------------------------------------------------------------------


def discover_windows_update_tracker_failures(section: Section) -> DiscoveryResult:
    yield Service()


def _succeeded_later(entry: HistoryEntry, history: Sequence[HistoryEntry]) -> bool:
    kbs = set(entry.kb)
    for other in history:
        if other.date <= entry.date or other.result not in ("succeeded", "succeeded_with_errors"):
            continue
        if (entry.id and other.id == entry.id) or (kbs and kbs & set(other.kb)):
            return True
    return False


def _hidden_text(resolved: int, not_pending: int) -> str:
    parts = []
    if resolved:
        parts.append(f"{resolved} installed successfully later")
    if not_pending:
        parts.append(f"{not_pending} replaced or no longer offered")
    return ", ".join(parts)


def check_windows_update_tracker_failures(
    params: Mapping[str, Any], section: Section
) -> CheckResult:
    now = time.time()
    lookback = params.get("lookback", 30 * DAY)
    ignore_resolved = params.get("ignore_if_succeeded_later", True)
    # Only trust "no longer pending" if there ever was a successful search
    ignore_not_pending = params.get("ignore_if_not_pending", True) and bool(
        section.meta.get("last_success")
    )
    pending_ids = {u.id for u in section.pending if u.id}
    pending_kbs = {kb for u in section.pending for kb in u.kb}
    fail_state = State(params.get("state", 1))

    failures: list[HistoryEntry] = []
    resolved = 0
    not_pending = 0
    for entry in section.history:
        if entry.result not in ("failed", "aborted") or now - entry.date > lookback:
            continue
        if ignore_resolved and _succeeded_later(entry, section.history):
            resolved += 1
            continue
        if ignore_not_pending and entry.id not in pending_ids and not (set(entry.kb) & pending_kbs):
            not_pending += 1
            continue
        failures.append(entry)

    window = f"{lookback / DAY:g} days" if lookback % DAY == 0 else render.timespan(lookback)
    yield Metric("windows_update_failures", len(failures))
    if not failures:
        text = f"No failed update installations in the last {window}"
        if hidden := _hidden_text(resolved, not_pending):
            text += f" ({hidden})"
        yield Result(state=State.OK, summary=text)
        if history_error := section.meta.get("history_error"):
            yield Result(
                state=State.UNKNOWN, summary=f"Reading update history failed: {history_error}"
            )
        return

    labels = sorted({(", ".join(e.kb) if e.kb else e.title[:60]) for e in failures})
    yield Result(
        state=fail_state,
        summary=f"{len(failures)} failed installation{'s' if len(failures) != 1 else ''} "
        f"in the last {window}: {', '.join(labels)}",
    )
    if hidden := _hidden_text(resolved, not_pending):
        yield Result(state=State.OK, notice=f"Ignored: {hidden}")
    for e in sorted(failures, key=lambda x: x.date, reverse=True):
        yield Result(
            state=State.OK,
            notice=f"{render.datetime(e.date)}: {e.title} - {e.result} ({e.hresult})",
        )


check_plugin_windows_update_tracker_failures = CheckPlugin(
    name="windows_update_tracker_failures",
    service_name="Windows Update failures",
    sections=["windows_update_tracker"],
    discovery_function=discover_windows_update_tracker_failures,
    check_function=check_windows_update_tracker_failures,
    check_ruleset_name="windows_update_tracker_failures",
    check_default_parameters={
        "state": 1,
        "lookback": 30 * DAY,
        "ignore_if_succeeded_later": True,
        "ignore_if_not_pending": True,
    },
)
