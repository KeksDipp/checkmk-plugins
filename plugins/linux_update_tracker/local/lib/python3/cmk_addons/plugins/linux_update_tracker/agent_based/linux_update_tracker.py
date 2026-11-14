#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Check plugins for the linux_update_tracker agent section.

Services:
  * Linux Updates pending  - per-package age thresholds, filters, index/search freshness
  * Linux Update reboot    - pending reboot with age thresholds, services to restart
  * Linux Update failures  - failed/aborted package transactions, broken packages
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
MAX_SUMMARY_NAMES = 10

CLASSIFICATION_TITLES = {
    "security": "Security",
    "bugfix": "Bugfix",
    "enhancement": "Enhancement",
    "other": "Other",
}

MANAGER_TITLES = {"apt": "APT", "dnf": "DNF", "dnf5": "DNF5", "yum": "YUM", "zypper": "Zypper"}

AGE_BASIS_TITLES = {
    "first_seen": "outdated since",
    "version_seen": "this version since",
    "published": "published",
}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Package:
    name: str
    arch: str
    installed: str
    candidate: str
    repo: str
    classification: str
    severity: str
    advisory: str
    published: int | None
    first_seen: int | None
    version_seen: int | None
    held: bool = False
    phased: bool = False

    @property
    def label(self) -> str:
        return self.name

    @property
    def display(self) -> str:
        arch = f" ({self.arch})" if self.arch else ""
        repo = f" [{self.repo}]" if self.repo else ""
        return f"{self.name}{arch} {self.installed or '?'} -> {self.candidate}{repo}"


@dataclass(frozen=True)
class HistoryEntry:
    date: int
    result: str
    command: str
    packages: tuple[str, ...]
    error: str


@dataclass(frozen=True)
class BrokenPackage:
    name: str
    status: str


@dataclass
class Section:
    meta: Mapping[str, Any] = field(default_factory=dict)
    pending: list[Package] = field(default_factory=list)
    reboot: Mapping[str, Any] | None = None
    history: list[HistoryEntry] = field(default_factory=list)
    broken: list[BrokenPackage] = field(default_factory=list)


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None
    # beyond any sensible timestamp or count: treat as garbage (render.datetime would crash)
    return number if abs(number) < 10**11 else None


def _str(value: object) -> str:
    return "" if value is None else str(value)


def _str_or_none(value: object) -> str | None:
    return None if value is None or value == "" else str(value)


def _str_list(value: object) -> list[str]:
    return [str(v) for v in value if v] if isinstance(value, list) else []


def _clean_meta(data: Mapping[str, Any]) -> dict[str, Any]:
    meta = dict(data)
    for key in (
        "error",
        "refresh_error",
        "history_error",
        "plugin_version",
        "manager",
        "manager_version",
        "distro",
        "refresh_mode",
    ):
        meta[key] = _str_or_none(meta.get(key))
    for key in (
        "search_ok",
        "refresh_attempted",
        "history_supported",
        "broken_supported",
        "in_container",
    ):
        meta[key] = meta.get(key) is True
    return meta


def _clean_reboot(data: Mapping[str, Any]) -> dict[str, Any]:
    reboot = dict(data)
    reboot["required"] = reboot.get("required") is True
    reboot["services_checked"] = reboot.get("services_checked") is True
    for key in ("sources", "details", "packages", "services"):
        reboot[key] = _str_list(reboot.get(key))
    return reboot


def parse_linux_update_tracker(string_table: StringTable) -> Section | None:
    section = Section()
    found_meta = False
    for line in string_table:
        if not line or not line[0].strip():
            continue
        try:
            data = json.loads(line[0])
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue
        kind = data.get("type")
        if kind == "meta":
            section.meta = _clean_meta(data)
            found_meta = True
        elif kind == "pending":
            section.pending.append(
                Package(
                    name=_str(data.get("name")),
                    arch=_str(data.get("arch")),
                    installed=_str(data.get("installed")),
                    candidate=_str(data.get("candidate")),
                    repo=_str(data.get("repo")),
                    classification=_str(data.get("classification")) or "other",
                    severity=_str(data.get("severity")).lower(),
                    advisory=_str(data.get("advisory")),
                    published=_int_or_none(data.get("published")),
                    first_seen=_int_or_none(data.get("first_seen")),
                    version_seen=_int_or_none(data.get("version_seen")),
                    held=data.get("held") is True,
                    phased=data.get("phased") is True,
                )
            )
        elif kind == "reboot":
            section.reboot = _clean_reboot(data)
        elif kind == "history":
            date = _int_or_none(data.get("date"))
            if date is None:
                continue
            section.history.append(
                HistoryEntry(
                    date=date,
                    result=_str(data.get("result")),
                    command=_str(data.get("command")),
                    packages=tuple(_str_list(data.get("packages"))),
                    error=_str(data.get("error")),
                )
            )
        elif kind == "broken":
            section.broken.append(
                BrokenPackage(name=_str(data.get("name")), status=_str(data.get("status")))
            )
    return section if found_meta else None


agent_section_linux_update_tracker = AgentSection(
    name="linux_update_tracker",
    parse_function=parse_linux_update_tracker,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _search(regex: str, text: str) -> bool:
    try:
        return re.search(regex, text, re.IGNORECASE) is not None
    except re.error:
        return False


def _any_match(regexes: Iterable[str], text: str) -> bool:
    return any(_search(rx, text) for rx in regexes if rx)


def _filter_reason(pkg: Package, params: Mapping[str, Any]) -> str | None:
    """Why a package is filtered (first matching filter), or None if it counts."""
    filters = set(params.get("filters", []))
    if "held" in filters and pkg.held:
        return "held back"
    if "phased" in filters and pkg.phased:
        return "phased update"
    if f"class_{pkg.classification}" in filters:
        return "classification"
    if _any_match(params.get("ignore_package_regexes", []), pkg.name):
        return "package pattern"
    if pkg.repo and _any_match(params.get("ignore_repo_regexes", []), pkg.repo):
        return "repository pattern"
    return None


def _rule_matches(rule: Mapping[str, Any], pkg: Package) -> bool:
    if (classes := rule.get("classifications")) and pkg.classification not in classes:
        return False
    if (sevs := rule.get("severities")) and (pkg.severity or "unspecified") not in sevs:
        return False
    if (rx := rule.get("package_regex")) and not _search(rx, pkg.name):
        return False
    if (rx := rule.get("repo_regex")) and not _search(rx, pkg.repo):
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


def _fmt_since(ts: int | None, now: float) -> str:
    if ts is None:
        return "n/a"
    return f"{render.datetime(ts)} ({_fmt_age(now - ts)})"


def _names(items: Sequence[str], limit: int = MAX_SUMMARY_NAMES) -> str:
    unique = list(dict.fromkeys(items))
    text = ", ".join(unique[:limit])
    if len(unique) > limit:
        text += f" +{len(unique) - limit} more"
    return text


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'s' if count != 1 else ''}"


def _manager_text(meta: Mapping[str, Any]) -> str:
    manager = meta.get("manager") or "none"
    title = MANAGER_TITLES.get(manager, manager)
    if version := meta.get("manager_version"):
        title += f" {version}"
    return title


# ---------------------------------------------------------------------------
# Service 1: pending updates
# ---------------------------------------------------------------------------


def discover_linux_update_tracker(section: Section) -> DiscoveryResult:
    yield Service()


def _check_index(params: Mapping[str, Any], meta: Mapping[str, Any], now: float) -> CheckResult:
    """Search result, last successful search, refresh errors and package index age."""
    error_state = State(params.get("search_error_state", 1))
    if not meta.get("search_ok"):
        yield Result(
            state=error_state,
            summary=f"Update search failed: {meta.get('error') or 'unknown error'}",
        )
    if (last_success := _int_or_none(meta.get("last_success"))) is not None:
        yield from check_levels(
            max(now - last_success, 0.0),
            levels_upper=params.get("search_age"),
            render_func=render.timespan,
            label="Last successful search",
            notice_only=True,
        )
    else:
        yield Result(state=error_state, summary="No successful update search yet")

    if meta.get("state_ok") is False:
        yield Result(
            state=State.WARN,
            summary="State file not writable: package ages are not tracked",
        )

    if meta.get("refresh_attempted") and meta.get("refresh_ok") is False:
        yield Result(
            state=State(params.get("refresh_error_state", 1)),
            summary=f"Package index refresh failed: {meta.get('refresh_error') or 'unknown error'}",
        )
    if (last_refresh := _int_or_none(meta.get("last_refresh"))) is not None:
        yield from check_levels(
            max(now - last_refresh, 0.0),
            levels_upper=params.get("index_age"),
            render_func=render.timespan,
            label="Package index age",
            notice_only=True,
        )
    elif meta.get("search_ok"):
        yield Result(state=State.OK, notice="Package index age: unknown")


def _package_line(
    pkg: Package,
    now: float,
    basis: str,
    used_basis: str,
    rule_name: str,
    state: State,
) -> str:
    tags = [CLASSIFICATION_TITLES.get(pkg.classification, pkg.classification)]
    if pkg.severity:
        tags.append(pkg.severity.capitalize())
    if pkg.advisory:
        tags.append(pkg.advisory)
    if pkg.held:
        tags.append("held")
    if pkg.phased:
        tags.append("phased")
    parts = [f"outdated since {_fmt_since(pkg.first_seen, now)}"]
    if pkg.version_seen is not None and pkg.version_seen != pkg.first_seen:
        parts.append(f"this version since {_fmt_since(pkg.version_seen, now)}")
    if pkg.published is not None:
        parts.append(f"published {_fmt_since(pkg.published, now)}")
    basis_text = AGE_BASIS_TITLES.get(used_basis, used_basis)
    if used_basis != basis:
        basis_text += " (no publish date)"
    return (
        f"{pkg.display} ({', '.join(tags)}) - {', '.join(parts)} "
        f"[{basis_text}, {rule_name}]{_STATE_MARK[state]}"
    )


def check_linux_update_tracker(params: Mapping[str, Any], section: Section) -> CheckResult:
    now = time.time()
    meta = section.meta

    yield from _check_index(params, meta, now)

    age_rules = params.get("age_rules", [])
    default_rule = params.get("default_rule", {})

    active: list[tuple[Package, State, str]] = []
    filtered: list[tuple[Package, str]] = []
    oldest_age: float | None = None

    for pkg in section.pending:
        if reason := _filter_reason(pkg, params):
            filtered.append((pkg, reason))
            continue
        rule = next((r for r in age_rules if _rule_matches(r, pkg)), default_rule)
        basis = rule.get("age_basis", "first_seen")
        used_basis = basis
        if basis == "published" and pkg.published is None:
            used_basis = "first_seen"
        ts = getattr(pkg, used_basis)
        age = max(now - ts, 0.0) if ts is not None else None
        state = _evaluate_age(age, rule.get("levels"))
        if pkg.first_seen is not None:
            seen_age = max(now - pkg.first_seen, 0.0)
            oldest_age = seen_age if oldest_age is None else max(oldest_age, seen_age)
        rule_name = rule.get("name") or ("default" if rule is default_rule else "rule")
        active.append((pkg, state, _package_line(pkg, now, basis, used_basis, rule_name, state)))

    count = len(active)
    security = sum(1 for p, _s, _l in active if p.classification == "security")
    worst = State.worst(*(s for _p, s, _l in active)) if active else State.OK

    summary = _plural(count, "pending update")
    extras = []
    if security:
        extras.append(f"{security} security")
    if filtered:
        extras.append(f"{len(filtered)} filtered")
    if extras:
        summary += f" ({', '.join(extras)})"
    by_state = {st: [p.label for p, s, _l in active if s is st] for st in (State.CRIT, State.WARN)}
    parts = [
        f"{st.name}: {_names(names)}" for st in (State.CRIT, State.WARN) if (names := by_state[st])
    ]
    if parts:
        summary += " - " + "; ".join(parts)
    yield Result(state=worst, summary=summary)

    if count_levels := params.get("levels_count"):
        yield from check_levels(
            count,
            levels_upper=count_levels,
            metric_name="linux_updates_pending",
            render_func=lambda v: f"{int(v)}",
            label="Pending updates",
            notice_only=True,
        )
    else:
        yield Metric("linux_updates_pending", count)
    yield Metric("linux_updates_security", security)
    yield Metric("linux_updates_filtered", len(filtered))
    if oldest_age is not None:
        yield Result(state=State.OK, summary=f"Oldest: {_fmt_age(oldest_age)}")
    yield Metric("linux_updates_oldest_age", oldest_age or 0.0)

    info = f"Package manager: {_manager_text(meta)}"
    if distro := meta.get("distro"):
        info += f" on {distro}"
    yield Result(state=State.OK, notice=info)
    if mode := meta.get("refresh_mode"):
        yield Result(state=State.OK, notice=f"Index refresh by the plugin: {mode}")

    # Long output: one package per line, worst state on top, then the filtered ones
    if active:
        yield Result(state=State.OK, notice=f"Pending updates ({count}):")
        for _p, _s, line in sorted(active, key=lambda t: (-t[1].value, t[0].name)):
            yield Result(state=State.OK, notice=f"- {line}")
    if filtered:
        yield Result(state=State.OK, notice=f"Filtered updates ({len(filtered)}):")
        for pkg, reason in sorted(filtered, key=lambda t: t[0].name):
            yield Result(state=State.OK, notice=f"- {pkg.display} [{reason}]")


check_plugin_linux_update_tracker = CheckPlugin(
    name="linux_update_tracker",
    service_name="Linux Updates pending",
    sections=["linux_update_tracker"],
    discovery_function=discover_linux_update_tracker,
    check_function=check_linux_update_tracker,
    check_ruleset_name="linux_update_tracker_pending",
    check_default_parameters={
        "default_rule": {
            "age_basis": "first_seen",
            "levels": ("fixed", (2 * DAY, 7 * DAY)),
        },
        "age_rules": [],
        "filters": [],
        "ignore_package_regexes": [],
        "ignore_repo_regexes": [],
        "search_age": ("fixed", (2 * DAY, 7 * DAY)),
        "index_age": ("fixed", (2 * DAY, 7 * DAY)),
        "search_error_state": 1,
        "refresh_error_state": 1,
    },
)


# ---------------------------------------------------------------------------
# Service 2: pending reboot
# ---------------------------------------------------------------------------


def discover_linux_update_tracker_reboot(section: Section) -> DiscoveryResult:
    if section.reboot is not None:
        yield Service()


def _check_services(params: Mapping[str, Any], reboot: Mapping[str, Any]) -> CheckResult:
    services = reboot.get("services") or []
    if services:
        yield Result(
            state=State(params.get("services_state", 0)),
            summary=f"{_plural(len(services), 'service')} to restart: {_names(services)}",
        )
        if len(services) > MAX_SUMMARY_NAMES:
            yield Result(state=State.OK, notice=f"Services to restart: {', '.join(services)}")
    elif reboot.get("services_checked"):
        yield Result(state=State.OK, notice="No services need a restart")


def check_linux_update_tracker_reboot(params: Mapping[str, Any], section: Section) -> CheckResult:
    reboot = section.reboot
    if reboot is None:
        yield Result(state=State.UNKNOWN, summary="No reboot information in agent output")
        return

    if not reboot.get("required"):
        yield Result(state=State.OK, summary="No reboot pending")
        yield Metric("linux_update_reboot_age", 0.0)
    else:
        sources = ", ".join(reboot.get("sources") or []) or "unknown"
        since = _int_or_none(reboot.get("since"))
        if since is None:
            yield Result(state=State.OK, summary=f"Reboot pending (source: {sources})")
        else:
            yield from check_levels(
                max(time.time() - since, 0.0),
                levels_upper=params.get("levels"),
                metric_name="linux_update_reboot_age",
                render_func=render.timespan,
                label="Reboot pending for",
            )
            yield Result(state=State.OK, notice=f"Pending since: {render.datetime(since)}")
        yield Result(state=State.OK, notice=f"Detected via: {sources}")
        for detail in reboot.get("details") or []:
            yield Result(state=State.OK, notice=detail)
        if packages := reboot.get("packages"):
            yield Result(state=State.OK, notice=f"Packages: {', '.join(packages)}")

    yield from _check_services(params, reboot)

    if running := reboot.get("running_kernel"):
        text = f"Running kernel: {running}"
        if (latest := reboot.get("latest_kernel")) and latest != running:
            text += f", newest installed: {latest}"
        yield Result(state=State.OK, notice=text)
    if (boot := _int_or_none(reboot.get("boot_time"))) is not None:
        yield Result(state=State.OK, notice=f"Last boot: {render.datetime(boot)}")


check_plugin_linux_update_tracker_reboot = CheckPlugin(
    name="linux_update_tracker_reboot",
    service_name="Linux Update reboot",
    sections=["linux_update_tracker"],
    discovery_function=discover_linux_update_tracker_reboot,
    check_function=check_linux_update_tracker_reboot,
    check_ruleset_name="linux_update_tracker_reboot",
    check_default_parameters={
        "levels": ("fixed", (1 * DAY, 3 * DAY)),
        "services_state": 0,
    },
)


# ---------------------------------------------------------------------------
# Service 3: failed transactions and broken packages
# ---------------------------------------------------------------------------


def discover_linux_update_tracker_failures(section: Section) -> DiscoveryResult:
    if section.meta.get("history_supported") or section.meta.get("broken_supported"):
        yield Service()


def _succeeded_later(entry: HistoryEntry, history: Sequence[HistoryEntry]) -> bool:
    """All packages of the failed transaction were handled successfully later
    (without package list: the same command succeeded later)."""
    later = [h for h in history if h.date > entry.date and h.result == "succeeded"]
    if not entry.packages:
        return any(entry.command and h.command == entry.command for h in later)
    done = {p for h in later for p in h.packages}
    return set(entry.packages) <= done


def _hidden_text(resolved: int, not_pending: int) -> str:
    parts = []
    if resolved:
        parts.append(f"{resolved} handled successfully later")
    if not_pending:
        parts.append(f"{not_pending} without pending packages")
    return ", ".join(parts)


def _entry_label(entry: HistoryEntry) -> str:
    if entry.packages:
        return _names(entry.packages, 3)
    return entry.command[:60] or "unknown transaction"


def check_linux_update_tracker_failures(params: Mapping[str, Any], section: Section) -> CheckResult:
    now = time.time()
    meta = section.meta
    lookback = params.get("lookback", 30 * DAY)
    ignore_resolved = params.get("ignore_if_succeeded_later", True)
    # Only trust "no longer pending" if there ever was a successful search
    ignore_not_pending = params.get("ignore_if_not_pending", True) and bool(
        meta.get("last_success")
    )
    pending_names = {p.name for p in section.pending}

    if meta.get("history_supported"):
        failures: list[HistoryEntry] = []
        resolved = 0
        not_pending = 0
        for entry in section.history:
            if entry.result not in ("failed", "aborted") or now - entry.date > lookback:
                continue
            if ignore_resolved and _succeeded_later(entry, section.history):
                resolved += 1
                continue
            if ignore_not_pending and entry.packages and not set(entry.packages) & pending_names:
                not_pending += 1
                continue
            failures.append(entry)

        window = f"{lookback / DAY:g} days" if lookback % DAY == 0 else render.timespan(lookback)
        yield Metric("linux_update_failures", len(failures))
        hidden = _hidden_text(resolved, not_pending)
        if not failures:
            text = f"No failed package transactions in the last {window}"
            yield Result(state=State.OK, summary=f"{text} ({hidden})" if hidden else text)
        else:
            yield Result(
                state=State(params.get("state", 1)),
                summary=f"{_plural(len(failures), 'failed transaction')} in the last {window}: "
                f"{'; '.join(_entry_label(e) for e in failures[-MAX_SUMMARY_NAMES:])}",
            )
            if hidden:
                yield Result(state=State.OK, notice=f"Ignored: {hidden}")
            for e in sorted(failures, key=lambda x: x.date, reverse=True):
                error = f" - {e.error}" if e.error else ""
                yield Result(
                    state=State.OK,
                    notice=f"{render.datetime(e.date)}: {e.result}: {e.command or '?'}{error} "
                    f"(packages: {', '.join(e.packages) or 'n/a'})",
                )
        if history_error := meta.get("history_error"):
            yield Result(
                state=State.UNKNOWN, summary=f"Reading the package history failed: {history_error}"
            )

    if meta.get("broken_supported"):
        broken = section.broken
        yield Metric("linux_update_broken", len(broken))
        if broken:
            yield Result(
                state=State(params.get("broken_state", 1)),
                summary=f"{_plural(len(broken), 'broken package')}: "
                f"{_names([b.name for b in broken])}",
            )
            for b in broken:
                yield Result(state=State.OK, notice=f"Broken: {b.name} ({b.status})")
        else:
            yield Result(state=State.OK, notice="No broken packages")


check_plugin_linux_update_tracker_failures = CheckPlugin(
    name="linux_update_tracker_failures",
    service_name="Linux Update failures",
    sections=["linux_update_tracker"],
    discovery_function=discover_linux_update_tracker_failures,
    check_function=check_linux_update_tracker_failures,
    check_ruleset_name="linux_update_tracker_failures",
    check_default_parameters={
        "state": 1,
        "lookback": 30 * DAY,
        "ignore_if_succeeded_later": True,
        "ignore_if_not_pending": True,
        "broken_state": 1,
    },
)
