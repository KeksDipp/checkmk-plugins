#!/usr/bin/env python3
# Copyright (C) 2026 Alexander Thomsen
# License: GNU General Public License v2.0 (see LICENSE)
# https://github.com/KeksDipp/checkmk-plugins
"""Shared helpers for the sophos_sfos plugin family (SFOS-FIREWALL-MIB)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from cmk.agent_based.v2 import OIDEnd, SNMPTree, StringTable, any_of, equals, startswith

SFOS_BASE = ".1.3.6.1.4.1.2604.5.1"

# Checkmk walks every OID column of an SNMPTree separately, but caches walks per OID within
# one fetch. All sections therefore use this identical tree: the complete SFOS subtree is
# walked once per check cycle (one bulkwalk) instead of once per value.
SFOS_TREE = SNMPTree(base=".1.3.6.1.4.1.2604.5", oids=[OIDEnd(), "1"])

# Sophos Firewall OS (XGS, XG, virtual/cloud). sysDescr is a generic "Linux localhost ...",
# so only sysObjectID is reliable.
DETECT_SFOS = any_of(
    equals(".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.2604.5"),
    startswith(".1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.2604.5."),
)


def to_int(value: str) -> int | None:
    """SNMP value -> int, None for empty or non-numeric values."""
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return None


def clean_text(value: str) -> str:
    """Collapse line breaks and repeated blanks (SFOS allows multi-line descriptions)."""
    return " ".join(value.split())


def sfos_values(string_table: StringTable) -> dict[str, str]:
    """Rows of SFOS_TREE -> {OID relative to SFOS_BASE: value}, e.g. {"4.1.0": "1"}."""
    return {row[0]: row[1] for row in string_table if len(row) == 2}


def scalar_row(values: Mapping[str, str], prefix: str, oids: Iterable[str]) -> list[str] | None:
    """Values of scalar OIDs below prefix; None if none of them is present."""
    row = [values.get(f"{prefix}.{oid}") for oid in oids]
    if all(value is None for value in row):
        return None
    return [value or "" for value in row]


def table_rows(values: Mapping[str, str], entry: str, columns: Iterable[str]) -> list[list[str]]:
    """Rows [index, column values ...] of the SNMP table with the given entry OID."""
    columns = list(columns)
    indices: set[str] = set()
    for column in columns:
        start = f"{entry}.{column}."
        indices.update(oid[len(start) :] for oid in values if oid.startswith(start))

    def _key(index: str) -> list[int]:
        return [int(part) if part.isdigit() else 0 for part in index.split(".")]

    return [
        [index, *(values.get(f"{entry}.{column}.{index}", "") for column in columns)]
        for index in sorted(indices, key=_key)
    ]
