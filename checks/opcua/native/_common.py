"""Shared browse/decode helpers for the OPC-UA anon-write check pair (dry-run + live). Ported
from a companion fuzzing toolkit Split out because both checks need the
same recursive Boolean-variable discovery — kept in one place rather than duplicated, matching
the wire-builder-vs-check-logic separation used throughout this project's other checks.
"""

from __future__ import annotations

from typing import Optional


async def browse_boolean_variables(start_node, max_depth: int, depth: int = 0, seen: Optional[set] = None):
    """Recursively find Variable nodes of type Boolean below start_node, skipping the standard
    OPC Foundation namespace (ns=0 — noise, not application data), matching the original PoC's
    default (--include-ns0 was opt-in there; not exposed at all here, kept at the safe default)."""
    from asyncua import ua

    if seen is None:
        seen = set()
    found = []
    if depth > max_depth:
        return found
    try:
        children = await start_node.get_children()
    except Exception:
        return found
    for child in children:
        nid = child.nodeid
        key = (nid.NamespaceIndex, str(nid.Identifier))
        if key in seen:
            continue
        seen.add(key)
        if nid.NamespaceIndex == 0:
            continue
        try:
            node_class = await child.read_node_class()
        except Exception:
            continue
        if node_class == ua.NodeClass.Variable:
            try:
                dv = await child.read_data_value()
                if dv.Value.VariantType == ua.VariantType.Boolean:
                    found.append(child)
            except Exception:
                pass
        found.extend(await browse_boolean_variables(child, max_depth, depth + 1, seen))
    return found


def decode_access_level(raw) -> str:
    """Decode the OPC-UA AccessLevel/UserAccessLevel bitmask (bit0=CurrentRead, bit1=CurrentWrite)."""
    try:
        bits = int(raw)
    except (TypeError, ValueError):
        return str(raw)
    flags = []
    if bits & 0x01:
        flags.append("Read")
    if bits & 0x02:
        flags.append("Write")
    if bits & 0x04:
        flags.append("HistoryRead")
    if bits & 0x08:
        flags.append("HistoryWrite")
    return f"{bits}({'|'.join(flags) if flags else 'none'})"
