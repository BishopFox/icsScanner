"""Field-level Zeek protocol-event policy renderer (the detection-gen standout, deepened).

The `zeek` (signature) and `zeek-policy` (NOTICE) renderers match the raw payload. This one emits a
TRUE field-level detection: it hooks a Zeek protocol-analyzer event and tests a parsed field, e.g.
"Modbus function_code == 6 (write single register)" or "DNP3 fc == 18 (COLD_RESTART)". It is driven by
a structured `detection_hints.protocol_event` block (which Zeek event + a condition expression), so —
unlike a byte signature — it reasons about the dissected protocol, not bytes on the wire.

Scope: Modbus and DNP3 use Zeek's BUILT-IN analyzers, so these policies load and run on stock Zeek
(validated against Zeek 9.0.1) with no extra parsers. The ICSNPP analyzers (ENIP/CIP, BACnet, etc.)
raise their own events with their own signatures; extending `_EVENT_SIGS` to those requires an
ICSNPP-equipped Zeek to validate against, so they are intentionally not emitted here yet.

`detection_hints.protocol_event`:
    zeek_event: modbus_message            # one of _EVENT_SIGS below
    condition:  "is_orig && headers$function_code == 6"   # a Zeek boolean expr over the event's args
    description: "..."                    # optional
The condition is authored against the event's arguments (documented per event below). The renderer
supplies the correct handler signature, the required @load, the Notice::Type, and the NOTICE.
"""
from __future__ import annotations

import re
from typing import Optional

from core.check_loader import CheckRecord

# zeek_event -> (handler signature, @load needed, a hint of the fields available to `condition`)
_EVENT_SIGS = {
    # modbus_message(c, headers: ModbusHeaders, is_orig). headers$ fields: tid, pid, uid, function_code, len.
    "modbus_message": ("(c: connection, headers: ModbusHeaders, is_orig: bool)", "base/protocols/modbus"),
    # dnp3_application_request_header(c, is_orig, application, fc). fc = DNP3 function code.
    "dnp3_application_request_header": ("(c: connection, is_orig: bool, application: count, fc: count)", "base/protocols/dnp3"),
    "dnp3_application_response_header": ("(c: connection, is_orig: bool, application: count, fc: count, iin: count)", "base/protocols/dnp3"),
}


def _base(check_id: str) -> str:
    return re.sub(r"[^0-9a-zA-Z]+", "_", check_id).strip("_")


def render(record: CheckRecord, mode: str) -> Optional[str]:
    # protocol_event is mode-independent; emit once (key to "narrow" so it isn't produced per mode).
    if mode != "narrow" or not record.has_hints:
        return None
    pe = record.detection_hints.get("protocol_event")
    if not isinstance(pe, dict):
        return None
    ev = pe.get("zeek_event")
    cond = (pe.get("condition") or "").strip()
    if not ev or not cond or ev not in _EVENT_SIGS:
        return None
    sig, load = _EVENT_SIGS[ev]

    hints = record.detection_hints
    app = hints.get("app_protocol") or "ics"
    mitre = hints.get("mitre_attack_id") or ""
    sub = f"{app}/{mitre}" if mitre else app
    base = _base(record.check_id)
    note_type = f"ICS_proto_{base}"
    msg = f"ICS-SCANNER PROTOCOL - {record.check_id}".replace('"', "'")

    meta = ["# detection_gen_mode: protocol_event", f"# check_id: {record.check_id}",
            f"# zeek_event: {ev}"]
    if record.cve_id:
        meta.append(f"# cve: {record.cve_id}")
    if mitre:
        meta.append(f"# mitre_attack_id: {mitre}")
    desc = pe.get("description") or record.description
    desc_comment = "\n".join(f"# {line}" for line in str(desc).split("\n"))

    return (
        f"# Auto-generated field-level Zeek policy by detection-gen from icsScanner check "
        f"'{record.check_id}'.\n"
        f"# Hooks the protocol-analyzer event and tests a PARSED field (not a byte pattern).\n"
        f"{desc_comment}\n"
        + "\n".join(meta) + "\n"
        f"@load {load}\n"
        f"@load base/frameworks/notice\n\n"
        f"module ICS_Scanner;\n\n"
        f"export {{\n\tredef enum Notice::Type += {{ {note_type} }};\n}}\n\n"
        f"event {ev}{sig}\n"
        f"\t{{\n"
        f"\tif ( {cond} )\n"
        f"\t\tNOTICE([$note=ICS_Scanner::{note_type},\n"
        f'\t\t        $msg="{msg}",\n'
        f'\t\t        $sub="{sub}",\n'
        f"\t\t        $conn=c]);\n"
        f"\t}}\n"
    )


def output_filename(record: CheckRecord, mode: str) -> str:
    return f"{record.check_id}.protocol.zeek"
