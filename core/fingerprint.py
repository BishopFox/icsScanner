"""Device fingerprinting utilities — reused near-verbatim from a companion fuzzing toolkit
(Milestone 0, 2026-08-12). Genuinely protocol-agnostic already; no scanner-specific changes
needed. This is the fingerprinting layer Check.fingerprint_matches() (check.py) consumes for
fingerprint_precondition evaluation before any active probe fires.

Two risk tiers:
  passive (active=False) — reads ARP cache only, sends zero packets.
  active  (active=True)  — sends one benign identity probe per protocol.
"""

from __future__ import annotations

import re
import struct
import subprocess
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FingerprintResult:
    vendor:     str = "unknown"
    model:      str = "unknown"
    firmware:   str = "unknown"
    serial:     str = "unknown"
    confidence: str = "none"      # "high" / "medium" / "low" / "none"
    method:     str = ""          # technique that produced this result
    extra:      dict = field(default_factory=dict)

    def is_known(self) -> bool:
        return self.confidence != "none" and self.vendor != "unknown"

    def as_dict(self) -> dict:
        return {
            "vendor":     self.vendor,
            "model":      self.model,
            "firmware":   self.firmware,
            "serial":     self.serial,
            "confidence": self.confidence,
            "method":     self.method,
        }


# ── OUI lookup table (curated for ICS/OT vendors) ────────────────────────────
# Key: uppercase colon-separated 3-octet prefix (e.g. "00:0E:8C")
# Source: IEEE OUI database, filtered to known ICS/OT manufacturers

_OUI_TABLE: dict[str, str] = {
    # Siemens
    "00:0E:8C": "Siemens AG",
    "00:1B:1B": "Siemens AG",
    "20:87:56": "Siemens AG",
    "28:63:36": "Siemens AG",
    "34:7C:25": "Siemens AG",
    "AC:64:17": "Siemens AG",
    # Rockwell Automation / Allen-Bradley
    "00:00:BC": "Rockwell Automation",
    "00:09:B0": "Rockwell Automation",
    "00:1D:9C": "Rockwell Automation",
    "00:60:35": "Rockwell Automation",
    "5C:88:16": "Rockwell Automation",
    # Schneider Electric / Modicon
    "00:30:64": "Schneider Electric",
    "00:50:F0": "Schneider Electric",
    "08:00:F4": "Schneider Electric",
    "D0:C7:C0": "Schneider Electric",
    # GE Automation / GE Digital
    "00:1B:22": "GE Automation",
    "38:60:77": "GE Digital",
    # National Instruments — CORRECTED 2026-10-07: 00:80:2F was mislabeled "GE Automation" here; the
    # IEEE OUI registry assigns 00:80:2F to NATIONAL INSTRUMENTS CORP (MA-L, Austin TX). Fixes a
    # real misattribution (NI cRIO/PXI were fingerprinted as GE) and gates the NI cRIO default-
    # credential check. Same IEEE-cross-check discipline as the ABB OUI correction below.
    "00:80:2F": "National Instruments Corp",
    # ABB — CORRECTED 2026-08-14 (Phase 9, default-credentials sweep): the two prior entries here
    # (00:0A:DC, 00:E0:85) were WRONG — cross-checked against the official IEEE OUI registry
    # (standards-oui.ieee.org/oui/oui.txt, fetched directly) while adding the ABB SREA-01 check
    # and found 00:0A:DC actually belongs to RuggedCom Inc. (a Siemens brand since 2012, already
    # covered under Siemens' RUGGEDCOM product line elsewhere in this sweep — NOT ABB) and
    # 00:E0:85 belongs to Global Maintech, Inc., an unrelated IT company with no ICS connection
    # at all. No shipped check depended on "ABB AB" yet (confirmed via grep before fixing), so
    # this was a real but so-far-inert data error, not a regression in a live check. Replaced with
    # IEEE-verified real ABB prefixes.
    "60:39:1F": "ABB AB",
    "00:1C:01": "ABB AB",
    "00:24:59": "ABB AB",
    # Honeywell
    "00:00:32": "Honeywell International",
    "00:40:C7": "Honeywell International",
    "10:5E:60": "Honeywell International",
    # Emerson Electric
    "00:13:06": "Emerson Electric",
    "00:E0:6A": "Emerson Electric",
    # APC (American Power Conversion) — added 2026-08-24 for the UPS Network Management Card 2
    # FTP default-creds check. Verified directly against the IEEE OUI registry
    # (standards-oui.ieee.org/oui/oui.txt), not assumed from a third-party lookup site. Kept as
    # its own vendor string (not folded into "Schneider Electric") to match this table's existing
    # precedent of keeping historically-separate acquired brands distinct (see GE Automation vs
    # GE Digital above) — APC's OUI registration itself is still under its pre-acquisition
    # corporate name.
    "00:C0:B7": "American Power Conversion",
    # Mitsubishi Electric
    "00:00:21": "Mitsubishi Electric",
    "00:14:C0": "Mitsubishi Electric",
    # Omron
    "00:00:66": "Omron Corporation",
    "00:20:D2": "Omron Corporation",
    # Phoenix Contact
    "00:A0:45": "Phoenix Contact",
    "A8:F9:4B": "Phoenix Contact",
    # WAGO
    "00:30:DE": "WAGO GmbH",
    # Beckhoff
    "00:01:05": "Beckhoff Automation",
    "00:12:87": "Beckhoff Automation",
    # Advantech
    "00:D0:C9": "Advantech Co. Ltd.",
    "00:60:64": "Advantech Co. Ltd.",
    # Moxa Technologies (ICS networking)
    "00:10:85": "Moxa Technologies",
    "00:90:E8": "Moxa Technologies",
    # Hirschmann / Belden
    "00:08:0F": "Hirschmann Automation",
    # Red Lion Controls
    "00:60:52": "Red Lion Controls",
    # HMS Networks (Anybus)
    "00:30:11": "HMS Networks",
    # Weidmüller
    "00:0D:F0": "Weidmuller Interface",
    # ProSoft Technology
    "00:20:4A": "ProSoft Technology",
    # Yaskawa Electric Corporation (added 2026-08-27, IEEE-verified via Wireshark's manuf
    # database derivative — standards-oui.ieee.org itself 403/418s automated fetches, same
    # bot-block pattern seen elsewhere in this project. No separate Motoman/robotics-division
    # OUI block found — robot controllers apparently use the parent corporation's own block.)
    "00:20:B5": "Yaskawa Electric Corp.",
    # Tridium (Niagara framework/JACE controllers) — added 2026-08-14, Phase 9, IEEE-verified
    "00:01:F0": "Tridium Inc.",
    # HollySys (Hangzhou Hollysys Automation) — added 2026-08-14, Phase 9, IEEE-verified
    "00:1C:47": "HollySys Automation",
    # B&B Electronics (Conel-brand industrial routers) — added 2026-08-15, Phase 12, IEEE-verified
    "00:0E:BE": "B&B Electronics",
    # Echelon Corp. (i.LON/LonWorks building automation) — added 2026-08-15, Phase 12, IEEE-verified
    "00:D0:71": "Echelon Corp.",
    # CAREL s.p.a. (HVAC/refrigeration controllers) — added 2026-08-15, Phase 13, IEEE-verified
    "00:0A:5C": "Carel s.p.a.",
    # Westermo Network Technologies AB (industrial networking) — added 2026-08-15, Phase 13, IEEE-verified
    "00:07:7C": "Westermo Network Technologies AB",
    "00:11:B4": "Westermo Network Technologies AB",
    # Phase 14 additions (2026-08-15), all IEEE-verified against the official OUI registry:
    "00:50:06": "TAC AB",
    "00:50:DB": "Contemporary Control Systems",
    "00:01:58": "Electro Industries/Gauge Tech",
    "00:0A:B0": "LOYTEC electronics GmbH",
    "00:0A:14": "TECO a.s.",
    "00:07:46": "TURCK Inc.",
    "00:E0:99": "SAMSON AG",
    "24:EA:40": "Helmholz GmbH & Co. KG",
    # Phase 15 additions (2026-08-15), IEEE-verified:
    "50:13:9D": "Sierra Wireless, ULC",
    "84:DB:2F": "Sierra Wireless, ULC",
    "00:26:77": "DEIF A/S",
    # Phase 16 addition (2026-08-15), IEEE-verified:
    "00:0E:66": "Hitachi Industry & Control Solutions, Ltd.",
    # Phase 17 addition (2026-08-15), IEEE-verified. NOTE: distinct from the unrelated
    # "SMA Railway Technology GmbH" (00:25:20) also in the registry — checked carefully not to
    # confuse the two similarly-named companies.
    "00:15:BB": "SMA Solar Technology AG",
    # Phase 18 addition (2026-08-15), IEEE-verified — AutomationDirect/PLC Direct, the first
    # manually-researched vendor (not sourced from SCADAPASS, which was fully closed out in
    # Phase 17). No real check depends on it yet (Phase 18 produced candidates only), but the
    # vendor identity is confirmed for whenever the CLICK PLC project-password candidate below
    # gets resolved.
    "68:EF:A8": "AutomationDirect.com",
    # Phase 19 additions (2026-08-15), IEEE-verified — first vendors sourced from Metoree
    # (us.metoree.com), the new vendor-discovery source confirmed this same session.
    "00:03:34": "Omega Engineering Inc.",
    "70:01:36": "FATEK Automation Corporation",
    # Phase 20 additions (2026-08-15), IEEE-verified — second Metoree category (Industrial
    # Ethernet Switch Manufacturers, us.metoree.com/categories/102285). Note: Omnitron Systems
    # Technology (00:06:87) was checked carefully against two DIFFERENT, similarly-named
    # companies also in the registry — OMNITRONIX, INC. and OMNITRONICS PTY LTD — neither of
    # which is the actual Omnitron Systems Technology from this category list; not confused.
    "00:06:87": "Omnitron Systems Technology, Inc.",
    "7C:CB:0D": "Antaira Technologies, LLC",
    # Phase 22 addition (2026-08-16), IEEE-verified — first vendor sourced from the
    # scadasecuritybootcamp.com credential-list triage (a new source, not SCADAPASS/Metoree).
    "00:04:D2": "Adcon Telemetry GmbH",
    # Espressif Systems (ESP32/ESP8266) — added 2026-08-13 for the emelianov/esp-modbus check
    # family (checks/modbus/). Espressif holds 300+ registered MA-L blocks total; this is a
    # small, best-effort subset retrieved via automated OUI lookup (maclookup.app, 2026-08-13),
    # NOT independently cross-checked against the primary IEEE registry — same "curated, not
    # exhaustive" caveat as every other vendor here, but flagged explicitly since it wasn't
    # hand-verified the way the rest of this table was. A match still only yields
    # confidence="low" (see fingerprint_from_oui() below), and this OUI match cannot distinguish
    # WHICH Modbus TCP library (emelianov vs esp-modbus) is running on the chip — both run on
    # the same Espressif silicon, so this narrows to "some ESP32 device," not the specific
    # library. See checks/modbus/emelianov-bare-fc.yaml's description for how that limitation is
    # handled in the actual check content.
    "00:4B:12": "Espressif Inc.",
    "00:70:07": "Espressif Inc.",
    "04:83:08": "Espressif Inc.",
    "04:B2:47": "Espressif Inc.",
    "08:3A:8D": "Espressif Inc.",
    "08:3A:F2": "Espressif Inc.",
    "08:92:72": "Espressif Inc.",
    "08:A6:F7": "Espressif Inc.",
    "08:AD:0A": "Espressif Inc.",
    "08:B6:1F": "Espressif Inc.",
    "08:D1:F9": "Espressif Inc.",
    "08:F9:E0": "Espressif Inc.",
    "0C:4E:A0": "Espressif Inc.",
    "0C:8B:95": "Espressif Inc.",
    "0C:B8:15": "Espressif Inc.",
    # Schweitzer Engineering Laboratories (SEL protection relays) — verified ICS OUI.
    "00:30:A7": "Schweitzer Engineering Laboratories",
    # GE protection/automation (the bundled IEEE table renders this registrant as a terse "Ge").
    "00:A0:F4": "General Electric",
    # Virtualization OUIs — in an OT segment a VM MAC on an asset port is itself worth flagging
    # (e.g. an engineering/attacker VM where a PLC is expected).
    "00:0C:29": "VMware (virtual)",
    "00:50:56": "VMware (virtual)",
    "00:05:69": "VMware (virtual)",
    "FA:16:3E": "OpenStack/KVM (virtual)",
}

# ── ODVA EtherNet/IP Vendor ID table ─────────────────────────────────────────
# Source: ODVA EtherNet/IP Vendor ID registry (partial — top ~40 ICS vendors)

# Curated ICS-relevant overrides. These win over the bulk-imported table below, so vendor names
# that candidate-check fingerprint_preconditions depend on (e.g. 1638 = "Hach Lange SARL") stay
# stable regardless of upstream wording. Bulk list: scripts/update_odva_vendors.py -> core/data/.
_ODVA_VENDOR_OVERRIDES: dict[int, str] = {
    1:    "Rockwell Automation / Allen-Bradley",
    2:    "Namco Controls Corp.",
    6:    "General Signal Corp.",
    7:    "SMC Corp.",
    10:   "Sumitomo Electric Industries",
    11:   "Digital Electronics Corp.",
    14:   "Belden Inc.",
    34:   "Eaton Corp.",
    40:   "Numatics Inc.",
    49:   "Turck Inc.",
    50:   "Pepperl+Fuchs GmbH",
    74:   "Siemens Energy & Automation",
    1638: "Hach Lange SARL",  # Hach sc-series water-quality controllers (ENIP ProdName e.g. "Hach SC4500 Controllers")
    96:   "Hirschmann Automation",
    105:  "WAGO Corp.",
    108:  "Molex Inc.",
    134:  "Schneider Electric",
    137:  "Honeywell Inc.",
    152:  "Omron Corp.",
    161:  "Beckhoff Automation GmbH",
    168:  "Murr Elektronik GmbH",
    198:  "Phoenix Contact GmbH",
    218:  "Sick AG",
    242:  "Banner Engineering",
    286:  "Cognex Corp.",
    302:  "Emerson Network Power",
    312:  "ABB Stotz-Kontakt GmbH",
    343:  "Weidmuller Interface GmbH",
    432:  "Endress+Hauser Flowtec AG",
    492:  "HMS Industrial Networks AB",
    529:  "GE Fanuc Automation",
    596:  "Advantech Co. Ltd.",
    752:  "ProSoft Technology Inc.",
    826:  "Yaskawa Electric Corp.",
    998:  "Mitsubishi Electric Corp.",
    1093: "Red Lion Controls",
}


def _load_odva_bulk() -> dict[int, str]:
    """Bulk ODVA Vendor ID -> name table generated by scripts/update_odva_vendors.py from the public
    Wireshark CIP vendor list (core/data/odva_vendors.json). Fails soft to {} if the file is absent
    or malformed, so the curated overrides alone still work."""
    import json as _json
    from pathlib import Path as _Path
    try:
        p = _Path(__file__).resolve().parent / "data" / "odva_vendors.json"
        return {int(k): v for k, v in _json.loads(p.read_text(encoding="utf-8"))["vendors"].items()}
    except Exception:
        return {}


# Full table = bulk import (~1600 vendors) with the curated overrides layered on top (overrides win).
_ODVA_VENDOR_TABLE: dict[int, str] = {**_load_odva_bulk(), **_ODVA_VENDOR_OVERRIDES}

# ── BACnet Vendor ID table ────────────────────────────────────────────────────
# Source: ASHRAE BACnet Vendor ID registry (partial — top ~30 vendors)

_BACNET_VENDOR_TABLE: dict[int, str] = {
    0:    "ASHRAE",
    5:    "Johnson Controls Inc.",
    7:    "Siemens Building Technologies",
    8:    "Trane",
    10:   "Alerton / Honeywell",
    11:   "Delta Controls",
    13:   "Automated Logic Corp.",
    23:   "Carrier Corporation",
    36:   "Reliable Controls Corp.",
    42:   "Temco Controls Ltd.",
    55:   "Cimetrics Inc.",
    86:   "FieldServer Technologies",
    116:  "TAC (Schneider Electric)",
    118:  "Distech Controls",
    154:  "Echelon Corp.",
    186:  "KMC Controls",
    260:  "Bosch Security Systems",
    303:  "Computrols Inc.",
    328:  "Tridium Inc.",
    374:  "Alerton",
    390:  "Honeywell Building Solutions",
    406:  "Siemens Industry Inc.",
}


# ── Lookup helpers ────────────────────────────────────────────────────────────

def lookup_oui(mac: str) -> str:
    """Return ICS vendor name for a MAC address, or 'unknown'.

    Accepts AA:BB:CC:DD:EE:FF, AA-BB-CC, or AABBCC formats.
    """
    if not mac:
        return "unknown"
    mac = mac.upper().replace("-", ":").replace(".", ":")
    if ":" not in mac:
        mac = ":".join(mac[i:i+2] for i in range(0, min(len(mac), 12), 2))
    parts = mac.split(":")
    if len(parts) < 3:
        return "unknown"
    prefix = ":".join(parts[:3])
    # Curated ICS-vendor table first (friendly canonical names); then the bundled full IEEE table.
    return _OUI_TABLE.get(prefix) or _bundled_oui().get(prefix, "unknown")


_BUNDLED_OUI: Optional[dict] = None


def _bundled_oui() -> dict:
    """Lazily load the bundled IEEE /24 OUI table (core/data/oui.tsv, ~40k entries) on first miss.
    Cached for the process; returns {} (never raises) if the file is absent/unreadable."""
    global _BUNDLED_OUI
    if _BUNDLED_OUI is None:
        _BUNDLED_OUI = {}
        try:
            from pathlib import Path
            path = Path(__file__).resolve().parent / "data" / "oui.tsv"
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("#") or "\t" not in line:
                        continue
                    prefix, _, vendor = line.partition("\t")
                    vendor = vendor.strip()
                    if vendor:
                        _BUNDLED_OUI[prefix.strip().upper()] = vendor
        except OSError:
            pass
    return _BUNDLED_OUI


def lookup_odva_vendor(vendor_id: int) -> str:
    return _ODVA_VENDOR_TABLE.get(vendor_id, f"vendor_{vendor_id}")


def lookup_bacnet_vendor(vendor_id: int) -> str:
    return _BACNET_VENDOR_TABLE.get(vendor_id, f"bacnet_vendor_{vendor_id}")


# ── Passive: ARP cache reader ─────────────────────────────────────────────────

def get_mac_from_arp(ip: str) -> Optional[str]:
    """Read the MAC address for ip from the OS ARP cache. Sends zero packets.

    Returns None if the entry is missing or the cache is inaccessible.
    """
    # Linux fast path: parse kernel ARP table
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac != "00:00:00:00:00:00":
                        return mac
    except OSError:
        pass
    # Fallback: run arp -n
    try:
        out = subprocess.check_output(
            ["arp", "-n", ip], stderr=subprocess.DEVNULL, timeout=3
        ).decode()
        m = re.search(
            r"([\dA-Fa-f]{2}[:\-][\dA-Fa-f]{2}[:\-][\dA-Fa-f]{2}"
            r"[:\-][\dA-Fa-f]{2}[:\-][\dA-Fa-f]{2}[:\-][\dA-Fa-f]{2})",
            out,
        )
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def fingerprint_from_oui(ip: str) -> FingerprintResult:
    """Passive OUI lookup — reads ARP cache, zero packets sent."""
    mac = get_mac_from_arp(ip)
    if mac is None:
        return FingerprintResult(confidence="none", method="oui_no_mac")
    vendor = lookup_oui(mac)
    if vendor == "unknown":
        return FingerprintResult(
            confidence="none", method="oui_unrecognized", extra={"mac": mac}
        )
    return FingerprintResult(
        vendor=vendor, confidence="low", method="oui", extra={"mac": mac}
    )


# ── EtherNet/IP List Identity parser ─────────────────────────────────────────

def parse_enip_list_identity(data: bytes) -> Optional[FingerprintResult]:
    """Parse an EtherNet/IP List Identity response (command 0x0063).

    data: full ENIP frame (24-byte header + CPF payload).
    Returns FingerprintResult(confidence='high') on success, None on parse error.
    """
    if len(data) < 26:
        return None
    cmd = struct.unpack_from('<H', data, 0)[0]
    if cmd != 0x0063:
        return None
    payload_len = struct.unpack_from('<H', data, 2)[0]
    if len(data) < 24 + payload_len or payload_len < 2:
        return None
    payload = data[24:24 + payload_len]
    item_count = struct.unpack_from('<H', payload, 0)[0]
    pos = 2
    for _ in range(item_count):
        if pos + 4 > len(payload):
            break
        item_type = struct.unpack_from('<H', payload, pos)[0]
        item_len  = struct.unpack_from('<H', payload, pos + 2)[0]
        item_data = payload[pos + 4: pos + 4 + item_len]
        pos += 4 + item_len
        if item_type != 0x000C:   # not Identity Item
            continue
        # Identity Item layout (all LE, starting at offset 0):
        # ProtocolVersion(2) SocketAddr(16) VendorID(2) DeviceType(2)
        # ProductCode(2) Revision(2) Status(2) SerialNumber(4)
        # ProductNameLen(1) ProductName(n) State(1)
        if len(item_data) < 33:
            continue
        try:
            vendor_id  = struct.unpack_from('<H', item_data, 18)[0]
            dev_type   = struct.unpack_from('<H', item_data, 20)[0]
            prod_code  = struct.unpack_from('<H', item_data, 22)[0]
            rev_major  = item_data[24]
            rev_minor  = item_data[25]
            serial_num = struct.unpack_from('<I', item_data, 28)[0]
            name_len   = item_data[32]
            name_raw   = item_data[33: 33 + name_len]
            product_name = name_raw.decode("ascii", errors="replace").strip()
        except (struct.error, IndexError):
            continue
        return FingerprintResult(
            vendor=lookup_odva_vendor(vendor_id),
            model=product_name or f"code_{prod_code}",
            firmware=f"{rev_major}.{rev_minor}",
            serial=f"{serial_num:08X}",
            confidence="high",
            method="enip_list_identity",
            extra={"vendor_id": vendor_id, "device_type": dev_type, "product_code": prod_code},
        )
    return None


# ── Modbus FC43 MEI Read Device Identification parser ─────────────────────────

def parse_modbus_fc43_mei(pdu: bytes) -> Optional[FingerprintResult]:
    """Parse a Modbus FC43 MEI Read Device Identification PDU (everything after MBAP).

    Returns FingerprintResult on success, None if the PDU is invalid or an exception.
    """
    if len(pdu) < 8:
        return None
    if pdu[0] & 0x80:   # exception response bit set
        return None
    if pdu[0] != 0x2B or pdu[1] != 0x0E:
        return None
    num_objs = pdu[6]
    pos = 7
    objects: dict[int, str] = {}
    for _ in range(num_objs):
        if pos + 2 > len(pdu):
            break
        obj_id  = pdu[pos]
        obj_len = pdu[pos + 1]
        if pos + 2 + obj_len > len(pdu):
            break
        obj_val = pdu[pos + 2: pos + 2 + obj_len].decode("ascii", errors="replace")
        objects[obj_id] = obj_val
        pos += 2 + obj_len
    if not objects:
        return None
    vendor   = objects.get(0x00, "unknown")
    model    = objects.get(0x01, "unknown")
    firmware = objects.get(0x02, "unknown")
    confidence = "high" if vendor != "unknown" and model != "unknown" else "medium"
    return FingerprintResult(
        vendor=vendor,
        model=model,
        firmware=firmware,
        confidence=confidence,
        method="modbus_fc43_mei",
        extra={k: v for k, v in objects.items() if k > 2},
    )


# ── BACnet I-Am APDU parser ───────────────────────────────────────────────────

def parse_bacnet_iam(apdu: bytes) -> Optional[dict]:
    """Parse a BACnet I-Am APDU. Returns {'device_id': int, 'vendor_id': int} or None.

    I-Am: PDU-type=0x10, Service=0x00
    Tags (in order): Object-Identifier, Max-APDU-Length, Segmentation, VendorID
    """
    if len(apdu) < 4 or apdu[0] != 0x10 or apdu[1] != 0x00:
        return None
    pos = 2
    device_id: Optional[int] = None
    vendor_id:  Optional[int] = None
    try:
        # Object Identifier (app tag 12 = 0xC4, 4 bytes)
        if pos + 5 <= len(apdu) and apdu[pos] == 0xC4:
            raw = struct.unpack_from('>I', apdu, pos + 1)[0]
            if (raw >> 22) & 0x3FF == 8:   # device object type
                device_id = raw & 0x3FFFFF
            pos += 5
        # Max-APDU-Length (app tag 2 = UINT, variable length)
        if pos < len(apdu) and (apdu[pos] & 0xF0) == 0x20:
            tag_len = apdu[pos] & 0x07
            pos += 1 + tag_len
        # Segmentation (app tag 9 = ENUMERATED, 1 byte)
        if pos < len(apdu) and (apdu[pos] & 0xF8) == 0x90:
            pos += 2
        # VendorID (app tag 2 = UINT)
        if pos < len(apdu):
            if apdu[pos] == 0x21 and pos + 2 <= len(apdu):
                vendor_id = apdu[pos + 1]
            elif apdu[pos] == 0x22 and pos + 3 <= len(apdu):
                vendor_id = struct.unpack_from('>H', apdu, pos + 1)[0]
    except (IndexError, struct.error):
        pass
    return {"device_id": device_id, "vendor_id": vendor_id}


# ── S7comm active protocol-identity probe ────────────────────────────────────
# Added Milestone 3 continuation (2026-08-14) — new, not part of the companion fuzzer's original
# fingerprint.py. Ported from a companion fuzzing toolkit (verified against
# source, not reconstructed from memory) and cross-checked against
# a companion fuzzing toolkit's independent is_up() helper, which checks the
# same resp[8]==0x03 condition via a different code path — two independent PoCs agreeing on the
# same byte offset is real corroboration, not just one source trusted blindly.
#
# Purpose: unblock the snap7 count=0xFFFF crash check (the single most destructive check in the
# inventory, deferred at the end of Milestone 3's first pass specifically because it had no
# working fingerprint_precondition). Two benign packets only (COTP CR, S7 Setup Communication) —
# same risk tier as the existing active=True probes above (ENIP List Identity, Modbus FC43 MEI).

import socket as _socket  # local alias — this module otherwise has no socket usage


def _s7_tpkt(cotp_dt_header: bytes, payload: bytes) -> bytes:
    total = 4 + len(cotp_dt_header) + len(payload)
    return struct.pack("!BBH", 0x03, 0x00, total) + cotp_dt_header + payload


_S7_COTP_CR = struct.pack("!BBH", 0x03, 0x00, 22) + bytes(
    [
        0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xC0, 0x01, 0x0A,
        0xC1, 0x02, 0x00, 0x01,
        0xC2, 0x02, 0x00, 0x01,
    ]
)

_S7_SETUP_COMM = _s7_tpkt(
    bytes([0x02, 0xF0, 0x80]),
    bytes(
        [
            0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
            0xF0, 0x00,
            0x00, 0x08,
            0x00, 0x08,
            0x03, 0xC0,
        ]
    ),
)


def _s7_recv_tpkt(sock: "_socket.socket", timeout: float) -> Optional[bytes]:
    sock.settimeout(timeout)
    try:
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                return b""
            hdr += chunk
        if hdr[0] != 0x03:
            return hdr
        claimed = struct.unpack("!H", hdr[2:4])[0]
        rest = claimed - 4
        if rest <= 0:
            return hdr
        body = b""
        while len(body) < rest:
            chunk = sock.recv(min(rest - len(body), 65536))
            if not chunk:
                break
            body += chunk
        return hdr + body
    except _socket.timeout:
        return None
    except (ConnectionResetError, OSError):
        return b""


def probe_s7comm_identity(host: str, port: int = 102, timeout: float = 5.0) -> FingerprintResult:
    """Active S7comm protocol-identity probe: COTP CR/CC handshake, then S7 Setup Communication
    on a fresh connection. Returns confidence='high' only on a full, positive S7comm Ack-Data
    confirmation (response byte[7]==0x32 protocol ID, byte[8]==0x03 ROSCTR); confidence='none'
    for anything else (unreachable, wrong protocol, timeout, or an ambiguous response) — this
    function does not guess, a partial/unclear result is treated the same as no match at all,
    consistent with fingerprint_precondition's fail-closed design (Check.fingerprint_matches).
    """
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_S7_COTP_CR)
        cc = _s7_recv_tpkt(sock, timeout)
        if not cc or len(cc) < 6 or cc[5] != 0xD0:
            return FingerprintResult(confidence="none", method="s7comm_identity_no_cotp_cc")
    except OSError:
        return FingerprintResult(confidence="none", method="s7comm_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # Fresh connection for Setup Comm — matches the source PoC's own approach (the COTP
    # handshake above is only used to confirm layer-4 reachability before spending a second
    # connection on the S7-specific step).
    sock2 = None
    try:
        sock2 = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock2.settimeout(timeout)
        sock2.connect((host, port))
        sock2.sendall(_S7_COTP_CR)
        cc2 = _s7_recv_tpkt(sock2, timeout)
        if not cc2 or len(cc2) < 6 or cc2[5] != 0xD0:
            return FingerprintResult(confidence="none", method="s7comm_identity_no_cotp_cc_fresh")
        sock2.sendall(_S7_SETUP_COMM)
        resp = _s7_recv_tpkt(sock2, timeout)
    except OSError:
        return FingerprintResult(confidence="none", method="s7comm_identity_unreachable_fresh")
    finally:
        if sock2 is not None:
            try:
                sock2.close()
            except OSError:
                pass

    if resp and len(resp) > 8 and resp[7] == 0x32 and resp[8] == 0x03:
        return FingerprintResult(
            vendor="unknown",  # confirms the PROTOCOL, not a hardware vendor — see the
            # protocol_probe precondition design note in check.py: this is deliberately NOT a
            # vendor-identity claim, just "this is genuinely S7comm."
            confidence="high",
            method="s7comm_identity",
        )
    return FingerprintResult(confidence="none", method="s7comm_identity_no_ack_data")


# ── Modbus active protocol-identity probe ────────────────────────────────────
# Added Milestone 3 continuation (2026-08-14), same session as probe_s7comm_identity — same
# underlying problem recurred immediately: the OpenPLC v4 Modbus multi-ADU hang check (destructive)
# has no hardware-vendor identity to narrow on either (it's a software server plugin, runs on
# arbitrary hardware), and protocol_only is disallowed on destructive checks. Applying the same
# fix: real narrowing via "does this genuinely speak Modbus TCP" rather than a vendor lookup —
# can't pin down which server library, but does exclude non-Modbus services, dead targets, and
# unrelated devices on the port, which is the actual safety property fingerprint_precondition
# exists for.


def probe_modbus_identity(host: str, port: int = 502, timeout: float = 5.0) -> FingerprintResult:
    """Active Modbus TCP protocol-identity probe: one valid FC03 (Read Holding Registers)
    request with a distinctive transaction ID, confirming a well-formed response that echoes
    that exact TID and carries a plausible function-code byte (0x03 success or 0x83 exception —
    either confirms a real Modbus stack processed the request; anything else, or no response,
    does not). confidence='high' only on that positive confirmation; confidence='none' for
    anything else, fail-closed like probe_s7comm_identity."""
    tid = 0x5A5A  # distinctive, unlikely to collide with anything else in flight
    pdu = struct.pack(">BHH", 0x03, 0x0000, 0x0001)  # FC03, start addr=0, qty=1
    payload = struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), 0x01) + pdu

    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(payload)
        response = sock.recv(256)
    except OSError:
        return FingerprintResult(confidence="none", method="modbus_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if len(response) < 8:
        return FingerprintResult(confidence="none", method="modbus_identity_short_response")

    resp_tid = struct.unpack_from(">H", response, 0)[0]
    resp_fc = response[7]
    if resp_tid == tid and resp_fc in (0x03, 0x83):
        return FingerprintResult(
            vendor="unknown",  # confirms the PROTOCOL, not a hardware/library vendor — same
            # deliberate non-claim as probe_s7comm_identity's vendor field.
            confidence="high",
            method="modbus_identity",
        )
    return FingerprintResult(confidence="none", method="modbus_identity_mismatch")


def probe_modbus_device_identity(host: str, port: int = 502, timeout: float = 5.0) -> FingerprintResult:
    """Active Modbus vendor/product identity probe via the standard Read Device Identification
    service (Function Code 0x2B, MEI Type 0x0E — Modbus Application Protocol V1.1b3 §6.21),
    requesting the Basic device ID category (VendorName/ProductCode/MajorMinorRevision) starting
    at object 0x00. Delegates parsing to the already-existing parse_modbus_fc43_mei() (ported
    from the companion fuzzer's original core/fingerprint.py, but never wired to a live probe until now —
    2026-08-16, side-quest from the GE Multilin 850 check). Optional service, not universally
    implemented (confirmed: GE Multilin's own 850/8-Series does NOT support it) — a device that
    doesn't implement it returns an ILLEGAL FUNCTION exception, which fails closed here exactly
    like an unreachable target, not a crash or a guess."""
    tid = 0x2B0E  # distinctive
    pdu = bytes([0x2B, 0x0E, 0x01, 0x00])  # MEI=Read Device ID, category=Basic, start object=0
    payload = struct.pack(">HHHB", tid, 0x0000, 1 + len(pdu), 0x01) + pdu

    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(payload)
        response = sock.recv(512)
    except OSError:
        return FingerprintResult(confidence="none", method="modbus_device_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if len(response) < 8:
        return FingerprintResult(confidence="none", method="modbus_device_identity_short_response")
    if struct.unpack_from(">H", response, 0)[0] != tid:
        return FingerprintResult(confidence="none", method="modbus_device_identity_tid_mismatch")

    result = parse_modbus_fc43_mei(response[7:])
    if result is None:
        return FingerprintResult(confidence="none", method="modbus_device_identity_no_parse")
    return result


# ── OPC-UA active protocol-identity probe ────────────────────────────────────
# Added same session as the OPC-UA anon-write checks (2026-08-14). Unlike S7comm/Modbus, this
# one uses the asyncua library (decided 2026-08-14 — see 00-PROJECT-CHARTER.md § Scope) rather
# than a hand-rolled wire parser, via asyncua.sync's synchronous wrapper API — verified against
# a REAL asyncua Server instance (not a hand-built mock) before writing this, confirming
# connect_and_get_server_endpoints() is the right call and returns a non-empty list on success.


def probe_opcua_identity(host: str, port: int = 4840, timeout: float = 5.0) -> FingerprintResult:
    """Active OPC-UA protocol-identity probe: a GetEndpoints call (standard OPC-UA discovery
    service — Hello/Acknowledge + GetEndpoints, no session or auth required) via asyncua's sync
    client wrapper. confidence='high' if at least one endpoint is returned; confidence='none'
    otherwise (unreachable, wrong protocol, or no endpoints) — fail-closed, same as the other
    protocol_probe functions."""
    try:
        from asyncua.sync import Client as SyncClient
    except ImportError:
        return FingerprintResult(confidence="none", method="opcua_identity_asyncua_not_installed")

    url = f"opc.tcp://{host}:{port}"
    client = None
    try:
        client = SyncClient(url=url, timeout=timeout)
        endpoints = client.connect_and_get_server_endpoints()
    except Exception:
        return FingerprintResult(confidence="none", method="opcua_identity_unreachable")
    finally:
        # SyncClient runs its own background ThreadLoop — never explicitly stopping it leaves
        # a non-daemon thread alive and the process hanging on exit (found via test, not
        # assumed: this exact symptom showed up in tests/smoke_test_milestone3_opcua.py).
        if client is not None:
            try:
                client.disconnect()
            except Exception:
                pass

    if endpoints:
        # GetEndpoints is unauthenticated, and each EndpointDescription carries an
        # ApplicationDescription (ApplicationUri / ProductUri / ApplicationName) + EndpointUrl that
        # often identify the vendor+product without a session — e.g. CODESYS Control embeds an OPC UA
        # server whose ApplicationUri/ProductUri name "CODESYS" (the companion fuzzer handoff 2026-10-08,
        # a companion fuzzing toolkit: the richest UNAUTH identity vector for modern
        # enforced-default CODESYS, which is silent on the legacy UDP 1740 name service). Extraction
        # is best-effort and fully guarded: any shape mismatch falls back to the verified
        # protocol-only result (confidence high, vendor unknown) rather than regressing.
        # KEEP THIS SESSION-FREE: connect_and_get_server_endpoints() = temp secure channel +
        # GetEndpoints, NO CreateSession. Do NOT add a Server/ServerStatus/BuildInfo version read
        # here — it needs a session, is refused by CODESYS's enforced-default no-anonymous policy,
        # and if retried would feed OPC-UA session exhaustion (lab-notes/icsfuzzer-coordination.md).
        # BuildInfo/version is a relaxed-or-credentialed-unit follow-on, not a default-unit probe.
        app_uri = product_uri = app_name = endpoint_url = ""
        try:
            for ep in endpoints:
                endpoint_url = endpoint_url or str(getattr(ep, "EndpointUrl", "") or "")
                srv = getattr(ep, "Server", None)
                if srv is None:
                    continue
                app_uri = app_uri or str(getattr(srv, "ApplicationUri", "") or "")
                product_uri = product_uri or str(getattr(srv, "ProductUri", "") or "")
                name_obj = getattr(srv, "ApplicationName", None)
                app_name = app_name or str(getattr(name_obj, "Text", "") or name_obj or "")
                if app_uri and product_uri and app_name:
                    break
        except Exception:
            app_uri = product_uri = app_name = endpoint_url = ""

        extra = {k: v for k, v in (("application_uri", app_uri), ("product_uri", product_uri),
                                   ("application_name", app_name), ("endpoint_url", endpoint_url)) if v}
        blob = " ".join((app_uri, product_uri, app_name)).lower()
        # 3S-Smart Software Solutions is the maker of CODESYS; "codesys"/"3s"/"smart software" all occur.
        if "codesys" in blob or "3s-smart" in blob or "smart software" in blob:
            # Prefer the product name from the ProductUri (urn:<vendor>:<product>:...), URL-decoded,
            # over the ApplicationName ("OPCUAServer@<host>") — validated live 2026-10-08 against
            # CODESYS Control 3.5.22: product_uri "urn:CODESYS GmbH:CODESYS Control for Linux SL:..."
            model = app_name or "unknown"
            try:
                from urllib.parse import unquote
                parts = [unquote(p) for p in (product_uri or "").split(":")]
                if len(parts) >= 3 and parts[0] == "urn" and parts[2]:
                    model = parts[2]            # the product segment, e.g. "CODESYS Control for Linux SL"
            except Exception:
                pass
            return FingerprintResult(
                vendor="CODESYS", model=model, confidence="high",
                method="opcua_identity_codesys", extra=extra,
            )
        return FingerprintResult(
            vendor="unknown",  # protocol confirmed; vendor not asserted unless the descriptors name it.
            confidence="high", method="opcua_identity", extra=extra,
        )
    return FingerprintResult(confidence="none", method="opcua_identity_no_endpoints")


# ── CODESYS V3 gateway (TCP 11740) presence probe ────────────────────────────
# Added 2026-10-08 from the the companion fuzzer CODESYS live-validation handoff
# (a companion fuzzing toolkit). Modern enforced-default CODESYS (3.5.17+) is SILENT
# on the legacy UDP 1740 name service (see core/discovery.py codesys_v3_broadcast_scan caveat), so
# TCP surfaces are the reliable modern tell. The embedded CODESYS gateway / block driver
# (CmpBlkDrvTcp) listens on TCP 11740 and, on the validated 3.5.22 runtime, ACCEPTS connections with
# NO banner and speaks its own framed gateway protocol (NOT the UDP name grammar). That protocol is
# not yet reverse-engineered, so this is deliberately a PORT-PRESENCE heuristic only — a bare TCP
# connect — NOT a protocol confirmation; hence confidence "low". No guessed handshake is sent (rigor
# gate: we do not ship an unvalidated frame). Open 11740 + OPC UA on 4840 (probe_opcua_identity) +
# UDP 1740 bound is the strong modern CODESYS correlation. Deepening to read the Identification
# payload (node/device/vendor/target_version) over 11740 needs the CmpBlkDrvTcp protocol RE'd
# against the coordinated live runtime — scoped follow-on, not built.
def probe_codesys_gateway(host: str, port: int = 11740, timeout: float = 5.0) -> FingerprintResult:
    """TCP 11740 presence check for the CODESYS V3 gateway (CmpBlkDrvTcp). A successful connect is a
    low-confidence CODESYS-V3 indicator (the gateway is banner-less and its frame grammar is not yet
    RE'd, so this cannot confirm the protocol). Fail-closed: confidence 'none' if unreachable."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
    except OSError:
        return FingerprintResult(confidence="none", method="codesys_gateway_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return FingerprintResult(
        vendor="unknown",  # port-presence only; not asserting vendor from a bare connect.
        confidence="low", method="codesys_gateway_port_open",
        extra={"protocol": "codesys_v3", "port": port,
               "note": "TCP 11740 open = CmpBlkDrvTcp gateway likely; banner-less, grammar not RE'd"},
    )


# ── PCOM/TCP (Unitronics) active protocol-identity probe ─────────────────────
# Added 2026-08-14 to unblock the CVE-2023-6448 default-password check (default-credentials
# sweep, high-priority KEV finding) — see core/pcom_tcp.py for the wire-format source and
# provenance (Claroty Team82's PCOM-Tools, reverse-engineered from real packet captures).


def probe_pcom_tcp_identity(host: str, port: int = 20256, timeout: float = 5.0) -> FingerprintResult:
    """Active PCOM/TCP protocol-identity probe: sends a 'Check Password' request with a
    deliberately WRONG dummy credential (not the real default "1111") and confirms a
    well-formed PCOM response comes back — confidence='high' if the response parses as valid
    PCOM (magic bytes + opcode 0x82), regardless of whether that dummy credential happened to be
    accepted or rejected. This deliberately does NOT test the real default password as part of
    fingerprinting — that's the actual check's job (checks/pcom-tcp/native/
    unitronics_default_password.py), not this identity probe's."""
    from core.pcom_tcp import check_password

    result = check_password(host, port, password="__icsscanner_probe__", timeout=timeout)
    if result is None:
        return FingerprintResult(confidence="none", method="pcom_tcp_identity_not_pcom")
    return FingerprintResult(vendor="unknown", confidence="high", method="pcom_tcp_identity")


# ── EtherNet/IP (CIP) active protocol-identity probe ─────────────────────────
# Added 2026-08-14 (default-credentials sweep, Phase 2, Rockwell) to unblock a version-fingerprint
# check for CVE-2021-22681. Unlike PCOM/TCP, EtherNet/IP's List Identity service (command 0x0063)
# is a published ODVA standard, not reverse-engineered — this project already had the response
# PARSER (parse_enip_list_identity, above, ported from the companion fuzzer in Milestone 0); this adds the
# active send/receive wrapper around it.

_ENIP_LIST_IDENTITY_REQUEST = struct.pack(
    "<HHIIQI",
    0x0063,  # Command: ListIdentity
    0,       # Length: 0 (no data in the request)
    0,       # Session handle
    0,       # Status
    0,       # Sender context (8 bytes)
    0,       # Options
)


def probe_enip_identity(host: str, port: int = 44818, timeout: float = 5.0) -> FingerprintResult:
    """Active EtherNet/IP identity probe: a standard List Identity request (command 0x0063,
    no session required — this is explicitly a discovery/unconnected service in the CIP spec).
    Delegates parsing to parse_enip_list_identity(), which already yields vendor/model/firmware
    at confidence='high' on a well-formed response."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_ENIP_LIST_IDENTITY_REQUEST)
        response = sock.recv(1024)
    except OSError:
        return FingerprintResult(confidence="none", method="enip_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    result = parse_enip_list_identity(response)
    if result is None:
        return FingerprintResult(confidence="none", method="enip_identity_no_parse")
    return result


# ── MSSQL (TDS) active protocol-identity probe ────────────────────────────────
# Added 2026-08-14 (default-credentials sweep, Phase 5, Wonderware Historian CVE-2017-5155) —
# several ICS products vendor a SQL Server backend with default logins (Historian, and Siemens
# WinCC's still-open CVE-2010-2772 candidate). Same dummy-wrong-credential pattern as
# probe_pcom_tcp_identity: a deliberately bogus login confirms genuine TDS/SQL Server via the
# SPECIFIC authentication-rejection behavior (pymssql.OperationalError), distinct from a generic
# connection failure (wrong protocol, unreachable) — without testing any real default credential
# as a side effect of fingerprinting.


# DB-Lib/FreeTDS error codes observed (verified 2026-08-14 against this environment's pymssql)
# to mean "never reached a real SQL Server" — connection-level failures, not an auth rejection
# from an actual server. 20009 = "Unable to connect" (nothing listening / connection refused),
# 20002 = "Adaptive Server connection failed" (something listening but not real TDS — confirmed
# against a garbage-response mock server). Widened with a couple of other well-known DB-Lib
# connection-tier codes (20003 unable to connect to socket, 20004 read failed, 20006 write
# failed, 20017 unexpected EOF) that share the same category even though not individually
# reproduced in this environment. IMPORTANT CAVEAT: this environment has no real SQL Server to
# test against, so the actual positive case (a genuine login-rejection code from a real server,
# commonly SQL Server engine error 18456) has NOT been observed directly — the classification
# assumes any OperationalError NOT matching this known-connection-failure set is a real server
# interaction, which is the safer direction to be wrong in (a false "high confidence" from an
# untested code is more recoverable than silently mis-scoping a real check), but should be
# revisited if this check ever produces a surprising result against real hardware.
_MSSQL_CONNECTION_LEVEL_DBLIB_CODES = {20002, 20003, 20004, 20006, 20009, 20017}


def _mssql_error_code(exc: Exception):
    """Extract the numeric DB-Lib error code from a pymssql.OperationalError, if present.
    Verified shape (2026-08-14): exc.args == ((code, message_bytes),)."""
    try:
        return exc.args[0][0]
    except (IndexError, TypeError):
        return None


def _mssql_is_connection_level_error(exc: Exception) -> bool:
    code = _mssql_error_code(exc)
    return code in _MSSQL_CONNECTION_LEVEL_DBLIB_CODES if code is not None else False


def probe_mssql_identity(host: str, port: int = 1433, timeout: float = 5.0) -> FingerprintResult:
    """Active MSSQL identity probe: a login attempt with a deliberately wrong dummy credential.
    confidence='high' only if the server responds with a genuine SQL-Server-level auth rejection
    (not a DB-Lib connection-level failure — see _mssql_is_connection_level_error, and its
    caveat about not having a real SQL Server available to verify the positive case against) or
    even accepts it (unlikely with this dummy value, but still confirms identity);
    confidence='none' otherwise (unreachable, wrong protocol, timeout)."""
    try:
        import pymssql
    except ImportError:
        return FingerprintResult(confidence="none", method="mssql_identity_pymssql_not_installed")

    conn = None
    try:
        conn = pymssql.connect(
            server=host, port=str(port), user="__icsscanner_probe__", password="__icsscanner_probe__",
            timeout=timeout, login_timeout=timeout,
        )
        return FingerprintResult(vendor="unknown", confidence="high", method="mssql_identity")
    except pymssql.OperationalError as e:
        if _mssql_is_connection_level_error(e):
            return FingerprintResult(confidence="none", method="mssql_identity_connection_level_error")
        return FingerprintResult(vendor="unknown", confidence="high", method="mssql_identity")
    except Exception:
        return FingerprintResult(confidence="none", method="mssql_identity_unreachable")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ── BACnet active protocol-identity probe ─────────────────────────────────────
# Added 2026-08-16 — ported from a companion fuzzing toolkit's fingerprint()
# method (read directly, not reconstructed from memory) after reviewing that sibling project for
# the generic-fingerprinter side-quest. Who-Is (unicast) -> I-Am -> three ReadProperty requests
# for Vendor-Name(121)/Model-Name(70)/Firmware-Revision(44) on the responding device object.
# Reuses parse_bacnet_iam(), already present in this file but previously unwired to any live
# probe (same dormant-code situation as parse_modbus_fc43_mei above).

_BACNET_PROP_VENDOR_NAME = 121
_BACNET_PROP_MODEL_NAME = 70
_BACNET_PROP_FIRMWARE_REVISION = 44
_BACNET_OBJ_DEVICE = 8
_BACNET_SVC_READ_PROPERTY = 0x0C
_BACNET_USVC_WHO_IS = 0x08


def _bacnet_bvll(func: int, data: bytes) -> bytes:
    return bytes([0x81, func]) + struct.pack(">H", 4 + len(data)) + data


def _bacnet_npdu(ctrl: int = 0x04) -> bytes:
    return bytes([0x01, ctrl])


def _bacnet_pkt(ctrl: int, apdu: bytes, func: int = 0x0A) -> bytes:  # 0x0A = BVLL Unicast
    return _bacnet_bvll(func, _bacnet_npdu(ctrl) + apdu)


def _bacnet_apdu_confirmed(service: int, invoke_id: int, data: bytes = b"", max_apdu: int = 0x05) -> bytes:
    return bytes([0x00, max_apdu, invoke_id & 0xFF, service]) + data


def _bacnet_apdu_unconfirmed(service: int, data: bytes = b"") -> bytes:
    return bytes([0x10, service]) + data


def _bacnet_ctx_tag(ctx: int, data: bytes) -> bytes:
    n = len(data)
    if n > 4:
        return bytes([(ctx << 4) | 0x08 | 5, n]) + data
    return bytes([(ctx << 4) | 0x08 | n]) + data


def _bacnet_prop_ctx_tag(ctx: int, prop_id: int) -> bytes:
    if prop_id <= 0xFF:
        return bytes([(ctx << 4) | 0x08 | 1, prop_id])
    return bytes([(ctx << 4) | 0x08 | 2]) + struct.pack(">H", prop_id)


def _bacnet_obj_id_bytes(obj_type: int, instance: int) -> bytes:
    return struct.pack(">I", (obj_type << 22) | (instance & 0x3FFFFF))


def _bacnet_who_is() -> bytes:
    return _bacnet_pkt(0x00, _bacnet_apdu_unconfirmed(_BACNET_USVC_WHO_IS))


def _bacnet_read_property(obj_type: int, instance: int, prop_id: int, invoke_id: int = 1) -> bytes:
    body = _bacnet_ctx_tag(0, _bacnet_obj_id_bytes(obj_type, instance))
    body += _bacnet_prop_ctx_tag(1, prop_id)
    return _bacnet_pkt(0x00, _bacnet_apdu_confirmed(_BACNET_SVC_READ_PROPERTY, invoke_id, body))


def _extract_bacnet_string(frame: bytes) -> Optional[str]:
    """Extract the first BACnet application-tag-7 (character string) value from a raw UDP
    Complex-ACK frame. Skips BVLL(4)+NPDU(2)+APDU header(3) = 9 bytes."""
    if len(frame) < 10:
        return None
    data = frame[9:]
    pos = 0
    while pos < len(data):
        tag = data[pos]
        tag_num = (tag >> 4) & 0x0F
        lvt = tag & 0x07
        if (tag & 0x08) == 0 and tag_num == 7:
            pos += 1
            if lvt < 5:
                str_len = lvt
            elif lvt == 5 and pos < len(data):
                str_len = data[pos]
                pos += 1
            else:
                break
            if pos + str_len > len(data) or str_len < 2:
                break
            encoding = data[pos]
            raw = data[pos + 1: pos + str_len]
            try:
                if encoding == 0:
                    return raw.decode("utf-8", errors="replace").strip()
                return raw.decode("latin-1", errors="replace").strip()
            except Exception:
                return None
        else:
            # Real bug found+fixed here 2026-08-16, porting from the companion fuzzer: the original always
            # `break`s on lvt==6/7 (context-tagged opening/closing brackets, e.g. the ctx3-open/
            # ctx3-close pair that wraps EVERY ReadProperty-ACK's actual value) — meaning this
            # scanner could never reach a real property value at all, only values that happened
            # to appear before the first such bracket. Fixed: an opening/closing tag has no length
            # payload beyond the tag byte itself already consumed by `pos += 1` above, so just
            # keep scanning instead of giving up.
            pos += 1
            if lvt < 5:
                pos += lvt
            elif lvt == 5 and pos < len(data):
                ext_len = data[pos]
                pos += 1 + ext_len
            elif lvt in (6, 7):
                pass  # opening/closing tag — already consumed, nothing more to skip
            else:
                break
    return None


def probe_bacnet_identity(host: str, port: int = 47808, timeout: float = 2.0) -> FingerprintResult:
    """Active BACnet/IP identity probe: Who-Is (unicast) -> I-Am, then three ReadProperty
    requests for Vendor-Name/Model-Name/Firmware-Revision on the responding device object.
    confidence='high' when both vendor and model resolve; 'medium' when only the I-Am itself
    resolves (device_id/vendor_id known but the property reads didn't fill in text); 'none'
    otherwise, fail-closed like every other probe in this module."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_bacnet_who_is(), (host, port))
        try:
            data, _ = sock.recvfrom(1024)
        except OSError:
            return FingerprintResult(confidence="none", method="bacnet_identity_no_iam")

        if len(data) < 8:
            return FingerprintResult(confidence="none", method="bacnet_identity_short_iam")
        iam_info = parse_bacnet_iam(data[6:])  # strip BVLL(4)+NPDU(2)
        device_id = (iam_info or {}).get("device_id")
        raw_vendor_id = (iam_info or {}).get("vendor_id")
        if device_id is None:
            return FingerprintResult(confidence="none", method="bacnet_identity_no_device_id")

        props: dict = {}
        prop_map = {
            "vendor_name": _BACNET_PROP_VENDOR_NAME,
            "model_name": _BACNET_PROP_MODEL_NAME,
            "firmware": _BACNET_PROP_FIRMWARE_REVISION,
        }
        for key, prop_id in prop_map.items():
            expected_iid = prop_id & 0xFF
            sock.sendto(_bacnet_read_property(_BACNET_OBJ_DEVICE, device_id, prop_id, invoke_id=expected_iid), (host, port))
            try:
                resp, _ = sock.recvfrom(1024)
            except OSError:
                continue
            # BVLL(4)+NPDU(2)+Complex-ACK-APDU-header — pdu-type(1),invoke-id(1),service-choice(1)
            # for a non-segmented response — puts invoke-id at overall offset 7, not the companion fuzzer's
            # original resp[10] (a second real bug caught porting this, alongside the DNP3 TL-byte
            # one above): _extract_bacnet_string() right below already skips exactly frame[9:]
            # (4+2+3), which only makes sense if invoke-id is the 2nd byte of that 3-byte header —
            # i.e. offset 7 — directly contradicting the resp[10] check that used to sit here.
            # Caveat: derived from BACnet Complex-ACK-PDU structure, not a fetched spec doc or
            # tested against real hardware — worth a primary-source/live check before high-stakes
            # use, same as any other unverified-against-real-hardware probe in this module.
            if len(resp) <= 7 or resp[7] != expected_iid:
                continue  # stale/mismatched UDP response — discard, don't misattribute
            txt = _extract_bacnet_string(resp)
            if txt:
                props[key] = txt
    except OSError:
        return FingerprintResult(confidence="none", method="bacnet_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    vendor_name = props.get("vendor_name") or (
        lookup_bacnet_vendor(raw_vendor_id) if raw_vendor_id is not None else "unknown"
    )
    model = props.get("model_name", "unknown")
    firmware = props.get("firmware", "unknown")
    confidence = "high" if (vendor_name != "unknown" and model != "unknown") else "medium"
    return FingerprintResult(
        vendor=vendor_name,
        model=model,
        firmware=firmware,
        confidence=confidence,
        method="bacnet_who_is_read_property",
        extra={"device_id": device_id, "vendor_id": raw_vendor_id},
    )


# ── DNP3 active protocol-identity probe ───────────────────────────────────────
# Added 2026-08-16 — ported from a companion fuzzing toolkit's fingerprint()
# method (read directly). Reads Group 0 Device Attributes (Var 243 = Device Manufacturer's Name,
# Var 245 = Device Model). Group 0 is optional per IEEE 1815 — most field devices don't implement
# it, so a device speaking real DNP3 but not this optional group fails closed the same as an
# unreachable one, not a false negative worth worrying about.
#
# REAL BUG FOUND AND FIXED while porting (not propagated): the companion fuzzer's own fingerprint() builds
# its DNP3 request as `_dll_frame(_app_request(...))` — passing Application Layer bytes straight
# to the Data Link frame builder with NO Transport Layer (TL) byte prepended. Every other request
# builder in that same file (_read_frame) correctly prepends `_tl_byte(...)` first. A frame
# missing its TL byte is malformed — a real outstation would misparse it, not just return an
# unsupported-function response. Fixed here by prepending the TL byte, matching _read_frame's own
# (correct) pattern elsewhere in the same source file.

_DNP3_START = b"\x05\x64"
_DNP3_MASTER_ADDR = 1
_DNP3_OUTSTATION_ADDR = 10
_DNP3_CTRL_UNCONF = 0xC4  # DIR=1,PRM=1,FCB=0,FCV=0,FC=4 (unconfirmed user data)
_DNP3_FC_READ = 0x01


def _dnp3_crc16(data: bytes) -> bytes:
    """CRC-16/DNP: poly=0x3D65 (reflected 0xA6BC), init=0, xorout=0xFFFF, little-endian."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return struct.pack("<H", (crc ^ 0xFFFF) & 0xFFFF)


def _dnp3_dll_frame(user_data: bytes, dst: int = _DNP3_OUTSTATION_ADDR, src: int = _DNP3_MASTER_ADDR, ctrl: int = _DNP3_CTRL_UNCONF) -> bytes:
    length = 5 + len(user_data)
    hdr_body = bytes([length & 0xFF, ctrl, dst & 0xFF, (dst >> 8) & 0xFF, src & 0xFF, (src >> 8) & 0xFF])
    header = _DNP3_START + hdr_body + _dnp3_crc16(_DNP3_START + hdr_body)
    blocks = b""
    for i in range(0, len(user_data), 16):
        chunk = user_data[i : i + 16]
        blocks += chunk + _dnp3_crc16(chunk)
    return header + blocks


def _dnp3_tl_byte(fir: bool = True, fin: bool = True, seq: int = 0) -> bytes:
    return bytes([(fir << 7) | (fin << 6) | (seq & 0x3F)])


def _dnp3_ac_byte(fir: bool = True, fin: bool = True, con: bool = False, uns: bool = False, seq: int = 0) -> int:
    return (fir << 7) | (fin << 6) | (con << 5) | (uns << 4) | (seq & 0x0F)


def _dnp3_app_request(fc: int, objects: bytes = b"", seq: int = 0) -> bytes:
    return bytes([_dnp3_ac_byte(seq=seq), fc]) + objects


def _dnp3_read_group0_request(variation: int, seq: int) -> bytes:
    al = _dnp3_app_request(_DNP3_FC_READ, bytes([0x00, variation, 0x06]), seq=seq)
    return _dnp3_dll_frame(_dnp3_tl_byte(seq=seq) + al)  # bug fix: TL byte now included


def _recv_dnp3(sock: "_socket.socket", timeout: float = 3.0) -> Optional[bytes]:
    """Read one DNP3 DLL frame (10-byte header + data blocks + block CRCs)."""
    buf = b""
    sock.settimeout(timeout)
    try:
        while len(buf) < 10:
            chunk = sock.recv(10 - len(buf))
            if not chunk:
                return None
            buf += chunk
        if buf[:2] != _DNP3_START:
            return None
        dll_len = buf[2]
        user_data = max(0, dll_len - 5)
        n_blocks = (user_data + 15) // 16
        total_with_crc = 10 + user_data + n_blocks * 2
        while len(buf) < total_with_crc:
            chunk = sock.recv(total_with_crc - len(buf))
            if not chunk:
                break
            buf += chunk
    except OSError:
        return None
    return buf


def _dnp3_strip_block_crcs(frame: bytes) -> bytes:
    """Return the frame's user_data (TL+AL bytes) with the 2-byte block CRCs removed. Every
    16 bytes of user_data in a real DNP3 frame is followed by its own CRC — a short response
    (<=16 bytes of user_data) has exactly one, but anything longer (e.g. a vendor/model string
    of more than a few characters, the realistic case this probe actually deals with) spans
    multiple blocks, each with its own CRC interspersed. A second real bug found+fixed 2026-08-16
    porting from the companion fuzzer: _extract_dnp3_string() used to scan the raw framed bytes directly,
    so any string crossing a 16-byte user_data boundary got a stray 2-byte CRC spliced into the
    middle of it — confirmed via a real mock server response with an 18-character vendor name."""
    if len(frame) < 10:
        return b""
    dll_len = frame[2]
    user_data_len = max(0, dll_len - 5)
    pos = 10
    out = bytearray()
    remaining = user_data_len
    while remaining > 0 and pos < len(frame):
        chunk_len = min(16, remaining)
        out += frame[pos : pos + chunk_len]
        pos += chunk_len + 2  # skip this block's 2-byte CRC
        remaining -= chunk_len
    return bytes(out)


def _extract_dnp3_string(frame: bytes, group: int, variation: int) -> Optional[str]:
    """Extract a DNP3 Group 0 Device Attribute string value from a response frame. Skips
    TL(1)+AC(1)+FC(1)=3 bytes of the de-blocked user_data, then scans for the group/variation
    object header (qualifier(1) count_or_index(1) len(1) value)."""
    if not frame or len(frame) < 14:
        return None
    data = _dnp3_strip_block_crcs(frame)[3:]
    i = 0
    while i < len(data) - 4:
        if data[i] == group and data[i + 1] == variation:
            attr_pos = i + 4
            if attr_pos + 1 < len(data):
                str_len = data[attr_pos]
                raw = data[attr_pos + 1 : attr_pos + 1 + str_len]
                try:
                    s = raw.decode("ascii", errors="replace").strip()
                    if len(s) >= 2:
                        return s
                except Exception:
                    pass
        i += 1
    return None


def probe_dnp3_identity(host: str, port: int = 20000, timeout: float = 4.0) -> FingerprintResult:
    """Active DNP3 identity probe: Read Group 0 Var 243 (Device Manufacturer's Name) then
    Var 245 (Device Model). confidence='medium' when the vendor name resolves; 'none' if the
    target doesn't respond to either (unreachable, wrong protocol, or Group 0 not implemented —
    all fail closed identically, matching this module's convention elsewhere)."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        vendor = "unknown"
        model = "unknown"

        sock.sendall(_dnp3_read_group0_request(0xF3, seq=1))  # Var 243 = vendor name
        resp = _recv_dnp3(sock, timeout=timeout)
        if resp:
            txt = _extract_dnp3_string(resp, 0x00, 0xF3)
            if txt:
                vendor = txt

        sock.sendall(_dnp3_read_group0_request(0xF5, seq=2))  # Var 245 = device model
        resp2 = _recv_dnp3(sock, timeout=timeout)
        if resp2:
            txt2 = _extract_dnp3_string(resp2, 0x00, 0xF5)
            if txt2:
                model = txt2
    except OSError:
        return FingerprintResult(confidence="none", method="dnp3_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if vendor == "unknown":
        return FingerprintResult(confidence="none", method="dnp3_identity_group0_unsupported")
    return FingerprintResult(
        vendor=vendor,
        model=model,
        confidence="medium",
        method="dnp3_group0_device_attributes",
    )


# ── SNMP active protocol-identity probe ───────────────────────────────────────
# Added 2026-08-16 — new, no the companion fuzzer precedent (SNMP isn't one of its 10 fuzzed protocols).
# Near-universal on managed industrial network gear (this project already has real checks for a
# lot of it — Antaira, Phoenix Contact FL SWITCH, Hirschmann, Moxa switches). Minimal hand-rolled
# BER/ASN.1 encoder for a single SNMPv1 GetRequest — no new dependency (matches this project's
# stdlib-only convention for hand-rolled protocol clients elsewhere: PCOM/TCP, S7comm COTP).
# community "public" (the overwhelmingly common read-only default) against sysDescr
# (1.3.6.1.2.1.1.1.0) and sysObjectID (1.3.6.1.2.1.1.2.0) — both from the standard MIB-II SNMPv2-MIB,
# present on essentially any SNMP-speaking device regardless of vendor.

_SNMP_SYSDESCR_OID = (1, 3, 6, 1, 2, 1, 1, 1, 0)


def _snmp_ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    encoded = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _snmp_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _snmp_ber_len(len(value)) + value


def _snmp_encode_oid(oid: tuple) -> bytes:
    body = bytes([oid[0] * 40 + oid[1]])
    for n in oid[2:]:
        if n < 0x80:
            body += bytes([n])
        else:
            chunks = []
            while n:
                chunks.insert(0, n & 0x7F)
                n >>= 7
            body += bytes([c | 0x80 for c in chunks[:-1]] + [chunks[-1]])
    return _snmp_tlv(0x06, body)  # OBJECT IDENTIFIER


def _snmp_get_request(oid: tuple, community: bytes = b"public", request_id: int = 0x1C15) -> bytes:
    null_val = _snmp_tlv(0x05, b"")  # NULL
    varbind = _snmp_tlv(0x30, _snmp_encode_oid(oid) + null_val)  # SEQUENCE
    varbind_list = _snmp_tlv(0x30, varbind)
    pdu_body = (
        _snmp_tlv(0x02, struct.pack(">i", request_id))  # request-id, INTEGER
        + _snmp_tlv(0x02, b"\x00")  # error-status = 0
        + _snmp_tlv(0x02, b"\x00")  # error-index = 0
        + varbind_list
    )
    pdu = _snmp_tlv(0xA0, pdu_body)  # GetRequest-PDU
    message = (
        _snmp_tlv(0x02, b"\x00")  # version = 0 (SNMPv1)
        + _snmp_tlv(0x04, community)  # OCTET STRING community
        + pdu
    )
    return _snmp_tlv(0x30, message)


def _snmp_parse_ber_len(data: bytes, pos: int):
    length = data[pos]
    pos += 1
    if length & 0x80:
        n_bytes = length & 0x7F
        length = int.from_bytes(data[pos : pos + n_bytes], "big")
        pos += n_bytes
    return length, pos


def _snmp_parse_response(data: bytes, expected_request_id: int,
                         expected_oid: Optional[tuple] = None) -> Optional[str]:
    """Extract the first varbind's OCTET STRING value from a GetResponse-PDU, verifying the request-id
    echoes back exactly (same anti-stale-response discipline as the other UDP probes here). When
    expected_oid is given, also verify the response varbind is FOR that OID — a device (or a lax proxy)
    that answers every GET with the same catch-all value (e.g. sysDescr) must not be mistaken for one
    that actually populates a specific OID (this is what keeps the NTCIP module-table probe from
    matching a plain SNMP agent). Deliberately minimal — walks only as far as the first varbind's value,
    doesn't build a general BER parser."""
    try:
        pos = 0
        if data[pos] != 0x30:
            return None
        _, pos = _snmp_parse_ber_len(data, pos + 1)
        if data[pos] != 0x02:  # version
            return None
        _, pos = _snmp_parse_ber_len(data, pos + 1)
        pos += 1  # skip version value byte (always 1 byte for v1/v2c)
        if data[pos] != 0x04:  # community
            return None
        clen, pos = _snmp_parse_ber_len(data, pos + 1)
        pos += clen
        if data[pos] not in (0xA2, 0xA0):  # GetResponse-PDU (0xA2) — accept 0xA0 leniently too
            return None
        _, pos = _snmp_parse_ber_len(data, pos + 1)
        if data[pos] != 0x02:  # request-id
            return None
        idlen, pos = _snmp_parse_ber_len(data, pos + 1)
        resp_id = int.from_bytes(data[pos : pos + idlen], "big", signed=True)
        pos += idlen
        if resp_id != expected_request_id:
            return None
        # error-status, error-index
        for _ in range(2):
            if data[pos] != 0x02:
                return None
            elen, pos = _snmp_parse_ber_len(data, pos + 1)
            pos += elen
        if data[pos] != 0x30:  # varbind-list
            return None
        _, pos = _snmp_parse_ber_len(data, pos + 1)
        if data[pos] != 0x30:  # varbind
            return None
        _, pos = _snmp_parse_ber_len(data, pos + 1)
        if data[pos] != 0x06:  # OID
            return None
        oid_tlv_start = pos
        oidlen, pos = _snmp_parse_ber_len(data, pos + 1)
        resp_oid_tlv = data[oid_tlv_start:pos + oidlen]
        pos += oidlen
        if expected_oid is not None and resp_oid_tlv != _snmp_encode_oid(expected_oid):
            return None  # the response varbind is for a different OID than we asked for
        value_tag = data[pos]
        vlen, pos = _snmp_parse_ber_len(data, pos + 1)
        if value_tag != 0x04:  # OCTET STRING (sysDescr) — NoSuchObject/other types return None
            return None
        return data[pos : pos + vlen].decode("ascii", errors="replace").strip()
    except (IndexError, ValueError):
        return None


def probe_snmp_identity(host: str, port: int = 161, timeout: float = 3.0) -> FingerprintResult:
    """Active SNMP identity probe: a single SNMPv1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0),
    community "public". sysDescr is free text (vendor-defined format, not a structured
    vendor/model split like the other probes here) — returned whole in `model` with `vendor`
    left "unknown" rather than guessing where to split it; a human/check author reads the actual
    string. confidence='medium' (not 'high') to reflect that ambiguity. confidence='none' if
    unreachable, the community string is wrong, or the device doesn't speak SNMP at all — SNMP
    silently drops requests with a bad community string rather than rejecting them, so a timeout
    here is indistinguishable from "wrong community" and both fail closed the same way."""
    request_id = 0x1C15
    payload = _snmp_get_request(_SNMP_SYSDESCR_OID, request_id=request_id)

    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))
        try:
            data, _ = sock.recvfrom(2048)
        except OSError:
            return FingerprintResult(confidence="none", method="snmp_identity_no_response")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    sysdescr = _snmp_parse_response(data, request_id)
    if not sysdescr:
        return FingerprintResult(confidence="none", method="snmp_identity_no_parse")
    return FingerprintResult(
        vendor="unknown",
        model=sysdescr,
        confidence="medium",
        method="snmp_sysdescr",
    )


# PROFINET DCP (Discovery and Configuration Protocol) — genuinely different risk/privilege shape
# from every probe above it in this file (2026-08-17, user: "start PROFINET DCP fingerprint
# probe"). DCP is Ethernet-native (EtherType 0x8892) with NO IP/UDP layer at all — a real DCP
# frame can only be sent/received via a raw AF_PACKET socket, which needs CAP_NET_RAW or root.
# Discussed directly with the user before building (AskUserQuestion): decided to build the probe
# now and have it FAIL CLOSED (confidence="none") whenever the process lacks that privilege,
# rather than gating it behind a new CLI flag or skipping it — same fail-closed philosophy every
# other probe here already has on any failure, just with one more failure mode (insufficient
# privilege) added to the list. This is a real, documented exception to this project's otherwise
# fully-unprivileged probe posture — see 04-USAGE-GUIDE.md.
#
# Wire format verified against scapy's own `scapy.contrib.pnio_dcp`/`pnio` modules (a maintained
# third-party reference implementation, installed locally) rather than guessed — this caught a
# real error in the sibling the companion fuzzer project's own (unported, fuzzing-only) PROFINET DCP code:
# the companion fuzzer's `_DCP_FRAME_IDENTIFY`/`_DCP_FRAME_GET_SET` constants (0xFEFC/0xFEFF) and its
# `_dcp_block()` builder (which omits the mandatory 2-byte block_info field every real DCP block
# carries) both disagree with scapy's reference values. NOT ported from the companion fuzzer as a result —
# this probe's constants and block layout are independently built from the scapy reference.
# Real values used here: Identify-Request FrameID=0xFEFE, Identify-Response FrameID=0xFEFF,
# ServiceType 0x00=Request/0x01=Response Success. A DCP block is
# option(1)+sub_option(1)+dcp_block_length(2,BE)+block_info(2,BE)+payload(dcp_block_length-2
# bytes)+[1 pad byte if dcp_block_length is odd] — dcp_block_length counts block_info+payload,
# not just payload (the companion fuzzer's builder counted payload only and dropped block_info entirely).
#
# Addressing problem, and how it's resolved: DCP has no concept of "the target's IP" at the wire
# level — a real DCP Identify request is sent to the standing multicast MAC
# (01:0e:cf:00:00:00), and on a real segment EVERY reachable PROFINET device answers it, not just
# one. Since this project's Target model is one exact host: (an IP), not a station name or MAC,
# this probe sends the standard Identify-All multicast request, collects every response that
# arrives within the timeout, and accepts only the one whose own IP-Parameter block (option
# 0x01/sub_option 0x02) reports the exact target IP — the same technique a real PROFINET
# engineering tool effectively uses when narrowing a broadcast discovery down to one known
# device. A response from some OTHER device on the same segment answering the same broadcast is
# correctly ignored, not mistaken for the target.
#
# No Profinet vendor-ID registry available offline, so vendor stays "unknown" (same posture as
# probe_snmp_identity's free-text sysDescr) — model is populated from whichever of the "Type of
# Station" (option 0x02/0x01, usually a vendor+product descriptive string) or NameOfStation
# (0x02/0x02) blocks is present; the numeric PROFINET vendor_id/device_id pair (option
# 0x02/0x03) is kept in `extra` for a future lookup table rather than guessed into `vendor`.
#
# Platform assumption (unchanged from the rest of this project): Linux only (WSL2 dev
# environment) — AF_PACKET and the SIOCGIFADDR/SIOCGIFHWADDR ioctls used to auto-detect the
# outbound interface and its MAC are both Linux-specific.

import fcntl  # local import — only this PROFINET section needs raw-socket/ioctl access
import time as _time

_ETH_P_PROFINET = 0x8892
_PROFINET_DCP_MCAST_MAC = bytes.fromhex("010ecf000000")
_SIOCGIFADDR = 0x8915
_SIOCGIFHWADDR = 0x8927

_DCP_IDENTIFY_REQUEST_FRAME_ID = 0xFEFE
_DCP_IDENTIFY_RESPONSE_FRAME_ID = 0xFEFF
_DCP_SVC_ID_IDENTIFY = 0x05
_DCP_SVC_TYPE_REQUEST = 0x00
_DCP_SVC_TYPE_RESPONSE_SUCCESS = 0x01
_DCP_OPT_ALL = 0xFF
_DCP_SUBOPT_ALL = 0xFF
_DCP_OPT_IP = 0x01
_DCP_SUBOPT_IP_PARAMETER = 0x02
_DCP_OPT_DEVICE_PROPERTIES = 0x02
_DCP_SUBOPT_TYPE_OF_STATION = 0x01
_DCP_SUBOPT_NAME_OF_STATION = 0x02
_DCP_SUBOPT_DEVICE_ID = 0x03
_DCP_XID = 0x01C15001

# DCP Set(Control/Signal) — Phase 2 of the PROFINET check-integration plan (2026-08-17). See
# project_icsscanner.md/project_open_tasks.md for the full Phase 1 sourcing trail: the primary
# source is PI/PROFIBUS & PROFINET International's own advisory PISA-001 ("Improper Access
# Control for DCP Services," CWE-862 + CWE-1314 — corrected from an earlier CWE-306 assumption),
# which documents that DCP-Set has no authentication at all. PISA-001's own cited examples are
# DCP-Set(NameOfStation) and DCP-Set(Reset-to-Factory), both of which carry real communication-
# disruption risk the advisory itself describes; decided with the user (AskUserQuestion) to use
# Signal (flash-LED) instead as a safe proxy — same unauthenticated Set code path, same root
# cause, but zero operational impact (no device parameter actually changes).
#
# Wire format verified against TWO independent sources, not guessed: scapy's DCPControlBlock/
# BLOCK_QUALIFIERS (contrib module, already used for the Identify probe) and Wireshark's own
# packet-pn-dcp.c dissector (fetched from its public GitHub mirror) — both agree exactly:
#   - BlockQualifier (0x0000="use temporary"/0x0001="save permanent") sits right after the
#     request's option/sub_option/dcp_block_length header for ANY Set suboption, not just
#     Signal. Pinned to 0x0000 here — never 0x0001 — per the Phase 1 plan's hard requirement
#     that nothing persist across a power cycle (Signal has no persistent state to save anyway,
#     but this keeps the encoding consistent and documents the requirement in the wire code
#     itself, not just prose).
#   - Control/Signal (option=0x05, sub_option=0x03) Set-request block: after BlockQualifier,
#     Wireshark's dissector treats any further bytes as vendor-optional/undecoded — this code
#     sends the minimal valid encoding, BlockQualifier only, nothing else.
#   - Control/Response (option=0x05, sub_option=0x04) Set-RESPONSE acknowledgment block has a
#     DIFFERENT shape from every block `_dcp_parse_blocks()` already handles (that function
#     assumes the generic option+sub_option+length+block_info(2)+payload layout the Identify
#     response uses). A Set-response ack is option(1)+sub_option(1)+dcp_block_length(2)+
#     response_option(1)+response_sub_option(1)+block_error(1)[+1 pad byte, dcp_block_length=3
#     is odd] — the echoed option/suboption IS the payload, there's no block_info field at all.
#     Confirmed identically by scapy's DCPControlBlock fields_desc and Wireshark's
#     PNDCP_SUBOPTION_CONTROL_RESPONSE case — needed its own parser, `_dcp_parse_control_response`,
#     not a reuse of `_dcp_parse_blocks()`.
#
# Real-world behavior of Signal, independently corroborated a third time (not wire-format, but
# confirms it's genuinely benign): a PROFINET Forum thread citing the official PROFINET
# Application Layer protocol spec (PN-AL-protocol_2722_V24MU4_May23.pdf §4.3.1.4.15 — the SAME
# spec version PISA-001 itself names as the one with the actual fix) states an LED should blink
# for 3 seconds at ~1 Hz in response to Signal — a transient, harmless, spec-defined behavior
# every real PROFINET engineering tool triggers routinely, not something this check invents.
#
# GET_SET uses a single FrameID (0xFEFD) for both request and response — unlike Identify's two
# separate IDs, direction is distinguished purely by the ServiceType field.

_DCP_GET_SET_FRAME_ID = 0xFEFD
_DCP_SVC_ID_SET = 0x04
_DCP_OPT_CONTROL = 0x05
_DCP_SUBOPT_CONTROL_SIGNAL = 0x03
_DCP_SUBOPT_CONTROL_RESPONSE = 0x04
_DCP_BLOCK_QUALIFIER_TEMPORARY = 0x0000
_DCP_BLOCK_ERRORS = {
    0x00: "Ok",
    0x01: "Option unsupported",
    0x02: "Suboption unsupported or no DataSet available",
    0x03: "Suboption not set",
    0x04: "Resource Error",
    0x05: "SET not possible by local reasons",
    0x06: "In operation, SET not possible",
}


def _dcp_set_signal_request(xid: int) -> bytes:
    """Builds a DCP Set(Control/Signal) request — the 'flash LED' identify-by-blink command,
    used as a safe proxy for PISA-001's own (riskier) NameOfStation/Reset-to-Factory examples.
    See the module comment above for the full sourcing/design trail."""
    block_qualifier = struct.pack("!H", _DCP_BLOCK_QUALIFIER_TEMPORARY)
    header = struct.pack(
        "!BBIHH",
        _DCP_SVC_ID_SET,
        _DCP_SVC_TYPE_REQUEST,
        xid,
        0,  # reserved
        6,  # dcp_data_length: option+sub_option+dcp_block_length(2)+block_qualifier(2) = 6
    )
    body = struct.pack("!BBH", _DCP_OPT_CONTROL, _DCP_SUBOPT_CONTROL_SIGNAL, 2) + block_qualifier
    return header + body


def _mac_from_frame(data: bytes) -> str:
    """Extracts the source MAC (bytes 6-11 of a raw Ethernet frame) as a colon-hex string. Split
    out as its own function so it's testable without a live raw socket, same reasoning as
    `_dcp_parse_blocks()` being separate from `probe_profinet_dcp()`'s own socket handling."""
    return data[6:12].hex(":")


def _dcp_parse_control_response(data: bytes) -> Optional[int]:
    """Parses a DCP Set-response's Control/Response acknowledgment block(s) — NOT the generic
    block_info+payload shape `_dcp_parse_blocks()` assumes, see the module comment above for why.
    Returns the block_error byte (0x00 = Ok, see `_DCP_BLOCK_ERRORS`) for the ack matching our
    own Signal request, or None if no matching ack block is found (malformed/short input just
    stops the walk early, same fail-soft discipline as `_dcp_parse_blocks()`)."""
    pos = 0
    while pos + 4 <= len(data):
        option = data[pos]
        sub_option = data[pos + 1]
        block_length = struct.unpack_from("!H", data, pos + 2)[0]
        block_start = pos + 4
        block_end = block_start + block_length
        if block_length < 3 or block_end > len(data):
            break
        if option == _DCP_OPT_CONTROL and sub_option == _DCP_SUBOPT_CONTROL_RESPONSE:
            resp_option = data[block_start]
            resp_sub_option = data[block_start + 1]
            block_error = data[block_start + 2]
            if resp_option == _DCP_OPT_CONTROL and resp_sub_option == _DCP_SUBOPT_CONTROL_SIGNAL:
                return block_error
        pos = block_end + (block_length % 2)
    return None


def _dcp_identify_all_request(xid: int) -> bytes:
    header = struct.pack(
        "!BBIHH",
        _DCP_SVC_ID_IDENTIFY,
        _DCP_SVC_TYPE_REQUEST,
        xid,
        0,  # reserved
        4,  # dcp_data_length: option+sub_option+dcp_block_length that follow
    )
    body = struct.pack("!BBH", _DCP_OPT_ALL, _DCP_SUBOPT_ALL, 0)
    return header + body


def _dcp_parse_blocks(data: bytes) -> dict:
    """Walks a DCP response's block list. Each block is option(1)+sub_option(1)+
    dcp_block_length(2,BE)+block_info(2,BE)+payload+[pad byte if dcp_block_length odd] — see the
    module comment above for why this differs from the companion fuzzer's own (unverified) block layout.
    Returns {(option, sub_option): payload_bytes}, deliberately minimal (no recursive/nested
    block types), malformed input just stops the walk early rather than raising."""
    blocks = {}
    pos = 0
    while pos + 4 <= len(data):
        option = data[pos]
        sub_option = data[pos + 1]
        block_length = struct.unpack_from("!H", data, pos + 2)[0]
        block_start = pos + 4
        block_end = block_start + block_length
        if block_length < 2 or block_end > len(data):
            break
        blocks[(option, sub_option)] = data[block_start + 2 : block_end]
        pos = block_end + (block_length % 2)
    return blocks


def _detect_local_ip(host: str) -> Optional[str]:
    """UDP connect() only sets up routing, sends nothing on the wire — safe to use purely to
    learn which local IP/interface the kernel would use to reach `host`."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.connect((host, 1))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _iface_for_ip(local_ip: str) -> Optional[str]:
    probe = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        for _, ifname in _socket.if_nameindex():
            try:
                packed = fcntl.ioctl(
                    probe.fileno(),
                    _SIOCGIFADDR,
                    struct.pack("256s", ifname.encode("ascii")[:15]),
                )
            except OSError:
                continue
            if _socket.inet_ntoa(packed[20:24]) == local_ip:
                return ifname
        return None
    finally:
        probe.close()


def _iface_mac(ifname: str) -> Optional[bytes]:
    probe = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(
            probe.fileno(),
            _SIOCGIFHWADDR,
            struct.pack("256s", ifname.encode("ascii")[:15]),
        )
        return info[18:24]
    except OSError:
        return None
    finally:
        probe.close()


def probe_profinet_dcp(host: str, timeout: float = 3.0, interface: Optional[str] = None) -> FingerprintResult:
    """Active PROFINET DCP identity probe: one Identify-All multicast request, matched back to
    `host` by its own reported IP-Parameter block (see the module comment above for why — DCP
    has no per-target addressing of its own). REQUIRES CAP_NET_RAW/root for the AF_PACKET socket
    this needs; fails closed (confidence="none") rather than raising when that privilege is
    missing, same as every other failure mode here. `interface` can be supplied explicitly
    (e.g. by a check's params); left unset, the outbound interface/MAC toward `host` are
    auto-detected via routing + ioctl (Linux only)."""
    try:
        target_ip = _socket.gethostbyname(host)
    except OSError:
        return FingerprintResult(confidence="none", method="profinet_dcp_no_resolve")

    ifname = interface
    if ifname is None:
        local_ip = _detect_local_ip(target_ip)
        if local_ip is None:
            return FingerprintResult(confidence="none", method="profinet_dcp_no_route")
        ifname = _iface_for_ip(local_ip)
        if ifname is None:
            return FingerprintResult(confidence="none", method="profinet_dcp_no_interface")

    src_mac = _iface_mac(ifname)
    if src_mac is None or len(src_mac) != 6:
        return FingerprintResult(confidence="none", method="profinet_dcp_no_mac")

    payload = _dcp_identify_all_request(_DCP_XID)
    frame = (
        _PROFINET_DCP_MCAST_MAC
        + src_mac
        + struct.pack("!H", _ETH_P_PROFINET)
        + struct.pack("!H", _DCP_IDENTIFY_REQUEST_FRAME_ID)
        + payload
    )
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))

    sock = None
    try:
        try:
            sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(_ETH_P_PROFINET))
            sock.bind((ifname, 0))
        except PermissionError:
            return FingerprintResult(confidence="none", method="profinet_dcp_insufficient_privilege")
        except (OSError, AttributeError):
            # AttributeError: AF_PACKET doesn't exist outside Linux — fail closed, not a crash.
            return FingerprintResult(confidence="none", method="profinet_dcp_socket_error")

        try:
            sock.send(frame)
        except OSError:
            return FingerprintResult(confidence="none", method="profinet_dcp_send_error")

        deadline = _time.monotonic() + timeout
        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                return FingerprintResult(confidence="none", method="profinet_dcp_no_response")
            sock.settimeout(remaining)
            try:
                data = sock.recv(2048)
            except OSError:
                return FingerprintResult(confidence="none", method="profinet_dcp_no_response")

            if len(data) < 16 or data[12:14] != struct.pack("!H", _ETH_P_PROFINET):
                continue
            frame_id_resp = struct.unpack_from("!H", data, 14)[0]
            if frame_id_resp != _DCP_IDENTIFY_RESPONSE_FRAME_ID:
                continue

            dcp = data[16:]
            if len(dcp) < 10:
                continue
            service_id, service_type = dcp[0], dcp[1]
            if service_id != _DCP_SVC_ID_IDENTIFY or service_type != _DCP_SVC_TYPE_RESPONSE_SUCCESS:
                continue
            resp_xid = struct.unpack_from("!I", dcp, 2)[0]
            if resp_xid != _DCP_XID:
                continue
            dcp_data_length = struct.unpack_from("!H", dcp, 8)[0]

            blocks = _dcp_parse_blocks(dcp[10 : 10 + dcp_data_length])
            ip_raw = blocks.get((_DCP_OPT_IP, _DCP_SUBOPT_IP_PARAMETER))
            if not ip_raw or len(ip_raw) < 4 or _socket.inet_ntoa(ip_raw[0:4]) != target_ip:
                continue  # a different device on the segment answered — not our target

            name_raw = blocks.get((_DCP_OPT_DEVICE_PROPERTIES, _DCP_SUBOPT_NAME_OF_STATION))
            type_raw = blocks.get((_DCP_OPT_DEVICE_PROPERTIES, _DCP_SUBOPT_TYPE_OF_STATION))
            device_id_raw = blocks.get((_DCP_OPT_DEVICE_PROPERTIES, _DCP_SUBOPT_DEVICE_ID))

            model = None
            if type_raw:
                model = type_raw.decode("ascii", errors="replace").strip("\x00").strip()
            elif name_raw:
                model = name_raw.decode("ascii", errors="replace").strip("\x00").strip()
            if not model:
                return FingerprintResult(confidence="none", method="profinet_dcp_no_identity_blocks")

            extra = {"mac_address": _mac_from_frame(data)}
            # DCP has no per-target unicast addressing of its own (see the module comment
            # above) — a caller that needs to send the device a Set request (e.g. the Signal
            # check) has to unicast it to this specific MAC, learned here from the Identify
            # exchange, rather than to the DCP multicast address every device would answer.
            if name_raw:
                extra["name_of_station"] = name_raw.decode("ascii", errors="replace").strip("\x00").strip()
            if device_id_raw and len(device_id_raw) >= 4:
                vid, did = struct.unpack_from("!HH", device_id_raw, 0)
                extra["profinet_vendor_id"] = f"0x{vid:04X}"
                extra["profinet_device_id"] = f"0x{did:04X}"

            return FingerprintResult(
                vendor="unknown",
                model=model,
                confidence="medium",
                method="profinet_dcp_identify",
                extra=extra,
            )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


_DCP_SET_XID = 0x01C15002  # distinct from _DCP_XID (Identify) — cheap insurance against any
# ambiguity if an Identify and a Set exchange happen to overlap; frame_id/service_id already
# distinguish them regardless, but a separate xid costs nothing and matches this file's existing
# anti-stale-response discipline everywhere else.


def signal_profinet_device(host: str, timeout: float = 3.0, interface: Optional[str] = None) -> Optional[int]:
    """Public orchestration entry point for the PROFINET DCP Signal check (Phase 3 of the
    check-integration plan, 2026-08-17 — see project_icsscanner.md for the full PISA-001
    sourcing trail). Deliberately the ONLY public function a check module needs to call — Phase
    2's `_dcp_set_signal_request()`/`_dcp_parse_control_response()` stay private, matching this
    project's established "don't reach into another module's private wire-format helpers"
    convention (see checks/snmp/native/snmp_community_default_creds.py's own docstring).

    Reuses `probe_profinet_dcp()` (not a duplicate Identify implementation) to locate the target
    by IP and capture its MAC — a Set request has to be UNICAST to that specific device, unlike
    Identify's multicast-then-match-by-IP.

    Returns the Set-response's block_error byte (0x00 = Ok = accepted with no authentication
    challenge, see `_DCP_BLOCK_ERRORS` for the full enum) for our own Signal request, or None if
    the device couldn't be located, the process lacks CAP_NET_RAW, or no ack arrived in time.
    Deliberately does NOT distinguish those None cases from each other — the caller (a
    CheckStatus-aware check module) is responsible for deciding what None means in its own
    terms, since this module intentionally has no CheckStatus concept of its own."""
    located = probe_profinet_dcp(host, timeout=timeout, interface=interface)
    if located.confidence == "none" or "mac_address" not in located.extra:
        return None
    target_mac = bytes.fromhex(located.extra["mac_address"].replace(":", ""))

    try:
        target_ip = _socket.gethostbyname(host)
    except OSError:
        return None

    ifname = interface
    if ifname is None:
        local_ip = _detect_local_ip(target_ip)
        if local_ip is None:
            return None
        ifname = _iface_for_ip(local_ip)
        if ifname is None:
            return None

    src_mac = _iface_mac(ifname)
    if src_mac is None or len(src_mac) != 6:
        return None

    payload = _dcp_set_signal_request(_DCP_SET_XID)
    frame = (
        target_mac
        + src_mac
        + struct.pack("!H", _ETH_P_PROFINET)
        + struct.pack("!H", _DCP_GET_SET_FRAME_ID)
        + payload
    )
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))

    sock = None
    try:
        try:
            sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(_ETH_P_PROFINET))
            sock.bind((ifname, 0))
        except (PermissionError, OSError, AttributeError):
            return None

        try:
            sock.send(frame)
        except OSError:
            return None

        deadline = _time.monotonic() + timeout
        while True:
            remaining = deadline - _time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data = sock.recv(2048)
            except OSError:
                return None

            if len(data) < 16 or data[12:14] != struct.pack("!H", _ETH_P_PROFINET):
                continue
            frame_id_resp = struct.unpack_from("!H", data, 14)[0]
            if frame_id_resp != _DCP_GET_SET_FRAME_ID:
                continue

            dcp = data[16:]
            if len(dcp) < 10:
                continue
            service_id, service_type = dcp[0], dcp[1]
            # Real devices communicate the Set outcome via the per-block block_error field
            # inside a normal ResponseSuccess frame, not via a frame-level rejection — same
            # simplification probe_profinet_dcp() already makes for Identify responses.
            if service_id != _DCP_SVC_ID_SET or service_type != _DCP_SVC_TYPE_RESPONSE_SUCCESS:
                continue
            resp_xid = struct.unpack_from("!I", dcp, 2)[0]
            if resp_xid != _DCP_SET_XID:
                continue
            dcp_data_length = struct.unpack_from("!H", dcp, 8)[0]

            block_error = _dcp_parse_control_response(dcp[10 : 10 + dcp_data_length])
            if block_error is None:
                continue
            return block_error
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ── InduSoft/AVEVA TCP/IP Server Task active protocol-identity probe ─────────────────────────
# Added 2026-09-05 (default-credentials sweep, InduSoft/AVEVA CVE-2018-17914/17916) to gate
# checks/indusoft_tcp/native/distributed_token_bypass.py. Same dummy-safe-action pattern as
# probe_pcom_tcp_identity, but using command 55's Pi() Built-in-Language call (read-only, zero
# side effects, byte-exact confirmed from Jacob Baines's Tenable techblog writeup) rather than a
# deliberately-wrong login attempt — this protocol has no documented response signature for the
# login command itself (command 69), so fingerprinting deliberately avoids that command
# entirely rather than relying on an unconfirmed response shape.
def probe_indusoft_tcp_identity(host: str, port: int = 1234, timeout: float = 5.0) -> FingerprintResult:
    """Active InduSoft/AVEVA TCP/IP Server Task identity probe: sends the hello frame + a Pi()
    Built-in-Language call (command 55, read-only) and confirms the exact, byte-verified
    response text comes back. confidence='high' only on that specific echo — this is a highly
    distinctive string (a math constant, in this protocol's own literal wire format) essentially
    nothing else would produce by coincidence. Deliberately does NOT touch the login/credential
    path (command 69) as part of fingerprinting — that's the actual check's job."""
    from core.indusoft_tcp import _PI_RESPONSE_SIGNATURE, probe_pi

    response = probe_pi(host, port, timeout=timeout)
    if response is None or _PI_RESPONSE_SIGNATURE not in response:
        return FingerprintResult(confidence="none", method="indusoft_tcp_identity_no_match")
    return FingerprintResult(vendor="AVEVA (InduSoft)", confidence="high", method="indusoft_tcp_identity")


# ── Galil Motion Control ASCII command-shell active protocol-identity probe ──────────────────
# Added 2026-09-14 (default-credentials sweep, user: "create the new-protocol for galil") to gate
# checks/telnet/native/galil_program_space_unlocked.py — see checks/candidates/
# galil-dmc-rio-program-space-unlocked-by-default.yaml for the full sourcing. New vendor for this
# project: Galil Motion Control (now part of Novanta) DMC/RIO motion controllers, TCP:23
# interactive ASCII command shell. Sends the documented `ID\r` command (no arguments — returns a
# multi-line free-text hardware-identity block, confirmed via Galil's own official "DMC-40x0
# Firmware Command Reference", 01/25/2017 edition) and checks the response for the distinctive
# "Connector" vocabulary that command's own documented output always contains (e.g.
# "Connector J1=...", "Connector P1=...") — a read-only identity query, zero side effects, the
# same "confirm the exact, byte-verified response text comes back" discipline as
# probe_indusoft_tcp_identity above. Deliberately does NOT touch ^L^K (the lock-status query) as
# part of fingerprinting — that's the actual check's job.
def probe_galil_identity(host: str, port: int = 23, timeout: float = 5.0) -> FingerprintResult:
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(b"ID\r")
        response = sock.recv(4096)
    except (OSError, _socket.timeout):
        return FingerprintResult(confidence="none", method="galil_identity_no_response")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if response is None or b"Connector" not in response:
        return FingerprintResult(confidence="none", method="galil_identity_no_match")
    return FingerprintResult(vendor="Galil Motion Control", confidence="high", method="galil_identity", extra={"id_response": response.decode("ascii", errors="replace").strip()})


# ── MQTT (v3.1.1) active protocol-identity probe ─────────────────────────────────────────────
# Added 2026-09-17 (user: "build mqtt candidate", to gate
# checks/mqtt/native/mqtt_unauthenticated_broker.py — see checks/candidates/
# moxa-mar-2000-mosquitto-unauthenticated-mqtt.yaml for the finding that motivated this). Hand-
# rolls a minimal MQTT 3.1.1 CONNECT/CONNACK exchange rather than importing paho-mqtt here, same
# stdlib-only discipline as every other probe in this file (core/discovery.py's Sparkplug B
# listener DOES use paho-mqtt, but that is a long-lived subscribe loop, a genuinely different
# shape from this file's single-request/single-response identity probes — pulling in a client
# library for one fixed-shape packet exchange isn't a good trade here).
#
# Wire format per the OASIS MQTT v3.1.1 spec: fixed header byte 0x10 (CONNECT) + remaining length
# (single-byte varint, always < 128 for this fixed-shape packet so no multi-byte encoding is
# needed); variable header = protocol name "MQTT" (length-prefixed UTF-8: 0x00 0x04 'M' 'Q' 'T'
# 'T'), protocol level 0x04, connect flags 0x02 (Clean Session only — no Will/username/password
# flags), keep-alive 0x00 0x3C (60s); payload = a single length-prefixed Client Identifier. A
# CONNACK reply is always exactly 4 bytes: 0x20 0x02 <session-present-flags> <return-code>. The
# return code (0=Accepted, 1=unacceptable protocol version, 2=identifier rejected, 3=server
# unavailable, 4=bad username/password, 5=not authorized) is NOT evaluated here — a REJECTION
# still proves the target speaks MQTT, so confidence="high" is returned for any well-formed
# CONNACK regardless of its return code. Judging whether that return code indicates a
# vulnerability (return code 0 with no credentials offered) is the actual check's job, not this
# identity probe's — same division of responsibility as every other protocol_probe in this file.
def probe_mqtt_identity(host: str, port: int = 1883, timeout: float = 3.0) -> FingerprintResult:
    connect_flags = 0x02  # Clean Session only
    variable_header = b"\x00\x04MQTT" + bytes([0x04, connect_flags]) + b"\x00\x3c"
    client_id = b"icsfp0000"
    payload = len(client_id).to_bytes(2, "big") + client_id
    remaining = variable_header + payload
    packet = bytes([0x10, len(remaining)]) + remaining

    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(packet)
        response = sock.recv(16)
    except (OSError, _socket.timeout):
        return FingerprintResult(confidence="none", method="mqtt_identity_no_response")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if len(response) != 4 or response[0] != 0x20 or response[1] != 0x02:
        return FingerprintResult(confidence="none", method="mqtt_identity_no_match")
    return_code = response[3]
    return FingerprintResult(
        vendor="unknown",
        confidence="high",
        method="mqtt_connack",
        extra={"session_present": bool(response[2] & 0x01), "connack_return_code": return_code},
    )


# Cisco Smart Install (SMI) active protocol-identity probe — added 2026-09-22 to unblock a
# generic exposure check (checks/cisco_smi/cisco-smart-install-unauthenticated-exposed.yaml).
# SMI has NO authentication in the protocol itself (Cisco's own advisories, cisco-sa-20180409-smi
# and cisco-sa-20170214-smi, and the 2019 NSA/CISA joint advisory on SMI protocol misuse, all
# describe this as the underlying issue) — so "the client role answers this specific query" IS
# the exposure, not a side effect of it.
#
# Wire format NOT reverse-engineered here — verified directly against the reference
# implementation of SIET (github.com/frostbits-security/SIET, formerly Sab0tag3d/SIET, the
# de-facto standard public Smart Install exploitation/testing tool cited by Cisco Talos's own
# 2018 writeup), specifically its `test_device()`/`conn_with_client()` functions (siet.py,
# fetched and read directly this pass, not recalled). That function sends a fixed 24-byte probe
# and treats an exact-byte-match 24-byte reply as "Smart Install Client feature active... is
# affected" — the unambiguous positive this probe reproduces. Two other SIET-documented outcomes
# (connection closes with 0 bytes = "Director feature active... not affected"; any other
# length/content = "unclear") are both treated here as confidence="none", matching this
# project's fail-closed convention (SNMP's own probe_snmp_identity is the precedent: silence and
# ambiguity are never a positive).
_CISCO_SMI_PROBE_REQUEST = bytes.fromhex(
    "00000001" "00000001" "00000004" "00000008" "00000001" "00000000"
)
_CISCO_SMI_CLIENT_ACTIVE_RESPONSE = bytes.fromhex(
    "00000004" "00000000" "00000003" "00000008" "00000001" "00000000"
)


def probe_cisco_smi_identity(host: str, port: int = 4786, timeout: float = 5.0) -> FingerprintResult:
    """Active Cisco Smart Install identity probe: sends SIET's own reference 24-byte SMI query
    and confirms confidence='high' only on an exact-byte-match 24-byte "Client feature active"
    reply — the same unambiguous-positive bar SIET itself uses. Purely a read: no TFTP
    redirection, no config/image push, no CLI execution (that's SIET's separate, genuinely
    destructive change_tftp()/update_ios() functionality, deliberately not reproduced here)."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_CISCO_SMI_PROBE_REQUEST)
        response = sock.recv(512)
    except OSError:
        return FingerprintResult(confidence="none", method="cisco_smi_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if response != _CISCO_SMI_CLIENT_ACTIVE_RESPONSE:
        return FingerprintResult(confidence="none", method="cisco_smi_identity_no_match")
    return FingerprintResult(
        vendor="Cisco Systems",
        confidence="high",
        method="cisco_smi_client_active",
    )


# AMX (Harman) ICSP active identity probe — added 2026-10-16 to un-gate the documented AMX
# Modero/MVP "Protected Setup" default-password check (checks/telnet/amx-modero-protected-setup-
# default-password.yaml), which was precondition-gated on vendor "AMX" with no probe to produce it.
#
# AMX NetLinx masters and the Modero/MVP G4/G5 touch panels speak ICSP (NetLinx Studio
# Communication Protocol) on a FIXED, IANA/SANS-registered port: TCP 1319 (ICSP) and TCP 1320
# (Secure ICSP / eICSP). Harman's own documentation states the ICSP port is fixed at 1319 and the
# Secure ICSP port at 1320 (harman.helpjuice.com "Changing the ICSP Port"), and the SANS ISC port
# registry lists 1319 as "amx-icsp / AMX-ICSP". That port is otherwise uncommon, so a listener on
# it is already a distinctive AMX indicator.
#
# IMPORTANT — the ICSP WIRE FORMAT IS NOT PUBLICLY DOCUMENTED. Harman states on its own forums
# that the ICSP/eICSP framing and its encryption are deliberately undocumented (proforums.harman.
# com), and a focused search (2026-10-16) found no vendor spec, open client, or Wireshark dissector
# giving a byte-level layout. Per this project's non-standard-protocol research rule (vendor spec >
# RE tool w/ source > Wireshark > scanner > lib > search), this probe therefore does NOT invent or
# decode framing. It relies only on two VERIFIABLE facts: (1) the registered-port assignment, and
# (2) the observable behaviour that an ICSP master/panel initiates the exchange on TCP connect
# (it sends an unsolicited banner first, unlike a generic server that waits for the client). The
# leading byte 0x02 is the widely-OBSERVED ICSP protocol-identifier byte (not asserted from a
# spec); it is used here only as an additional positive gate to raise specificity. Using it as a
# gate is fail-closed: if it is wrong, the probe simply stays inert (a false negative, matching the
# pre-2026-10-16 state) rather than mis-attributing a non-AMX host — exactly the bias wanted for a
# gate in front of a destructive (login-attempting) check.
#
# Confidence is capped at "low": the registered-port + server-first-banner + 0x02-marker triad is a
# strong practical AMX signal but is NOT a decoded, verified ICSP exchange, so it must not claim the
# "high" that the fully-decoded probes above (MQTT CONNACK, Cisco SMI byte-match) earn. "low" is
# still is_known() (confidence != "none"), which is all the vendor-match precondition needs. The
# probe never writes to the device and never attempts the ICSP handshake — it reads the unsolicited
# banner and closes. Needs live-device confirmation on a real Modero/MVP/NetLinx unit to promote
# confidence or relax the 0x02 gate.
def probe_amx_icsp_identity(host: str, port: int = 1319, timeout: float = 5.0) -> FingerprintResult:
    """Active AMX ICSP identity probe (TCP 1319 ICSP / 1320 Secure ICSP). Read-only: connects,
    reads the unsolicited banner an ICSP endpoint sends on connect, and closes — never sends an
    ICSP message or attempts the (undocumented) handshake. Returns vendor='AMX' confidence='low'
    only when the registered AMX-ICSP port both accepts the connection AND the endpoint speaks
    first with a banner whose leading byte is the observed ICSP marker 0x02; otherwise 'none'
    (fail-closed). See the block comment above for why the wire format is not decoded."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        # ICSP endpoints speak first; read whatever unsolicited banner arrives. Do NOT send.
        banner = sock.recv(64)
    except (OSError, _socket.timeout):
        return FingerprintResult(confidence="none", method="amx_icsp_identity_no_response")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # No server-first banner → indistinguishable from an arbitrary listener on this port. Fail
    # closed (do NOT attribute AMX on a bare open port alone — that would risk firing the
    # destructive telnet default-login at a non-AMX host).
    if not banner:
        return FingerprintResult(confidence="none", method="amx_icsp_identity_no_banner")
    # Positive only when the banner leads with the observed ICSP protocol-identifier byte 0x02.
    if banner[0] != 0x02:
        return FingerprintResult(
            confidence="none",
            method="amx_icsp_identity_unexpected_banner",
            extra={"banner_head_hex": banner[:8].hex()},
        )
    return FingerprintResult(
        vendor="AMX",
        confidence="low",
        method="amx_icsp_server_banner",
        extra={
            "icsp_port": port,
            "banner_head_hex": banner[:8].hex(),
            "note": "ICSP wire format undocumented; identity inferred from registered AMX-ICSP "
                    "port + server-first 0x02-led banner. Confirm on a live Modero/MVP/NetLinx unit.",
        },
    )


# TFTP (RFC 1350) active exposure probe — added 2026-09-22 alongside the Smart Install probe
# above (the two are commonly discussed together: Smart Install's real exploitation path, per
# CVE-2018-0171 and SIET's own change_tftp()/update_ios(), works by directing a switch to fetch
# a malicious config/image over TFTP). TFTP has no authentication concept anywhere in the
# protocol (RFC 1350 defines no credential/auth field at all), so this probe's job is narrower
# than the other identity probes here: it isn't distinguishing "right vs. wrong credential," it
# is confirming "a real TFTP server is listening and answered," which is the exposure (CWE-306)
# by itself, regardless of vendor.
#
# A Read Request for a deliberately implausible, scanner-tagged filename is used (never a
# realistic config/firmware filename) specifically so a DATA reply, if one ever comes back,
# can't plausibly be real device data — the only two outcomes this probe treats as a positive
# are a well-formed ERROR packet (opcode 5, "file not found" is the expected/common case) or a
# well-formed DATA packet (opcode 3) with a valid block-number field; anything else (no reply,
# malformed opcode) is confidence="none", same fail-closed convention as every probe above.
_TFTP_OPCODE_RRQ = 1
_TFTP_OPCODE_DATA = 3
_TFTP_OPCODE_ERROR = 5
_TFTP_PROBE_FILENAME = b"icsscanner-probe-nonexistent-file"


def probe_tftp_identity(host: str, port: int = 69, timeout: float = 5.0) -> FingerprintResult:
    """Active TFTP exposure probe: a single RRQ (octet mode) for a scanner-tagged, deliberately
    nonexistent filename. confidence='high' on any well-formed DATA or ERROR reply (RFC 1350
    opcode 3 or 5) — either one proves an unauthenticated TFTP server answered, which is the
    finding itself. Never retries, never follows up a DATA reply with further reads (no transfer
    is completed), so this never actually retrieves file content even in the unlikely case the
    probed filename happens to exist."""
    request = (
        struct.pack(">H", _TFTP_OPCODE_RRQ)
        + _TFTP_PROBE_FILENAME
        + b"\x00"
        + b"octet"
        + b"\x00"
    )

    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(request, (host, port))
        try:
            data, _ = sock.recvfrom(1024)
        except OSError:
            return FingerprintResult(confidence="none", method="tftp_identity_no_response")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if len(data) < 4:
        return FingerprintResult(confidence="none", method="tftp_identity_short_response")
    opcode = struct.unpack(">H", data[0:2])[0]
    if opcode not in (_TFTP_OPCODE_DATA, _TFTP_OPCODE_ERROR):
        return FingerprintResult(confidence="none", method="tftp_identity_unexpected_opcode")

    extra = {"opcode": opcode}
    if opcode == _TFTP_OPCODE_ERROR:
        error_code = struct.unpack(">H", data[2:4])[0]
        extra["error_code"] = error_code
        extra["error_message"] = data[4:-1].decode("ascii", errors="replace") if data.endswith(b"\x00") else ""
    else:
        extra["block_number"] = struct.unpack(">H", data[2:4])[0]

    return FingerprintResult(
        vendor="unknown",
        confidence="high",
        method="tftp_rrq_response",
        extra=extra,
    )


# ── uTasker embedded web-server HTTP identity probe ───────────────────────────
# Added 2026-10-03, out of the AMX/SolarEdge/Adeunis firmware-sidecar pass (see
# project_open_tasks -150). While triaging AMX's MNETbootloader2BappV1025.S19 we confirmed its
# firmware-upload web server is the uTasker reference embedded HTTP stack (M.J. Butcher
# Consulting), identifiable by its HTTP Basic realm. This is a STACK fingerprint, not a vendor or
# device-model claim: uTasker is a licensable reference TCP/IP+web stack used across many
# unrelated products, so a realm match says "a uTasker reference web server answered here", NOT
# who made the device (vendor stays "unknown", same deliberate non-claim as probe_s7comm_identity
# et al.). Deliberately NOT paired with any default-credential check: unlike RomPager/GoAhead,
# uTasker ships no universal default login — the AMX image's "ADMIN" was AMX's own compiled-in
# parameter value, not a uTasker default (verified against the uTasker-Kinetis reference source,
# which defines no such default), so there is nothing stack-generic to safely test. One benign
# unauthenticated GET, headers only — same risk tier as the other active probes here.
_UTASKER_HTTP_GET_TEMPLATE = (
    "GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
)


def probe_utasker_http_identity(host: str, port: int = 80, timeout: float = 5.0) -> FingerprintResult:
    """Active uTasker embedded web-server identity probe: one unauthenticated ``GET /`` and a
    header-only read. confidence='high' when the response carries a ``WWW-Authenticate: Basic``
    challenge whose realm is ``uTasker`` (quotes optional, case-insensitive) — the reference
    stack's distinctive realm; confidence='none' for anything else (unreachable, non-HTTP, no
    such realm, or a page that isn't auth-gated), fail-closed like every other probe here. This
    confirms the uTasker web STACK only — vendor/model stay 'unknown' because uTasker is used
    across many unrelated products (see the design note above). Never sends credentials and never
    requests anything but ``/``."""
    request = _UTASKER_HTTP_GET_TEMPLATE.format(host=host).encode("ascii", errors="ignore")

    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request)
        # Headers only: read until the blank-line terminator or the server closes, capped so a
        # chatty/garbage service can't make us read its whole body.
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            chunk = sock.recv(2048)
            if not chunk:
                break
            buf += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="utasker_http_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if not buf:
        return FingerprintResult(confidence="none", method="utasker_http_identity_no_response")

    header_blob = buf.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
    lines = header_blob.split("\r\n")
    status_line = lines[0] if lines else ""
    if not status_line.upper().startswith("HTTP/"):
        return FingerprintResult(confidence="none", method="utasker_http_identity_not_http")

    www_auth = ""
    server_hdr = ""
    for line in lines[1:]:
        name, _, value = line.partition(":")
        name = name.strip().lower()
        if name == "www-authenticate":
            www_auth = value.strip()
        elif name == "server":
            server_hdr = value.strip()

    # Match: Basic auth challenge with realm uTasker (tolerate realm=uTasker and realm="uTasker").
    m = re.search(r'realm\s*=\s*"?([^",]+)"?', www_auth, re.IGNORECASE)
    realm = m.group(1).strip() if m else ""
    if "basic" in www_auth.lower() and realm.lower() == "utasker":
        return FingerprintResult(
            vendor="unknown",  # uTasker is a multi-vendor reference stack — realm identifies the
            # web SERVER, not the device maker. See the design note above.
            confidence="high",
            method="utasker_http_identity",
            extra={"realm": realm, "www_authenticate": www_auth, "server": server_hdr,
                   "status": status_line},
        )
    return FingerprintResult(confidence="none", method="utasker_http_identity_no_realm_match")


# ── MELSEC SLMP / MC-protocol (3E binary) active protocol-identity probe ─────
# Added 2026-10-06 alongside the SLMP unauthenticated-read check (checks/slmp/). Sends ONE benign,
# read-only SLMP 3E batch-read (one word at D0) and confirms a well-formed 3E RESPONSE (subheader
# 0xD000) — which a real MELSEC/SLMP stack returns whether the read succeeds (end code 0x0000) or
# errors (non-zero end code); either way the device spoke the 3E protocol. confidence='high' only on
# that 0xD000 response; 'none' otherwise (fail-closed, same as probe_modbus_identity). Frame
# cross-verified against the MELSEC Communication Protocol manual (SH-080008) + senrust/pymcprotocol;
# see checks/slmp/native/melsec_slmp_unauth_read.py for the full sourcing.
def probe_slmp_identity(host: str, port: int = 5000, timeout: float = 5.0) -> FingerprintResult:
    command_block = (
        struct.pack("<H", 0x0401) + struct.pack("<H", 0x0000)   # batch read, word units
        + (0).to_bytes(3, "little") + bytes([0xA8])             # D0 (device code 0xA8)
        + struct.pack("<H", 1)                                  # 1 point
    )
    payload = (
        b"\x50\x00" + bytes([0x00, 0xFF])                       # subheader 0x5000 (BE), network, PC
        + struct.pack("<H", 0x03FF) + bytes([0x00])             # dest module I/O, station
        + struct.pack("<H", 2 + len(command_block))             # request data length
        + struct.pack("<H", 4)                                  # monitoring timer
        + command_block
    )
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(payload)
        response = sock.recv(256)
    except OSError:
        return FingerprintResult(confidence="none", method="slmp_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if len(response) >= 11 and response[0:2] == b"\xd0\x00":
        return FingerprintResult(
            vendor="unknown",  # confirms the SLMP/MC PROTOCOL, not a hardware vendor — same
            # deliberate non-claim as probe_modbus_identity/probe_s7comm_identity.
            confidence="high",
            method="slmp_identity",
        )
    return FingerprintResult(confidence="none", method="slmp_identity_mismatch")


# MELSEC CPU model names returned by the SLMP / MC-Protocol "read CPU model name" command (0x0101): a
# 16-byte ASCII field (space-padded) followed by a 2-byte CPU type code, in the response data. The shape
# is validated strictly (Q/L/R/FX/iQ families — all contain "CPU" or an FX prefix) so this never fires on
# an ordinary device-read response that happens to carry ASCII. Format from the SLMP reference /
# MC Protocol SH-080008. NOTE: spec-derived; a real 0x0101 capture is needed to promote confidence and is
# tracked as the MX Component RE sidequest (reference_mxcomponent_v5).
_MELSEC_CPU_RE = re.compile(r"^[A-Z0-9][A-Z0-9 /\-]{2,15}$")


def _melsec_cpu_from_slmp_response(payload: bytes, data_off: int):
    """If an SLMP response carries a 'read CPU model name' (0x0101) result — a 16-byte ASCII CPU model +
    2-byte type code starting at the response-data offset `data_off` (11 for a 3E frame, 15 for 4E) —
    return (model_name, type_code_or_None). Strictly validated to the MELSEC CPU-name shape, so it stays
    quiet on ordinary read responses. None when it does not match."""
    if len(payload) < data_off + 16:
        return None
    try:
        name = payload[data_off:data_off + 16].rstrip(b"\x00 ").decode("ascii")
    except UnicodeDecodeError:
        return None
    up = name.upper()
    if not _MELSEC_CPU_RE.match(up):
        return None
    if "CPU" not in up and not up.startswith("FX") and not re.match(r"^(Q|L|R|QS|QJ)\d", up):
        return None
    tc_off = data_off + 16
    type_code = int.from_bytes(payload[tc_off:tc_off + 2], "little") if len(payload) >= tc_off + 2 else None
    return name, type_code


def parse_slmp_frame(payload: bytes) -> FingerprintResult:
    """Parse an SLMP / MELSEC-Communication frame for passive discovery (TCP/UDP 5000/5062). Binary SLMP
    header: subheader 0x5000 (request) / 0xD000 (response), network, station, dest module I/O(2), dest
    station, request data length(2), then for a request a monitoring timer(2) + command(2) + subcommand(2)
    and for a response an end code(2). Validates the subheader + the data-length consistency (so it is not
    confused with the structurally-identical CC-Link IE Field Basic framing, which is port-separated on
    61450/61451 with command 0x0E70). Returns SLMP presence; multi-vendor (predominantly Mitsubishi
    MELSEC), so no hardware vendor is claimed. Both SLMP binary frame formats are handled: the 3E frame
    (subheader 0x5000/0xD000) and the 4E frame (0x5400/0xD400), which inserts a 2-byte serial number + a
    2-byte reserved field after the subheader (shifting every later field by 4) and is what CC-Link IE
    Field interface boards use. 4E layout confirmed against Mitsubishi SH-081155 (Ethernet Based Open
    Network / SLMP reference). Frame format for 3E taken from probe_slmp_identity's verified request."""
    if len(payload) < 11:
        return FingerprintResult(confidence="none", method="slmp_mismatch")
    sub = payload[0:2]
    if sub in (b"\x50\x00", b"\xd0\x00"):
        delta, frame = 0, "3E"
        direction = "request" if sub == b"\x50\x00" else "response"
    elif sub in (b"\x54\x00", b"\xd4\x00"):
        delta, frame = 4, "4E"                               # 4E = 3E + serial(2) + reserved(2)
        direction = "request" if sub == b"\x54\x00" else "response"
    else:
        return FingerprintResult(confidence="none", method="slmp_mismatch")
    if len(payload) < 11 + delta:
        return FingerprintResult(confidence="none", method="slmp_mismatch")
    data_len = int.from_bytes(payload[7 + delta:9 + delta], "little")
    if data_len < 2 or len(payload) < 9 + delta + data_len:  # length must be consistent with the datagram
        return FingerprintResult(confidence="none", method="slmp_mismatch")
    extra = {"protocol": "slmp", "slmp_direction": direction, "slmp_frame": frame}
    if direction == "request" and len(payload) >= 15 + delta:
        extra["slmp_command"] = int.from_bytes(payload[11 + delta:13 + delta], "little")
    elif direction == "response":
        end_code = int.from_bytes(payload[9 + delta:11 + delta], "little")
        extra["slmp_end_code"] = end_code
        if end_code == 0x0000:                               # success: may carry a CPU-model-name result
            cpu = _melsec_cpu_from_slmp_response(payload, 11 + delta)
            if cpu is not None:
                name, type_code = cpu
                extra["slmp_cpu_name"] = name
                if type_code is not None:
                    extra["slmp_cpu_type_code"] = f"0x{type_code:04x}"
                # a MELSEC CPU model name identifies the vendor + model (enables CVE correlation),
                # unlike the multi-vendor presence case below which claims no vendor.
                return FingerprintResult(vendor="Mitsubishi Electric", model=name, confidence="medium",
                                         method="slmp_cpu_model", extra=extra)
    return FingerprintResult(vendor="unknown", model="Mitsubishi MELSEC / SLMP device", confidence="low",
                             method="slmp_passive", extra=extra)


def parse_melsoft_frame(payload: bytes) -> Optional[FingerprintResult]:
    """Parse a MELSOFT frame — the Mitsubishi GX Works <-> MELSEC engineering protocol on TCP/UDP 5562
    (distinct from SLMP). Frame: subheader 0x5700 (request) / 0xD700 (response), a fixed 0x1111 marker at
    offset 5, routing, a 2-byte data length at offset 19, then a command (0x021c request / 0x029c response)
    and data. Unlike multi-vendor SLMP, MELSOFT is Mitsubishi-proprietary, so a MELSOFT speaker IS a
    Mitsubishi MELSEC PLC. The subheader + the 0x1111 marker keep false positives off other 5562 traffic.
    Validated against a real GX Works capture (ITI ICS-Security-Tools melsoft_tcp, 38k frames). Presence-
    level: this capture carries no ASCII CPU-model field, so no model is asserted. Returns None on mismatch."""
    if len(payload) < 21:
        return None
    sub = payload[0:2]
    direction = "request" if sub == b"\x57\x00" else ("response" if sub == b"\xd7\x00" else None)
    if direction is None or payload[5:7] != b"\x11\x11":     # fixed MELSOFT marker at offset 5
        return None
    extra = {"protocol": "melsoft", "melsoft_direction": direction,
             "melsoft_data_length": int.from_bytes(payload[19:21], "little")}
    if len(payload) >= 23:
        extra["melsoft_command"] = f"0x{int.from_bytes(payload[21:23], 'little'):04x}"
    return FingerprintResult(vendor="Mitsubishi Electric",
                             model="Mitsubishi MELSEC PLC (MELSOFT / GX Works connection)",
                             confidence="medium", method="melsoft_passive", extra=extra)


# ── LS Electric XGT dedicated-protocol active protocol-identity probe ────────
# Added 2026-10-06 for parity with the XGT unauthenticated-read check (checks/xgt/). Sends ONE
# benign, read-only XGT dedicated-protocol read (one word at %MW0) with a distinctive invoke ID and
# confirms a well-formed RESPONSE: the "LSIS-XGT" company-ID header, the response direction byte
# 0x11 (vs 0x33 request) at offset 13, and the echoed invoke ID at offset 14-15 (like
# probe_modbus_identity's TID echo). A real XGT stack returns this whether the read succeeds or
# errors. confidence='high' only on that match; 'none' otherwise (fail-closed). Frame cross-verified
# against the LS XGT FEnet manual V2.30 + golanglsplc + ciaoly's Wireshark dissector; see
# checks/xgt/native/xgt_unauth_read.py for the full sourcing.
def probe_xgt_identity(host: str, port: int = 2004, timeout: float = 5.0) -> FingerprintResult:
    invoke = 0x5A5A  # distinctive, echoed back by the device at offset 14-15
    name = b"%MW0"
    app = (
        struct.pack("<H", 0x0054) + struct.pack("<H", 0x0002)   # read request, word units
        + struct.pack("<H", 0x0000) + struct.pack("<H", 1)       # reserved, variable count
        + struct.pack("<H", len(name)) + name                    # name length + "%MW0"
    )
    payload = (
        b"LSIS-XGT\x00\x00" + struct.pack("<H", 0x0000) + bytes([0x00]) + bytes([0x33])
        + struct.pack("<H", invoke) + struct.pack("<H", len(app)) + bytes([0x00, 0x00]) + app
    )
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(payload)
        response = sock.recv(256)
    except OSError:
        return FingerprintResult(confidence="none", method="xgt_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if (len(response) >= 16 and response[0:8] == b"LSIS-XGT"
            and response[13] == 0x11 and response[14:16] == struct.pack("<H", invoke)):
        return FingerprintResult(
            vendor="unknown",  # confirms the XGT PROTOCOL, not a hardware vendor — same deliberate
            # non-claim as probe_modbus_identity/probe_slmp_identity.
            confidence="high",
            method="xgt_identity",
        )
    return FingerprintResult(confidence="none", method="xgt_identity_mismatch")


# ── Schneider UMAS (Modicon, over Modbus/TCP fn 0x5A) active protocol-identity probe ──
# Added 2026-10-06 with the Modicon UMAS unauthenticated-info check (checks/modbus/). Sends ONE
# benign UMAS READ_ID (Modbus fn 0x5A + pairing 0x00 + UMAS fn 0x02 "Get PLC info") and confirms a
# UMAS response (Modbus fn 0x5A echoed at offset 7) with a UMAS status 0xFE (success) / 0xFD (error)
# -- either proves a real Modicon UMAS stack answered unauthenticated. confidence='high' on that;
# 'none' otherwise (fail-closed). Frame cross-verified against the Kaspersky UMAS paper + the OSS
# dissectors (kushfj/se-umas) + 0xedh/schneider_plc_exploit; see
# checks/modbus/native/modicon_umas_unauth_info.py for sourcing.
def probe_umas_identity(host: str, port: int = 502, timeout: float = 5.0) -> FingerprintResult:
    pdu = bytes([0x5A, 0x00, 0x02])  # Modbus fn 0x5A, UMAS pairing 0x00 (unpaired), UMAS fn 0x02
    payload = struct.pack(">HHHB", 0x0001, 0x0000, 1 + len(pdu), 0x00) + pdu
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(payload)
        response = sock.recv(256)
    except OSError:
        return FingerprintResult(confidence="none", method="umas_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if len(response) >= 9 and response[7] == 0x5A and response[8] in (0xFE, 0xFD):
        return FingerprintResult(
            vendor="Schneider Electric",  # UMAS (Modbus fn 0x5A) is Schneider-proprietary (Modicon)
            confidence="high",
            method="umas_identity",
        )
    return FingerprintResult(confidence="none", method="umas_identity_mismatch")


# ── Omron FINS (Factory Interface Network Service) active protocol-identity probe ──
# Added 2026-10-06 as the first Tier-1 discovery-backlog probe (see
# lab-notes/discovery-protocol-backlog.md). FINS is Omron's proprietary PLC protocol on port 9600
# (UDP by default, also TCP). This sends ONE benign "Controller Data Read" command (FINS command
# 0x0501, read model+version only) and reads back the controller model/version — a read-only
# identity query, the same benign discipline as the other probes here. Frame bytes are taken
# VERBATIM from nmap mainline scripts/omron-info.nse (the request, the FINS/TCP node-address
# handshake, and the response offsets: model at byte 14, version at byte 34, +16 for the FINS/TCP
# frame header). Unlike XGT/SLMP's identity frames, the FINS Controller Data Read response carries
# the actual Omron controller model string, so this probe names the vendor ("Omron") — same
# vendor-specific-protocol reasoning as probe_umas_identity (Schneider).
_FINS_PORT = 9600
_FINS_UDP_CONTROLLER_DATA_READ = bytes.fromhex("800002000000006300ef050100")
_FINS_TCP_NODE_ADDR_REQ = bytes.fromhex("46494e530000000c000000000000000000000000")
_FINS_TCP_CDR_PREFIX = bytes.fromhex("46494e5300000015000000020000000080000200")
_FINS_TCP_CDR_SUFFIX = bytes.fromhex("000000ef050501")


def _fins_parse(response: bytes, offset: int) -> "FingerprintResult | None":
    """Validate a FINS Controller Data Read response and extract model/version. `offset` is 0 for
    UDP and 16 for FINS/TCP (the FINS/TCP frame header), matching nmap omron-info.nse."""
    if len(response) < 14 + offset:
        return None
    # MRC/SRC must echo 0x05/0x01 and the end code (MRES,SRES) must be 0x0000 (normal completion).
    if response[10 + offset] != 0x05 or response[11 + offset] != 0x01:
        return None
    if response[12 + offset : 14 + offset] != b"\x00\x00":
        return None
    model = response[14 + offset : 34 + offset].split(b"\x00", 1)[0].decode("ascii", "replace").strip()
    version = response[34 + offset : 54 + offset].split(b"\x00", 1)[0].decode("ascii", "replace").strip()
    return FingerprintResult(
        vendor="Omron",  # FINS is Omron-proprietary; the response carries a real Omron controller model
        model=model or "unknown",
        confidence="high",
        method="fins_controller_data_read",
        extra={"version": version} if version else {},
    )


def probe_fins_identity(host: str, port: int = _FINS_PORT, timeout: float = 5.0) -> FingerprintResult:
    # 1) FINS/UDP (the default): single Controller Data Read datagram.
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_FINS_UDP_CONTROLLER_DATA_READ, (host, port))
        try:
            data, src = sock.recvfrom(2048)
            if src[0] == host:  # discipline against a stale/mismatched datagram
                parsed = _fins_parse(data, offset=0)
                if parsed is not None:
                    return parsed
        except OSError:
            pass
    except OSError:
        pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # 2) FINS/TCP fallback: node-address handshake, then the Controller Data Read with the
    #    server-assigned client node inserted at the DA1 position (byte 24 of the handshake reply).
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_FINS_TCP_NODE_ADDR_REQ)
        reply = sock.recv(256)
        if len(reply) >= 24 and reply[0:4] == b"FINS":
            node = reply[23]  # nmap reads byte 24 (1-indexed) = the assigned client node
            sock.sendall(_FINS_TCP_CDR_PREFIX + bytes([node]) + _FINS_TCP_CDR_SUFFIX + b"\x00")
            response = sock.recv(512)
            if response[0:4] == b"FINS":
                parsed = _fins_parse(response, offset=16)
                if parsed is not None:
                    return parsed
    except OSError:
        return FingerprintResult(confidence="none", method="fins_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return FingerprintResult(confidence="none", method="fins_identity_mismatch")


def parse_iec104_frame(payload: bytes) -> FingerprintResult:
    """Parse an IEC 60870-5-104 APDU for passive discovery (TCP 2404). An APDU is APCI = start 0x68,
    length(1), 4 control octets; an I-format APDU (control octet 0 bit0 == 0) then carries an ASDU whose
    fixed 2-octet common address (offset 10, little-endian) is the station/sector address. S-format
    (ctrl0 & 0x03 == 1) and U-format (== 3, the TESTFR/STARTDT/STOPDT keepalives) carry no ASDU. Returns
    IEC-104 protocol presence + the common address / ASDU type id when present; multi-vendor, so no
    hardware vendor is claimed (same non-claim as the active probe). Frame format verified against a real
    IEC-104 capture."""
    if len(payload) < 6 or payload[0] != 0x68:
        return FingerprintResult(confidence="none", method="iec104_mismatch")
    apdu_len = payload[1]
    if not (4 <= apdu_len <= 253) or len(payload) < apdu_len + 2:
        return FingerprintResult(confidence="none", method="iec104_mismatch")
    ctrl0 = payload[2]
    fmt = "I" if (ctrl0 & 0x01) == 0 else ("S" if (ctrl0 & 0x03) == 0x01 else "U")
    extra = {"protocol": "iec104", "apdu_format": fmt}
    if fmt == "I" and len(payload) >= 12:
        extra["iec104_type_id"] = payload[6]
        extra["iec104_common_address"] = int.from_bytes(payload[10:12], "little")
    return FingerprintResult(vendor="unknown", model="IEC 60870-5-104 station", confidence="low",
                             method="iec104_passive", extra=extra)


# ── Niagara Fox (Tridium) active protocol-identity probe ──
# Added 2026-10-06 as Tier-1 discovery-backlog probe #3 (see discovery-protocol-backlog.md). Niagara
# Fox is Tridium's proprietary building-automation protocol (Niagara framework / JACE controllers),
# TCP 1911 (plain) or 4911 (TLS). This sends the standard unauthenticated "fox hello" handshake and
# reads the server's hello reply, which discloses host/app/station identity (hostName, fox.version,
# app.name/version, station.name, brandId, hostId, …) with NO authentication — the disclosure IS the
# finding. hello bytes taken verbatim from nmap mainline scripts/fox-info.nse; a valid reply starts
# "fox a 0" and carries a "{...}" key=type:value block. This probe is plain-TCP (1911); the 4911 TLS
# variant would need an SSL wrap (documented future extension). confidence='high' on a well-formed
# hello reply, 'none' otherwise (fail-closed).
_FOX_HELLO = b"fox a 1 -1 fox hello\n{\nfox.version=s:1.0\nid=i:1\n};;\n"
_FOX_FIELDS_WANTED = ("fox.version", "hostName", "app.name", "app.version", "vm.name", "vm.version",
                      "os.name", "station.name", "brandId", "hostId")


def probe_fox_identity(host: str, port: int = 1911, timeout: float = 5.0, tls: bool = False) -> FingerprintResult:
    suffix = "_tls" if tls else ""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if tls:
            # Niagara "Fox-S" on TCP 4911 is the same fox-hello wrapped in TLS. Industrial devices use
            # self-signed certs, so verification is disabled — we are fingerprinting, not trusting it.
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(_FOX_HELLO)
        response = sock.recv(4096)
    except OSError:
        # covers connect/recv failures AND ssl.SSLError (a subclass of OSError) — a TLS handshake
        # failure just means "not a Fox-S endpoint here"
        return FingerprintResult(confidence="none", method=f"fox_identity{suffix}_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return parse_fox_hello(response, tls=tls)


def parse_fox_hello(response: bytes, tls: bool = False) -> FingerprintResult:
    """Parse a Niagara Fox hello greeting (`fox a 0 ... {...}`) into identity. The Fox server sends this
    greeting UNSOLICITED on every connection, so it is extractable passively from captured traffic (no
    request needed) — this parser is shared by the active probe and the passive capture path. Returns
    confidence='high' on a parsed hello, 'none' otherwise."""
    suffix = "_tls" if tls else ""
    text = response.decode("latin-1", "replace")
    if not text.startswith("fox a 0") or "{" not in text:
        return FingerprintResult(confidence="none", method=f"fox_identity{suffix}_mismatch")

    fields: dict = {}
    for line in text.splitlines():
        for sep in ("=s:", "=i:", "=b:"):
            if sep in line:
                k, v = line.split(sep, 1)
                fields[k.strip()] = v.strip()
                break
    extra = {k: fields[k] for k in _FOX_FIELDS_WANTED if k in fields}
    if tls:
        extra["transport"] = "tls"
    model = fields.get("hostName") or fields.get("station.name") or fields.get("app.name") or "unknown"
    return FingerprintResult(
        vendor="Tridium",  # Niagara Fox is Tridium-proprietary (same vendor-specific-protocol
        # reasoning as probe_umas_identity=Schneider / probe_fins_identity=Omron).
        model=model,
        confidence="high",
        method=f"fox_hello{suffix}",
        extra=extra,
    )


def probe_fox_tls_identity(host: str, port: int = 4911, timeout: float = 5.0) -> FingerprintResult:
    """Niagara Fox-S — the TLS-wrapped Fox hello on TCP 4911 (vs plain 1911). Same benign hello
    handshake, inside TLS. See lab-notes/discovery-protocol-backlog.md (the 4911 FUTURE-WORK item)."""
    return probe_fox_identity(host, port=port, timeout=timeout, tls=True)


# ── PCWorx (Phoenix Contact) active protocol-identity probe ──
# Added 2026-10-06 as Tier-1 discovery-backlog probe #4 (see discovery-protocol-backlog.md). PCWorx
# is the Phoenix Contact ILC/RFC PLC runtime protocol on TCP 1962 (the project already tracks
# Phoenix Contact candidates). Sends the standard INIT request and confirms a 0x81 reply — that
# alone is a confident PROTOCOL match. It then best-effort replays nmap's benign identity read
# sequence (INIT -> session-id'd init_comms2 -> req_info) to enrich the PLC Type / firmware strings;
# that enrichment is wrapped so a parse/IO miss never downgrades the confirmed match. All three
# frames are benign reads (no writes), taken verbatim from nmap mainline scripts/pcworx-info.nse,
# including the response string offsets (PLC Type @30, firmware version @66, model number @152,
# 0-indexed). The PLC generates a session id in the INIT reply (byte 18, 1-indexed) that the two
# follow-up frames echo.
_PCWORX_INIT = bytes.fromhex("0101001a0000000078800003000c") + b"IBETH01N0_M\x00"


def _pcworx_cstr(blob: bytes, off: int) -> str:
    """Zero-terminated ASCII string at a 0-indexed offset (nmap get_string = string.unpack 'z')."""
    if off >= len(blob):
        return ""
    end = blob.find(b"\x00", off)
    raw = blob[off:] if end == -1 else blob[off:end]
    return raw.decode("ascii", "replace").strip()


def probe_pcworx_identity(host: str, port: int = 1962, timeout: float = 5.0) -> FingerprintResult:
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_PCWORX_INIT)
        response = sock.recv(512)
        if parse_pcworx_frame(response).confidence == "none":  # 0x81 presence gate (shared w/ passive)
            return FingerprintResult(confidence="none", method="pcworx_identity_mismatch")

        extra: dict = {}
        model = "unknown"
        try:  # best-effort enrichment; never downgrades the confirmed match on a miss
            if len(response) >= 18:
                sid = response[17:18]  # PLC-generated session id (byte 18, 1-indexed)
                init2 = bytes.fromhex("0105001600010000788000") + sid + bytes.fromhex("00000006000402950000")
                sock.sendall(init2)
                sock.recv(512)
                req_info = bytes.fromhex("0106000e00020000000000") + sid + bytes.fromhex("0400")
                sock.sendall(req_info)
                info = sock.recv(1024)
                if info and info[0] == 0x81:
                    plc_type = _pcworx_cstr(info, 30)
                    if plc_type:
                        model = plc_type
                    for key, off in (("firmware_version", 66), ("model_number", 152)):
                        val = _pcworx_cstr(info, off)
                        if val:
                            extra[key] = val
        except OSError:
            pass
    except OSError:
        return FingerprintResult(confidence="none", method="pcworx_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return FingerprintResult(
        vendor="Phoenix Contact",  # PCWorx is Phoenix Contact's ILC/RFC runtime protocol
        model=model,
        confidence="high",
        method="pcworx_init",
        extra=extra,
    )


# ── ProConOS PLC-runtime active protocol-identity probe (TCP 20547) ──
# Added 2026-11-11 (discovery-backlog gated item, unblocked via the Digital Bond Redpoint
# proconos-info.nse — already a cited backlog source). ProConOS is a widely-OEM'd PLC ladder-logic
# runtime (Phoenix Contact / ex-KW-Software) shipped on many controllers (Bristol/Emerson ControlWave,
# etc.); it exposes a PCCOM info service on TCP 20547. The request below is the Redpoint info query —
# a READ-ONLY identity read, NOT a control/command frame: it returns the ladder-logic runtime version,
# PLC type, and project name. Wire format confirmed by the Redpoint script's real captured output
# (Bristol ControlWave: "ProConOS V4.1.0267", "Bristol: CWM V05:50:00 07/31", project "trode"). The
# older backlog note that called 20547 "a state-changing .NET-remoting channel with no read-only frame"
# referred to the programming channel; this PCCOM info query is the benign discovery frame.
_PROCONOS_INFO_REQ = bytes.fromhex("cc01000b4002000047ee")  # Redpoint proconos-info query (read-only)


def probe_proconos_identity(host: str, port: int = 20547, timeout: float = 5.0) -> FingerprintResult:
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_PROCONOS_INFO_REQ)
        response = sock.recv(512)
    except OSError:
        return FingerprintResult(confidence="none", method="proconos_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # Reply parsing (0xcc marker + null-terminated identity fields) is shared with the passive path.
    return parse_proconos_frame(response)


# ── Saia-Burgess Ether-S-Bus (S-Bus over IP) active protocol-identity probe (UDP 5050) ──
# Added 2026-11-11 (new SCADA protocol; grounded in the Wireshark SampleCaptures sbus.pcap). Ether-S-Bus
# is the IP transport of Saia-Burgess (now Honeywell/SBC) S-Bus, used by PCD-family PLCs. The probe sends
# the "Read firmware version" telegram (command 0x20) — a benign read-only identity request — and parses
# the response firmware/identification string. Wire format fully confirmed against sbus.pcap:
#   telegram = length[u32 BE, counts whole telegram incl. itself] + version[0x01] + protocol-type[0x00]
#              + sequence[u16 BE] + attribute[0x00=Request] + destination-station[u8] + command[u8]
#              + CRC-16/XMODEM[u16 BE, poly 0x1021 init 0x0000 over all preceding bytes]
#   capture request (station 10): 00 00 00 0d 01 00 00 01 00 0a 20 53 18 (CRC 0x5318 reproduced exactly).
#   capture response: attribute byte (offset 8) == 0x01 (Response); firmware string follows at offset 9
#   (e.g. "D2M48020"), then the 2-byte CRC.
# CAVEAT (documented, fail-safe): an Ether-S-Bus PCD answers on its CONFIGURED S-Bus station number; a
# blind probe can't know it. Default destination 0 (the common factory/first station); overridable. A
# device on a non-zero station simply yields no response (confidence none) — never a false positive.
def _crc16_xmodem(data: bytes) -> int:
    """CRC-16/XMODEM (poly 0x1021, init 0x0000) — the Ether-S-Bus telegram checksum."""
    crc = 0x0000
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def _saia_sbus_read_fw_request(station: int = 0, seq: int = 1) -> bytes:
    """Build an Ether-S-Bus 'Read firmware version' (cmd 0x20) request telegram with a valid CRC."""
    inner = bytes([0x01, 0x00]) + struct.pack(">H", seq & 0xFFFF) + bytes([0x00, station & 0xFF, 0x20])
    telegram = struct.pack(">I", 4 + len(inner) + 2) + inner  # length counts the whole telegram incl. CRC
    return telegram + struct.pack(">H", _crc16_xmodem(telegram))


def probe_saia_sbus_identity(host: str, port: int = 5050, timeout: float = 5.0,
                             station: int = 0) -> FingerprintResult:
    req = _saia_sbus_read_fw_request(station=station)
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(req, (host, port))
        try:
            data, src = sock.recvfrom(512)
        except OSError:
            return FingerprintResult(confidence="none", method="saia_sbus_identity_noreply")
        if src[0] != host:  # discipline against a stale/mismatched datagram
            return FingerprintResult(confidence="none", method="saia_sbus_identity_srcmismatch")
    except OSError:
        return FingerprintResult(confidence="none", method="saia_sbus_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # Response-telegram parsing (length/protocol/attribute gate + CRC + firmware string) is shared
    # with the passive path.
    return parse_saia_sbus_frame(data, station=station)


# ── IEEE C37.118 synchrophasor (PMU/PDC) active protocol-identity probe (TCP 4712) ──
# Added 2026-11-11 (new protocol; grounded in ITI/ICS-Security-Tools pcaps/C37.118). C37.118.2 is the
# synchrophasor data-transfer protocol for Phasor Measurement Units / PDCs on the power grid (TCP/UDP
# 4712). The probe sends ONE benign Command frame requesting the CFG-2 configuration frame (CMD=5) --
# read-only, starts no data stream -- and parses the PMU's CFG-2 reply for the Station Name (STN) and
# IDCODE. Frame format + the CRC-CCITT (init 0xFFFF) checksum are confirmed against C37.118_1PMU_TCP.pcap:
# command aa41 0012 00f1 00000000 00000000 0005 d7d0 -> CFG-2 aa31 .. with STN "Blue PMU" at offset 20.
# CAVEAT (documented, fail-safe): a PMU answers a command addressed to its own IDCODE; a blind probe
# can't know it. Default IDCODE 1 (common), overridable. A PMU on another IDCODE yields no reply
# (confidence none) -- never a false positive.
def _crc16_ccitt_false(data: bytes) -> int:
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) -- the C37.118.2 frame checksum (CHK)."""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def _c37118_command(idcode: int, cmd: int) -> bytes:
    """Build a C37.118.2 Command frame (SYNC 0xAA41) with a valid CHK. SOC/FRACSEC left 0 (PMUs do
    not validate command timestamps; confirmed in the capture)."""
    body = (bytes([0xAA, 0x41]) + struct.pack(">H", 18) + struct.pack(">H", idcode & 0xFFFF)
            + b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + struct.pack(">H", cmd & 0xFFFF))
    return body + struct.pack(">H", _crc16_ccitt_false(body))


def probe_c37118_identity(host: str, port: int = 4712, timeout: float = 5.0,
                          idcode: int = 1) -> FingerprintResult:
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_c37118_command(idcode, 5))  # CMD 5 = send CFG-2 (read-only)
        resp = sock.recv(2048)
    except OSError:
        return FingerprintResult(confidence="none", method="c37118_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return parse_c37118_frame(resp)


def parse_c37118_frame(resp: bytes) -> FingerprintResult:
    """Parse any IEEE C37.118 frame — shared by the active probe and the passive capture path. A
    CFG-1/CFG-2 frame carries the Station Name (offset 20); other frame types confirm the protocol +
    IDCODE. A CFG frame rides the wire whenever a PDC requests configuration, so it is extractable
    passively. confidence='high' on a CRC-valid frame, 'none' otherwise."""
    if len(resp) < 16 or resp[0] != 0xAA:
        return FingerprintResult(confidence="none", method="c37118_identity_mismatch")
    framesize = struct.unpack(">H", resp[2:4])[0]
    if framesize != len(resp):
        return FingerprintResult(confidence="none", method="c37118_identity_badsize")
    if _crc16_ccitt_false(resp[:-2]) != struct.unpack(">H", resp[-2:])[0]:
        return FingerprintResult(confidence="none", method="c37118_identity_badcrc")

    frame_type = (resp[1] >> 4) & 0x7  # 0 DATA, 1 HDR, 2 CFG1, 3 CFG2, 5 CFG3
    resp_idcode = struct.unpack(">H", resp[4:6])[0]
    extra: dict = {"protocol": "c37118", "idcode": resp_idcode, "frame_type": frame_type}
    station = ""
    if frame_type in (2, 3) and len(resp) >= 36:  # CFG-1 / CFG-2 carry the Station Name at offset 20
        station = resp[20:36].decode("ascii", "replace").strip("\x00 ").strip()
        if station:
            extra["station_name"] = station

    return FingerprintResult(
        vendor="unknown",  # C37.118 is an open IEEE standard, multi-vendor (SEL/GE/Schweitzer/…) --
        # confirms the PROTOCOL + the configured station name, not a hardware vendor.
        model=station or "PMU/PDC (C37.118)",
        confidence="high",
        method="c37118_cfg2",
        extra=extra,
    )


# ── IEC 61850 MMS (Manufacturing Message Specification) active protocol-identity probe ──
# Added 2026-10-06 as Tier-1 discovery-backlog probe #5 (see discovery-protocol-backlog.md). MMS is
# the IEC 61850 substation-IED protocol over ISO-on-TCP (TPKT/COTP) on TCP 102 — the SAME port as
# S7comm, so this probe discriminates carefully: it does the COTP connect, sends an MMS
# Initiate-Request, and requires a COTP-DT response that carries the MMS initiate-Response tag
# (0xa9) and is NOT an S7comm reply (S7 puts protocol-id 0x32 right after the COTP DT header, at
# offset 7). It then best-effort sends an MMS Identify and parses vendorName(0x80)/modelName(0x81)/
# revision(0x82). All three request frames (COTP CR, MMS Initiate, MMS Identify) are taken verbatim
# from nmap mainline scripts/iec61850-mms.nse. confidence='high' only on a validated MMS
# initiate-Response (fail-closed otherwise, so a plain S7comm host on 102 does not false-positive).
_MMS_CR_TPDU = b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x00\x00\xc2\x02\x00\x01\xc0\x01\x0a"
_MMS_INITIATE = (
    b"\x03\x00\x00\xd3\x02\xf0\x80\x0d\xca\x05\x06\x13\x01\x00\x16\x01\x02\x14\x02\x00\x02\x33\x02"
    b"\x00\x01\x34\x02\x00\x01\xc1\xb4\x31\x81\xb1\xa0\x03\x80\x01\x01"
    b"\xa2\x81\xa9\x81\x04\x00\x00\x00\x01\x82\x04\x00\x00\x00\x01\xa4"
    b"\x23\x30\x0f\x02\x01\x01\x06\x04\x52\x01\x00\x01\x30\x04\x06\x02"
    b"\x51\x01\x30\x10\x02\x01\x03\x06\x05\x28\xca\x22\x02\x01\x30\x04"
    b"\x06\x02\x51\x01\x61\x76\x30\x74\x02\x01\x01\xa0\x6f\x60\x6d\xa1"
    b"\x07\x06\x05\x28\xca\x22\x02\x03\xa2\x07\x06\x05\x29\x01\x87\x67"
    b"\x01\xa3\x03\x02\x01\x0c\xa4\x03\x02\x01\x00\xa5\x03\x02\x01\x00"
    b"\xa6\x06\x06\x04\x29\x01\x87\x67\xa7\x03\x02\x01\x0c\xa8\x03\x02"
    b"\x01\x00\xa9\x03\x02\x01\x00\xbe\x33\x28\x31\x06\x02\x51\x01\x02"
    b"\x01\x03\xa0\x28\xa8\x26\x80\x03\x00\xfd\xe8\x81\x01\x0a\x82\x01"
    b"\x0a\x83\x01\x05\xa4\x16\x80\x01\x01\x81\x03\x05\xf1\x00\x82\x0c"
    b"\x03\xee\x1c\x00\x00\x00\x00\x00\x00\x00\xed\x18"
)
_MMS_IDENTIFY = (
    b"\x03\x00\x00\x1b\x02\xf0\x80\x01\x00\x01\x00\x61\x0e\x30\x0c\x02"
    b"\x01\x03\xa0\x07\xa0\x05\x02\x01\x01\x82\x00"
)


def _mms_parse_identify(buf: bytes) -> dict:
    """Pull vendorName/modelName/revision out of an MMS Identify-Response. Locates the identify
    constructed tag (0xa2) whose immediate child is a context-primitive 0x80/0x81/0x82, then walks
    those short-form TLVs. Guarded + bounded; returns {} on anything unexpected."""
    tagmap = {0x80: "vendorName", 0x81: "modelName", 0x82: "revision"}
    i = buf.find(b"\xa2")
    while i != -1:
        if i + 1 < len(buf):
            ln = buf[i + 1]
            if ln < 0x80 and i + 2 + ln <= len(buf) and i + 2 < len(buf) and buf[i + 2] in tagmap:
                body = buf[i + 2 : i + 2 + ln]
                out, p = {}, 0
                while p + 2 <= len(body):
                    tag, vlen = body[p], body[p + 1]
                    if vlen >= 0x80 or p + 2 + vlen > len(body):
                        break
                    if tag in tagmap:
                        out[tagmap[tag]] = body[p + 2 : p + 2 + vlen].decode("ascii", "replace").strip()
                    p += 2 + vlen
                if out:
                    return out
        i = buf.find(b"\xa2", i + 1)
    return {}


def probe_iec61850_mms_identity(host: str, port: int = 102, timeout: float = 5.0) -> FingerprintResult:
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_MMS_CR_TPDU)
        cc = sock.recv(512)
        # COTP Connection Confirm: TPKT 0x03, COTP TPDU type 0xd0 at offset 5.
        if not (len(cc) >= 6 and cc[0] == 0x03 and (cc[5] & 0xF0) == 0xD0):
            return FingerprintResult(confidence="none", method="mms_identity_no_cotp_cc")

        sock.sendall(_MMS_INITIATE)
        init = sock.recv(1024)
        # Must be a COTP-DT reply (0xf0 @5), carry the MMS initiate-Response tag 0xa9, and NOT be an
        # S7comm reply (S7 protocol-id 0x32 @7) — the key S7comm-on-102 disambiguation.
        if not (len(init) >= 8 and init[0] == 0x03 and init[5] == 0xF0
                and init[7] != 0x32 and b"\xa9" in init):
            return FingerprintResult(confidence="none", method="mms_identity_not_mms")

        extra, vendor, model = {}, "unknown", "unknown"
        try:  # best-effort Identify enrichment; never downgrades the confirmed MMS match
            sock.sendall(_MMS_IDENTIFY)
            ident = sock.recv(2048)
            fields = _mms_parse_identify(ident)
            if fields.get("vendorName"):
                vendor = fields["vendorName"]
            if fields.get("modelName"):
                model = fields["modelName"]
            extra = {k: v for k, v in fields.items() if v}
        except OSError:
            pass
    except OSError:
        return FingerprintResult(confidence="none", method="mms_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return FingerprintResult(
        vendor=vendor,  # IEC 61850 MMS is an open multi-vendor standard; vendor stays "unknown"
        # unless the device's own Identify-Response self-reports a vendorName.
        model=model,
        confidence="high",
        method="iec61850_mms_initiate",
        extra=extra,
    )


# ── HART-IP active protocol-identity probe (Tier-2 #1) ──
# Added 2026-10-06 (discovery-protocol-backlog Tier-2). HART-IP is the IP transport for HART field
# devices/gateways on TCP 5094. Sends the standard Session Initiate request and confirms a HART-IP
# Session Initiate *response* (version 1, message type 1=Response, message id 0, status 0), then
# best-effort sends HART command 0 (Read Unique Identifier) to enrich the device type / HART major
# revision. Both request frames are taken verbatim from nmap mainline scripts/hartip-info.nse. HART
# is multi-vendor so vendor stays "unknown". confidence='high' on a valid session response.
_HARTIP_SESSION_INIT = bytes.fromhex("010000000001000D0100004E20")
_HARTIP_CMD0 = bytes.fromhex("010003000002000D0280000082")


def probe_hartip_identity(host: str, port: int = 5094, timeout: float = 5.0) -> FingerprintResult:
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_HARTIP_SESSION_INIT)
        resp = sock.recv(512)
        # HART-IP header (8 bytes): version, msg type, msg id, status, seq(2), byte count(2).
        # Presence gate is shared with the passive path.
        if parse_hartip_frame(resp).confidence == "none":
            return FingerprintResult(confidence="none", method="hartip_identity_mismatch")

        extra: dict = {}
        try:  # best-effort Read Unique Identifier enrichment; device info begins at offset 15 (0-idx)
            sock.sendall(_HARTIP_CMD0)
            info = sock.recv(512)
            if len(info) >= 19 and info[0] == 0x01:
                extra["expanded_device_type"] = int.from_bytes(info[15:17], "big")
                extra["hart_protocol_major_revision"] = info[18]
        except OSError:
            pass
    except OSError:
        return FingerprintResult(confidence="none", method="hartip_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return FingerprintResult(
        vendor="unknown",  # HART-IP is a multi-vendor FieldComm standard — confirms the PROTOCOL
        confidence="high",
        method="hartip_session_init",
        extra=extra,
    )


# ── Red Lion Crimson active protocol-identity probe (Tier-2 #2) ──
# Added 2026-10-06 (discovery-protocol-backlog Tier-2). Crimson is Red Lion's HMI/PLC config protocol
# on TCP 789. This reuses the exact benign identity queries already verified by this project's own
# built check (checks/crimson/native/crimson_unauth_identity_read.py, CVE-2020-27285): a manufacturer
# identity query (register 0x012B, packet_type 0x1B00) and a model query (0x012A/0x1A00). A device
# that answers with packet_type 0x0300 and a non-empty string has processed a Crimson request with no
# authentication — confirms the protocol (and names Red Lion, a proprietary protocol). One
# connection per query, matching the verified executor's behavior.
_CRIMSON_MFR_QUERY = bytes([0x00, 0x04, 0x01, 0x2B, 0x1B, 0x00])
_CRIMSON_MODEL_QUERY = bytes([0x00, 0x04, 0x01, 0x2A, 0x1A, 0x00])


def _crimson_decode(resp) -> "str | None":
    if resp and len(resp) > 6 and resp[4:6] == b"\x03\x00":
        return resp[6:].split(b"\x00", 1)[0].decode("latin-1", "replace").strip() or None
    return None


def _crimson_query(host: str, port: int, request: bytes, timeout: float):
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request)
        return sock.recv(1024)
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_crimson_identity(host: str, port: int = 789, timeout: float = 5.0) -> FingerprintResult:
    manufacturer = _crimson_decode(_crimson_query(host, port, _CRIMSON_MFR_QUERY, timeout))
    model = _crimson_decode(_crimson_query(host, port, _CRIMSON_MODEL_QUERY, timeout))
    if not (manufacturer or model):
        return FingerprintResult(confidence="none", method="crimson_identity_mismatch")
    extra = {}
    if manufacturer:
        extra["manufacturer"] = manufacturer
    return FingerprintResult(
        vendor="Red Lion Controls",  # canonical form (matches the OUI table + the device's own manufacturer string)
        model=model or manufacturer or "unknown",
        confidence="high",
        method="crimson_identity",
        extra=extra,
    )


# ── Beckhoff ADS/AMS active protocol-identity probe (Tier-2 #3) ──
# Added 2026-10-06 (discovery-protocol-backlog Tier-2). ADS/AMS is Beckhoff's TwinCAT protocol on
# TCP 48898. Sends an ADS "Read Device Info" (command id 1, no request data) and confirms an AMS/TCP
# response that echoes our invoke id with command id 1 — that alone proves an AMS/ADS router
# answered us (even an AMS error reply confirms the protocol). On a success result it parses the
# TwinCAT version + 16-byte device name. Frame built from the Beckhoff ADS/AMS specification
# (Beckhoff InfoSys) + the Wireshark AMS dissector — NO nmap source exists for ADS.
# CAVEAT (documented, not hidden): AMS is route-gated — a hardened TwinCAT router may silently drop
# a request from an unknown source NetId, giving a false negative. The target NetId uses the common
# "<IPv4>.1.1" convention and AMS port 10000 (system service). vendor="Beckhoff".
_ADS_SRC_NETID = bytes([1, 1, 1, 1, 1, 1])
_ADS_SRC_PORT = 40000
_ADS_INVOKE = 0x5A5A5A5A


def _ads_read_device_info_request(host: str) -> "bytes | None":
    try:
        octets = bytes(int(x) for x in host.split("."))
    except ValueError:
        return None
    if len(octets) != 4:  # IPv4-only NetId convention
        return None
    target_netid = octets + bytes([1, 1])            # <IPv4>.1.1
    ams = (
        target_netid + struct.pack("<H", 10000)      # target NetId + AMS port (system service)
        + _ADS_SRC_NETID + struct.pack("<H", _ADS_SRC_PORT)
        + struct.pack("<H", 0x0001)                  # command id = Read Device Info
        + struct.pack("<H", 0x0004)                  # state flags = ADS command, request
        + struct.pack("<I", 0)                        # data length
        + struct.pack("<I", 0)                        # error code
        + struct.pack("<I", _ADS_INVOKE)             # invoke id
    )
    return b"\x00\x00" + struct.pack("<I", len(ams)) + ams   # AMS/TCP header (reserved + length)


def probe_beckhoff_ads_identity(host: str, port: int = 48898, timeout: float = 5.0) -> FingerprintResult:
    request = _ads_read_device_info_request(host)
    if request is None:
        return FingerprintResult(confidence="none", method="ads_identity_bad_host")
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request)
        resp = sock.recv(512)
    except OSError:
        return FingerprintResult(confidence="none", method="ads_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # AMS/TCP header (6) + AMS header (32). command id @ AMS off 16 -> abs 22; invoke id @ AMS off 28
    # -> abs 34. A reply echoing our invoke id with command id 1 is an AMS/ADS Read-Device-Info reply.
    if not (len(resp) >= 38 and resp[0:2] == b"\x00\x00"
            and resp[22:24] == struct.pack("<H", 0x0001)
            and resp[34:38] == struct.pack("<I", _ADS_INVOKE)):
        return FingerprintResult(confidence="none", method="ads_identity_mismatch")

    extra: dict = {}
    model = "unknown"
    try:  # ADS data starts after the 32-byte AMS header (abs offset 38): result(4), major, minor,
          # build(2), deviceName(16). Parse only on a success result.
        result = struct.unpack("<I", resp[38:42])[0]
        if result == 0 and len(resp) >= 62:
            major, minor = resp[42], resp[43]
            build = struct.unpack("<H", resp[44:46])[0]
            name = resp[46:62].split(b"\x00", 1)[0].decode("ascii", "replace").strip()
            if name:
                model = name
            extra["twincat_version"] = f"{major}.{minor}.{build}"
    except (OSError, struct.error):
        pass

    return FingerprintResult(
        vendor="Beckhoff",  # ADS/AMS is Beckhoff's proprietary TwinCAT protocol
        model=model,
        confidence="high",
        method="ads_read_device_info",
        extra=extra,
    )


def parse_ads_frame(payload: bytes) -> FingerprintResult:
    """Parse a Beckhoff ADS/AMS frame for passive discovery (TCP 48898). AMS/TCP header: reserved(2)=0x0000
    + length(4); then the 32-byte AMS header (target NetId/port, source NetId/port, command id(2) at AMS
    offset 16 = abs 22, state flags, data length, error, invoke id). A Read-Device-Info response (command
    1) carries ADS data: result(4) at abs 38, major/minor/build, deviceName(16) at abs 46. Returns ADS
    presence; on a Read-Device-Info response also the TwinCAT version + device name. vendor Beckhoff (ADS
    is proprietary). Frame format lifted from probe_beckhoff_ads_identity (Beckhoff InfoSys + Wireshark)."""
    if len(payload) < 38 or payload[0:2] != b"\x00\x00":
        return FingerprintResult(confidence="none", method="ads_mismatch")
    ams_len = int.from_bytes(payload[2:6], "little")
    if ams_len < 32 or len(payload) < 6 + ams_len:
        return FingerprintResult(confidence="none", method="ads_mismatch")
    command = int.from_bytes(payload[22:24], "little")        # AMS command id @ abs 22
    if not (1 <= command <= 9):                               # valid ADS command range
        return FingerprintResult(confidence="none", method="ads_mismatch")
    extra = {"protocol": "ads", "ads_command": command}
    model = "Beckhoff TwinCAT (ADS)"
    if command == 1 and len(payload) >= 62:                   # Read-Device-Info response
        try:
            if int.from_bytes(payload[38:42], "little") == 0:
                major, minor = payload[42], payload[43]
                build = int.from_bytes(payload[44:46], "little")
                name = payload[46:62].split(b"\x00", 1)[0].decode("ascii", "replace").strip()
                if name:
                    model = name
                extra["twincat_version"] = f"{major}.{minor}.{build}"
        except (struct.error, IndexError):
            pass
    return FingerprintResult(vendor="Beckhoff", model=model, confidence="low",
                             method="ads_passive", extra=extra)


# ── GE-SRTP active protocol-identity probe (Tier-2 #4) ──
# Added 2026-10-06 (discovery-protocol-backlog Tier-2, after a dedicated sourcing pass). GE-SRTP
# (Service Request Transport Protocol) is the GE PACSystems / GE Fanuc PLC protocol on TCP 18245.
# GE-SRTP opens with a mandatory two-packet init handshake: the client sends an INIT message of 56
# NULL bytes and the PLC replies with a 56-byte INIT_ACK whose packet-type byte (byte 0) == 0x01 —
# a benign, read-only handshake that confirms the protocol. Best-effort, it then sends the read-only
# "Return Controller Type and ID" service (service code 0x43) and surfaces any device string.
# Frame cross-verified across TWO sources that AGREE on byte 0 = packet type (INIT 0x00 / INIT_ACK
# 0x01 / REQ 0x02 / REQ_ACK 0x03): the Wireshark dissector Palatis/packet-ge-srtp (built from real
# captures) and the RE'd Python lib jobeastwood/gesrtp-py. (A third source, the carbon-evolution
# mock server, mis-modeled the header as a u16 and was discarded — see
# lab-notes/discovery-protocol-backlog.md.) vendor="GE". NO nmap-mainline source exists.
_GE_SRTP_INIT = bytes(56)  # INIT message = 56 null bytes (both sources agree)


def _ge_srtp_controller_type_request(seq: int = 1) -> bytes:
    pkt = bytearray(56)
    pkt[0] = 0x02                                   # packet type = REQ
    pkt[2] = seq & 0xFF
    pkt[9] = 0x01
    pkt[17] = 0x01
    pkt[30] = seq & 0xFF
    pkt[31] = 0xC0                                  # message type = SHORT (request)
    pkt[36:40] = bytes([0x10, 0x0E, 0x00, 0x00])    # mailbox destination (slot 1)
    pkt[40] = 0x01                                  # packet number
    pkt[41] = 0x01                                  # total packets
    pkt[42] = 0x43                                  # service = RETURN_CONTROLLER_TYPE_AND_ID (read-only)
    return bytes(pkt)


def _longest_printable(buf: bytes, minlen: int = 3) -> str:
    best, cur = "", []
    for b in buf:
        if 0x20 <= b < 0x7F:
            cur.append(chr(b))
        else:
            if len(cur) > len(best):
                best = "".join(cur)
            cur = []
    if len(cur) > len(best):
        best = "".join(cur)
    best = best.strip()
    return best if len(best) >= minlen else ""


def probe_ge_srtp_identity(host: str, port: int = 18245, timeout: float = 5.0) -> FingerprintResult:
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_GE_SRTP_INIT)
        resp = sock.recv(256)
        # INIT_ACK: 56-byte reply whose packet-type byte (byte 0) is 0x01.
        if not (len(resp) >= 1 and resp[0] == 0x01):
            return FingerprintResult(confidence="none", method="ge_srtp_identity_no_init_ack")

        extra: dict = {}
        model = "unknown"
        try:  # best-effort read-only Return Controller Type and ID enrichment
            sock.sendall(_ge_srtp_controller_type_request(seq=1))
            r2 = sock.recv(512)
            if len(r2) >= 32 and r2[0] == 0x03:   # REQ_ACK
                extra["message_type"] = r2[31]
                ident = _longest_printable(r2[56:]) if len(r2) > 56 else ""
                if ident:
                    model = ident
                    extra["controller_id"] = ident
        except OSError:
            pass
    except OSError:
        return FingerprintResult(confidence="none", method="ge_srtp_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return FingerprintResult(
        vendor="GE",  # GE-SRTP is GE PACSystems / GE Fanuc (now Emerson) — proprietary protocol
        model=model,
        confidence="high",
        method="ge_srtp_init_ack",
        extra=extra,
    )


def parse_ge_srtp_frame(data: bytes) -> FingerprintResult:
    """Parse a single GE-SRTP frame for the passive capture path. A Return-Controller-Type REQ_ACK
    (packet type 0x03) carries the controller id string at offset 56; an INIT_ACK (0x01) confirms the
    protocol. Returns confidence='high' on either, 'none' otherwise. (The active probe drives the full
    two-step handshake; this reads whichever frame is already on the wire.)"""
    if not data:
        return FingerprintResult(confidence="none", method="ge_srtp_mismatch")
    if data[0] == 0x03 and len(data) > 56:            # REQ_ACK — controller-type response
        ident = _longest_printable(data[56:])
        return FingerprintResult(
            vendor="GE", model=ident or "unknown", confidence="high",
            method="ge_srtp_reqack", extra={"controller_id": ident} if ident else {"protocol": "ge_srtp"})
    if data[0] == 0x01 and len(data) >= 56:           # INIT_ACK — protocol presence
        return FingerprintResult(vendor="GE", confidence="high", method="ge_srtp_init_ack",
                                 extra={"protocol": "ge_srtp"})
    return FingerprintResult(confidence="none", method="ge_srtp_mismatch")


def parse_s7comm_frame(data: bytes) -> FingerprintResult:
    """Detect S7comm protocol presence in a captured frame (passive). An S7comm PDU is TPKT (0x03) +
    COTP DT (length byte then PDU-type 0xf0) + the S7 protocol id 0x32 at offset 7. Vendor is left
    unknown — S7comm is Siemens-defined but third-party devices speak it too; the signal is 'this host
    speaks S7comm', which is strong inventory value on its own. 'none' otherwise."""
    if len(data) >= 8 and data[0] == 0x03 and data[5] == 0xF0 and data[7] == 0x32:
        return FingerprintResult(vendor="unknown", model="S7comm endpoint", confidence="high",
                                 method="s7comm_presence", extra={"protocol": "s7comm"})
    return FingerprintResult(confidence="none", method="s7comm_mismatch")


# ── phase-2 passive lift-outs: response-frame parsers shared by the active probes below and the
# passive capture path (core/passive.py). Each takes the bytes already on the wire and returns a
# FingerprintResult (confidence='none' on a non-match), so passive mode reads whichever reply is
# present without ever sending the active request. Lifted 2026-11-11 (passive-coverage backlog). ──
def parse_proconos_frame(data: bytes) -> FingerprintResult:
    """Parse a ProConOS PCCOM info reply (TCP 20547). Validated by the 0xCC marker; identity fields
    (ladder-logic runtime, PLC type, project name) are null-terminated at fixed offsets 12/44/77.
    Vendor is the PLC-Type leading token (ProConOS is multi-OEM; never hardcoded). 'none' on mismatch."""
    if not (data and data[0] == 0xCC):
        return FingerprintResult(confidence="none", method="proconos_mismatch")
    runtime = _pcworx_cstr(data, 12)   # "Ladder Logic Runtime" (e.g. ProConOS V4.1.0267 ...)
    plc_type = _pcworx_cstr(data, 44)  # "PLC Type" (e.g. Bristol: CWM V05:50:00 07/31)
    project = _pcworx_cstr(data, 77)   # "Project Name"
    extra: dict = {"protocol": "proconos"}
    if runtime:
        extra["ladder_logic_runtime"] = runtime
    if project:
        extra["project_name"] = project
    vendor = "unknown"
    if plc_type:
        vendor = plc_type.split(":")[0].split()[0].strip() or "unknown"
    confidence = "high" if (runtime or plc_type) else "medium"
    return FingerprintResult(vendor=vendor, model=plc_type or "ProConOS PLC",
                             firmware=runtime or "unknown", confidence=confidence,
                             method="proconos_info", extra=extra)


def parse_saia_sbus_frame(data: bytes, station: int = 0) -> FingerprintResult:
    """Parse an Ether-S-Bus response telegram (UDP 5050). Validates the declared length, protocol
    type 0x00, attribute byte (offset 8) == 0x01 (Response), and the trailing CRC-16/XMODEM; the
    firmware/identification string is the printable run at offset 9..len-2. Saia-Burgess / SBC PCD.
    'none' on a non-match. (The active probe drives the read-firmware request; this reads the reply.)"""
    if len(data) < 11:
        return FingerprintResult(confidence="none", method="saia_sbus_short")
    declared = struct.unpack(">I", data[0:4])[0]
    if declared != len(data) or data[5] != 0x00 or data[8] != 0x01:
        return FingerprintResult(confidence="none", method="saia_sbus_mismatch")
    crc_ok = _crc16_xmodem(data[:-2]) == struct.unpack(">H", data[-2:])[0]
    fw = _longest_printable(data[9:-2]) if len(data) > 11 else ""
    extra = {"protocol": "ether_s_bus", "station": station, "crc_valid": crc_ok}
    confidence = "high" if crc_ok else "medium"   # structure-only (odd CRC) is medium
    return FingerprintResult(vendor="Saia-Burgess", model="PCD (S-Bus)", firmware=fw or "unknown",
                             confidence=confidence, method="saia_sbus_read_fw", extra=extra)


def parse_pcworx_frame(data: bytes) -> FingerprintResult:
    """Parse a PCWorx reply (TCP 1962) for protocol presence. A reply led by 0x81 confirms Phoenix
    Contact's PCWorx runtime (ILC/RFC). Model/firmware enrichment needs an active multi-step follow-up
    (session id -> info query), so the passive signal is presence only. 'none' otherwise."""
    if not (data and data[0] == 0x81):
        return FingerprintResult(confidence="none", method="pcworx_mismatch")
    return FingerprintResult(vendor="Phoenix Contact", confidence="high", method="pcworx_init",
                             extra={"protocol": "pcworx"})


def parse_hartip_frame(data: bytes) -> FingerprintResult:
    """Parse a HART-IP frame (TCP/UDP 5094) for protocol presence. The 8-byte HART-IP header on a
    session-init response is version 0x01, msg type 0x01, msg id 0x00. Vendor stays unknown (HART-IP
    is a multi-vendor FieldComm standard — the signal is 'this host speaks HART-IP'). 'none' otherwise."""
    if len(data) >= 8 and data[0] == 0x01 and data[1] == 0x01 and data[2] == 0x00:
        return FingerprintResult(vendor="unknown", confidence="high", method="hartip_session_init",
                                 extra={"protocol": "hart_ip"})
    return FingerprintResult(confidence="none", method="hartip_mismatch")


def parse_crimson_frame(data: bytes) -> FingerprintResult:
    """Parse a Red Lion Crimson reply (TCP 789). A reply with packet_type 0x0300 (bytes 4:6) carries a
    null-terminated identity string (manufacturer or model). Red Lion proprietary HMI/PLC. 'none'
    otherwise. (The active probe issues manufacturer + model queries; this reads whichever reply lands.)"""
    ident = _crimson_decode(data)
    if not ident:
        return FingerprintResult(confidence="none", method="crimson_mismatch")
    return FingerprintResult(vendor="Red Lion Controls", model=ident, confidence="high",
                             method="crimson_identity", extra={"protocol": "crimson"})


# ── CoAP active protocol-identity probe (Tier-3 IIoT #1) ──
# Added 2026-10-06 (discovery-protocol-backlog Tier-3). CoAP (RFC 7252) is the constrained-device
# IoT protocol on UDP 5683. This sends the standard resource-discovery request GET
# /.well-known/core (RFC 6690) and confirms a CoAP response (version 1, our message id echoed), then
# surfaces the CoRE link-format payload. Benign read-only discovery — the single most standard CoAP
# request there is. Frame built from RFC 7252 (message format) + RFC 6690 (/.well-known/core).
# vendor stays "unknown" (CoAP is a multi-vendor IoT standard). Also the transport under LwM2M
# (UDP 5683/5684) — an LwM2M-specific probe is tracked as future work.
# Request: ver1/CON/TKL0 (0x40), code 0.01 GET (0x01), msg id, Uri-Path ".well-known" then "core".
_COAP_MSG_ID = 0xB1C2
_COAP_WELLKNOWN_CORE = (
    bytes([0x40, 0x01]) + struct.pack(">H", _COAP_MSG_ID)
    + bytes([0xBB]) + b".well-known"      # option: Uri-Path (delta 11, len 11)
    + bytes([0x04]) + b"core"             # option: Uri-Path (delta 0, len 4)
)


def probe_coap_identity(host: str, port: int = 5683, timeout: float = 5.0) -> FingerprintResult:
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_COAP_WELLKNOWN_CORE, (host, port))
        try:
            data, src = sock.recvfrom(4096)
        except OSError:
            return FingerprintResult(confidence="none", method="coap_identity_no_response")
        if src[0] != host:
            return FingerprintResult(confidence="none", method="coap_identity_stale_src")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # CoAP response: version (top 2 bits of byte 0) == 1, and the message id (bytes 2-3) echoed.
    if not (len(data) >= 4 and (data[0] & 0xC0) == 0x40 and data[2:4] == struct.pack(">H", _COAP_MSG_ID)):
        return FingerprintResult(confidence="none", method="coap_identity_mismatch")

    extra = {"code": f"{data[1] >> 5}.{data[1] & 0x1F:02d}"}  # CoAP response code c.dd (e.g. 2.05)
    marker = data.find(b"\xff")  # payload marker; CoRE link-format follows on a 2.05 Content
    if marker != -1 and marker + 1 < len(data):
        links = data[marker + 1:].decode("latin-1", "replace").strip()
        if links:
            extra["core_links"] = links[:300]
    return FingerprintResult(
        vendor="unknown",  # CoAP is a multi-vendor IoT standard — confirms the PROTOCOL
        confidence="high",
        method="coap_wellknown_core",
        extra=extra,
    )


# ── AMQP active protocol-identity probe (Tier-3 IIoT #2) ──
# Added 2026-10-06 (discovery-protocol-backlog Tier-3). AMQP is the message-queue/telemetry broker
# protocol on TCP 5672 (the project tracks Vertiv/Liebert AMQP candidates). AMQP opens with a fixed
# 8-byte protocol header; a broker that receives a header replies with a protocol header for the
# version it supports (always begins with the literal "AMQP"), so sending an AMQP 1.0 header and
# getting any "AMQP..."-prefixed reply confirms an AMQP broker regardless of its actual version.
# Frame from the AMQP 1.0 (OASIS) + 0-9-1 specs. vendor stays "unknown" (multi-vendor).
_AMQP_HEADER_10 = b"AMQP\x00\x01\x00\x00"   # protocol id 0 (open), major 1, minor 0, revision 0


def probe_amqp_identity(host: str, port: int = 5672, timeout: float = 5.0) -> FingerprintResult:
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_AMQP_HEADER_10)
        resp = sock.recv(64)
    except OSError:
        return FingerprintResult(confidence="none", method="amqp_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # A broker answers a protocol header with its own "AMQP"-prefixed header (version negotiation or
    # a SASL header). An 8-byte header carries proto id + major.minor.revision.
    if not (len(resp) >= 4 and resp[0:4] == b"AMQP"):
        return FingerprintResult(confidence="none", method="amqp_identity_mismatch")

    extra = {}
    if len(resp) >= 8:
        extra["protocol_id"] = resp[4]
        extra["version"] = f"{resp[5]}.{resp[6]}.{resp[7]}"
    return FingerprintResult(
        vendor="unknown",  # AMQP is a multi-vendor broker standard — confirms the PROTOCOL
        confidence="high",
        method="amqp_protocol_header",
        extra=extra,
    )


# ── NTCIP active protocol-identity probe (Transportation / ITS) ──
# Added 2026-10-06 (in-charter-gap-sweep-register, Transportation gap). NTCIP (National Transportation
# Communications for ITS Protocol) is the US standard for traffic-signal controllers, dynamic message
# signs, environmental sensor stations, ramp meters, etc. — carried over **SNMP** (UDP 161). Every
# NTCIP device implements the NTCIP 1201 *global module table* (make/model/version per module), so a
# benign SNMP GET of `moduleMake` identifies the device AND self-reports vendor/model/version. This
# reuses the SNMP plumbing (`_snmp_get_request`/`_snmp_parse_response`) — it IS an SNMP probe, keyed on
# the NTCIP 1201 OID subtree instead of sysDescr. OIDs taken from the official ITE NTCIP 1201 MIB
# (ite-org/NTCIP-1201, NTCIP1201-Glo.mib): NEMA enterprise 1206 -> transportation(4) -> devices(2) ->
# global(6) -> globalConfiguration(1) -> globalModuleTable(3) -> moduleTableEntry(1) -> make(3)/
# model(4)/version(5); module index 1. A non-NTCIP SNMP host returns noSuchName (NULL) -> no match.
# GETs are read-only regardless of community; tries the documented NTCIP read communities.
_NTCIP_MODULE_MAKE = (1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 1, 3, 1, 3, 1)
_NTCIP_MODULE_MODEL = (1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 1, 3, 1, 4, 1)
_NTCIP_MODULE_VERSION = (1, 3, 6, 1, 4, 1, 1206, 4, 2, 6, 1, 3, 1, 5, 1)
_NTCIP_COMMUNITIES = (b"public", b"administrator")  # documented NTCIP 1201 default read communities


def _ntcip_snmp_get(host: str, port: int, oid: tuple, community: bytes, request_id: int,
                    timeout: float) -> "str | None":
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_snmp_get_request(oid, community=community, request_id=request_id), (host, port))
        data, src = sock.recvfrom(2048)
        if src[0] != host:
            return None
        return _snmp_parse_response(data, request_id, expected_oid=oid)
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_ntcip_identity(host: str, port: int = 161, timeout: float = 5.0) -> FingerprintResult:
    for community in _NTCIP_COMMUNITIES:
        make = _ntcip_snmp_get(host, port, _NTCIP_MODULE_MAKE, community, 0x4E01, timeout)
        if not make:
            continue
        model = _ntcip_snmp_get(host, port, _NTCIP_MODULE_MODEL, community, 0x4E02, timeout)
        version = _ntcip_snmp_get(host, port, _NTCIP_MODULE_VERSION, community, 0x4E03, timeout)
        extra = {"community": community.decode("ascii", "replace")}
        if version:
            extra["module_version"] = version
        return FingerprintResult(
            vendor=make,                     # moduleMake self-reported by the device (e.g. "Econolite")
            model=model or "unknown",        # moduleModel
            confidence="high",
            method="ntcip_global_module_table",
            extra=extra,
        )
    return FingerprintResult(confidence="none", method="ntcip_identity_mismatch")


# ── LXI / VXI-11 active protocol-identity probe (instrumentation / test & measurement) ──
# Added 2026-10-07 (in-charter-gap-sweep-register, instrumentation gap). VXI-11 (the TCP/IP Instrument
# Protocol) is the ONC-RPC-based control protocol under virtually all LXI instruments + GPIB-Ethernet
# gateways (NI, Keysight, Tektronix, Rohde & Schwarz, Fluke...). This asks the ONC RPC portmapper
# (TCP 111) a single benign PMAPPROC_GETPORT: "which port is the VXI-11 Device Core program on?" — a
# non-zero answer confirms a VXI-11/LXI instrument without opening any instrument link or sending any
# SCPI. A plain rpcbind/NFS host that has not registered VXI-11 returns port 0 -> no match (no false
# positive). Constants verified against python-vxi11 (python-ivi/python-vxi11): Device Core program =
# 0x0607af, version 1; portmap program 100000 v2, PMAPPROC_GETPORT=3, IPPROTO_TCP=6, AUTH_NULL. vendor
# stays "unknown" (multi-vendor LXI standard); full *IDN? vendor/model enrichment (a VXI-11
# create_link/device_write/device_read sequence) is tracked as a future enhancement.
_VXI11_CORE_PROG = 0x0607AF
_VXI11_XID = 0x4C584931  # "LXI1"


def _rpc_getport_vxi11_request(xid: int = _VXI11_XID) -> bytes:
    rpc = struct.pack(">IIIIII", xid, 0, 2, 100000, 2, 3)   # xid, CALL, rpcvers2, portmap prog, vers2, GETPORT
    rpc += struct.pack(">II", 0, 0)                          # cred = AUTH_NULL (flavor 0, len 0)
    rpc += struct.pack(">II", 0, 0)                          # verf = AUTH_NULL
    rpc += struct.pack(">IIII", _VXI11_CORE_PROG, 1, 6, 0)   # GETPORT args: prog, vers, IPPROTO_TCP, port
    return struct.pack(">I", 0x80000000 | len(rpc)) + rpc    # TCP record marker (last fragment)


def _parse_getport_reply(resp: bytes, xid: int) -> "int | None":
    try:
        if len(resp) < 4:
            return None
        body = resp[4:]  # strip the 4-byte record marker
        rxid, mtype, rstat = struct.unpack(">III", body[0:12])
        if rxid != xid or mtype != 1 or rstat != 0:   # REPLY (1), MSG_ACCEPTED (0)
            return None
        _vflavor, vlen = struct.unpack(">II", body[12:20])
        off = 20 + vlen                                # skip the verifier body
        accept_stat, port = struct.unpack(">II", body[off:off + 8])
        if accept_stat != 0:                           # SUCCESS
            return None
        return port
    except (struct.error, IndexError):
        return None


# VXI-11 Core RPC procedures (python-vxi11): CREATE_LINK 10, DEVICE_WRITE 11, DEVICE_READ 12,
# DESTROY_LINK 23. XDR: int/uint/bool = 4-byte BE; opaque/string = 4-byte length + bytes + pad to 4.
def _xdr_opaque(data: bytes) -> bytes:
    pad = (-len(data)) % 4
    return struct.pack(">I", len(data)) + data + (b"\x00" * pad)


def _vxi11_rpc(sock, proc: int, args: bytes, xid: int) -> "bytes | None":
    """One ONC RPC call to the VXI-11 Device Core program; returns the proc-result payload bytes
    (after the accepted/SUCCESS envelope) or None."""
    rpc = struct.pack(">IIIIII", xid, 0, 2, _VXI11_CORE_PROG, 1, proc)
    rpc += struct.pack(">II", 0, 0) + struct.pack(">II", 0, 0)  # cred + verf = AUTH_NULL
    rpc += args
    sock.sendall(struct.pack(">I", 0x80000000 | len(rpc)) + rpc)
    resp = sock.recv(4096)
    try:
        body = resp[4:]  # strip record marker
        rxid, mtype, rstat = struct.unpack(">III", body[0:12])
        if rxid != xid or mtype != 1 or rstat != 0:
            return None
        _vflavor, vlen = struct.unpack(">II", body[12:20])
        off = 20 + vlen
        accept_stat = struct.unpack(">I", body[off:off + 4])[0]
        if accept_stat != 0:
            return None
        return body[off + 4:]
    except (struct.error, IndexError):
        return None


def _vxi11_query_idn(host: str, core_port: int, timeout: float) -> "str | None":
    """Best-effort benign SCPI *IDN? over VXI-11: create_link -> device_write('*IDN?') ->
    device_read -> destroy_link. Returns the raw identity string (vendor,model,serial,fw) or None."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, core_port))
        # CREATE_LINK: clientId=0, lockDevice=false, lock_timeout=0, device="inst0"
        res = _vxi11_rpc(sock, 10, struct.pack(">Iii", 0, 0, 0) + _xdr_opaque(b"inst0"), 0x56583101)
        if not res or len(res) < 16 or struct.unpack(">i", res[0:4])[0] != 0:
            return None
        link = struct.unpack(">i", res[4:8])[0]
        # DEVICE_WRITE: link, io_timeout, lock_timeout, flags=8 (END), data="*IDN?\n"
        wargs = struct.pack(">iIIi", link, 2000, 0, 8) + _xdr_opaque(b"*IDN?\n")
        if not _vxi11_rpc(sock, 11, wargs, 0x56583102):
            _vxi11_rpc(sock, 23, struct.pack(">i", link), 0x56583104)
            return None
        # DEVICE_READ: link, request_size=256, io_timeout, lock_timeout, flags=0, term_char=0
        rargs = struct.pack(">iIIiii", link, 256, 2000, 0, 0, 0)
        rres = _vxi11_rpc(sock, 12, rargs, 0x56583103)
        _vxi11_rpc(sock, 23, struct.pack(">i", link), 0x56583104)  # DESTROY_LINK (cleanup)
        if not rres or len(rres) < 12 or struct.unpack(">i", rres[0:4])[0] != 0:
            return None
        dlen = struct.unpack(">I", rres[8:12])[0]       # error, reason, then opaque(len+data)
        idn = rres[12:12 + dlen].decode("latin-1", "replace").strip()
        return idn or None
    except (OSError, struct.error, IndexError):
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_lxi_vxi11_identity(host: str, port: int = 111, timeout: float = 5.0) -> FingerprintResult:
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_rpc_getport_vxi11_request())
        resp = sock.recv(256)
    except OSError:
        return FingerprintResult(confidence="none", method="lxi_vxi11_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    vxi_port = _parse_getport_reply(resp, _VXI11_XID)
    if vxi_port:   # non-zero VXI-11 Device Core port registered -> it's a VXI-11/LXI instrument
        extra = {"vxi11_core_port": vxi_port}
        vendor, model = "unknown", "unknown"
        # Best-effort benign SCPI *IDN? to self-report vendor/model; never downgrades the match.
        idn = _vxi11_query_idn(host, vxi_port, timeout)
        if idn:
            extra["idn"] = idn
            fields = idn.split(",")
            if fields and fields[0].strip():
                vendor = fields[0].strip()
            if len(fields) > 1 and fields[1].strip():
                model = fields[1].strip()
        return FingerprintResult(
            vendor=vendor,  # from *IDN? field 0 when available; else "unknown" (multi-vendor LXI)
            model=model,
            confidence="high",
            method="vxi11_portmap_getport",
            extra=extra,
        )
    return FingerprintResult(confidence="none", method="lxi_vxi11_identity_mismatch")


# ── SECS/GEM over HSMS active protocol-identity probe (semiconductor / electronic-mfg equipment) ──
# Added 2026-10-07 (in-charter-gap-sweep-register, semiconductor gap). HSMS (SEMI E37) is the TCP
# transport for SECS-II/GEM on semiconductor / SMT / ATE equipment, TCP 5000. This sends the standard
# HSMS **Select.req** control message and confirms a **Select.rsp** (or a Reject.req — either proves an
# HSMS peer); it carries NO SECS-II data and issues no equipment command (benign handshake). Message =
# 4-byte big-endian length + 10-byte header: sessionID(2)=0xFFFF, stream(1)=0, function(1)=0, pType(1)=0,
# sType(1), system(4). SType 1=Select.req / 2=Select.rsp / 7=Reject.req. Layout + example verified
# against the secsgem OSS lib (bparzella/secsgem, hsms/header.py: Linktest example ff:ff:00:00:00:05:...).
# PORT COLLISION NOTE: 5000 is also MELSEC SLMP — disambiguated by the frame (SLMP uses subheader 0x5000
# / response 0xd000; an HSMS peer instead returns a Select.rsp with sType 0x02 and our echoed system
# bytes), so slmp_identity and hsms_identity never cross-match. vendor stays "unknown" (multi-vendor).
_HSMS_SYSTEM = 0x53454331  # "SEC1" — distinctive, echoed back by the peer
_HSMS_SELECT_REQ = struct.pack(">I", 10) + struct.pack(">HBBBBI", 0xFFFF, 0, 0, 0, 0x01, _HSMS_SYSTEM)


def probe_hsms_identity(host: str, port: int = 5000, timeout: float = 5.0) -> FingerprintResult:
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_HSMS_SELECT_REQ)
        resp = sock.recv(64)
    except OSError:
        return FingerprintResult(confidence="none", method="hsms_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # 4-byte length + 10-byte header; sType at header offset 5 (abs 9), system at header 6:10 (abs 10:14).
    if len(resp) < 14:
        return FingerprintResult(confidence="none", method="hsms_identity_short")
    s_type = resp[9]
    if s_type == 0x02 and resp[10:14] == struct.pack(">I", _HSMS_SYSTEM):   # Select.rsp echoing our system
        return FingerprintResult(vendor="unknown", confidence="high", method="hsms_select_rsp")
    if s_type == 0x07:   # Reject.req — still proves an HSMS peer answered
        return FingerprintResult(vendor="unknown", confidence="high", method="hsms_reject_req")
    return FingerprintResult(confidence="none", method="hsms_identity_mismatch")


# ── SICK device REST-API identity probe ─────────────────────────────────────
# Added 2026-10-12 alongside the SICK REST default-credential check (checks/http/
# sick-rest-api-service-default-creds.yaml). SICK's modern sensor/reader/camera REST API (AppSpace
# / "device REST", seen across picoScan, Inspector/InspectorP, Lector, RFU and siblings) answers an
# UNAUTHENTICATED GET /api/FirmwareVersion with its distinctive JSON envelope {"header":{...},
# "data":{"FirmwareVersion":"<ver>"}} -- confirmed directly from SICK AG's own MIT-licensed
# firmware_update_example.py (shipped in the firmware ingest: it calls exactly this endpoint with no
# auth to read the version before logging in). This probe sends ONE read-only GET and confirms that
# exact shape; it never sends credentials and never touches any protected endpoint. vendor="SICK";
# model stays "unknown" because this REST stack is shared across many SICK product families (the
# version string lands in `firmware`/extra). confidence="high" only on a parsed data.FirmwareVersion;
# "none" otherwise (unreachable / non-HTTP / not the SICK envelope), fail-closed like every probe here.
def probe_sick_rest_identity(host: str, port: int = 80, timeout: float = 5.0) -> FingerprintResult:
    """Active SICK device-REST identity probe: one unauthenticated ``GET /api/FirmwareVersion``.
    confidence='high' when the JSON body carries ``data.FirmwareVersion`` (the SICK REST envelope);
    'none' for anything else. Read-only, no credentials, only ``/api/FirmwareVersion``."""
    import json as _json
    request = (
        f"GET /api/FirmwareVersion HTTP/1.1\r\nHost: {host}\r\n"
        "Accept: application/json\r\nConnection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")

    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request)
        buf = b""
        # Cap the read: a chatty/garbage service can't make us read forever, but allow enough for
        # the small JSON body to arrive after the headers.
        while len(buf) < 16384:
            try:
                chunk = sock.recv(4096)
            except _socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="sick_rest_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if not buf:
        return FingerprintResult(confidence="none", method="sick_rest_identity_no_response")
    head, _, body = buf.partition(b"\r\n\r\n")
    if not head.upper().startswith(b"HTTP/"):
        return FingerprintResult(confidence="none", method="sick_rest_identity_not_http")
    # Parse the JSON body (best-effort: tolerate chunked framing by locating the outermost object).
    text = body.decode("latin-1", errors="replace")
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        return FingerprintResult(confidence="none", method="sick_rest_identity_no_json")
    try:
        obj = _json.loads(text[start:end + 1])
    except ValueError:
        return FingerprintResult(confidence="none", method="sick_rest_identity_bad_json")
    data = obj.get("data") if isinstance(obj, dict) else None
    ver = data.get("FirmwareVersion") if isinstance(data, dict) else None
    if isinstance(ver, str) and ver:
        return FingerprintResult(
            vendor="SICK",            # the SICK device-REST stack — shared across product families,
            confidence="high",        # so model stays unknown; the version lands in firmware/extra.
            firmware=ver,
            method="sick_rest_identity",
            extra={"firmware_version": ver, "endpoint": "/api/FirmwareVersion"},
        )
    return FingerprintResult(confidence="none", method="sick_rest_identity_no_version")


# ── Hesai LiDAR web-control (pandar.cgi) identity probe ──────────────────────
# Added 2026-10-13 alongside the Hesai default-login check (checks/http/
# hesai-lidar-web-default-login.yaml). Hesai LiDARs (Pandar/AT/XT/QT/JT/OT families) expose a web
# control whose API lives at the distinctive path `/pandar.cgi?action=get&object=<obj>` returning a
# JSON body -- confirmed from Hesai's own sample code (github.com/HesaiTechnology/Cyber_Security,
# ptc_cgi_sample/cgi/py/http.py, which GETs `object=workmode` and json-parses the reply). This probe
# sends ONE read-only unauthenticated GET for `object=workmode` and treats a JSON-object reply from
# `pandar.cgi` as a Hesai web-control identification (the path is vendor-distinctive). Web auth is OFF
# by default (gated behind the device's "Cyber Security Master Switch"), so on a default unit this GET
# returns data without a cookie. vendor="Hesai"; model stays unknown (shared across many LiDAR
# families). confidence="high" on a JSON-object reply, "none" otherwise, fail-closed like every probe
# here. INFERRED (not live-verified): the exact reply shape when login control is ENABLED -- it may be
# an auth-required JSON error (still identifies Hesai) or a redirect (would read as no-match). Never
# sends credentials; only GETs one benign object.
def probe_hesai_pandar_web_identity(host: str, port: int = 80, timeout: float = 5.0) -> FingerprintResult:
    """Active Hesai LiDAR web-control identity probe: one unauthenticated
    ``GET /pandar.cgi?action=get&object=workmode``. confidence='high' when the reply body is a JSON
    object (the Hesai pandar.cgi web API); 'none' otherwise. Read-only, no credentials."""
    import json as _json
    request = (
        "GET /pandar.cgi?action=get&object=workmode HTTP/1.1\r\n"
        f"Host: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")

    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request)
        buf = b""
        while len(buf) < 16384:
            try:
                chunk = sock.recv(4096)
            except _socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="hesai_pandar_web_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if not buf:
        return FingerprintResult(confidence="none", method="hesai_pandar_web_identity_no_response")
    head, _, body = buf.partition(b"\r\n\r\n")
    if not head.upper().startswith(b"HTTP/"):
        return FingerprintResult(confidence="none", method="hesai_pandar_web_identity_not_http")
    text = body.decode("latin-1", errors="replace")
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        return FingerprintResult(confidence="none", method="hesai_pandar_web_identity_no_json")
    try:
        obj = _json.loads(text[start:end + 1])
    except ValueError:
        return FingerprintResult(confidence="none", method="hesai_pandar_web_identity_bad_json")
    if isinstance(obj, dict):
        return FingerprintResult(
            vendor="Hesai",           # the pandar.cgi web-control stack -- shared across LiDAR families,
            confidence="high",        # so model stays unknown.
            method="hesai_pandar_web_identity",
            extra={"endpoint": "/pandar.cgi", "object": "workmode"},
        )
    return FingerprintResult(confidence="none", method="hesai_pandar_web_identity_not_json_object")


# ── EMQX dashboard (MQTT broker web console) identity probe ──────────────────
# Added 2026-10-13 alongside the EMQX/Moxa-DLM dashboard default-creds check (checks/http/
# moxa-dlm-emqx-dashboard-default-creds.yaml). EMQX 5.x exposes its dashboard REST API at the
# version-distinctive path `/api/v5/login` (POST-only; a GET returns HTTP 405 Method Not Allowed).
# This probe sends ONE read-only unauthenticated GET to /api/v5/login and treats an HTTP 405, or a
# body mentioning emqx, as an EMQX-5 dashboard identification -- the `/api/v5/login` path is
# EMQX-specific. Default dashboard port 18083. vendor="EMQX". confidence="high" on the 405/emqx
# signal, "none" otherwise, fail-closed. INFERRED (not live-verified): the exact GET-on-login-
# endpoint status on every EMQX build; documented as such. Never sends credentials.
def probe_emqx_dashboard_identity(host: str, port: int = 18083, timeout: float = 5.0) -> FingerprintResult:
    """Active EMQX dashboard identity probe: one unauthenticated ``GET /api/v5/login`` (a POST-only
    endpoint). confidence='high' on HTTP 405 or an 'emqx'-bearing body (the EMQX 5 dashboard API);
    'none' otherwise. Read-only, no credentials."""
    request = (
        "GET /api/v5/login HTTP/1.1\r\n"
        f"Host: {host}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request)
        buf = b""
        while len(buf) < 8192:
            try:
                chunk = sock.recv(2048)
            except _socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="emqx_dashboard_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if not buf:
        return FingerprintResult(confidence="none", method="emqx_dashboard_identity_no_response")
    head, _, body = buf.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    if not status_line.upper().startswith("HTTP/"):
        return FingerprintResult(confidence="none", method="emqx_dashboard_identity_not_http")
    low = (status_line + " " + body.decode("latin-1", errors="replace")).lower()
    if " 405" in status_line or "emqx" in low:
        return FingerprintResult(vendor="EMQX", confidence="high", method="emqx_dashboard_identity",
                                 extra={"endpoint": "/api/v5/login", "status": status_line.strip()})
    return FingerprintResult(confidence="none", method="emqx_dashboard_identity_no_match")


# ── Ouster LiDAR device HTTP API identity probe ──────────────────────────────
# Added 2026-10-13 alongside the Ouster unauthenticated-API check (checks/http/
# ouster-lidar-unauthenticated-http-api.yaml). Ouster OS-series sensors expose a device HTTP API at
# /api/v1/ that the SDK (github.com/ouster-lidar/ouster-sdk SensorHttp) drives with NO auth. This
# probe sends ONE read-only unauthenticated GET /api/v1/sensor/metadata and confirms the Ouster
# sensor_info JSON envelope (distinctive keys prod_line / image_rev / build_rev). It is both the
# fingerprint AND the direct evidence of the missing-auth state (the endpoint answers with no
# credential). vendor="Ouster"; firmware from build_rev when present. confidence="high" on the
# Ouster JSON keys, "none" otherwise, fail-closed. Read-only, no credentials, metadata endpoint only
# (never the cmd/* endpoints). INFERRED (not live-verified): exact metadata key set across all fw.
def probe_ouster_http_identity(host: str, port: int = 80, timeout: float = 5.0) -> FingerprintResult:
    """Active Ouster LiDAR identity probe: one unauthenticated ``GET /api/v1/sensor/metadata``.
    confidence='high' when the JSON body carries the Ouster sensor_info keys (prod_line + image_rev/
    build_rev); 'none' otherwise. Read-only, no credentials."""
    import json as _json
    request = (
        "GET /api/v1/sensor/metadata HTTP/1.1\r\n"
        f"Host: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request)
        buf = b""
        while len(buf) < 65536:
            try:
                chunk = sock.recv(8192)
            except _socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="ouster_http_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if not buf:
        return FingerprintResult(confidence="none", method="ouster_http_identity_no_response")
    head, _, body = buf.partition(b"\r\n\r\n")
    if not head.upper().startswith(b"HTTP/"):
        return FingerprintResult(confidence="none", method="ouster_http_identity_not_http")
    text = body.decode("latin-1", errors="replace")
    s, e = text.find("{"), text.rfind("}")
    if s == -1 or e <= s:
        return FingerprintResult(confidence="none", method="ouster_http_identity_no_json")
    try:
        obj = _json.loads(text[s:e + 1])
    except ValueError:
        return FingerprintResult(confidence="none", method="ouster_http_identity_bad_json")
    if isinstance(obj, dict) and "prod_line" in obj and ("image_rev" in obj or "build_rev" in obj):
        fw = obj.get("image_rev") or obj.get("build_rev") or "unknown"
        return FingerprintResult(vendor="Ouster", model=str(obj.get("prod_line", "unknown")),
                                 firmware=str(fw), confidence="high", method="ouster_http_identity",
                                 extra={"prod_line": obj.get("prod_line"), "prod_sn": obj.get("prod_sn")})
    return FingerprintResult(confidence="none", method="ouster_http_identity_no_match")


# ── LXI HTTP identification probe ─────────────────────────────────────────────
# Added 2026-11-09. The LXI standard defines a benign, authentication-free HTTP identification
# document served at `/lxi/identification` (root <LXIDevice> in namespace
# http://www.lxistandard.org/InstrumentIdentification/1.0, carrying Manufacturer/Model/SerialNumber/
# FirmwareRevision/Interface). Confirmed as a standard discovery mechanism by the LXI Consortium's own
# reference "Discovery Tool for LXI Devices" v1.11 (Pickering Interfaces), which fetches exactly this
# path. Complements probe_lxi_vxi11_identity (VXI-11/ONC-RPC on 111): this HTTP identification is
# reachable on TCP/80 even when the VXI-11 portmapper is filtered, and is cleaner/safer than *IDN?.
# One read-only unauthenticated GET. vendor = the device-reported Manufacturer (LXI is multi-vendor:
# Keysight, Tektronix, Rohde & Schwarz, NI, Ametek/Sorensen, ...). Fail-closed. No credentials.
def probe_lxi_http_identity(host: str, port: int = 80, timeout: float = 5.0) -> FingerprintResult:
    """Active LXI identity probe: one unauthenticated ``GET /lxi/identification``.
    confidence='high' when the XML body is an LXI identification document (root LXIDevice / the
    lxistandard.org InstrumentIdentification namespace) carrying a Manufacturer; 'none' otherwise.
    Read-only, no credentials."""
    import xml.etree.ElementTree as _ET
    request = (
        "GET /lxi/identification HTTP/1.1\r\n"
        f"Host: {host}\r\nAccept: application/xml\r\nConnection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request)
        buf = b""
        while len(buf) < 65536:
            try:
                chunk = sock.recv(8192)
            except _socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="lxi_http_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if not buf:
        return FingerprintResult(confidence="none", method="lxi_http_identity_no_response")
    head, _, body = buf.partition(b"\r\n\r\n")
    if not head.upper().startswith(b"HTTP/"):
        return FingerprintResult(confidence="none", method="lxi_http_identity_not_http")
    s = body.find(b"<")
    if s == -1:
        return FingerprintResult(confidence="none", method="lxi_http_identity_no_xml")
    try:
        root = _ET.fromstring(body[s:])
    except _ET.ParseError:
        return FingerprintResult(confidence="none", method="lxi_http_identity_bad_xml")

    def _local(tag: str) -> str:  # strip any {namespace} prefix
        return tag.rsplit("}", 1)[-1]

    if _local(root.tag) != "LXIDevice" and "lxistandard.org" not in root.tag:
        return FingerprintResult(confidence="none", method="lxi_http_identity_no_match")
    fields = {_local(child.tag): (child.text or "").strip() for child in root}
    mfr = fields.get("Manufacturer", "")
    if not mfr:
        return FingerprintResult(confidence="none", method="lxi_http_identity_no_manufacturer")
    return FingerprintResult(
        vendor=mfr,
        model=fields.get("Model") or "unknown",
        firmware=fields.get("FirmwareRevision") or "unknown",
        serial=fields.get("SerialNumber") or "unknown",
        confidence="high", method="lxi_http_identity",
        extra={"manufacturer_description": fields.get("ManufacturerDescription")},
    )


# ── Trihedral VTScada Internet-Server identity probe ─────────────────────────
# Added 2026-11-10 (dam-lock-scada-sweep; Dams-sector lead). VTScada's built-in Internet/Thin-Client
# ("VTScada Anywhere") web server identifies itself with a `Server: VTScada` (or versioned
# `Server: VTS/<version> (OrLater)`) response header, and emits a distinctive CORS header
# `Access-Control-Allow-Headers: ... X-VTScadaAuth` (with AppGUID / Realm / Session-ID). Both strings
# were read verbatim from the VTScada 12.3.01 runtime binary VTS.exe (installed via Wine from the
# vendor trial; see dam-lock-scada-sweep-2026-11.md), not recalled. Read-only unauthenticated GET /,
# no credentials. Port is configurable (80/443 default) so the probe keys on the header, not the port.
def probe_vtscada_http_identity(host: str, port: int = 80, timeout: float = 5.0) -> FingerprintResult:
    """Active Trihedral VTScada identity probe: one unauthenticated ``GET /``.
    confidence='high' when the HTTP response carries ``Server: VTScada`` / ``Server: VTS/<version>`` or
    the distinctive ``X-VTScadaAuth`` CORS header; 'none' otherwise. Read-only, no credentials."""
    import re as _re
    request = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request)
        buf = b""
        while len(buf) < 65536:
            try:
                chunk = sock.recv(8192)
            except _socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="vtscada_http_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if not buf:
        return FingerprintResult(confidence="none", method="vtscada_http_identity_no_response")
    head, _, _body = buf.partition(b"\r\n\r\n")
    if not head.upper().startswith(b"HTTP/"):
        return FingerprintResult(confidence="none", method="vtscada_http_identity_not_http")
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        name, sep, val = line.partition(b":")
        if sep:
            headers[name.strip().lower().decode("ascii", "ignore")] = val.strip().decode("latin-1", "ignore")
    server = headers.get("server", "")
    acah = headers.get("access-control-allow-headers", "")
    server_match = server.lower().startswith("vtscada") or server.lower().startswith("vts/")
    cors_match = "x-vtscadaauth" in acah.lower()
    if not (server_match or cors_match):
        return FingerprintResult(confidence="none", method="vtscada_http_identity_no_match")
    version = "unknown"
    vm = _re.match(r"vts/([0-9][0-9.]*)", server, _re.IGNORECASE)
    if vm:
        version = vm.group(1)
    return FingerprintResult(
        vendor="Trihedral", model="VTScada", firmware=version,
        confidence="high",
        method="vtscada_http_identity" if server_match else "vtscada_http_identity_cors",
        extra={"server_header": server or None, "x_vtscadaauth": cors_match},
    )


# ── Opto 22 OptoMMP unauthenticated identity probe ───────────────────────────
# Added 2026-11-10 (opto22 firmware-sweep follow-up). OptoMMP is Opto 22's IEEE-1394-based
# memory-mapped protocol (TCP 2001) spoken by SNAP PAC, groov EPIC, groov RIO, and SNAP I/O brains.
# It has NO authentication -- any client that can reach TCP/2001 can read/write the device memory map
# (I/O points, control, config). This probe sends ONE benign READ-BLOCK request for the firmware-
# version memory-map address (0xF030001C, 4 bytes) and confirms a read-block RESPONSE (tcode 7). It is
# READ-ONLY; it never issues a write/control. The read-block request byte layout + the firmware-version
# address are taken verbatim from the public OptoMMP toolkit (github.com/optodeveloper/optommp:
# optommp/__init__.py BuildReadBlockRequest + O22SIOUT.py BASE_FIRMWARE_VERSION/TCODE_READ_BLOCK_*) and
# the OptoMMP Protocol Guide (Opto 22 form 1465) -- not recalled. Response framing (16-byte header then
# data; IEEE-1394 read-block-response tcode 7 at header byte 3's upper nibble) follows the 1394 standard
# the toolkit's data[16:] unpack assumes; the probe FAILS CLOSED, so a framing mismatch yields no match
# (never a false positive). Live-device confirmation is advisable before treating a match as definitive.
_OPTOMMP_FW_ADDR = 0xF030001C  # BASE_FIRMWARE_VERSION memory-map address
# read-block request (16 bytes): [0,0, tl<<2, tcode<<4, 0,0, 0xFF,0xFF, dest(4 BE), 0, size, 0,0]
_OPTOMMP_READ_FW = bytes([0, 0, 0, (5 << 4), 0, 0, 0xFF, 0xFF]) + struct.pack(">I", _OPTOMMP_FW_ADDR) + bytes([0, 4, 0, 0])


def probe_optommp_identity(host: str, port: int = 2001, timeout: float = 5.0) -> FingerprintResult:
    """Active Opto 22 OptoMMP identity probe: one benign unauthenticated READ-BLOCK of the firmware-
    version memory-map address (0xF030001C). confidence='high' on a well-formed read-block response
    (tcode 7, >=16-byte header + 4 data bytes); 'none' otherwise. Read-only, no write, no credentials."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_OPTOMMP_READ_FW)
        resp = sock.recv(64)
    except OSError:
        return FingerprintResult(confidence="none", method="optommp_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if len(resp) < 20:
        return FingerprintResult(confidence="none", method="optommp_identity_short")
    if (resp[3] >> 4) != 7:   # IEEE-1394 read-block-response tcode
        return FingerprintResult(confidence="none", method="optommp_identity_mismatch")
    # firmware version: data bytes [V, v, N, c] at offset 16; N (resp[18]) maps 0->A 1->B 2->R 3->S
    v, vv, n, c = resp[16], resp[17], resp[18], resp[19]
    letter = {0: "A", 1: "B", 2: "R", 3: "S"}.get(n, "?")
    return FingerprintResult(
        vendor="Opto 22", firmware=f"{letter}{v}.{vv}{c}",
        confidence="high", method="optommp_identity",
        extra={"memory_map_read": "0xF030001C"},
    )


def parse_optommp_frame(payload: bytes) -> FingerprintResult:
    """Parse an Opto 22 OptoMMP frame for passive discovery (TCP/UDP 2001). OptoMMP is Opto 22's
    IEEE-1394-based memory-mapped protocol (SNAP PAC, groov EPIC/RIO, SNAP I/O). The transaction code
    (high nibble of byte 3) identifies the 1394 packet type. Returns OptoMMP presence (vendor Opto 22);
    firmware is NOT extracted passively because it depends on which memory-map address was read, which
    lives in the request -- the active probe (which reads 0xF030001C) is the identity path for that."""
    if len(payload) < 16:
        return FingerprintResult(confidence="none", method="optommp_mismatch")
    tcode = payload[3] >> 4
    if tcode not in (0, 1, 4, 5, 6, 7, 9):                    # valid IEEE-1394 transaction codes
        return FingerprintResult(confidence="none", method="optommp_mismatch")
    return FingerprintResult(vendor="Opto 22", model="Opto 22 OptoMMP device", confidence="low",
                             method="optommp_passive", extra={"protocol": "optommp", "tcode": tcode})


# ── Veeder-Root TLS / ATG serial-command-port identity probe ─────────────────
# Added 2026-11-10 (TSA sweep §7 Automatic Tank Gauge lead). Veeder-Root TLS-300/350/450/4 Automatic
# Tank Gauge consoles expose their "Serial Command Port" over TCP (default 10001, confirmed in the
# Veeder-Root TCP/IP Interface Module guide 577013-776 and the TLS-3XX setup manual 576013-623). The
# TLS-350 "computer format" command protocol is one SOH byte (0x01 / Ctrl-A) + a command code; I-series
# codes are READ-only information reports. This probe sends ONE benign I90200 SYSTEM SOFTWARE VERSION
# report request (0x01 + "I90200") -- the least-sensitive read (console software/type, no tank or fuel
# data) -- and matches a TLS-350 response. It issues NO S-series set command and reads no inventory.
# Command bytes + the 9999FF1B "command not understood" error sentinel are taken verbatim from the public
# Rapid7 Metasploit ATG module (rapid7/metasploit-framework modules/auxiliary/admin/atg/atg_client.rb:
# TLS-350_CMD "\x01I90200", RPORT 10001), not recalled. Fails closed. A successful unauthenticated
# response also means the Serial Command Port accepts commands with NO security code (CWE-306) -- the
# exposure the Veeder-Root TLS4 security notification 576047-407 warns about and the Bitsight/CISA 2024
# ATG advisories cover. Live-device confirmation of the exact response framing is advisable before
# treating a match as definitive.
_ATG_TLS350_VERSION_CMD = b"\x01I90200"


def probe_atg_tls350_identity(host: str, port: int = 10001, timeout: float = 5.0) -> FingerprintResult:
    """Active Veeder-Root TLS / ATG identity probe: one benign TLS-350 I90200 (system software version)
    read over the Serial Command Port. confidence='high' when the console returns a TLS-350 version
    report (echoes 'I90200') or the 9999 TLS error; 'none' otherwise. Read-only, no set command, no
    inventory read, no credentials."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_ATG_TLS350_VERSION_CMD)
        resp = b""
        while len(resp) < 4096:
            try:
                chunk = sock.recv(1024)
            except _socket.timeout:
                break
            if not chunk:
                break
            resp += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="atg_tls350_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if not resp:
        return FingerprintResult(confidence="none", method="atg_tls350_identity_no_response")
    text = resp.decode("latin-1", errors="ignore")
    # A TLS-350 computer-format response echoes the command code (I90200). The 9999FF1B sentinel means
    # the console understood a command was sent but rejected it -- still a TLS-350 ATG command processor.
    if "I90200" in text:
        return FingerprintResult(
            vendor="Veeder-Root", model="TLS-350/450/4 ATG",
            confidence="high", method="atg_tls350_version_report",
            extra={"serial_command_port": "unauthenticated", "raw_prefix": text[:48]},
        )
    if "9999FF1B" in text or text.startswith("9999"):
        return FingerprintResult(
            vendor="Veeder-Root", model="TLS ATG",
            confidence="high", method="atg_tls350_error_sentinel",
            extra={"serial_command_port": "reachable"},
        )
    return FingerprintResult(confidence="none", method="atg_tls350_identity_no_match")


# ── Opto 22 FTP-banner identity probe ────────────────────────────────────────
# Added 2026-11-10 (promotes the SNAP PAC web/FTP exposure candidate, ICSA-23-236-02). Opto 22 SNAP
# PAC / SNAP I/O controllers run a built-in FTP management service whose greeting banner is the
# distinctive "220 Opto 22 FTP server ready." -- read verbatim from SNAP PAC S1 firmware R10.7c
# (snap-pac-s1-R10.7c.bin), not recalled. This probe reads ONLY the FTP 220 greeting (no USER/PASS,
# no authentication) and matches that banner. A match confirms an exposed Opto 22 FTP management
# service (the CVE-2023-40708 "FTP open by default" condition). Read-only, no credentials.
def probe_opto22_ftp_identity(host: str, port: int = 21, timeout: float = 5.0) -> FingerprintResult:
    """Active Opto 22 FTP identity probe: read the FTP 220 greeting on port 21 and match the Opto 22
    FTP server banner. confidence='high' on a '220 ... Opto 22 FTP server' greeting; 'none' otherwise.
    Read-only -- no USER/PASS is sent, no authentication is attempted."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        banner = sock.recv(256)
    except OSError:
        return FingerprintResult(confidence="none", method="opto22_ftp_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if not banner:
        return FingerprintResult(confidence="none", method="opto22_ftp_identity_no_banner")
    text = banner.decode("latin-1", errors="ignore")
    line = text.splitlines()[0] if text.splitlines() else ""
    if line.startswith("220") and "opto 22 ftp" in text.lower():
        return FingerprintResult(
            vendor="Opto 22", confidence="high", method="opto22_ftp_identity",
            extra={"ftp_banner": line.strip()[:120]},
        )
    return FingerprintResult(confidence="none", method="opto22_ftp_identity_no_match")


# ── CODESYS WebVisu identity probe ───────────────────────────────────────────
# Added 2026-10-13 to promote the ABB AC500 CODESYS WebVisu candidate (checks/candidates/
# abb-ac500-ckit-codesys-webvisu-no-login.yaml), which was blocked on "no WebVisu probe/executor
# exists". CODESYS V3's HTML5 WebVisu runtime serves `webvisu.cfg.json` (a JSON config carrying the
# `PlcAddress` the canvas connects to) alongside `webvisu.htm`. This probe sends ONE read-only
# unauthenticated GET /webvisu.cfg.json and treats a JSON object with a WebVisu key (PlcAddress /
# UpdateRate) as a CODESYS WebVisu identification. vendor stays "unknown" (CODESYS WebVisu ships in
# many PLC brands -- ABB AC500, WAGO, Berghof, Schneider M2xx, etc.). confidence="high" on the JSON
# match, "none" otherwise, fail-closed. INFERRED (not live-verified): the exact served path/port of
# webvisu.cfg.json across runtimes (the candidate took it from ABB PM5650 firmware; default port 8080
# is the common CODESYS V3 webserver port). Read-only, no credentials.
def probe_codesys_webvisu_identity(host: str, port: int = 8080, timeout: float = 5.0) -> FingerprintResult:
    """Active CODESYS WebVisu identity probe: one unauthenticated ``GET /webvisu.cfg.json``.
    confidence='high' when the JSON body carries a WebVisu key (PlcAddress/UpdateRate); 'none'
    otherwise. Read-only, no credentials."""
    import json as _json
    request = (
        "GET /webvisu.cfg.json HTTP/1.1\r\n"
        f"Host: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request)
        buf = b""
        while len(buf) < 16384:
            try:
                chunk = sock.recv(4096)
            except _socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="codesys_webvisu_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if not buf:
        return FingerprintResult(confidence="none", method="codesys_webvisu_identity_no_response")
    head, _, body = buf.partition(b"\r\n\r\n")
    if not head.upper().startswith(b"HTTP/"):
        return FingerprintResult(confidence="none", method="codesys_webvisu_identity_not_http")
    text = body.decode("latin-1", errors="replace")
    s, e = text.find("{"), text.rfind("}")
    if s == -1 or e <= s:
        return FingerprintResult(confidence="none", method="codesys_webvisu_identity_no_json")
    try:
        obj = _json.loads(text[s:e + 1])
    except ValueError:
        return FingerprintResult(confidence="none", method="codesys_webvisu_identity_bad_json")
    if isinstance(obj, dict) and ("PlcAddress" in obj or "UpdateRate" in obj):
        return FingerprintResult(vendor="unknown", confidence="high", method="codesys_webvisu_identity",
                                 extra={"plc_address": obj.get("PlcAddress"), "endpoint": "/webvisu.cfg.json"})
    return FingerprintResult(confidence="none", method="codesys_webvisu_identity_no_match")


# ── Omron/Microscan MicroHAWK WebLink identity probe ─────────────────────────
# Added 2026-10-13 alongside the MicroHAWK unauthenticated-API check (checks/http/
# omron-microhawk-weblink-unauthenticated-api.yaml). MicroHAWK readers (V320-F/V330-F/V420-F/V430-F,
# QX/MINI Hawk, etc.) serve the WebLink SPA, whose Angular bootstrap loads device config UNauthenticated
# from /api/v1/file/device/parameters.json -- a JSON ARRAY of parameter-schema objects (each with
# `uid` like "K100.01" + `editor`/`type`). This probe GETs that endpoint read-only and confirms that
# array shape = a MicroHAWK WebLink reachable with no credential (the device-REST API is unauthenticated;
# the WebLink login itself is client-side-only, see the candidate). vendor="Omron (Microscan)".
# confidence="high" on the param-schema array; "none" otherwise, fail-closed. Read-only, no credentials.
def probe_microhawk_weblink_identity(host: str, port: int = 80, timeout: float = 5.0) -> FingerprintResult:
    """Active Omron/Microscan MicroHAWK WebLink identity probe: one unauthenticated
    ``GET /api/v1/file/device/parameters.json``. confidence='high' when the body is a JSON array of
    objects carrying the MicroHAWK param-schema keys (uid + editor/type); 'none' otherwise. Read-only."""
    import json as _json
    request = (
        "GET /api/v1/file/device/parameters.json HTTP/1.1\r\n"
        f"Host: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(request)
        buf = b""
        while len(buf) < 262144:
            try:
                chunk = sock.recv(16384)
            except _socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="microhawk_weblink_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if not buf:
        return FingerprintResult(confidence="none", method="microhawk_weblink_identity_no_response")
    head, _, body = buf.partition(b"\r\n\r\n")
    if not head.upper().startswith(b"HTTP/"):
        return FingerprintResult(confidence="none", method="microhawk_weblink_identity_not_http")
    text = body.decode("latin-1", errors="replace")
    s, e = text.find("["), text.rfind("]")
    if s == -1 or e <= s:
        return FingerprintResult(confidence="none", method="microhawk_weblink_identity_no_array")
    try:
        obj = _json.loads(text[s:e + 1])
    except ValueError:
        return FingerprintResult(confidence="none", method="microhawk_weblink_identity_bad_json")
    if isinstance(obj, list) and any(isinstance(it, dict) and "uid" in it and ("editor" in it or "type" in it)
                                     for it in obj[:50]):
        return FingerprintResult(vendor="Omron (Microscan)", confidence="high",
                                 method="microhawk_weblink_identity", extra={"endpoint": "/api/v1/file/device/parameters.json"})
    return FingerprintResult(confidence="none", method="microhawk_weblink_identity_no_match")


# ── Milesight / Ursalink industrial-router web-identity probe ────────────────
# Added 2026-10-19 to give the Milesight router web default-credential candidate
# (checks/candidates/milesight-m35x-5g-router-web-default-creds.yaml) a concrete, remote-capable
# identity gate. Grounded on CVE-2023-43261 (VulnCheck's public PoC, `curl -ks https://<ip>/login |
# jq`): the Milesight/Ursalink router httpd answers an UNAUTHENTICATED GET /login with a distinctive
# JSON envelope that discloses device identity, e.g. --
#   {"id":-1,"model":"UR35","pn":"","oem":"0000","rtver":"35.2.0.10","status":-2,
#    "result":[{"login":"false","ysrole":...,"timeout":...,"upgrade_error":...}]}
# The (model + rtver + result[].login) field combination is the vendor-distinctive signature; it is
# model-agnostic (`model` is whatever UR/M-series unit answers, firmware lands in `rtver`), so one
# probe covers the whole router line. This probe sends ONE read-only, unauthenticated GET /login over
# TLS -- these routers serve the web on HTTPS/443 with a self-signed cert, so verification is disabled
# (we are fingerprinting, not trusting it) -- and matches ONLY on that envelope. No credentials.
# vendor="Milesight"; confidence="high" on a match, "none" otherwise, fail-closed like every probe
# here. SCOPE: this identifies the Milesight ROUTER platform (UR/M35x). The Milesight camera/IoT
# platform (the shared-root `ms3456` issue, checks/ssh/milesight-camera-shared-root-ms3456-...) is a
# DIFFERENT stack with no documented unauth identity endpoint, so this probe deliberately does NOT
# gate the camera check -- a camera-specific identity probe remains a separate follow-up.
def probe_milesight_router_identity(host: str, port: int = 443, timeout: float = 5.0) -> FingerprintResult:
    """Active Milesight/Ursalink router identity probe: one unauthenticated TLS ``GET /login``.
    confidence='high' when the JSON body is the Milesight router httpd envelope (model + rtver +
    result[].login, per CVE-2023-43261); 'none' otherwise. Read-only, no credentials."""
    import json as _json
    request = (
        "GET /login HTTP/1.1\r\n"
        f"Host: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    ).encode("ascii", errors="ignore")
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        import ssl
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(request)
        buf = b""
        while len(buf) < 65536:
            try:
                chunk = sock.recv(8192)
            except _socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    except OSError:
        # includes ssl.SSLError (an OSError subclass): a TLS/connect failure just means "not a
        # Milesight router httpd here", not an error to surface
        return FingerprintResult(confidence="none", method="milesight_router_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if not buf:
        return FingerprintResult(confidence="none", method="milesight_router_identity_no_response")
    head, _, body = buf.partition(b"\r\n\r\n")
    if not head.upper().startswith(b"HTTP/"):
        return FingerprintResult(confidence="none", method="milesight_router_identity_not_http")
    text = body.decode("latin-1", errors="replace")
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end <= start:
        return FingerprintResult(confidence="none", method="milesight_router_identity_no_json")
    try:
        obj = _json.loads(text[start:end + 1])
    except ValueError:
        return FingerprintResult(confidence="none", method="milesight_router_identity_bad_json")
    if not isinstance(obj, dict):
        return FingerprintResult(confidence="none", method="milesight_router_identity_no_match")
    model = obj.get("model")
    rtver = obj.get("rtver")
    result = obj.get("result")
    # Require the full distinctive envelope: a non-empty model string, a non-empty rtver version
    # string, AND a result[] list whose first entry carries the router's `login` flag (the exact
    # CVE-2023-43261 response shape) -- so a generic JSON object carrying only a "model" key elsewhere
    # cannot match.
    login_flag = (
        isinstance(result, list) and result
        and isinstance(result[0], dict) and "login" in result[0]
    )
    if isinstance(model, str) and model and isinstance(rtver, str) and rtver and login_flag:
        return FingerprintResult(
            vendor="Milesight",   # Milesight/Ursalink router httpd; model (UR/M-series) in `model`
            model=model,
            firmware=rtver,
            confidence="high",
            method="milesight_router_identity",
            extra={"model": model, "rtver": rtver, "oem": obj.get("oem"), "endpoint": "/login (TLS)"},
        )
    return FingerprintResult(confidence="none", method="milesight_router_identity_no_match")


# ── FactoryTalk Linx RNA active protocol-identity probe ──────────────────────
# Added 2026-11-05 (side-quests.md #1, FactoryTalk — the protocol-RE blocker that opened that entry
# is resolved). RNA (Rockwell FactoryTalk Linx, RnaDaSvr.dll inside RSLinxNG.exe) runs on TCP 4241.
# No public spec — the wire format was reverse-engineered from Tenable's four PoC scripts
# byte-for-byte (tenable/poc, RockwellAutomation/FactoryTalk, fetched 2026-09-26) and is documented
# in the published guide alosafuzz.github.io/_guides/factorytalk-rna.md + the the companion fuzzer module
# a companion fuzzing toolkit (the source these helpers are ported from).
#
# SCOPE (deliberate, stated honestly): this is a SERVICE-IDENTITY probe, not a version-gated
# vulnerability verdict. The benign OpenNamespace handshake is the exact connect phase every Tenable
# PoC performs BEFORE any malformed case, so it is non-destructive — it never exercises
# CVE-2020-5801 (double OpenNamespace) or CVE-2020-5802 (ConfigureItems oversized `count`). The
# handshake is also not confirmed to disclose any firmware/version string, so those CVEs are NOT
# determinable from it and are NOT claimed here; a CONFIRMED result means only "FactoryTalk Linx RNA
# is reachable on this port." CVE cataloguing belongs in a check/candidate's `references`, not this
# probe. NOTE: verified only against an independently-built framing mock (tests/
# smoke_test_factorytalk_rna_identity.py) — never against a real RSLinxNG.exe, same testbed
# limitation the guide and the the companion fuzzer responder both carry.

_RNA_MAGIC = b"rna\xF2"

# The benign OpenNamespace XML, verbatim from the PoC-derived the companion fuzzer module's _open_namespace_xml
# default (RNA://$Global sample path, Token placeholder). Trailing NUL is part of the data block.
_RNA_OPEN_NAMESPACE_XML = (
    '\r\n<OpenNamespace xmlns="http://FactoryTalk.net/schemas/LiveData/server/2" '
    'namespacePath="RNA://$Global/SomeApp/SomeServer" leaseTime="300" '
    'clientMachineInfo="localhost" securityToken="Token">'
    '\r\n<requestService>http://FactoryTalk.net/schemas/LiveData/server/NamespaceBrowse/1</requestService>'
    '\r\n<requestService>http://FactoryTalk.net/schemas/LiveData/server/Configuration/1</requestService>'
    '</OpenNamespace>\x00'
).encode("utf-8", errors="replace")


def _rna_block(data: bytes, pad: bool = False) -> bytes:
    """Length-prefix `data`. When pad=True, zero-pad to a 4-byte boundary FIRST so the length field
    reflects the PADDED length (matches the PoC source — the pre-pad length is dead code there)."""
    if pad and len(data) % 4:
        data = data + b"\x00" * (4 - len(data) % 4)
    return struct.pack("<L", len(data)) + data


def _rna_header(fields: dict) -> bytes:
    """Flat 'key=value\\x00' text, keys sorted, matching the PoC's rna_msg() header encoding."""
    parts = []
    for k in sorted(fields.keys()):
        v = fields[k]
        parts.append(f"{k}={'' if v is None else v}\x00")
    return "".join(parts).encode("utf-8", errors="replace")


def _rna_open_namespace_request() -> bytes:
    """A complete benign OpenNamespace envelope: magic + padded header block + data block."""
    header = _rna_header({"command": "XmlCommand", "transid": 1, "session-id": None})
    return _RNA_MAGIC + _rna_block(header, pad=True) + _rna_block(_RNA_OPEN_NAMESPACE_XML, pad=False)


def _rna_parse_msg(raw: bytes):
    """Parse a response envelope -> (header_dict, data_bytes), or None if the framing is broken
    (wrong magic / truncated). Ported from the the companion fuzzer module's _parse_rna_msg."""
    if len(raw) < 4 or raw[:4] != _RNA_MAGIC:
        return None
    off = 4
    if len(raw) < off + 4:
        return None
    hlen = struct.unpack_from("<L", raw, off)[0]
    off += 4
    if len(raw) < off + hlen:
        return None
    header_bytes = raw[off:off + hlen]
    off += hlen
    if len(raw) < off + 4:
        return None
    dlen = struct.unpack_from("<L", raw, off)[0]
    off += 4
    if len(raw) < off + dlen:
        return None
    data_bytes = raw[off:off + dlen]
    header = {}
    for part in header_bytes.split(b"\x00"):
        if part and b"=" in part:
            k, _, v = part.partition(b"=")
            header[k.decode(errors="replace")] = v.decode(errors="replace")
    return header, data_bytes


def _rna_recv_envelope(sock: "_socket.socket", timeout: float) -> Optional[bytes]:
    """Read exactly one RNA envelope (magic + 2 length-prefixed blocks) off the wire, following the
    protocol's own length fields rather than a fixed recv size — so a reply split across TCP segments
    is reassembled and an oversized reply isn't over-read. Returns the raw envelope or None."""
    def _recv_exact(n: int) -> Optional[bytes]:
        got = b""
        while len(got) < n:
            try:
                chunk = sock.recv(n - len(got))
            except OSError:
                return None
            if not chunk:
                return None
            got += chunk
        return got

    sock.settimeout(timeout)
    magic = _recv_exact(4)
    if magic is None:
        return None
    hlen_b = _recv_exact(4)
    if hlen_b is None:
        return None
    hlen = struct.unpack("<L", hlen_b)[0]
    if hlen > 0x100000:  # 1 MiB sanity cap — a real header is tens of bytes; refuse a lying length
        return None
    header = _recv_exact(hlen) if hlen else b""
    if header is None:
        return None
    dlen_b = _recv_exact(4)
    if dlen_b is None:
        return None
    dlen = struct.unpack("<L", dlen_b)[0]
    if dlen > 0x1000000:  # 16 MiB cap on the data block
        return None
    data = _recv_exact(dlen) if dlen else b""
    if data is None:
        return None
    return magic + hlen_b + header + dlen_b + data


def probe_factorytalk_rna_identity(host: str, port: int = 4241, timeout: float = 5.0) -> FingerprintResult:
    """Active FactoryTalk Linx RNA identity probe (TCP 4241). Sends the benign OpenNamespace
    handshake and confirms the service by the response envelope: a well-formed `rna\\xF2` reply
    carrying a non-empty `session-id` header key is a genuine RNA server (confidence='high'); a
    well-formed envelope with no session-id assigned is still RNA framing but a degraded/partial
    answer (confidence='medium'). This is identity only — it does NOT test CVE-2020-5801/5802 and
    reads no version string (none is exposed in this handshake). See the section comment above."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_rna_open_namespace_request())
        response = _rna_recv_envelope(sock, timeout)
    except OSError:
        return FingerprintResult(confidence="none", method="factorytalk_rna_identity_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if response is None:
        return FingerprintResult(confidence="none", method="factorytalk_rna_identity_no_response")
    parsed = _rna_parse_msg(response)
    if parsed is None:
        return FingerprintResult(confidence="none", method="factorytalk_rna_identity_no_parse")
    header, _data = parsed
    session_id = (header.get("session-id") or "").strip()
    if session_id:
        return FingerprintResult(
            vendor="Rockwell Automation",
            model="FactoryTalk Linx (RNA)",
            confidence="high",
            method="factorytalk_rna_identity",
            extra={"service": "RnaDaSvr", "port": port, "session_id": session_id},
        )
    # Valid rna\xF2 envelope echoed back but no session assigned — framing matched, server didn't
    # complete the handshake. Report RNA framing at medium rather than claiming a confirmed server.
    return FingerprintResult(
        vendor="Rockwell Automation",
        model="FactoryTalk Linx (RNA)",
        confidence="medium",
        method="factorytalk_rna_identity_no_session",
        extra={"service": "RnaDaSvr", "port": port},
    )


# ── ROBOTIS RoboPlus Motion control server identity probe (TCP 6501) ──
# Added 2026-11-12 (robotis-firmware-sweep-2026-11). The RoboPlus Motion PC tool reaches a networked
# ROBOTIS controller (e.g. the DARwIn-OP / ROBOTIS-OP2 humanoid, factory IP 192.168.123.1) over a TCP
# control server on port 6501. IOActive's 2017 "Hacking Robots Before Skynet" reported that server
# exposes motion control with NO authentication (CWE-306). This probe performs ONLY the tool's own
# benign, NON-ACTUATING identity handshake: it connects, sends the single ASCII byte "v" (the version
# query), and reads the controller's braced "{...model:version...}" reply. It NEVER sends a
# PlayMotion/actuation command. A model:version frame returned with no credential exchange both
# identifies the controller AND demonstrates the missing-authentication exposure.
#
# Wire format recovered verbatim from the official client (RoboPlus Motion 1.0.29.1, Common.dll,
# ROBOTIS.MotionEditor.Common.CMComm.ConnectBoard + NetworkClient): TcpClient.Connect(ip, 6501) ->
# Write("v") -> ReturnParser() does ReadTo("{") then ReadTo("}") -> the first token Split(':') is
# [model, version]. No login/handshake precedes the "v" query. vendor = "ROBOTIS". Read-only.
_ROBOTIS_MOTION_VERSION_QUERY = b"v"   # the exact byte the official client sends; no motion command
_ROBOTIS_MOTION_RE = re.compile(r"([A-Za-z0-9_.\- ]{1,40}):([0-9]+(?:\.[0-9]+)?)")


def probe_robotis_motion_identity(host: str, port: int = 6501, timeout: float = 5.0) -> FingerprintResult:
    """Active ROBOTIS RoboPlus Motion identity probe. Connects to the TCP 6501 control server, sends
    the benign "v" version query (NOT a motion command), and parses the braced "{...model:version...}"
    reply. confidence='high' with vendor=ROBOTIS + model/firmware on a well-formed reply received with
    no authentication (demonstrates the CWE-306 missing-auth exposure); 'none' otherwise. Read-only:
    issues no PlayMotion/actuation. An actuation proof-of-impact belongs in scripts/safety_critical/,
    never here."""
    sock = None
    buf = b""
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_ROBOTIS_MOTION_VERSION_QUERY)
        while len(buf) < 512 and b"}" not in buf:   # response is a "{ ... }" text frame
            try:
                chunk = sock.recv(256)
            except _socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="robotis_motion_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    start, end = buf.find(b"{"), buf.find(b"}")
    if start < 0 or end < 0 or end < start:
        return FingerprintResult(confidence="none", method="robotis_motion_mismatch")
    body = buf[start:end + 1].decode("latin-1", "replace")
    m = _ROBOTIS_MOTION_RE.search(body)
    if not m:
        return FingerprintResult(confidence="none", method="robotis_motion_mismatch")
    model, version = m.group(1).strip(), m.group(2)
    return FingerprintResult(
        vendor="ROBOTIS",
        model=model or "unknown",
        firmware=version,
        confidence="high",
        method="robotis_motion_version",
        # The "v" handshake completing with no credential exchange IS the CWE-306 exposure.
        extra={"protocol": "roboplus_motion", "port": 6501, "unauthenticated_motion_control": True},
    )


# ── IEC 60870-5-104 (IEC-104) identity probe (TCP 2404) ──
# Added 2026-11-12 (WWS Tier-1 build). IEC 60870-5-104 is the TCP/IP telecontrol protocol widely used in
# water/wastewater and electric SCADA and a first-class Geo SCADA Expert driver. Its base form has no
# authentication. This probe performs ONLY the standard session-start handshake: it sends a U-format
# STARTDT activation (Start Data Transfer) and checks for the station's STARTDT confirmation. STARTDT is
# the benign link-management handshake every 104 master issues before any data -- it is NOT a process
# command (the actuating commands are C_SC/C_DC/C_RC/C_SE ASDUs, which this probe never sends). A station
# returning STARTDT_CON with no authentication both identifies IEC-104 and shows it accepts an
# unauthenticated master. APCI U-frame byte values per IEC 60870-5-104 / lib60870 (MZ Automation) and the
# Wireshark 104apci dissector: STARTDT act = 68 04 07 00 00 00, STARTDT con = 68 04 0B 00 00 00. vendor
# stays "unknown" (multi-vendor standard). Read-only. Live-device confirmation of a specific station's
# framing is advisable before treating a match as authoritative.
_IEC104_STARTDT_ACT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
_IEC104_STARTDT_CON = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00])


def probe_iec104_identity(host: str, port: int = 2404, timeout: float = 5.0) -> FingerprintResult:
    """Active IEC 60870-5-104 identity probe. Connects TCP 2404, sends a U-format STARTDT activation (the
    benign session-start handshake, NOT a process command), and checks for the station's STARTDT
    confirmation. confidence='high' with a STARTDT_CON reply (identifies IEC-104 and shows the station
    accepts an unauthenticated master); 'none' otherwise. Read-only: sends no C_SC/C_DC/C_SE command."""
    sock = None
    resp = b""
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_IEC104_STARTDT_ACT)
        try:
            resp = sock.recv(64)
        except _socket.timeout:
            resp = b""
    except OSError:
        return FingerprintResult(confidence="none", method="iec104_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if _IEC104_STARTDT_CON in resp:   # the station confirmed our unauthenticated Start Data Transfer
        return FingerprintResult(
            vendor="unknown", confidence="high", method="iec104_startdt_con",
            extra={"protocol": "iec104", "port": 2404, "unauthenticated_session": True})
    return FingerprintResult(confidence="none", method="iec104_mismatch")


# ── Schneider Geo SCADA Expert / ClearSCADA WebX web interface identity probe ──
# Added 2026-11-12 (WWS Tier-1, Geo SCADA water-SCADA host). Geo SCADA Expert (formerly ClearSCADA) runs
# the WebX web interface + the DBServer on TCP 5481; WebX is commonly on 80/443/8080. This probe does ONE
# unauthenticated HTTP GET "/" and matches the distinctive Geo SCADA WebX response. Fingerprint confirmed
# live against a Geo SCADA Expert 2025 R2 server (DBServer.exe run under Wine): EVERY path returns an XML
# "<Page ...>" document that references the "/file/xsl/" stylesheet path and names the "Geo SCADA Expert
# web server" (WebX/ViewX). Both markers together are required so a generic XML page cannot false-match.
# WebX serves plaintext HTTP and self-signed HTTPS; the probe does TLS for port 443 (unverified -- WebX
# ships a self-signed cert), plaintext otherwise. vendor="Schneider Electric". Read-only GET, no login.
_GEOSCADA_WEBX_MARKERS = ("/file/xsl/", ("geo scada expert", "clearscada"))


def probe_geoscada_webx_identity(host: str, port: int = 8080, timeout: float = 5.0) -> FingerprintResult:
    """Active Schneider Geo SCADA Expert / ClearSCADA WebX identity probe: one unauthenticated HTTP(S)
    GET "/". confidence='high' when the response is the Geo SCADA WebX XML page (references /file/xsl/
    AND names Geo SCADA Expert/ClearSCADA); 'none' otherwise. Read-only; sends no credentials."""
    request = (f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ics-scanner\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n").encode()
    sock = None
    data = b""
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port == 443:  # WebX HTTPS: self-signed cert, so verification is intentionally disabled
            import ssl as _ssl
            ctx = _ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(request)
        while len(data) < 16384:
            try:
                chunk = sock.recv(4096)
            except _socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="geoscada_webx_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    body = data.decode("latin-1", "replace").lower()
    xsl, products = _GEOSCADA_WEBX_MARKERS
    if xsl in body and any(p in body for p in products):
        return FingerprintResult(
            vendor="Schneider Electric", model="Geo SCADA Expert (WebX)",
            confidence="high", method="geoscada_webx_xml_page",
            extra={"protocol": "geoscada_webx", "port": port,
                   "note": "WebX web interface exposed; DBServer typically on TCP 5481"})
    return FingerprintResult(confidence="none", method="geoscada_webx_mismatch")


# ── Schneider Geo SCADA Expert / ClearSCADA unauthenticated SOAP query probe (WebX port) ──
# Added 2026-11-12 (WWS Tier-1). Geo SCADA's WebX web server exposes a SOAP web service at
# /webservices/scx (SCXService). Per Schneider's own Knowledge Base ("Using SOAP interface to connect to
# Geo SCADA", KB 279083) the service can be used as the built-in Guest user WITHOUT logging in, and
# ExecuteQuery runs SQL SELECTs against the live SCADA database (e.g. "SELECT FullName FROM CDBPoint").
# When the server permits non-secure/Guest access, an unauthenticated network client can therefore READ
# the SCADA database over HTTP (CWE-306) -- a materially worse exposure than the WebX landing page alone.
# This probe sends ONE benign, read-only ExecuteQuery (a SELECT, never ExecuteMethod which is the write/
# control path) and confirms the server returned query results. SOAP format is authoritative (the shipped
# WWW/Schemas/SCX.wsdl): namespace http://serck-controls.com/webservices/SCX6/, SOAPAction .../ExecuteQuery,
# response <ExecuteQueryResponse><ResultSet>. Request verified accepted (HTTP 200) against a live Geo SCADA
# Expert 2025 R2 server. vendor="Schneider Electric". READ-ONLY; never writes.
_GEOSCADA_SOAP_NS = "http://serck-controls.com/webservices/SCX6/"
_GEOSCADA_SOAP_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
    '<ExecuteQuery xmlns="http://serck-controls.com/webservices/SCX6/">'
    '<SQL>SELECT FullName FROM CDBPoint</SQL></ExecuteQuery>'
    '</soap:Body></soap:Envelope>'
).encode()


def probe_geoscada_soap_unauth_query(host: str, port: int = 8080, timeout: float = 6.0) -> FingerprintResult:
    """Active Geo SCADA / ClearSCADA unauthenticated SOAP-query probe: ONE Guest (no-login) ExecuteQuery
    SELECT to /webservices/scx. confidence='high' when the server returns an ExecuteQueryResponse/ResultSet
    (the SCADA database was read with no authentication, CWE-306); 'none' when the request is gated (self-
    signed-cert warning, /logon redirect, SOAP fault) or the host is not Geo SCADA. READ-ONLY: sends a
    SELECT only, never ExecuteMethod (the write/control path)."""
    req = (b"POST /webservices/scx HTTP/1.1\r\nHost: " + host.encode() +
           b"\r\nContent-Type: text/xml; charset=utf-8\r\n"
           b'SOAPAction: "' + _GEOSCADA_SOAP_NS.encode() + b'ExecuteQuery"\r\n'
           b"Content-Length: " + str(len(_GEOSCADA_SOAP_BODY)).encode() +
           b"\r\nConnection: close\r\n\r\n" + _GEOSCADA_SOAP_BODY)
    sock = None
    data = b""
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port == 443:
            import ssl as _ssl
            sock = _ssl._create_unverified_context().wrap_socket(sock, server_hostname=host)
        sock.sendall(req)
        while len(data) < 32768:
            try:
                chunk = sock.recv(4096)
            except _socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    except OSError:
        return FingerprintResult(confidence="none", method="geoscada_soap_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    body = data.decode("latin-1", "replace")
    low = body.lower()
    if "executequeryresponse" in low or "<resultset" in low:
        return FingerprintResult(
            vendor="Schneider Electric", model="Geo SCADA Expert (SOAP)",
            confidence="high", method="geoscada_soap_unauth_executequery",
            extra={"protocol": "geoscada_soap", "port": port,
                   "unauthenticated_db_read": True, "endpoint": "/webservices/scx"})
    return FingerprintResult(confidence="none", method="geoscada_soap_gated_or_mismatch")


# ── Franklin Fueling Systems web-console identity (bb-web-server platform) ───────────────────────────
# Added 2026-11-13 (WWS/fuel coverage). Franklin Fueling Systems fuel-site controllers run a common
# Debian-based Linux platform (packages "bb-*"/"mc-*"/"tg-*", armhf) whose web UI is served by
# mc-web-server (platform "mc") or tg-web-server (platform "tg"), both on libbb-web-server (boost::beast).
#
# Markers are FIRMWARE-VERIFIED (no live device) from three images extracted this session:
#   RCS 1.6.3 (platform "mc", motor/pump control; handlers handleEstop / handlePostSwitchModule),
#   EVO 600/6000 3.31.4 and EVO ONE LLD 200/400 3.32.2 (platform "tg", tank gauge + line-leak detection;
#   tg-modbus / tg-lld / tg-vr / tg-ifsf / tg-dispenser-security). The exact web-facing evidence:
#   (1) the web root /usr/share/bb-web-server/scripts/*.js are STATIC assets the login page loads before
#       authentication; every file begins with
#          // Copyright (c) <year> Franklin Fueling Systems|Franklin Electric. All rights reserved.
#       and 12 of them -- including /scripts/default.js -- are byte-common across all three platforms.
#   (2) libbb-web-server-core (boost::beast) writes the NON-STANDARD response header "Set-Login" (plus
#       X-Powered-By / CSP / HSTS) on its responses.
# So the probe reads the firmware-known static asset first (exact, unauth), then falls back to the root
# response's distinctive Set-Login header. A reachable console is the exposed-ICS-web-management surface
# CISA fuel/WWS guidance warns against; the devices are otherwise hardened (WebAuthn/FIDO2, all OS
# accounts locked, no baked keys) -- so this is an exposure/identity fingerprint, NOT a credential bypass.
#   Read-only: GET of a static JS asset and (fallback) GET "/"; no credentials, no writes.
#   NOTE: the static-asset path+content is firmware-exact; it is exercised against a mock in
#   tests/smoke_test_franklin_fueling_web_console.py. Live confirmation is still welcome but the primary
#   marker is read from the shipped file, not inferred.
_FRANKLIN_BRAND = ("franklin fueling systems", "franklin electric")
_FRANKLIN_ASSET_PATH = "/scripts/default.js"   # byte-common across mc + tg web roots; starts with the copyright banner
_FRANKLIN_SETLOGIN_HDR = "set-login:"          # non-standard bb-web-server response header (distinctive)


def _franklin_http_get(host: str, port: int, path: str, timeout: float):
    """One unauthenticated HTTP(S) GET; returns the raw decoded response (headers+body) or None."""
    request = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ics-scanner\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n").encode()
    sock = None
    data = b""
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in (443, 8443):  # device HTTPS uses a self-signed/boot-generated cert
            import ssl as _ssl
            sock = _ssl._create_unverified_context().wrap_socket(sock, server_hostname=host)
        sock.sendall(request)
        while len(data) < 16384:
            try:
                chunk = sock.recv(4096)
            except _socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return data.decode("latin-1", "replace")


def probe_franklin_fueling_web_identity(host: str, port: int = 443, timeout: float = 5.0) -> FingerprintResult:
    """Active Franklin Fueling Systems web-console identity probe. Reads the firmware-known static asset
    /scripts/default.js (unauth; begins with the Franklin copyright banner) -> confidence 'high'; falls
    back to GET "/" and the distinctive Set-Login response header and/or served Franklin brand. Fails
    closed (no brand and no Set-Login -> 'none'). Read-only; sends no credentials. See the module note."""
    # 1) Firmware-exact: the static login-asset /scripts/default.js starts with the Franklin copyright.
    asset = _franklin_http_get(host, port, _FRANKLIN_ASSET_PATH, timeout)
    if asset is None:
        return FingerprintResult(confidence="none", method="franklin_web_unreachable")
    low = asset.lower()
    ok200 = low.startswith("http/1.1 200") or low.startswith("http/1.0 200")
    if ok200 and "copyright" in low and any(b in low for b in _FRANKLIN_BRAND):
        return FingerprintResult(
            vendor="Franklin Fueling Systems",
            model="Fuel-site controller (bb-web-server console)",
            confidence="high", method="franklin_fueling_static_asset",
            extra={"protocol": "franklin_fueling_web", "port": port, "asset": _FRANKLIN_ASSET_PATH,
                   "note": "served /scripts/*.js carry the Franklin copyright banner (firmware-verified, "
                           "byte-common across mc+tg platforms). Exposed console only -- device login is "
                           "WebAuthn/FIDO2, not a credential bypass. Tank-gauge (tg) builds also commonly "
                           "expose the ATG serial command port TCP/10001 -- see atg_tls350_identity."})

    # 2) Fallback: the root response's distinctive Set-Login header and/or served Franklin brand.
    root = _franklin_http_get(host, port, "/", timeout) or ""
    rlow = root.lower()
    brand = any(b in rlow for b in _FRANKLIN_BRAND)
    setlogin = _FRANKLIN_SETLOGIN_HDR in rlow
    if not brand and not setlogin:
        return FingerprintResult(confidence="none", method="franklin_web_mismatch")
    return FingerprintResult(
        vendor="Franklin Fueling Systems",
        model="Fuel-site controller (bb-web-server console)",
        confidence="high" if (brand and setlogin) else "medium",
        method="franklin_fueling_web_banner",
        extra={"protocol": "franklin_fueling_web", "port": port,
               "brand": brand, "set_login_header": setlogin,
               "note": "exposed Franklin Fueling web console (mc/tg bb-web-server platform); device auth "
                       "is WebAuthn/FIDO2 -- interface reachability, not a credential bypass."})


# ── ProMinent "taco" water-treatment controller web identity (HTTP, port 80) ─────────────────────
# Added 2026-11-19 (WWS coverage). ProMinent's Aegis II (cooling-tower biocide controller), DCM3/
# DCM5b (Dulcometer dosing) and SF5 controllers share one embedded web stack -- a ".cgi file server"
# the firmware itself calls "taco". Markers are FIRMWARE-VERIFIED (no live device) from the 2024-25
# update images AP/APX/APQ/APS: served pages carry a `method="get" action="/taco.cgi"` form plus
# `./css/taco.css` + `./js/taco.js`, and the device uses the `/taco.cgi?F0=..&F1=..` command grammar.
# The httpd has a literal "taco.cgi with no command runs" default branch, so a parameterless GET is a
# benign read and does NOT count toward the firmware's "5 incorrect logins" lockout (a login is a
# SPECIFIC command, not any GET). The web UI is reachable unauthenticated (status-only per ProMinent
# manuals), so this is an exposure/identity fingerprint, NOT a credential bypass.
#   Read-only: GET "/" then (fallback) a no-command GET "/taco.cgi"; never sends credentials or any
#   F0/F1 command value (F8 = factory reset). Exercised against a mock in
#   tests/smoke_test_prominent_taco_web_identity.py.
#   CAUTION: the bare "taco.cgi" token is not vendor-unique (cf. Taco Inc. HVAC controls), so a
#   ProMinent brand string echoed in the page is REQUIRED for 'high'; taco markers alone are 'low'.
_PROMINENT_BRAND = ("prominent", "aegis", "dulco")


def _prominent_http_get(host: str, port: int, path: str, timeout: float):
    """One unauthenticated HTTP(S) GET; returns the raw decoded response (headers+body) or None."""
    request = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ics-scanner\r\n"
               "Accept: */*\r\nConnection: close\r\n\r\n").encode()
    sock = None
    data = b""
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        if port in (443, 8443):  # some units may front the UI with TLS
            import ssl as _ssl
            sock = _ssl._create_unverified_context().wrap_socket(sock, server_hostname=host)
        sock.sendall(request)
        while len(data) < 16384:
            try:
                chunk = sock.recv(4096)
            except _socket.timeout:
                break
            if not chunk:
                break
            data += chunk
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return data.decode("latin-1", "replace")


def _prominent_taco_markers(resp: str) -> bool:
    """Firmware-exact taco signature: the /taco.cgi form action plus a taco.js/taco.css asset ref."""
    low = resp.lower()
    return "/taco.cgi" in low and ("taco.js" in low or "taco.css" in low)


def probe_prominent_taco_web_identity(host: str, port: int = 80, timeout: float = 5.0) -> FingerprintResult:
    """Active ProMinent taco-platform controller web-identity probe. Matches the firmware-exact taco
    web markers (`/taco.cgi` form action + taco.js/taco.css) in GET "/", falling back to a benign
    no-command GET "/taco.cgi". Vendor is confirmed ProMinent only when a brand string is echoed in the
    page ('high'); taco markers without a brand are reported at 'low' (the bare taco.cgi token is not
    vendor-unique). Fails closed. Read-only; sends no credentials and no F0/F1 commands."""
    root = _prominent_http_get(host, port, "/", timeout)
    if root is None:
        return FingerprintResult(confidence="none", method="prominent_taco_unreachable")
    resp, path = root, "/"
    if not _prominent_taco_markers(root):
        cgi = _prominent_http_get(host, port, "/taco.cgi", timeout)  # benign: "no command runs"
        if cgi is None or not _prominent_taco_markers(cgi):
            return FingerprintResult(confidence="none", method="prominent_taco_mismatch")
        resp, path = cgi, "/taco.cgi"
    low = resp.lower()
    brand = next((b for b in _PROMINENT_BRAND if b in low), None)
    model = "taco-platform water-treatment controller"
    if "aegis" in low:
        model = "Aegis II cooling-tower controller"
    return FingerprintResult(
        vendor="ProMinent",
        model=model,
        confidence="high" if brand else "low",
        method="prominent_taco_web",
        extra={"protocol": "prominent_taco_web", "port": port, "path": path,
               "brand_echoed": bool(brand),
               "note": "taco .cgi web stack shared by ProMinent Aegis II / DCM3 / DCM5b / SF5 "
                       "(firmware-verified markers). Pre-auth web UI is status-only -- exposure/"
                       "identity, not a credential bypass. 'low' when no ProMinent brand string is "
                       "echoed on the unauth page (bare taco.cgi is not vendor-unique; distinguish "
                       "from Taco Inc. HVAC controls on a live check)."})


# ── Open Automation Software (OAS) Platform identity (HTTP REST, /OASREST/v2) ─────────────────────
# Added 2026-11-20. OAS Platform / OAS Engine is a networked .NET SCADA / IIoT data-broker (NOT device
# firmware). Markers are FIRMWARE-VERIFIED (no live instance) from the OAS 22.03.0000 Linux build: the
# REST API is served at the OAS-unique path `/OASREST/v2` (assembly OPCSystemsService.OASRESTv2.RESTAPI;
# also `/OASREST/v2/ws/{token}` + `/OPCREST`), and the product string is "Open Automation Software".
# Cisco Talos documented (2022-2023) that the REST API is reachable WITHOUT authentication
# (CVE-2022-26833), so a benign unauthenticated GET of the REST base identifies the platform. This is an
# exposure/identity fingerprint that feeds CVE correlation (the OAS Talos cluster via
# candidate-cve-2022-26833-oas), NOT a credential test or exploit. Read-only: one GET of /OASREST/v2; no
# credentials, no writes. Default OAS web/REST host port = TCP/58725 (CONFIRMED from the 22.03 install:
# mcp_http_config.json binds http://localhost:58725/mcp, and the same Kestrel host serves /OASREST/v2);
# operator-configurable, so the probe also matches whatever port it is given (TLS on 443/8443). The
# separate OAS config/data port TCP/58727 (cleartext, CVE-2022-26077) is noted in the result but not
# probed here.
_OAS_REST_PATH = "/OASREST/v2"
# Unauthenticated OAS identity endpoint (decompiled from OASEngineService.dll, OPCSystemsService.
# OASRESTv2.RESTAPI): GET /OASREST/v2/webconfig/secureinfo returns exactly {"securePort":N,"enabled":b}
# with NO credentials (it is mapped before auth and exempted from the Require-Secure-REST gate). When
# plaintext REST is disabled, that gate instead returns a 403 whose body names "Require Secure REST".
_OAS_SECUREINFO_PATH = "/OASREST/v2/webconfig/secureinfo"
_OAS_MARKERS = ("open automation software", "oasrest", "/oasrest/v2", "oas engine")
# OAS self-signed TLS certificate identity (decompiled from the 22.03 OASConfiguration client:
# subject/issuer "CN=Open Automation Software@localhost/O=Open Automation Software"). When OAS TLS is
# enabled on a port, the server presents this cert; the O/CN strings appear verbatim in the DER, so a
# plain substring match on the cert bytes is a definitive OAS marker without a cert-parsing dependency.
_OAS_CERT_MARKER = b"Open Automation Software"


def _oas_cert_has_marker(host: str, port: int, timeout: float) -> bool:
    """TLS handshake only (no application data sent): True when the server certificate carries the OAS
    identity marker. Returns False on any connect/TLS failure (just 'not an OAS TLS endpoint here')."""
    import ssl as _ssl_oas
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        ctx = _ssl_oas.SSLContext(_ssl_oas.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = _ssl_oas.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
        der = sock.getpeercert(binary_form=True) or b""
        return _OAS_CERT_MARKER in der
    except OSError:
        return False
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def probe_oas_identity(host: str, port: int = 58725, timeout: float = 5.0) -> FingerprintResult:
    """Active Open Automation Software (OAS) Platform identity probe. Two read-only vectors, no
    credentials, fail-closed: (1) a TLS handshake whose server cert carries O/CN "Open Automation
    Software" is DEFINITIVE (when OAS TLS is enabled, incl. the config port TCP/58727); (2) otherwise an
    unauthenticated GET of the firmware-known REST base /OASREST/v2 (unauth per CVE-2022-26833) with an
    OAS marker (the OAS-unique path merely served, non-404, is a weaker positive). Feeds the OAS Talos
    CVE cluster via candidate-cve-2022-26833-oas."""
    if _oas_cert_has_marker(host, port, timeout):
        return FingerprintResult(
            vendor="Open Automation Software", model="OAS Platform (OAS Engine)",
            firmware="unknown", confidence="high", method="oas_tls_cert",
            extra={"protocol": "oas_tls", "port": port,
                   "note": "server TLS cert O/CN 'Open Automation Software' (decompiled from the OAS "
                           "config client) -> definitive OAS. Known-CVE cluster (Talos 2022-2023): "
                           "CVE-2022-26833/26077/26303 + CVE-2023-31242/34998/34353/32615 -> "
                           "candidate-cve-2022-26833-oas. Config/data port TCP/58727 is cleartext by "
                           "default (CVE-2022-26077)."})
    # (2) Definitive unauthenticated endpoint: GET /OASREST/v2/webconfig/secureinfo. Firmware-exact body
    # {"securePort":N,"enabled":b}; or the "Require Secure REST" 403 when plaintext is disabled. No creds.
    import re as _re_oas
    si = _franklin_http_get(host, port, _OAS_SECUREINFO_PATH, timeout)
    if si is not None:
        low_si = si.lower()
        if '"secureport"' in low_si and '"enabled"' in low_si:
            pm = _re_oas.search(r'"secureport"\s*:\s*(\d+)', low_si)
            return FingerprintResult(
                vendor="Open Automation Software", model="OAS Platform (OAS Engine)",
                firmware="unknown", confidence="high", method="oas_secureinfo",
                extra={"protocol": "oas_rest", "port": port, "path": _OAS_SECUREINFO_PATH,
                       "secure_port": pm.group(1) if pm else None,
                       "note": "unauth GET /OASREST/v2/webconfig/secureinfo returns {securePort,enabled} "
                               "(firmware-exact, OASEngineService.dll) -> definitive OAS. Talos cluster "
                               "-> candidate-cve-2022-26833-oas; config port TCP/58727 cleartext "
                               "(CVE-2022-26077)."})
        if "require secure rest" in low_si or "plaintext rest is disabled" in low_si:
            return FingerprintResult(
                vendor="Open Automation Software", model="OAS Platform (OAS Engine)",
                firmware="unknown", confidence="high", method="oas_secure_rest_disabled",
                extra={"protocol": "oas_rest", "port": port, "path": _OAS_SECUREINFO_PATH,
                       "note": "OAS 'Require Secure REST' 403 on plaintext (firmware-exact) -> definitive "
                               "OAS; secure REST is on a separate HTTPS port. candidate-cve-2022-26833-oas."})
    # (3) Weaker fallback: the OAS-unique REST base path + brand marker.
    resp = _franklin_http_get(host, port, _OAS_REST_PATH, timeout)  # generic unauth HTTP(S) GET
    if resp is None:
        return FingerprintResult(confidence="none", method="oas_unreachable")
    low = resp.lower()
    brand = any(m in low for m in _OAS_MARKERS)
    status = low.split("\r\n", 1)[0]
    served = ("http/1." in status) and (" 404 " not in status) and ("http/1.1 404" not in status)
    if not brand and not served:
        return FingerprintResult(confidence="none", method="oas_mismatch")
    import re as _re_oas
    vm = _re_oas.search(r'"?version"?\s*[:=]\s*"?v?(\d+\.\d+(?:\.\d+){0,2})', low)
    version = vm.group(1) if vm else "unknown"
    return FingerprintResult(
        vendor="Open Automation Software",
        model="OAS Platform (OAS Engine)",
        firmware=version,
        confidence="high" if brand else "low",
        method="oas_rest_identity",
        extra={"protocol": "oas_rest", "port": port, "path": _OAS_REST_PATH, "brand": bool(brand),
               "note": "OAS Platform REST API at /OASREST/v2 (firmware-verified), reachable unauth per "
                       "CVE-2022-26833. Known-CVE cluster (Cisco Talos 2022-2023): CVE-2022-26833/26077/"
                       "26303 + CVE-2023-31242/34998/34353/32615 -> candidate-cve-2022-26833-oas. Also "
                       "check the OAS config/data port TCP/58727 (cleartext, CVE-2022-26077)."})


# ── KNXnet/IP (building automation, UDP 3671) identity + discovery ───────────────────────────────
# KNXnet/IP is the dominant European building-automation transport (KNX over IP). Discovery is a benign,
# documented service: a SEARCH_REQUEST to the KNX multicast group 224.0.23.12:3671 (segment sweep) or a
# unicast DESCRIPTION_REQUEST to host:3671 (per-host) returns a Device Information DIB carrying the KNX
# individual address, serial (first 2 bytes = KNX manufacturer id), medium, and a 30-byte friendly name.
# Same shape as Nmap's knx-gateway-discover / knx-gateway-info. Read-only -- it never issues a group
# write, so it never touches the KNX bus. The parser is shared by the active probe (here), the multicast
# scan (core/discovery.py knxnet_search_scan), and the passive sniff adapter (core/passive.py).
_KNXNET_HEADER = bytes([0x06, 0x10])  # header length 6, KNXnet/IP protocol version 1.0
# HPAI 0.0.0.0:0 -> the responder replies to the request's own source address (NAT-friendly, no local IP).
_KNXNET_DESCRIPTION_REQUEST = _KNXNET_HEADER + bytes([0x02, 0x03, 0x00, 0x0E, 0x08, 0x01, 0, 0, 0, 0, 0, 0])
_KNXNET_SEARCH_REQUEST = _KNXNET_HEADER + bytes([0x02, 0x01, 0x00, 0x0E, 0x08, 0x01, 0, 0, 0, 0, 0, 0])
_KNX_MEDIUM = {0x01: "reserved", 0x02: "TP (twisted pair)", 0x04: "PL (powerline)", 0x10: "RF", 0x20: "IP"}


# KNX/IP Secure (KNXnet/IP Secure) service types — the encrypted transport. The device-info DIB is inside
# the encrypted payload (not extractable), but the service type still identifies a KNX Secure device.
_KNX_SECURE_SERVICES = {0x0950: "secure_wrapper", 0x0951: "session_request", 0x0952: "session_response",
                        0x0953: "session_authenticate", 0x0954: "session_status", 0x0955: "timer_notify"}


def parse_knxnet_frame(data: bytes) -> Optional["FingerprintResult"]:
    """Parse a KNXnet/IP SEARCH_RESPONSE (0x0202) or DESCRIPTION_RESPONSE (0x0204): identity from its
    Device Information DIB (friendly name, KNX individual address, serial/manufacturer, medium). Also
    recognises KNX/IP Secure service types (0x0950-0x0955) as presence (their payload is encrypted).
    Returns None on anything else."""
    if len(data) < 8 or data[0] != 0x06 or data[1] != 0x10:
        return None
    svc = (data[2] << 8) | data[3]
    if svc in _KNX_SECURE_SERVICES:
        return FingerprintResult(vendor="unknown", model="KNXnet/IP Secure device", confidence="low",
                                 method="knxnet_secure",
                                 extra={"protocol": "knxnet_ip", "knx_secure": _KNX_SECURE_SERVICES[svc]})
    if svc not in (0x0202, 0x0204):
        return None
    i = -1  # locate the Device Information DIB: struct length 0x36 (54), description type 0x01
    for j in range(6, len(data) - 1):
        if data[j] == 0x36 and data[j + 1] == 0x01 and j + 54 <= len(data):
            i = j
            break
    if i < 0:
        return None
    dib = data[i:i + 54]
    area, line, dev = dib[4] >> 4, dib[4] & 0x0F, dib[5]
    mfr_id = (dib[8] << 8) | dib[9]
    name = dib[24:54].split(b"\x00", 1)[0].decode("latin-1", "replace").strip()
    return FingerprintResult(
        vendor="unknown", model=name or "KNXnet/IP device", confidence="high",
        method="knxnet_search" if svc == 0x0202 else "knxnet_description",
        serial=dib[8:14].hex(),
        extra={"protocol": "knxnet_ip", "knx_individual_address": f"{area}.{line}.{dev}",
               "knx_manufacturer_id": mfr_id, "knx_medium": _KNX_MEDIUM.get(dib[2], f"medium_{dib[2]:#04x}")})


def probe_knxnet_identity(host: str, port: int = 3671, timeout: float = 5.0) -> FingerprintResult:
    """Active KNXnet/IP identity probe: one unicast DESCRIPTION_REQUEST on udp/3671, parse the
    DESCRIPTION_RESPONSE device-info DIB. Read-only (no group/bus write). 'none' if no KNXnet/IP reply."""
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(_KNXNET_DESCRIPTION_REQUEST, (host, port))
        data, _ = sock.recvfrom(1024)
    except OSError:
        return FingerprintResult(confidence="none", method="knxnet_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    res = parse_knxnet_frame(data)
    return res if res is not None else FingerprintResult(confidence="none", method="knxnet_no_parse")


# Named active probes a `protocol_probe` fingerprint_precondition can reference (see
# core/check.py's Check.fingerprint_matches and core/registry.py's load-time validation).
# host/port -> FingerprintResult; confidence != "none" counts as a match.
PROTOCOL_PROBES = {
    "geoscada_soap_unauth_query": probe_geoscada_soap_unauth_query,
    "geoscada_webx_identity": probe_geoscada_webx_identity,
    "franklin_fueling_web_identity": probe_franklin_fueling_web_identity,
    "prominent_taco_web_identity": probe_prominent_taco_web_identity,
    "oas_identity": probe_oas_identity,
    "robotis_motion_identity": probe_robotis_motion_identity,
    "milesight_router_identity": probe_milesight_router_identity,
    "microhawk_weblink_identity": probe_microhawk_weblink_identity,
    "codesys_webvisu_identity": probe_codesys_webvisu_identity,
    "ouster_http_identity": probe_ouster_http_identity,
    "emqx_dashboard_identity": probe_emqx_dashboard_identity,
    "hesai_pandar_web_identity": probe_hesai_pandar_web_identity,
    "sick_rest_identity": probe_sick_rest_identity,
    "s7comm_identity": probe_s7comm_identity,
    "modbus_identity": probe_modbus_identity,
    "modbus_device_identity": probe_modbus_device_identity,
    "opcua_identity": probe_opcua_identity,
    "pcom_tcp_identity": probe_pcom_tcp_identity,
    "enip_identity": probe_enip_identity,
    "mssql_identity": probe_mssql_identity,
    "bacnet_identity": probe_bacnet_identity,
    "knxnet_identity": probe_knxnet_identity,
    "dnp3_identity": probe_dnp3_identity,
    "snmp_identity": probe_snmp_identity,
    "profinet_dcp": probe_profinet_dcp,
    "indusoft_tcp_identity": probe_indusoft_tcp_identity,
    "galil_identity": probe_galil_identity,
    "mqtt_identity": probe_mqtt_identity,
    "cisco_smi_identity": probe_cisco_smi_identity,
    "amx_icsp_identity": probe_amx_icsp_identity,
    "tftp_identity": probe_tftp_identity,
    "utasker_http_identity": probe_utasker_http_identity,
    "slmp_identity": probe_slmp_identity,
    "xgt_identity": probe_xgt_identity,
    "umas_identity": probe_umas_identity,
    "fins_identity": probe_fins_identity,
    "iec104_identity": probe_iec104_identity,
    "fox_identity": probe_fox_identity,
    "fox_tls_identity": probe_fox_tls_identity,
    "pcworx_identity": probe_pcworx_identity,
    "proconos_identity": probe_proconos_identity,
    "saia_sbus_identity": probe_saia_sbus_identity,
    "c37118_identity": probe_c37118_identity,
    "iec61850_mms_identity": probe_iec61850_mms_identity,
    "hartip_identity": probe_hartip_identity,
    "crimson_identity": probe_crimson_identity,
    "beckhoff_ads_identity": probe_beckhoff_ads_identity,
    "ge_srtp_identity": probe_ge_srtp_identity,
    "coap_identity": probe_coap_identity,
    "amqp_identity": probe_amqp_identity,
    "ntcip_identity": probe_ntcip_identity,
    "lxi_vxi11_identity": probe_lxi_vxi11_identity,
    "lxi_http_identity": probe_lxi_http_identity,
    "vtscada_http_identity": probe_vtscada_http_identity,
    "optommp_identity": probe_optommp_identity,
    "opto22_ftp_identity": probe_opto22_ftp_identity,
    "atg_tls350_identity": probe_atg_tls350_identity,
    "hsms_identity": probe_hsms_identity,
    "codesys_gateway": probe_codesys_gateway,
    "factorytalk_rna_identity": probe_factorytalk_rna_identity,
}

# OPC Classic (DCOM/MS-RPC, tcp/135) discovery probes live in core/dcom.py; registered here after
# FingerprintResult is defined so core.dcom's `from core.fingerprint import FingerprintResult` sees it.
from core.dcom import probe_dcom_serveralive2 as _probe_dcom_serveralive2, probe_dcom_opc_epm as _probe_dcom_opc_epm  # noqa: E402
PROTOCOL_PROBES["dcom_serveralive2"] = _probe_dcom_serveralive2
PROTOCOL_PROBES["dcom_opc_epm"] = _probe_dcom_opc_epm

from core.roc_plus import probe_roc_plus_identity as _probe_roc_plus_identity  # noqa: E402
PROTOCOL_PROBES["roc_plus_identity"] = _probe_roc_plus_identity

from core.opcua import probe_opcua_identity as _probe_opcua_identity  # noqa: E402
PROTOCOL_PROBES["opcua_identity"] = _probe_opcua_identity

from core.crestron import probe_crestron_cip_identity as _probe_crestron_cip_identity  # noqa: E402
PROTOCOL_PROBES["crestron_cip_identity"] = _probe_crestron_cip_identity

# Per-probe operator notes — surfaced in the interface (web probe picker + CLI active-discover) when the
# probe is selected, for probes whose behaviour the operator should understand before running them.
PROBE_NOTES: dict = {
    "roc_plus_identity": ("Addresses the ROC at unit/group 1/2 (the common default). A ROC configured "
                          "with a different station address may not reply — set roc_unit/roc_group to "
                          "match the target. The probe sends only a benign opcode-6 System Configuration "
                          "read; it never writes or controls."),
    "opcua_identity": ("Read-only: Hello/Acknowledge, OpenSecureChannel with SecurityPolicy #None, then "
                       "GetEndpoints (no session, no credentials, reads no node). Servers that disable "
                       "the #None security policy report presence only, not full identity."),
    "crestron_cip_identity": ("Benign: connects and reads the processor's unsolicited greeting; sends "
                              "no panel registration or join values. SCIP/TLS devices (port 41796) will "
                              "not answer on 41794."),
}


def probe_note(probe_name: str):
    """Return the operator note for a probe (accepting the name with or without the '_identity' suffix),
    or None. Used by the CLI and web interfaces to annotate a selected probe."""
    return PROBE_NOTES.get(probe_name) or PROBE_NOTES.get(f"{probe_name}_identity")


# identify_protocol() — a meta-probe over PROTOCOL_PROBES (2026-08-17, user: "can you create a
# probe that identifies the protocol"). Every probe above answers "is THIS specific protocol
# present, and if so what's its vendor/model" for a caller who already knows which protocol to
# ask about (that's what fingerprint_precondition: {protocol_probe: ...} needs). This answers
# the opposite, genuinely new question: "I have a host (and maybe a port) — what protocol, if
# any, is even speaking here at all." Sweeps every registered probe and reports which one(s)
# matched, rather than picking a single "best" answer — a real device answering more than one
# protocol (common on ICS gear: e.g. Modbus + HTTP + SNMP all running at once) legitimately
# produces multiple matches, and collapsing that to one would throw away real information.

import inspect  # local import — only identify_protocol() needs this, to read each probe's own
# default port straight from its function signature rather than hand-maintaining a second,
# driftable port table alongside the one that already lives in every probe_*()'s own signature.


def _probe_default_port(probe_fn) -> Optional[int]:
    try:
        return inspect.signature(probe_fn).parameters["port"].default
    except (KeyError, ValueError):
        return None  # profinet_dcp has no port param — Ethernet-native, see probe_profinet_dcp


def identify_protocol(
    host: str,
    port: Optional[int] = None,
    timeout: Optional[float] = 3.0,
    probes: Optional[dict] = None,
    rate_limiter=None,
) -> list:
    """Sweeps every probe in `probes` (default: all of PROTOCOL_PROBES) against `host`, returns
    the ones that actually matched (confidence != "none") as a list of (probe_name,
    FingerprintResult) pairs, in `probes`' iteration order.

    Two modes, chosen by whether `port` is given:
      - port=None (default): each probe is tried against ITS OWN default port (read straight off
        the probe function's own signature) — "what ICS protocols does this host speak at all."
        Slowest mode: up to len(probes) sequential probes, each up to `timeout` seconds if a
        given port doesn't respond — worst case len(probes)*timeout with nothing listening
        anywhere.
      - port=<int>: every port-taking probe is tried against that ONE port instead — "I already
        know something is listening on port N, what protocol is it." Cheaper (still sequential,
        but every non-response is on the same real port instead of len(probes) different ones,
        so a firewalled/dead port fails the same way for all of them rather than each waiting
        out its own probe-specific default).

    `timeout=None` means "let every probe use its OWN default timeout" (the value baked into
    each probe_*()'s signature — 5.0 for most, 2.0-4.0 for a few) instead of forcing one uniform
    value across all of them. That's what makes a batched sweep decide pass/fail identically to
    a lazy per-check `probe_fn(host, port)` call (core/check.py:fingerprint_matches), which also
    relies on each probe's own default — pass None when the sweep must not diverge from the lazy
    path, a concrete number when a bounded worst-case sweep time matters more.

    profinet_dcp is special-cased in both modes: DCP has no TCP/UDP port at all (Ethernet-native,
    needs a raw socket — see probe_profinet_dcp) so it's always tried the same way regardless of
    `port`, and per its own fail-closed contract simply won't match without CAP_NET_RAW/root
    rather than raising — always safe to include in a sweep even unprivileged.

    Any single probe raising an unexpected exception (a real bug in that probe, not one of the
    documented fail-closed paths every probe already has for ordinary failures) is caught and
    skipped rather than aborting the whole sweep — this function's job is orchestrating many
    probes for a caller who doesn't yet know which one is relevant, so one probe's bug shouldn't
    deny a result from the other ten.

    `rate_limiter`, if given, has `.acquire(host)` called once per probe attempted — same
    optional-rate-limiter convention every check's own `probe(target, rate_limiter=None)` method
    already uses. Without one, this function sends its own real network traffic ungated, same as
    calling any single probe_*() function directly always has — matters when a caller (e.g.
    ScanEngine) is batching several probe attempts together instead of interleaving them with a
    per-check rate-limiter acquire the way a lazy per-check evaluation loop would."""
    probes = probes if probes is not None else PROTOCOL_PROBES
    matches = []
    for name, probe_fn in probes.items():
        if rate_limiter is not None:
            rate_limiter.acquire(host)
        timeout_kwargs = {} if timeout is None else {"timeout": timeout}
        try:
            if name == "profinet_dcp":
                result = probe_fn(host, **timeout_kwargs)
            else:
                probe_port = port if port is not None else _probe_default_port(probe_fn)
                result = probe_fn(host, port=probe_port, **timeout_kwargs)
        except Exception:
            continue
        if result.confidence != "none":
            matches.append((name, result))
    return matches
