"""core/dcom.py — OPC Classic (DA/AE/HDA over DCOM / MS-RPC) discovery.

icsScanner already identifies OPC *UA* (probe_opcua_identity, tcp/4840). OPC *Classic* is a different,
older world: COM/DCOM over MS-RPC (tcp/135 + dynamically-negotiated high ports), with the OpcEnum
service enumerating the OPC servers installed on a Windows host. Those hosts are the SCADA/engineering/
historian PCs the fieldbus probes never see. This module adds three complementary, read-only discovery
vectors that key off that architecture (see the OPC-Classic analysis in the Hach firmware review):

  1. PASSIVE  — classify OPC Classic from captured DCE/RPC traffic by its interface UUIDs
                (classify_opc_dcerpc_endpoint; wired into core/passive.py's Zeek dce_rpc.log ingest).
                Zero packets sent.
  2. ACTIVE   — probe_dcom_serveralive2: one DCE/RPC bind to IOXIDResolver + ServerAlive2 (opnum 5) on
                tcp/135. Confirms a Windows DCOM host and best-effort-extracts its network bindings
                (the dual-homed host-discovery technique). Benign read; no auth, no activation.
  3. ACTIVE   — probe_dcom_opc_epm: enumerate the RPC Endpoint Mapper (tcp/135) and flag registered OPC
                Classic interface UUIDs -> which OPC servers a host exposes. Needs impacket (optional,
                like asyncua for OPC UA / pymssql for MSSQL); degrades to a clear not-installed result.

NOTE (verify-wire-format): the hand-rolled ServerAlive2 request is fixed, spec-shaped bytes exercised
against a mock in tests/smoke_test_dcom_opc.py; live-device confirmation is advisable before treating a
CONFIRMED as definitive (same discipline as probe_atg_tls350_identity).
"""
from __future__ import annotations

import socket as _socket
import struct as _struct
import uuid as _uuid
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:  # annotations only (kept lazy as strings via `from __future__ import annotations`)
    from core.fingerprint import FingerprintResult

# FingerprintResult is imported lazily inside the probe bodies (not at module top) so core.dcom has no
# import-time dependency on core.fingerprint -- fingerprint.py registers these probes into
# PROTOCOL_PROBES, which would otherwise be a circular import.

# ── Well-known OPC Classic interface UUIDs (lowercase, no braces) ─────────────────────────────────
# OPC DA (OPC Data Access), the OpcEnum server-list service, OPC Alarms&Events, OPC HDA. These are
# stable, published interface IIDs; a DCE/RPC endpoint bound to one of them == an OPC Classic server.
_OPC_CLASSIC_UUIDS: dict[str, str] = {
    "39c13a4d-011e-11d0-9675-0020afd8adb3": "IOPCServer (OPC DA)",
    "39c13a4e-011e-11d0-9675-0020afd8adb3": "IOPCServerPublicGroups (OPC DA)",
    "39c13a4f-011e-11d0-9675-0020afd8adb3": "IOPCBrowseServerAddressSpace (OPC DA)",
    "39c13a50-011e-11d0-9675-0020afd8adb3": "IOPCGroupStateMgt (OPC DA)",
    "39c13a51-011e-11d0-9675-0020afd8adb3": "IOPCAsyncIO (OPC DA)",
    "39c13a52-011e-11d0-9675-0020afd8adb3": "IOPCSyncIO (OPC DA)",
    "39c13a54-011e-11d0-9675-0020afd8adb3": "IOPCItemMgt (OPC DA)",
    "39c13a70-011e-11d0-9675-0020afd8adb3": "IOPCDataCallback (OPC DA)",
    "39c13a71-011e-11d0-9675-0020afd8adb3": "IOPCAsyncIO2 (OPC DA)",
    "13486d44-4821-11d2-a494-3cb306c10000": "IOPCServerList (OpcEnum)",
    "13486d50-4821-11d2-a494-3cb306c10000": "IOPCServerList2 (OpcEnum)",
    "65168851-5783-11d1-84a0-00608cb8a7e9": "IOPCEventServer (OPC A&E)",
    "1f1217b0-dee0-11d2-a5e5-000086339399": "IOPCHDA_Server (OPC HDA)",
}
# Zeek's dce_rpc.log resolves some UUIDs to names; map those too so the passive path matches either form.
_OPC_ENDPOINT_NAMES = {"iopcserver", "iopcserverlist", "opcenum", "iopceventserver", "iopchda_server"}


def classify_opc_dcerpc_endpoint(endpoint: str) -> Optional[str]:
    """Return an OPC interface label if a DCE/RPC endpoint (a raw UUID or a Zeek-resolved name) is an
    OPC Classic interface, else None. Used by the passive dce_rpc.log classifier."""
    if not endpoint:
        return None
    e = endpoint.strip().lower().strip("{}")
    if e in _OPC_CLASSIC_UUIDS:
        return _OPC_CLASSIC_UUIDS[e]
    if e in _OPC_ENDPOINT_NAMES:
        return f"{endpoint.strip()} (OPC Classic)"
    return None


# ── Vector 2: active DCE/RPC IObjectExporter::ServerAlive2 on tcp/135 ─────────────────────────────
_IOXIDRESOLVER_UUID = _uuid.UUID("99fcfec4-5260-101b-bbcb-00aa0021347a")   # DCOM OXID resolver
_NDR_TRANSFER_UUID = _uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")    # NDR v2.0
_DREP = b"\x10\x00\x00\x00"  # little-endian, ASCII, IEEE float


def _dcerpc_bind(interface: _uuid.UUID, call_id: int = 1) -> bytes:
    abstract = interface.bytes_le + _struct.pack("<HH", 0, 0)             # IOXIDResolver v0.0
    transfer = _NDR_TRANSFER_UUID.bytes_le + _struct.pack("<HH", 2, 0)    # NDR v2.0
    ctx = _struct.pack("<HBH", 0, 1, 0) + abstract + transfer  # p_cont_id, n_transfer_syn, reserved2
    body = _struct.pack("<HHI", 5840, 5840, 0) + _struct.pack("<BBH", 1, 0, 0) + ctx
    frag_len = 16 + len(body)
    header = _struct.pack("<BBBB4sHHI", 5, 0, 11, 0x03, _DREP, frag_len, 0, call_id)  # ptype 11 = bind
    return header + body


def _dcerpc_request(opnum: int, call_id: int = 1) -> bytes:
    body = _struct.pack("<IHH", 0, 0, opnum)  # alloc_hint=0, p_cont_id=0, opnum
    frag_len = 16 + len(body)
    header = _struct.pack("<BBBB4sHHI", 5, 0, 0, 0x03, _DREP, frag_len, 0, call_id)  # ptype 0 = request
    return header + body


def _extract_utf16_bindings(stub: bytes) -> list[str]:
    """Best-effort: pull readable UTF-16LE runs (host/NIC bindings) out of a ServerAlive2 DUALSTRINGARRAY."""
    out, cur = [], []
    for i in range(0, len(stub) - 1, 2):
        ch = stub[i]
        if stub[i + 1] == 0 and 32 <= ch < 127:
            cur.append(chr(ch))
        else:
            if len(cur) >= 2:
                out.append("".join(cur))
            cur = []
    if len(cur) >= 2:
        out.append("".join(cur))
    # de-dup, keep order
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s); uniq.append(s)
    return uniq


def probe_dcom_serveralive2(host: str, port: int = 135, timeout: float = 5.0) -> FingerprintResult:
    """Active DCOM host probe: bind IOXIDResolver + ServerAlive2 (opnum 5) on tcp/135. A valid DCE/RPC
    response == a Windows DCOM/MS-RPC host (the layer OPC Classic rides on); best-effort extracts the
    host's network bindings. Read-only: no authentication, no object activation, no writes."""
    from core.fingerprint import FingerprintResult
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(_dcerpc_bind(_IOXIDRESOLVER_UUID))
        bind_ack = sock.recv(4096)
        if len(bind_ack) < 16 or bind_ack[0] != 5 or bind_ack[2] != 12:  # ptype 12 = bind_ack
            return FingerprintResult(confidence="none", method="dcom_no_bind_ack")
        sock.sendall(_dcerpc_request(5))  # ServerAlive2
        resp = b""
        while len(resp) < 8192:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
            if len(chunk) < 4096:
                break
    except OSError:
        return FingerprintResult(confidence="none", method="dcom_unreachable")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if len(resp) < 16 or resp[0] != 5 or resp[2] not in (2, 3):  # 2 = response, 3 = fault
        return FingerprintResult(confidence="none", method="dcom_no_response")
    if resp[2] == 3:  # a fault still proves a DCOM host answered our ServerAlive2
        return FingerprintResult(vendor="unknown", model="Windows DCOM/MS-RPC host",
                                 confidence="medium", method="dcom_serveralive2_fault",
                                 extra={"protocol": "dcom", "port": port, "dcom": True})
    bindings = _extract_utf16_bindings(resp[24:])
    return FingerprintResult(
        vendor="unknown", model="Windows DCOM/MS-RPC host",
        confidence="high", method="dcom_serveralive2",
        extra={"protocol": "dcom", "port": port, "dcom": True,
               "network_bindings": bindings,
               "note": "DCOM OXID resolver answered on 135; OPC Classic servers (if any) ride this "
                       "layer -- see probe_dcom_opc_epm for the OPC interface inventory."})


# ── Vector 3: RPC Endpoint Mapper enumeration -> OPC interface detection (impacket-gated) ─────────
def probe_dcom_opc_epm(host: str, port: int = 135, timeout: float = 5.0) -> FingerprintResult:
    """Enumerate the RPC Endpoint Mapper (tcp/135) and flag registered OPC Classic interface UUIDs ->
    which OPC servers a host exposes. Needs impacket (optional dependency); returns a clear
    'not installed' result otherwise. Read-only enumeration, no authentication/activation."""
    from core.fingerprint import FingerprintResult
    try:
        from impacket.dcerpc.v5 import transport, epm  # type: ignore
    except ImportError:
        return FingerprintResult(confidence="none", method="dcom_epm_impacket_not_installed",
                                 extra={"hint": "pip install impacket to enable OPC EndpointMapper enumeration"})
    try:
        strbind = f"ncacn_ip_tcp:{host}[{port}]"
        rpctransport = transport.DCERPCTransportFactory(strbind)
        rpctransport.set_connect_timeout(timeout)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        entries = epm.hept_lookup(None, dce=dce)  # all registered endpoints
        dce.disconnect()
    except Exception:  # noqa: BLE001 — any reachability/RPC error = not an answerable 135
        return FingerprintResult(confidence="none", method="dcom_epm_unreachable")

    found_uuids, opc = set(), {}
    for e in entries or []:
        try:
            u = str(e["tower"]["Floors"][0].get_uuid()).lower()
        except Exception:  # noqa: BLE001 — impacket tower shapes vary; skip unparseable floors
            continue
        found_uuids.add(u)
        if u in _OPC_CLASSIC_UUIDS:
            opc[u] = _OPC_CLASSIC_UUIDS[u]
    if opc:
        return FingerprintResult(
            vendor="unknown", model="OPC Classic (DCOM) server",
            confidence="high", method="dcom_epm_opc",
            extra={"protocol": "opc_classic", "port": port,
                   "opc_interfaces": sorted(opc.values()),
                   "registered_interfaces": len(found_uuids)})
    if found_uuids:
        return FingerprintResult(
            vendor="unknown", model="Windows DCOM/MS-RPC host (no OPC interfaces registered)",
            confidence="medium", method="dcom_epm_no_opc",
            extra={"protocol": "dcom", "port": port, "registered_interfaces": len(found_uuids)})
    return FingerprintResult(confidence="none", method="dcom_epm_empty")
