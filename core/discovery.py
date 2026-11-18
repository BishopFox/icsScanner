"""Network discovery — active ARP scanning and a passive multi-protocol listener, for
direct-L2-connection engagements where the device inventory isn't known ahead of time.

This is a genuinely different capability class from every Check in this project: discovery
answers "what's out here," not "does this known device have a specific vulnerability."
`DiscoveredDevice` results feed into the existing exact-IP `Target`/`load_target_inventory()`
model (core/target.py) via a separate export step (the web UI's "copy to scanner tab") —
discovery itself operates on a subnet/interface, which core/target.py deliberately does NOT
support for checks (00-PROJECT-CHARTER.md § Scope: "one exact IP or FQDN, never a CIDR range").
That charter decision governs the check-target model, not this module — discovery is a separate
concept by design, not an exception carved into the existing one.

Two risk tiers, mirroring core/fingerprint.py's own passive/active taxonomy (module docstring
there: "passive (active=False) — reads ARP cache only, sends zero packets; active (active=True)
— sends one benign identity probe per protocol"):
  active  — arp_scan() sends one broadcast ARP request per host in a CIDR. Classified
            destructive=False (an ARP request is mandatory IP-stack behavior with zero side
            effects on the target — the same "benign" reasoning already used for this project's
            other zero-impact probes), but genuinely "active" in that it injects packets rather
            than only listening. See 01-METHODOLOGY-AND-CHECKLISTS.md for the formalized rule.
            micom_courier_scan() is the same risk tier, one protocol-specific query (an ONC-RPC
            portmapper GETPORT lookup, plain UDP) per host instead of an ARP request — see its own
            docstring for the vendor-tool capture this was built from. mqtt_active_scan() is also
            this tier (one MQTT CONNECT/CONNACK handshake per host) but — being TCP, not UDP — is
            run through a bounded thread pool rather than micom_courier_scan()'s fire-all-then-
            collect pattern; see its own module-level comment for why. It can also auto-chain
            into a short Sparkplug B passive-listen pass against any anonymous broker it finds,
            closing a gap _listen_sparkplug's own docstring documents (no broker auto-discovery).
  passive — passive_listen()'s ARP listener sends zero packets, ever. Its Sparkplug B listener is
            a read-only MQTT subscribe: one real TCP connection is opened, but no data is ever
            published — classified as "passive" for this project's purposes (no probe sent to any
            device), documented explicitly rather than glossed over as truly zero-packet.

Platform assumption (unchanged from core/fingerprint.py's PROFINET DCP section, reused here):
Linux only — AF_PACKET raw sockets and the SIOCGIFADDR/SIOCGIFHWADDR ioctls are Linux-specific.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import socket as _socket
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from core.fingerprint import _detect_local_ip, _iface_for_ip, _iface_mac, lookup_oui, probe_mqtt_identity

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None


_ETH_P_ARP = 0x0806
_ARP_HTYPE_ETHERNET = 1
_ARP_PTYPE_IPV4 = 0x0800
_ARP_OP_REQUEST = 1
_ARP_OP_REPLY = 2
_BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"
_ZERO_MAC = b"\x00" * 6

# Safety cap on an active broadcast sweep — nothing else in this project addresses raw-Layer-2
# subnet-wide sends, so there's no existing precedent for "how big is too big." /20 = 4094 usable
# hosts, a large but bounded engagement-sized segment; anything bigger needs force=True.
MAX_HOSTS_WITHOUT_FORCE = 4096


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DiscoveredDevice:
    """One host learned about via discovery (active ARP scan or a passive listener) — mirrors
    core/fingerprint.py:FingerprintResult's convention: fixed core fields with safe sentinel
    defaults, plus a free-form `extra` dict for protocol-specific payload instead of growing new
    dataclass fields per protocol (the same convention probe_profinet_dcp already uses)."""

    ip: str
    mac: Optional[str] = None
    vendor: str = "unknown"
    method: str = ""  # "arp_active" | "arp_passive" | "sparkplug_b"
    first_seen: str = ""
    last_seen: str = ""
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "method": self.method,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "extra": self.extra,
        }


def _build_arp_request(src_mac: bytes, src_ip: str, target_ip: str) -> bytes:
    """RFC 826 ARP request frame (Ethernet header + ARP payload), broadcast dest, padded to the
    minimum 60-byte Ethernet frame length — same padding convention core/fingerprint.py already
    uses for its PROFINET DCP frames."""
    eth_header = _BROADCAST_MAC + src_mac + struct.pack("!H", _ETH_P_ARP)
    arp_payload = (
        struct.pack("!HHBBH", _ARP_HTYPE_ETHERNET, _ARP_PTYPE_IPV4, 6, 4, _ARP_OP_REQUEST)
        + src_mac
        + _socket.inet_aton(src_ip)
        + _ZERO_MAC
        + _socket.inet_aton(target_ip)
    )
    frame = eth_header + arp_payload
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def _parse_arp_frame(data: bytes) -> Optional[tuple]:
    """Parses a raw Ethernet frame as an ARP request or reply. Returns (op, sender_ip,
    sender_mac) or None if this isn't a well-formed ARP frame. `op` is _ARP_OP_REQUEST or
    _ARP_OP_REPLY — the passive listener records both (a request already reveals the requester's
    own IP/MAC), while the active scanner only cares about replies to its own requests."""
    if len(data) < 42 or data[12:14] != struct.pack("!H", _ETH_P_ARP):
        return None
    arp = data[14:]
    if len(arp) < 28:
        return None
    htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", arp, 0)
    if htype != _ARP_HTYPE_ETHERNET or ptype != _ARP_PTYPE_IPV4 or hlen != 6 or plen != 4:
        return None
    sender_mac = arp[8:14]
    sender_ip = _socket.inet_ntoa(arp[14:18])
    return op, sender_ip, sender_mac.hex(":")


def _resolve_interface(routing_hint_ip: str, iface: Optional[str]) -> tuple:
    """Returns (ifname, src_mac_bytes), or (None, None) if auto-detection failed. Reuses
    core/fingerprint.py's PROFINET-DCP-era helpers verbatim rather than re-implementing
    interface/MAC discovery — same cross-module underscore-helper-import pattern already used by
    checks/mssql/native/mssql_default_creds.py."""
    if iface is None:
        local_ip = _detect_local_ip(routing_hint_ip)
        if local_ip is None:
            return None, None
        iface = _iface_for_ip(local_ip)
        if iface is None:
            return None, None
    src_mac = _iface_mac(iface)
    if src_mac is None or len(src_mac) != 6:
        return None, None
    return iface, src_mac


_RPC_PORTMAP_PROGRAM = 100000
_RPC_PORTMAP_VERSION = 2
_RPC_PROC_GETPORT = 3
_RPC_AUTH_NULL = 0

# Schneider Electric / GE Vernova MiCOM relays' "Courier over Ethernet" network service (also the
# discovery step for an IEC 103 Quick Connect — both modes of MiCOM S1 Studio's own "Scan network"
# feature produced an IDENTICAL request, confirmed via a live capture of the real client tool
# against a real subnet: an ONC-RPC (RFC 1057/1833) portmapper GETPORT query for this exact
# program/version/protocol tuple. Not a guessed/derived value — read byte-for-byte off the wire.
# S1 Studio also tried a direct TCP connect to port 4422 against every host in parallel with this
# RPC query (same capture) — a real, observed secondary signal, but deliberately NOT implemented
# here: an open TCP port alone doesn't confirm which service is listening, unlike a portmapper
# resolving this specific program to a nonzero port. Documented as a known future enhancement, not
# silently dropped.
_MICOM_COURIER_RPC_PROGRAM = 20002001
_MICOM_COURIER_RPC_VERSION = 1
_IPPROTO_TCP = 6


def _build_portmap_getport_request(xid: int, program: int, version: int, protocol: int, port: int) -> bytes:
    """ONC RPC portmapper v2 GETPORT call (AUTH_NULL credentials/verifier) — 14 big-endian u32
    fields, 56 bytes total. Field-by-field byte offsets confirmed against a real capture rather
    than assembled from the RFC alone (see this module's own header comment)."""
    return struct.pack(
        "!14I",
        xid,
        0,  # msg_type = CALL
        2,  # rpcvers = 2
        _RPC_PORTMAP_PROGRAM,
        _RPC_PORTMAP_VERSION,
        _RPC_PROC_GETPORT,
        _RPC_AUTH_NULL, 0,  # cred: flavor, length
        _RPC_AUTH_NULL, 0,  # verf: flavor, length
        program, version, protocol, port,
    )


def _parse_portmap_getport_reply(data: bytes, expected_xid: int) -> Optional[int]:
    """Parses an ONC RPC reply to a GETPORT call. Returns the resolved port (0 means the
    portmapper exists but this program isn't registered there), or None if this isn't a
    well-formed, xid-matching, successfully-accepted reply."""
    if len(data) < 20:
        return None
    xid, msg_type, reply_stat = struct.unpack_from("!III", data, 0)
    if xid != expected_xid or msg_type != 1 or reply_stat != 0:  # 1=REPLY, 0=MSG_ACCEPTED
        return None
    verf_len = struct.unpack_from("!I", data, 16)[0]
    offset = 20 + verf_len
    if len(data) < offset + 8:
        return None
    accept_stat, port = struct.unpack_from("!II", data, offset)
    if accept_stat != 0:  # 0 = SUCCESS
        return None
    return port


# detection_hints for micom_courier_scan()'s own probe traffic, same shape as the
# `detection_hints:` field on `checks/**/*.yaml` (see core/check.py's CheckMetadata) — narrow is
# this scanner's own literal request (minus the unpredictable XID), broad is the underlying
# RPC-program-20002001 signature regardless of who's asking. Both regexes verified directly
# against the real captured request bytes and against synthetic alt-xid/alt-program payloads
# (see tests/smoke_test_discovery.py) — not hand-derived from the RFC alone.
#
# NOT currently wired into any loader: detection-gen's `check_loader.py` only ever reads
# `checks/**/*.yaml` (Check objects), and `core/discovery.py`'s methods are deliberately not
# Checks (01-METHODOLOGY-AND-CHECKLISTS.md's "Network discovery" section: "Discovery output does
# not need detection_hints... discovery isn't a vulnerability finding and has no such template
# to generate"). This constant exists so the hints are captured and verified now, in the same
# schema used everywhere else in this project, in case a future session extends detection-gen to
# also render discovery-probe signatures — or for direct manual use in a SIEM/IDS rule today.
DETECTION_HINTS_MICOM_COURIER_SCAN = {
    "transport": "udp",
    "app_protocol": "rpc",
    "mitre_attack_id": "T0846",  # Remote System Discovery (tactic: Discovery, TA0102) —
    # verified against MITRE ATT&CK for ICS directly, not guessed; a much closer fit for an
    # active network-discovery probe than this project's usual T0812 (Default Credentials),
    # which is for credential-guessing checks, not recon.
    "narrow": {
        "description": (
            "This scanner's own exact micom_courier_scan() request: an ONC-RPC portmapper "
            "(UDP/111) v2 GETPORT call for RPC program 20002001, version 1, protocol TCP "
            "(IPPROTO_TCP=6), port 0 — byte-for-byte identical to the real capture this module "
            "was built from, except the 4-byte XID (this scanner derives it from the current "
            "time, so it varies per run and per host and cannot be a fixed byte match). "
            "Verified against the actual captured request bytes and against this scanner's own "
            "_build_portmap_getport_request() output, not hand-derived from the RFC alone."
        ),
        "patterns": [
            {
                "context": "request",
                "regex": (
                    "^.{4}\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x01\\x86\\xa0\\x00\\x00"
                    "\\x00\\x02\\x00\\x00\\x00\\x03\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
                    "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x31\\x34\\xd1\\x00\\x00\\x00\\x01"
                    "\\x00\\x00\\x00\\x06\\x00\\x00\\x00\\x00$"
                ),
            }
        ],
    },
    "broad": {
        "description": (
            "Any ONC-RPC portmapper v2 GETPORT call naming RPC program 20002001 (the vendor "
            "program number MiCOM Courier-over-Ethernet / IEC 103 devices register), regardless "
            "of the requesting XID or the specific version/protocol/port arguments asked for — "
            "the underlying 'someone is probing for a MiCOM Courier/IEC 103 service' signal in "
            "general, not tied to this scanner's own version=1/protocol=TCP/port=0 guess. "
            "Verified to correctly reject an otherwise-identical GETPORT call naming a different "
            "RPC program (e.g. NFS-family program numbers), so it doesn't false-positive on "
            "ordinary portmapper traffic unrelated to MiCOM."
        ),
        "patterns": [
            {
                "context": "request",
                "regex": (
                    "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x01\\x86\\xa0\\x00\\x00\\x00"
                    "\\x02\\x00\\x00\\x00\\x03\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
                    "\\x00\\x00\\x00\\x00\\x00\\x00\\x01\\x31\\x34\\xd1"
                ),
            }
        ],
    },
}
def micom_courier_scan(
    cidr: str,
    timeout: float = 2.0,
    rate_limiter=None,
    force: bool = False,
) -> list:
    """Active discovery of MiCOM "Courier over Ethernet" / IEC 103 Quick-Connect-capable devices,
    replicating MiCOM S1 Studio's own "Scan network" feature: an ONC-RPC portmapper (UDP/111)
    GETPORT query per host for RPC program 20002001. A host that resolves this to a nonzero port
    is running a matching service; a host with a portmapper but no such registration replies with
    port 0 (recorded, not included as found); most hosts have no portmapper at all and are simply
    absent from the results — both behaviors observed directly against ordinary non-MiCOM LAN
    devices in the capture this was built from.

    Plain UDP sockets only — unlike arp_scan(), this needs no raw socket or elevated privilege,
    and works the same on any platform with a standard socket module.

    Same /20-host safety cap and fail-closed-on-oversized-request behavior as arp_scan(), for the
    same reason: this is still an active, subnet-wide packet send, not a single-target probe.
    """
    hosts = _hosts_for_active_scan(cidr, force, "subnet sweep")
    if not hosts:
        return []

    sock = None
    try:
        try:
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            sock.settimeout(0.2)
        except OSError:
            return []

        xid_to_ip: dict = {}
        base_xid = int(time.time()) & 0xFFFFFFFF
        for i, host in enumerate(hosts):
            if rate_limiter is not None:
                rate_limiter.acquire(str(host))
            xid = (base_xid + i) & 0xFFFFFFFF
            xid_to_ip[xid] = str(host)
            try:
                sock.sendto(
                    _build_portmap_getport_request(
                        xid, _MICOM_COURIER_RPC_PROGRAM, _MICOM_COURIER_RPC_VERSION,
                        _IPPROTO_TCP, 0,
                    ),
                    (str(host), 111),
                )
            except OSError:
                continue

        found: dict = {}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
            except OSError:
                continue
            for xid, ip in xid_to_ip.items():
                if ip != addr[0] or ip in found:
                    continue
                port = _parse_portmap_getport_reply(data, xid)
                if port is not None and port > 0:
                    now = _now_iso()
                    found[ip] = DiscoveredDevice(
                        ip=ip,
                        mac=None,
                        vendor="unknown",
                        method="micom_courier_active",
                        first_seen=now,
                        last_seen=now,
                        extra={
                            "rpc_program": _MICOM_COURIER_RPC_PROGRAM,
                            "resolved_port": port,
                        },
                    )
                break
        return list(found.values())
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _hosts_for_active_scan(cidr: str, force: bool, kind: str) -> list:
    """Shared safety-cap check for `arp_scan()`/`micom_courier_scan()`: checks the range size via
    `network.num_addresses` (an O(1) property) BEFORE materializing the full host list, then
    returns `list(network.hosts())` for anything that passes.

    Checking size first matters: `ipaddress`'s `.hosts()` is a generator, but calling `list()` on
    it for something like a /8 (16,777,214 usable hosts) means constructing over 16 million
    `IPv4Address` objects — measured at ~10-12 seconds on this project's own dev sandbox, even for
    the REJECTED-as-oversized case. Checking `num_addresses` first makes the oversized-range
    rejection itself near-instant, matching the "a caller mistake should be reported immediately"
    intent of raising ValueError here at all. `num_addresses` counts the network+broadcast
    addresses that `.hosts()` excludes (off by exactly 2 for IPv4), which never changes the
    accept/reject outcome for the /20 boundary this project actually uses (4096 either way).
    """
    network = ipaddress.ip_network(cidr, strict=False)
    if network.num_addresses > MAX_HOSTS_WITHOUT_FORCE and not force:
        raise ValueError(
            f"{cidr} has {network.num_addresses} addresses, over the {MAX_HOSTS_WITHOUT_FORCE}-"
            f"host (/20) default safety cap for an active {kind} — pass force=True to override."
        )
    return list(network.hosts())


def arp_scan(
    cidr: str,
    iface: Optional[str] = None,
    timeout: float = 2.0,
    rate_limiter=None,
    force: bool = False,
) -> list:
    """Active ARP scan of a subnet: sends one broadcast ARP request per host, collects replies
    for `timeout` seconds, returns one DiscoveredDevice per unique responding MAC.

    REQUIRES CAP_NET_RAW or root for the AF_PACKET socket; fails closed (returns []) on missing
    privilege or any socket error — same fail-closed philosophy as
    core/fingerprint.py:probe_profinet_dcp, never raises for a privilege/environment problem.

    Raises ValueError only for a genuinely oversized request (see MAX_HOSTS_WITHOUT_FORCE) — that
    is a caller mistake to surface, not an environment failure to swallow.
    """
    hosts = _hosts_for_active_scan(cidr, force, "broadcast sweep")
    if not hosts:
        return []

    ifname, src_mac = _resolve_interface(str(hosts[0]), iface)
    if ifname is None or src_mac is None:
        return []
    # Cheap re-parse (no host enumeration, unlike _hosts_for_active_scan's list(network.hosts()))
    # — only needed for the fallback src_ip below.
    network = ipaddress.ip_network(cidr, strict=False)
    src_ip = _detect_local_ip(str(hosts[0])) or str(network.network_address)

    sock = None
    try:
        try:
            sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(_ETH_P_ARP))
            sock.bind((ifname, 0))
        except (PermissionError, OSError, AttributeError):
            # AttributeError: AF_PACKET doesn't exist outside Linux — fail closed, not a crash.
            return []

        for host in hosts:
            if rate_limiter is not None:
                rate_limiter.acquire(str(host))
            try:
                sock.send(_build_arp_request(src_mac, src_ip, str(host)))
            except OSError:
                continue

        seen: dict = {}
        deadline = time.monotonic() + timeout
        sock.settimeout(0.2)
        while time.monotonic() < deadline:
            try:
                data = sock.recv(2048)
            except OSError:
                continue
            parsed = _parse_arp_frame(data)
            if parsed is None:
                continue
            op, sender_ip, sender_mac = parsed
            if op != _ARP_OP_REPLY:
                continue
            now = _now_iso()
            if sender_mac in seen:
                seen[sender_mac].last_seen = now
            else:
                seen[sender_mac] = DiscoveredDevice(
                    ip=sender_ip,
                    mac=sender_mac,
                    vendor=lookup_oui(sender_mac),
                    method="arp_active",
                    first_seen=now,
                    last_seen=now,
                )
        return list(seen.values())
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# MQTT active broker discovery — added 2026-09-17 (user: "discuss mqtt active discovery module"),
# following the new checks/mqtt/native/mqtt_unauthenticated_broker.py check and its
# core.fingerprint.probe_mqtt_identity protocol_probe. Discussed with the user (AskUserQuestion)
# before building: bounded ThreadPoolExecutor over sequential (see below), port 1883 only (no
# TLS/8883 support — not yet needed by any real finding), and auto-chaining into a Sparkplug B
# passive listen pass for any broker found accepting anonymous connections.
#
# ARCHITECTURAL DIFFERENCE FROM micom_courier_scan(), the other active subnet-sweep in this file:
# that scanner fires all its UDP requests up front and collects replies within one shared timeout
# window — a "fire and forget" pattern that works because UDP has no per-host connection state.
# MQTT needs a real TCP handshake per host, which doesn't fit that pattern (a host that silently
# drops the SYN stalls that one probe for its full timeout, and there is no way to overlap that
# wait across hosts without real concurrency). Uses a bounded `concurrent.futures.
# ThreadPoolExecutor` instead — the same concurrency primitive core/scan_engine.py already uses
# for its own per-target parallelism (`max_concurrent_targets`) — rather than either blocking
# sequentially (impractically slow across a large range with several filtered hosts) or a raw
# non-blocking-socket/selectors event loop (more "correct" for scale, but a new pattern this
# project doesn't use anywhere else, for a feature no real engagement has yet needed at that
# scale). `max_workers` defaults to 32, matched loosely to this file's existing willingness to
# sweep up to a /20 (4096 hosts) without `force`.
#
# CLOSES A DOCUMENTED GAP: `_listen_sparkplug`'s own docstring says plainly "No broker
# auto-discovery exists for Sparkplug B — sparkplug_broker (host, port) must be supplied by the
# caller." Sparkplug B runs over MQTT, so a broker this scan finds accepting anonymous
# connections (CONNACK return code 0 — i.e. reachable with no credential this project would need
# to supply) is automatically fed into a short passive_listen() Sparkplug B pass by default
# (`auto_sparkplug=True`). A broker that REQUIRES auth (any nonzero return code) is still recorded
# as a discovered MQTT broker, but is deliberately NOT auto-chained into Sparkplug listening,
# since this project has no credential to offer it and forcing the attempt would just be a
# guaranteed-failing connection for no benefit.
def mqtt_active_scan(
    cidr: str,
    port: int = 1883,
    timeout: float = 2.0,
    max_workers: int = 32,
    force: bool = False,
    rate_limiter=None,
    auto_sparkplug: bool = True,
    sparkplug_duration: float = 10.0,
) -> list:
    """Active discovery of MQTT brokers across a subnet: one CONNECT/CONNACK probe per host via
    core.fingerprint.probe_mqtt_identity, run through a bounded thread pool (see the module-level
    comment above for why this differs from micom_courier_scan()'s fire-all-then-collect UDP
    pattern). Records any host with confidence != "none" — i.e. a well-formed CONNACK reply,
    whether it accepts or rejects the connection; judging vulnerability is
    checks/mqtt/mqtt-unauthenticated-broker.yaml's job, not this discovery function's.

    Same /20-host safety cap as arp_scan()/micom_courier_scan() (`force=True` to override) — this
    is still an active, subnet-wide packet send, not a single-target probe.
    """
    hosts = _hosts_for_active_scan(cidr, force, "MQTT CONNECT sweep")
    if not hosts:
        return []

    def _probe_one(host) -> tuple:
        if rate_limiter is not None:
            rate_limiter.acquire(str(host))
        return str(host), probe_mqtt_identity(str(host), port, timeout=timeout)

    devices: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for ip, fp in executor.map(_probe_one, hosts):
            if fp.confidence == "none":
                continue
            now = _now_iso()
            devices[ip] = DiscoveredDevice(
                ip=ip,
                mac=None,
                vendor="unknown",
                method="mqtt_active",
                first_seen=now,
                last_seen=now,
                extra={"port": port, "connack_return_code": fp.extra.get("connack_return_code")},
            )

    if auto_sparkplug and mqtt is not None:
        anonymous_brokers = [ip for ip, d in devices.items() if d.extra.get("connack_return_code") == 0]
        for ip in anonymous_brokers:
            for spark_device in passive_listen(sparkplug_duration, protocols=["sparkplug_b"], sparkplug_broker=(ip, port)):
                key = f"sparkplug_via:{ip}:{spark_device.extra.get('group_id')}:{spark_device.extra.get('edge_node_id')}"
                devices[key] = spark_device

    return list(devices.values())


# ── Active multi-protocol identity-probe sweep ────────────────────────────────
#
# Surfaces core/fingerprint.py's PROTOCOL_PROBES as a Discovery active-scan method (2026-10-06):
# "which hosts on this subnet speak S7comm / Modbus / OPC-UA / EtherNet/IP / SLMP / XGT / UMAS /
# MQTT / MSSQL / PCOM?" Until now those probes only ran implicitly as a scan's fingerprint GATE
# (core/scan_engine.py) — never as an operator-driven discovery sweep. Mirrors mqtt_active_scan()'s
# bounded-thread-pool shape exactly (that function is itself just probe_mqtt_identity over a subnet).
#
# Default port per probe (the port each probe targets). Only probes with the standard
# (host, port, timeout) signature are swept; L2/odd-signature probes (profinet_dcp) are excluded.
_PROBE_SCAN_PORTS = {
    "s7comm_identity": 102, "modbus_identity": 502, "opcua_identity": 4840,
    "enip_identity": 44818, "mqtt_identity": 1883, "slmp_identity": 5000,
    "xgt_identity": 2004, "umas_identity": 502, "mssql_identity": 1433,
    "pcom_tcp_identity": 20256, "fins_identity": 9600, "iec104_identity": 2404,
    "fox_identity": 1911, "fox_tls_identity": 4911, "pcworx_identity": 1962, "iec61850_mms_identity": 102,
    "proconos_identity": 20547, "saia_sbus_identity": 5050, "c37118_identity": 4712,
    "hartip_identity": 5094, "crimson_identity": 789, "beckhoff_ads_identity": 48898,
    "ge_srtp_identity": 18245, "coap_identity": 5683, "amqp_identity": 5672,
    "ntcip_identity": 161, "lxi_vxi11_identity": 111, "lxi_http_identity": 80, "hsms_identity": 5000,
    "vtscada_http_identity": 80, "optommp_identity": 2001, "opto22_ftp_identity": 21, "atg_tls350_identity": 10001,
    "factorytalk_rna_identity": 4241,
}
# Safe default sweep set (TCP ICS protocols incl. the four built this arc: slmp/xgt/umas/s7comm).
_DEFAULT_PROBE_SCAN = list(_PROBE_SCAN_PORTS.keys())


def protocol_probe_scan(
    cidr: str,
    probes: Optional[list] = None,
    timeout: float = 3.0,
    max_workers: int = 32,
    force: bool = False,
    rate_limiter=None,
    ports: Optional[dict] = None,
) -> list:
    """Active discovery sweep running selected core.fingerprint PROTOCOL_PROBES across a subnet,
    one DiscoveredDevice per (host, protocol) that responds (probe confidence != "none"). `probes`
    is a list of probe names (keys in PROTOCOL_PROBES); default = the TCP ICS set in
    _PROBE_SCAN_PORTS. Each probe runs on its default port (override via `ports`). Unknown or
    odd-signature probes are skipped fail-closed (never crash the sweep).

    Same /20-host safety cap as arp_scan()/mqtt_active_scan() (`force=True` to override) — this is
    an active, subnet-wide, MULTI-protocol packet send. Judging vulnerability is each check's job;
    this only answers "does this host speak protocol X".
    """
    from core.fingerprint import PROTOCOL_PROBES

    requested = probes if probes else _DEFAULT_PROBE_SCAN
    port_map = dict(_PROBE_SCAN_PORTS)
    if ports:
        port_map.update(ports)

    # Accept both the full probe name ("slmp_identity") and the display/stripped name ("slmp").
    def _normalize(name: str) -> Optional[str]:
        if name in PROTOCOL_PROBES and name in port_map:
            return name
        alt = f"{name}_identity"
        if alt in PROTOCOL_PROBES and alt in port_map:
            return alt
        return None

    selected = [n for n in (_normalize(p) for p in requested) if n is not None]
    if not selected:
        return []

    hosts = _hosts_for_active_scan(cidr, force, "protocol-probe sweep")
    if not hosts:
        return []

    tasks = [(str(h), pn) for h in hosts for pn in selected]

    def _probe_one(task) -> tuple:
        ip, pn = task
        if rate_limiter is not None:
            rate_limiter.acquire(ip)
        port = port_map[pn]
        try:
            fp = PROTOCOL_PROBES[pn](ip, port, timeout=timeout)
        except Exception:  # odd signature / probe bug must not kill the sweep
            return ip, pn, port, None
        return ip, pn, port, fp

    devices: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for ip, pn, port, fp in executor.map(_probe_one, tasks):
            if fp is None or fp.confidence == "none":
                continue
            now = _now_iso()
            devices[f"{ip}:{pn}"] = DiscoveredDevice(
                ip=ip,
                mac=None,
                vendor=fp.vendor if getattr(fp, "vendor", "unknown") not in (None, "", "unknown") else "unknown",
                method=f"probe_active:{pn}",
                first_seen=now,
                last_seen=now,
                extra={"protocol": pn[:-9] if pn.endswith("_identity") else pn,
                       "port": port, "probe_method": getattr(fp, "method", "")},
            )
    return list(devices.values())


# ── Active FactoryTalk Linx RNA subnet sweep ──────────────────────────────────
#
# Added 2026-11-05 (side-quests.md #1, FactoryTalk). A dedicated single-protocol sweep: "which hosts
# on this subnet are running FactoryTalk Linx (RnaDaSvr.dll, TCP 4241)?" Runs
# core/fingerprint.py:probe_factorytalk_rna_identity — the benign OpenNamespace handshake — against
# each host through the same bounded ThreadPoolExecutor shape as mqtt_active_scan() (RNA needs a real
# per-host TCP handshake, so the fire-all-then-collect UDP pattern micom_courier_scan() uses does not
# fit; a host that silently drops the SYN would stall its probe for the full timeout with no way to
# overlap the wait without concurrency). RNA is also reachable through the generic protocol_probe_scan
# (registered in _PROBE_SCAN_PORTS); this is the named, operator-facing "sweep for FactoryTalk Linx"
# entry point, mirroring how mqtt_active_scan() exists as a dedicated method even though a generic
# sweep could reach MQTT too.
#
# SCOPE: identity only, like the probe it wraps. A hit means "RNA service reachable on 4241" — NOT
# "vulnerable to CVE-2020-5801/5802" (the handshake exposes no version; those CVEs are catalogued in
# the published guide, not asserted by a discovery hit). Never validated against a real RSLinxNG.exe.
DETECTION_HINTS_FACTORYTALK_RNA_SCAN = {
    "transport": "tcp",
    "app_protocol": "rna",
    "mitre_attack_id": "T0846",  # Remote System Discovery (Discovery, TA0102) — same rationale as
    # DETECTION_HINTS_MICOM_COURIER_SCAN: this is active recon, not credential guessing (T0812).
    "narrow": {
        "description": (
            "This scanner's own exact factorytalk_rna_scan() request: the benign RNA OpenNamespace "
            "envelope on TCP 4241 — magic b'rna\\xF2', a 44-byte 4-byte-aligned text header block "
            "(command=XmlCommand, empty session-id, transid=1, sorted and NUL-padded) with its "
            "little-endian length 0x2C, then a 0x194-byte data-block length and the OpenNamespace "
            "XML. Fully deterministic (no per-run varying field, unlike the MiCOM scan's XID), so "
            "this is a byte-exact match of the request this scanner emits. Verified against "
            "core/fingerprint.py:_rna_open_namespace_request()'s actual output, not hand-derived."
        ),
        "patterns": [
            {
                "context": "request",
                "regex": (
                    "^rna\\xf2\\x2c\\x00\\x00\\x00command=XmlCommand\\x00session-id=\\x00"
                    "transid=1\\x00\\x00\\x00\\x00\\x94\\x01\\x00\\x00\\r\\n<OpenNamespace"
                ),
            }
        ],
    },
    "broad": {
        "description": (
            "Any FactoryTalk Linx RNA envelope opening a namespace: the b'rna\\xF2' magic followed "
            "anywhere by an <OpenNamespace element — i.e. 'something is opening an RNA session on "
            "4241', independent of this scanner's specific header fields or XML attributes. Verified "
            "to reject ordinary HTTP and an rna\\xF2 envelope that carries no OpenNamespace, so it "
            "does not false-positive on unrelated TCP traffic."
        ),
        "patterns": [
            {
                "context": "request",
                "regex": "^rna\\xf2[\\s\\S]*<OpenNamespace",
            }
        ],
    },
}


def factorytalk_rna_scan(
    cidr: str,
    port: int = 4241,
    timeout: float = 3.0,
    max_workers: int = 32,
    force: bool = False,
    rate_limiter=None,
) -> list:
    """Active discovery of FactoryTalk Linx RNA servers across a subnet: one benign OpenNamespace
    handshake per host via core.fingerprint.probe_factorytalk_rna_identity, run through a bounded
    thread pool (same shape as mqtt_active_scan(); see the module-level comment above for why a TCP
    handshake needs real concurrency rather than micom_courier_scan()'s UDP fire-and-collect).
    Records any host the probe resolves to RNA (confidence != "none" — high = session assigned,
    medium = valid envelope but no session). Identity only: a hit is "RNA reachable", never a
    vulnerability verdict — judging CVE-2020-5801/5802 is out of scope for a discovery sweep.

    Same /20-host safety cap as arp_scan()/mqtt_active_scan() (`force=True` to override) — this is an
    active, subnet-wide TCP send, not a single-target probe.
    """
    from core.fingerprint import probe_factorytalk_rna_identity

    hosts = _hosts_for_active_scan(cidr, force, "FactoryTalk RNA sweep")
    if not hosts:
        return []

    def _probe_one(host) -> tuple:
        if rate_limiter is not None:
            rate_limiter.acquire(str(host))
        return str(host), probe_factorytalk_rna_identity(str(host), port, timeout=timeout)

    devices: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for ip, fp in executor.map(_probe_one, hosts):
            if fp.confidence == "none":
                continue
            now = _now_iso()
            devices[ip] = DiscoveredDevice(
                ip=ip,
                mac=None,
                vendor=fp.vendor if fp.vendor not in (None, "", "unknown") else "Rockwell Automation",
                method="factorytalk_rna_active",
                first_seen=now,
                last_seen=now,
                extra={
                    "port": port,
                    "protocol": "factorytalk_rna",
                    "model": fp.model,
                    "confidence": fp.confidence,
                    "probe_method": fp.method,
                    "session_id": fp.extra.get("session_id"),
                },
            )
    return list(devices.values())


# ── CODESYS V3 name-service broadcast discovery ───────────────────────────────
#
# Added 2026-10-06 (ABB sweep). CODESYS V3 devices answer a UDP/1740 name-service broadcast with an
# "Identification" response carrying node/device/vendor name + target id/version. The CODESYS IDE's
# own "Scan network" uses this; it fingerprints the entire CODESYS ecosystem at once (ABB AC500,
# Hitachi EHV+, Opto22 groov EPIC, Schneider M241/M251/M258, WAGO, Beckhoff, ...). Frame + parser
# ported faithfully from rapid7/data/codesys (nmap codesys3.lua / broadcast-codesys-discover.nse).
#
# ⚠ VALIDATED CAVEAT (2026-10-08, the companion fuzzer live-validation handoff — a companion fuzzing toolkit
# codesys-v3-research.md): this rapid7-era frame got NO reply from a real CODESYS Control for Linux
# SL 3.5.22.30 runtime — not unicast, not interface-broadcast, not 255.255.255.255, matching OR
# foreign sender subnet — and NOT EVEN with the comm security policy relaxed
# (SECURITY.DeactivateSecurityPolicy=1 / CommunicationMode=1 / CommunicationPolicy=0). tcpdump
# confirmed the requests left the host; the runtime bound UDP 1740 per-interface (unicast + bcast)
# but answered and logged nothing. So modern enforced-default CODESYS (3.5.17+) is SILENT on this
# path: the scan finds only legacy / relaxed / older-OEM runtimes, not current units. Root cause is
# not (only) the security policy — likely grammar drift from the ~2015 codesys3.lua frame, or the NS
# reply now happens only via the gateway's own scan path (TCP 11740 CmpBlkDrvTcp, protocol not yet
# RE'd). For modern units, fingerprint over TCP instead: probe_codesys_gateway (11740 presence) +
# probe_opcua_identity (4840 GetEndpoints) in core/fingerprint.py. Re-validate this UDP scan against
# a KNOWN-REPLYING device (older OEM runtime / real PLC) before trusting a negative result.
_CODESYS_V3_PORT = 1740


def _ipv4_to_int(ip: str) -> int:
    return int(ipaddress.IPv4Address(ip))


def build_codesys_v3_name_request(local_ip: str, netmask_cidr: int, portindex: int = 0,
                                  broadcast_id: Optional[int] = None) -> bytes:
    """Build a CODESYS V3 Name Service (ResolveAddr) request, byte-identical to rapid7 codesys3.lua."""
    import random
    if broadcast_id is None:
        broadcast_id = random.randint(0, 0xFFFF)
    magic, hop_count, header_length = 0xC5, 0x0F, 0x04
    priority, signal, address_type, data_length = 0x01, 0, 0, 0
    service_id, message_id = 0x03, 0x00  # NameServiceRequest

    local_bits = 32 - netmask_cidr
    port_bits = 2
    sender_words = ((local_bits + port_bits) + 15) // 16          # 16-bit words
    address_lengths = ((sender_words & 0xF) << 4) | (0 & 0xF)      # receiver length 0
    my_addr = _ipv4_to_int(local_ip)
    sender_address = ((portindex & 3) << local_bits) | (my_addr & ((1 << local_bits) - 1))

    hopinfo = ((hop_count & 0x1F) << 3) | (header_length & 7)
    packetinfo = ((priority & 3) << 6) | ((signal & 1) << 5) | ((address_type & 1) << 4) | (data_length & 0xF)
    pkt = struct.pack(">BBBBBBH", magic, hopinfo, packetinfo, service_id, message_id, address_lengths, broadcast_id)
    for i in range(sender_words):
        j = sender_words - 1 - i
        pkt += struct.pack(">H", (sender_address >> (16 * j)) & 0xFFFF)
    if len(pkt) % 4 != 0:                                          # faithful to the source's pad
        pkt += b"\x00" * (len(pkt) % 4)
    pkt += struct.pack("<HHI", 0xC202, 0x0400, 0x04206969)        # ResolveAddr, v4.00, request id
    return pkt


def parse_codesys_v3_response(data: bytes) -> Optional[dict]:
    """Parse a CODESYS V3 Name Service Identification response (magic 0xC5, service_id 0x04).
    Returns {node, device, vendor, target_id, target_version} or None. Faithful to codesys3.lua."""
    if not data or len(data) < 8 or data[0] != 0xC5 or data[3] != 0x04:  # magic + NameServiceResponse
        return None
    hopinfo = data[1]
    header_length = hopinfo & 7
    address_lengths = data[5]
    pos = header_length * 2
    pos += (address_lengths & 0xF) * 2 + (address_lengths >> 4) * 2
    if pos % 4 != 0:
        pos += pos % 4
    try:
        package_type, version = struct.unpack_from("<HH", data, pos)
        if package_type != 0xC280 or version != 0x0400:  # Identification, v4.00
            return None
        pos += 8  # package_type(2) + version(2) + request_id(4)
        # maxChannels(2) byteorder(1) addrDiff(1) parentAddrSize(2)
        _max, _bo, _ad, parent = struct.unpack_from("<HBBH", data, pos); pos += 6
        node_len, dev_len, vend_len = struct.unpack_from("<HHH", data, pos); pos += 6
        target_type, target_id, target_ver, flags = struct.unpack_from("<IIII", data, pos); pos += 16
        ser_len, oem_len, _blk = struct.unpack_from("<BBB", data, pos); pos += 3 + 1 + 8  # + pad/reserved
        pos += parent
        def _s(n):
            nonlocal pos
            raw = data[pos:pos + n]; pos += n
            return raw.split(b"\x00", 1)[0].decode("latin-1", "replace")
        node = _s(node_len); device = _s(dev_len); vendor = _s(vend_len)
        return {"node": node, "device": device, "vendor": vendor,
                "target_id": f"0x{target_id:08x}", "target_version": f"0x{target_ver:08x}"}
    except (struct.error, IndexError):
        return {"node": "", "device": "", "vendor": ""}  # a 0x04 response, but couldn't fully parse


_KNXNET_MCAST = "224.0.23.12"
_KNXNET_PORT = 3671


def knxnet_search_scan(timeout: float = 3.0, rate_limiter=None, mcast: str = _KNXNET_MCAST,
                       port: int = _KNXNET_PORT, **_ignored) -> list:
    """Active KNXnet/IP discovery: one SEARCH_REQUEST to the KNX multicast group (224.0.23.12:3671),
    collecting SEARCH_RESPONSEs -> one DiscoveredDevice per KNX/IP gateway on the segment. Multicast
    (L2-segment reach), read-only -- never issues a KNX group/bus write. One packet (like mDNS/SSDP), so
    no CIDR/host cap applies; a `cidr`/`iface` passed by the shared active-discover CLI is ignored."""
    from core.fingerprint import _KNXNET_SEARCH_REQUEST, parse_knxnet_frame
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)
        if rate_limiter is not None:
            rate_limiter.acquire(mcast)
        sock.sendto(_KNXNET_SEARCH_REQUEST, (mcast, port))
        found: dict = {}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(1024)
            except _socket.timeout:
                continue
            except OSError:
                break
            ip = addr[0]
            if ip in found:
                continue
            res = parse_knxnet_frame(data)
            if res is None:
                continue
            now = _now_iso()
            found[ip] = DiscoveredDevice(
                ip=ip, mac=None, vendor=res.vendor or "unknown", method="knxnet_search_active",
                first_seen=now, last_seen=now,
                extra={"model": res.model, "serial": res.serial, **(res.extra or {})})
        return list(found.values())
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


_ENIP_PORT = 44818


def enip_list_identity_scan(cidr: str, timeout: float = 3.0, force: bool = False,
                            rate_limiter=None, port: int = _ENIP_PORT) -> list:
    """Active EtherNet/IP discovery: one UDP/44818 List Identity (CIP encapsulation command 0x63)
    broadcast to `cidr`'s broadcast address, collecting Identity responses for `timeout` seconds --
    one DiscoveredDevice per responding CIP device (any ODVA vendor). List Identity is the CIP
    spec's unconnected discovery service (no session, read-only), and a UDP broadcast is its
    canonical whole-segment sweep -- what RSLinx / pycomm3 discovery send. L2-segment reach only
    (a broadcast does not route); for cross-subnet identification use the per-host TCP
    probe_enip_identity instead. Same /20 safety cap + force override as the other active sweeps;
    benign, sends exactly one packet. Vendor name comes from the (bulk + override) ODVA table.
    """
    from core.fingerprint import _ENIP_LIST_IDENTITY_REQUEST, parse_enip_list_identity
    network = ipaddress.ip_network(cidr, strict=False)
    if network.num_addresses > MAX_HOSTS_WITHOUT_FORCE and not force:
        raise ValueError(f"{cidr} has {network.num_addresses} addresses, over the "
                         f"{MAX_HOSTS_WITHOUT_FORCE}-host cap for an EtherNet/IP broadcast — pass force=True.")
    bcast = str(network.broadcast_address)
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
        sock.settimeout(0.5)
        if rate_limiter is not None:
            rate_limiter.acquire(bcast)
        sock.sendto(_ENIP_LIST_IDENTITY_REQUEST, (bcast, port))
        found: dict = {}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
            except _socket.timeout:
                continue
            except OSError:
                break
            ip = addr[0]
            if ip in found:
                continue
            fp = parse_enip_list_identity(data)
            if fp is None:
                continue
            now = _now_iso()
            found[ip] = DiscoveredDevice(
                ip=ip, mac=None,
                vendor=fp.vendor or "unknown",
                method="enip_list_identity_active",
                first_seen=now, last_seen=now,
                extra={"protocol": "ethernetip", "port": port,
                       "model": fp.model, "firmware": fp.firmware, "serial": fp.serial,
                       **(fp.extra or {})},
            )
        return list(found.values())
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def codesys_v3_broadcast_scan(cidr: str, timeout: float = 3.0, force: bool = False,
                              rate_limiter=None, port: int = _CODESYS_V3_PORT) -> list:
    """Active CODESYS V3 discovery: one UDP/1740 name-service broadcast to `cidr`'s broadcast
    address, collecting Identification responses for `timeout` seconds -- one DiscoveredDevice per
    responding CODESYS host (any vendor). Mirrors the CODESYS IDE "Scan network" / rapid7's
    broadcast-codesys-discover.nse. L2-segment reach only (a broadcast doesn't route), same as
    arp_scan(). Same /20 safety cap + force override as the other active sweeps.
    """
    network = ipaddress.ip_network(cidr, strict=False)
    if network.num_addresses > MAX_HOSTS_WITHOUT_FORCE and not force:
        raise ValueError(f"{cidr} has {network.num_addresses} addresses, over the "
                         f"{MAX_HOSTS_WITHOUT_FORCE}-host cap for a CODESYS broadcast — pass force=True.")
    bcast = str(network.broadcast_address)
    sock = None
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
        sock.settimeout(0.5)
        try:
            sock.connect((bcast, port)); local_ip = sock.getsockname()[0]; sock.close()
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_BROADCAST, 1)
            sock.settimeout(0.5)
        except OSError:
            local_ip = "0.0.0.0"
        if rate_limiter is not None:
            rate_limiter.acquire(bcast)
        sock.sendto(build_codesys_v3_name_request(local_ip, network.prefixlen), (bcast, port))
        found: dict = {}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
            except _socket.timeout:
                continue
            except OSError:
                break
            ip = addr[0]
            if ip in found:
                continue
            ident = parse_codesys_v3_response(data)
            if ident is None:
                continue
            now = _now_iso()
            found[ip] = DiscoveredDevice(
                ip=ip, mac=None,
                vendor=ident.get("vendor") or "unknown",
                method="codesys_v3_active",
                first_seen=now, last_seen=now,
                extra={"protocol": "codesys_v3", "port": port,
                       "device": ident.get("device", ""), "node": ident.get("node", ""),
                       "target_id": ident.get("target_id", ""), "target_version": ident.get("target_version", "")},
            )
        return list(found.values())
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


# ── Passive multi-protocol listener ───────────────────────────────────────────
#
# Every listener function shares one signature — (iface, stop_event, results, lock, **kwargs) —
# so PASSIVE_LISTENERS mirrors core/fingerprint.py:PROTOCOL_PROBES' registry shape exactly and
# adding a future listener (mDNS, LLDP, BACnet Who-Is broadcast, EtherNet/IP List-Identity) is a
# one-line registration, not a special case.


def _listen_arp(iface: str, stop_event: threading.Event, results: dict, lock: threading.Lock, **_kwargs) -> None:
    """Purely passive — opens a receive-only raw socket, sends nothing. Sees broadcast ARP
    traffic (requests and replies) without promiscuous mode on a normal switched port; also sees
    other hosts' unicast ARP if this box happens to be attached to a mirror/span port."""
    sock = None
    try:
        try:
            sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(_ETH_P_ARP))
            sock.bind((iface, 0))
        except (PermissionError, OSError, AttributeError):
            return
        sock.settimeout(0.5)
        while not stop_event.is_set():
            try:
                data = sock.recv(2048)
            except OSError:
                continue
            parsed = _parse_arp_frame(data)
            if parsed is None:
                continue
            _, sender_ip, sender_mac = parsed
            now = _now_iso()
            with lock:
                if sender_mac in results:
                    results[sender_mac].last_seen = now
                else:
                    results[sender_mac] = DiscoveredDevice(
                        ip=sender_ip,
                        mac=sender_mac,
                        vendor=lookup_oui(sender_mac),
                        method="arp_passive",
                        first_seen=now,
                        last_seen=now,
                    )
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _listen_sparkplug(
    iface: str,
    stop_event: threading.Event,
    results: dict,
    lock: threading.Lock,
    *,
    sparkplug_broker: Optional[tuple] = None,
    **_kwargs,
) -> None:
    """Read-only Sparkplug B discovery: subscribes to the standard spBv1.0/# topic wildcard on a
    user-supplied broker and records the group_id/edge_node_id/device_id present in each
    message's OWN topic string — Sparkplug B's namespace is self-describing by design
    (spBv1.0/{group_id}/{message_type}/{edge_node_id}[/{device_id}]), matching the NBIRTH/DBIRTH
    "birth certificate" convention the spec defines. Does not decode the protobuf payload — that
    is a metrics-level follow-up, not required to answer "what devices are out here."

    Classified as passive for this project's purposes (no data is ever published, only
    subscribed), though it does open one real TCP connection to the broker — a real distinction
    from the zero-packet ARP listener, documented here rather than glossed over.

    No broker auto-discovery exists for Sparkplug B — `sparkplug_broker` (host, port) must be
    supplied by the caller. If it's not given, or paho-mqtt isn't installed, this fails closed
    (returns immediately) rather than raising.
    """
    if mqtt is None or not sparkplug_broker:
        return
    host, port = sparkplug_broker

    def on_message(_client, _userdata, msg) -> None:
        parts = msg.topic.split("/")
        if len(parts) < 4 or parts[0] != "spBv1.0":
            return
        group_id, message_type, edge_node_id = parts[1], parts[2], parts[3]
        device_id = parts[4] if len(parts) > 4 else None
        key = f"sparkplug:{group_id}/{edge_node_id}/{device_id or ''}"
        now = _now_iso()
        with lock:
            if key in results:
                results[key].last_seen = now
            else:
                results[key] = DiscoveredDevice(
                    ip=host,  # the broker's own address — Sparkplug's topic namespace carries
                    mac=None,  # the edge node's logical identity, not its IP/MAC.
                    vendor="unknown",
                    method="sparkplug_b",
                    first_seen=now,
                    last_seen=now,
                    extra={
                        "group_id": group_id,
                        "edge_node_id": edge_node_id,
                        "device_id": device_id,
                        "message_type": message_type,
                        "broker": f"{host}:{port}",
                    },
                )

    client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
    client.on_message = on_message
    try:
        client.connect(host, port, keepalive=30)
    except (OSError, ValueError):
        return  # connect refused/timeout/bad address — fail closed, never raise
    client.subscribe("spBv1.0/#")
    client.loop_start()
    try:
        stop_event.wait()
    finally:
        client.loop_stop()
        try:
            client.disconnect()
        except OSError:
            pass


# ── RaSTA (Rail Safe Transport Application) passive listener ──
# Added 2026-10-07 per lab-notes/rasta-safe-build-research.md. RaSTA (DIN VDE V 0831-200 / IEC 62280)
# is the safe-transport layer between railway interlockings and object controllers — SAFETY-CRITICAL.
# This project NEVER transmits a RaSTA frame: the safety code is installation-keyed, so an active
# Connection Request is both useless (rejected as a safety-code error) and unsafe (an injected frame
# into signalling risks a safety event). RaSTA is therefore a PASSIVE listener ONLY — read-only
# observation of mirrored UDP traffic, or offline replay of a capture. The read-only PDU parser is
# ported from the Railway-CCS Wireshark dissector and validated against its example pcaps
# (dumps/rasta_from_standard.pcapng, rasta_c_ESTW_C.pcapng).
_RASTA_MSG_TYPES = {
    6200: "ConnReq", 6201: "ConnResp", 6212: "RetrReq", 6213: "RetrResp",
    6216: "DiscReq", 6220: "Heartbeat", 6240: "Data", 6241: "RetrData",
}


def parse_rasta_pdu(payload: bytes) -> Optional[dict]:
    """Read-only parse of one RaSTA UDP payload -> identity fields (message type, sender/receiver
    IDs, SN/CS, and protocol version for ConnReq/ConnResp) or None if not a structurally valid RaSTA
    PDU. Transmits nothing; computes/validates NO safety code (installation-keyed and unneeded for
    identity). Offsets verified against the Railway-CCS pcaps. Layout (little-endian): redundancy
    length @0; safety layer @8 -> length @8, type @10, receiver id @12 (u32), sender id @16 (u32),
    SN @20, CS @24, timestamps @28/@32, protocol version @36 (4 ASCII, ConnReq/ConnResp only)."""
    try:
        if len(payload) < 28:
            return None
        red_len = struct.unpack("<H", payload[0:2])[0]
        safety_len = struct.unpack("<H", payload[8:10])[0]
        # structural invariants -> a random UDP datagram is vanishingly unlikely to match
        if red_len != len(payload) or safety_len != red_len - 8:
            return None
        msg_type = struct.unpack("<H", payload[10:12])[0]
        if msg_type not in _RASTA_MSG_TYPES:
            return None
        out = {
            "message_type": msg_type,
            "message_type_name": _RASTA_MSG_TYPES[msg_type],
            "receiver_id": struct.unpack("<I", payload[12:16])[0],
            "sender_id": struct.unpack("<I", payload[16:20])[0],
            "sn": struct.unpack("<I", payload[20:24])[0],
            "cs": struct.unpack("<I", payload[24:28])[0],
        }
        if msg_type in (6200, 6201) and len(payload) >= 40:
            raw = payload[36:40].decode("latin-1", "replace")
            if len(raw) == 4 and raw.isdigit():
                out["protocol_version"] = f"{raw[0:2]}.{raw[2:4]}"  # "0303" -> "03.03"
        return out
    except (struct.error, IndexError):
        return None


def _rasta_record(results: dict, lock, src_ip, pdu: dict, method: str) -> None:
    key = f"rasta:{pdu['sender_id']}->{pdu['receiver_id']}"
    now = _now_iso()
    with lock:
        if key in results:
            dev = results[key]
            dev.last_seen = now
            types = set(dev.extra.get("message_types", []))
            types.add(pdu["message_type_name"])
            dev.extra["message_types"] = sorted(types)
            if pdu.get("protocol_version"):
                dev.extra["protocol_version"] = pdu["protocol_version"]
        else:
            extra = {
                "rasta_sender_id": pdu["sender_id"],
                "rasta_receiver_id": pdu["receiver_id"],
                "message_types": [pdu["message_type_name"]],
            }
            if pdu.get("protocol_version"):
                extra["protocol_version"] = pdu["protocol_version"]
            results[key] = DiscoveredDevice(
                ip=src_ip, mac=None,
                vendor="unknown",  # RaSTA IDs are logical endpoint ids, not a hardware vendor
                method=method, first_seen=now, last_seen=now, extra=extra,
            )


def rasta_replay_pcap(pcap_path: str) -> list:
    """OFFLINE, read-only: replay a capture file through parse_rasta_pdu and return one
    DiscoveredDevice per RaSTA sender->receiver pair. The safe way to fingerprint RaSTA — no network,
    no transmitted frame, reproducible against a stored capture (e.g. the Railway-CCS example pcaps).
    Needs scapy; returns [] (never raises) if scapy is missing or the file can't be read."""
    try:
        from scapy.all import rdpcap, UDP
    except Exception:
        return []
    try:
        packets = rdpcap(pcap_path)
    except Exception:
        return []
    results: dict = {}
    lock = threading.Lock()
    for pkt in packets:
        try:
            if UDP not in pkt:
                continue
            payload = bytes(pkt[UDP].payload)
        except Exception:
            continue
        pdu = parse_rasta_pdu(payload)
        if pdu is None:
            continue
        src_ip = pkt["IP"].src if pkt.haslayer("IP") else None
        _rasta_record(results, lock, src_ip, pdu, "rasta_passive_pcap")
    return list(results.values())


def _udp_payload_from_eth(frame: bytes) -> Optional[tuple]:
    """Minimal read-only Ethernet II / IPv4 / UDP decap -> (src_ip, udp_payload) or None. Bounded, no
    reassembly; used only to reach the RaSTA payload in a sniffed frame."""
    try:
        if len(frame) < 14 + 20 + 8:
            return None
        if struct.unpack(">H", frame[12:14])[0] != 0x0800:  # EtherType IPv4
            return None
        if frame[14] >> 4 != 4:
            return None
        ihl = (frame[14] & 0x0F) * 4
        if ihl < 20 or frame[14 + 9] != 17:  # IHL sane, protocol = UDP(17)
            return None
        src_ip = ".".join(str(b) for b in frame[14 + 12:14 + 16])
        udp_off = 14 + ihl
        udp_len = struct.unpack(">H", frame[udp_off + 4:udp_off + 6])[0]
        return (src_ip, frame[udp_off + 8: udp_off + udp_len])
    except (struct.error, IndexError):
        return None


def _listen_rasta(iface: str, stop_event: threading.Event, results: dict, lock: threading.Lock, **_kwargs) -> None:
    """Purely passive live RaSTA observation: a receive-only raw socket that parses mirrored
    Ethernet/IPv4/UDP frames and feeds the UDP payloads to parse_rasta_pdu. TRANSMITS NOTHING (no
    ConnReq, ever — RaSTA is safety-critical). Fails closed without CAP_NET_RAW, same as _listen_arp.
    Best run on a SPAN/mirror port of an AUTHORIZED rail network."""
    sock = None
    try:
        try:
            sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW, _socket.htons(0x0800))  # ETH_P_IP
            sock.bind((iface, 0))
        except (PermissionError, OSError, AttributeError):
            return
        sock.settimeout(0.5)
        while not stop_event.is_set():
            try:
                frame = sock.recv(2048)
            except OSError:
                continue
            decap = _udp_payload_from_eth(frame)
            if decap is None:
                continue
            pdu = parse_rasta_pdu(decap[1])
            if pdu is None:
                continue
            _rasta_record(results, lock, decap[0], pdu, "rasta_passive")
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


PASSIVE_LISTENERS: dict[str, Callable] = {
    "arp": _listen_arp,
    "sparkplug_b": _listen_sparkplug,
    "rasta": _listen_rasta,
}


def passive_listen(
    duration: float,
    iface: Optional[str] = None,
    protocols: Optional[list] = None,
    sparkplug_broker: Optional[tuple] = None,
) -> list:
    """Runs every requested listener in PASSIVE_LISTENERS concurrently for exactly `duration`
    seconds, then stops all of them and returns the merged device list.

    `protocols=None` runs every registered listener; pass e.g. ["arp"] to run just one.
    Auto-detects the outbound interface (same routing-hint technique as arp_scan()) if `iface`
    isn't given; fails closed (returns []) if no usable interface is found, same posture as
    every other privilege/environment failure in this module.
    """
    if iface is None:
        local_ip = _detect_local_ip("8.8.8.8")
        iface = _iface_for_ip(local_ip) if local_ip else None
    if iface is None:
        return []

    names = protocols if protocols is not None else list(PASSIVE_LISTENERS.keys())
    stop_event = threading.Event()
    results: dict = {}
    lock = threading.Lock()

    threads = []
    for name in names:
        listener = PASSIVE_LISTENERS.get(name)
        if listener is None:
            continue
        t = threading.Thread(
            target=listener,
            args=(iface, stop_event, results, lock),
            kwargs={"sparkplug_broker": sparkplug_broker},
            daemon=True,
        )
        t.start()
        threads.append(t)

    time.sleep(duration)
    stop_event.set()
    for t in threads:
        t.join(timeout=5.0)

    return list(results.values())
