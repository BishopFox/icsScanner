"""OPC UA (binary / opc.tcp) active identity probe.

OPC UA is the dominant vendor-neutral industrial middleware; its binary transport (opc.tcp) listens on
TCP 4840 by default. This probe performs the standard, read-only discovery exchange used by every OPC UA
client -- Hello -> Acknowledge, OpenSecureChannel with SecurityPolicy #None, then GetEndpoints -- and
reads the server's own ApplicationDescription (applicationUri, productUri, applicationName, application
type) out of the response. GetEndpoints requires no session, no credentials, and no security, and the
probe never reads or writes a single node: it is the OPC UA equivalent of asking a server to describe
itself. If the fuller exchange fails but the Hello/Acknowledge handshake succeeded, the probe still
reports OPC UA presence.

Message framing and the GetEndpoints/OpenSecureChannel request bodies follow OPC UA Part 6 (binary
mapping); the request-type NodeIds (OpenSecureChannelRequest=446, GetEndpointsRequest=428) are the
OPC Foundation DefaultBinary encoding ids. Validated against the spec and a self-consistent mock;
live-server interop is not yet confirmed.
"""
import socket
import struct
import time
from typing import Optional

OPCUA_PORT = 4840
_SECURITY_POLICY_NONE = b"http://opcfoundation.org/UA/SecurityPolicy#None"
_APP_TYPE = {0: "Server", 1: "Client", 2: "ClientAndServer", 3: "DiscoveryServer"}


# ─────────────────────────── encoding helpers ───────────────────────────
def _ua_str(s: Optional[bytes]) -> bytes:
    """OPC UA String/ByteString: Int32 length (-1 = null) + bytes."""
    if s is None:
        return struct.pack("<i", -1)
    return struct.pack("<i", len(s)) + s


def _node_id(numeric: int) -> bytes:
    """Four-byte NodeId in namespace 0 (encoding 0x01): used for the service request TypeIds."""
    return bytes([0x01, 0x00]) + struct.pack("<H", numeric)


def _request_header(handle: int) -> bytes:
    filetime = int((time.time() + 11644473600) * 10_000_000)   # DateTime: 100ns ticks since 1601
    return (bytes([0x00, 0x00])                                 # authenticationToken: null NodeId
            + struct.pack("<q", filetime)                       # timestamp
            + struct.pack("<I", handle)                         # requestHandle
            + struct.pack("<I", 0)                              # returnDiagnostics
            + _ua_str(None)                                     # auditEntryId
            + struct.pack("<I", 0)                              # timeoutHint
            + bytes([0x00, 0x00, 0x00]))                        # additionalHeader: null ExtensionObject


def _message(magic: bytes, rest: bytes) -> bytes:
    return magic + b"F" + struct.pack("<I", 8 + len(rest)) + rest


# ─────────────────────────── decoding cursor ───────────────────────────
class _R:
    __slots__ = ("b", "i")

    def __init__(self, b: bytes, i: int = 0):
        self.b, self.i = b, i

    def u32(self) -> int:
        v = struct.unpack_from("<I", self.b, self.i)[0]; self.i += 4; return v

    def skip(self, n: int):
        self.i += n

    def string(self) -> Optional[str]:
        n = struct.unpack_from("<i", self.b, self.i)[0]; self.i += 4
        if n < 0:
            return None
        s = self.b[self.i:self.i + n]; self.i += n
        return s.decode("utf-8", "replace")

    def node_id(self):
        enc = self.b[self.i]; self.i += 1
        if enc == 0x00:
            self.i += 1
        elif enc == 0x01:
            self.i += 3
        elif enc == 0x02:
            self.i += 6
        else:                                                  # string/guid/bytestring node ids
            self.i += 2
            self.string()

    def localized_text(self) -> Optional[str]:
        mask = self.b[self.i]; self.i += 1
        locale = self.string() if mask & 0x01 else None
        text = self.string() if mask & 0x02 else None
        return text or locale

    def response_header(self):
        self.skip(8 + 4)                                       # timestamp + requestHandle
        service_result = self.u32()                            # StatusCode
        diag = self.b[self.i]; self.i += 1                     # DiagnosticInfo mask (0 = empty)
        if diag:                                               # rare on success; bail rather than misparse
            raise ValueError("non-empty diagnostic info")
        n = struct.unpack_from("<i", self.b, self.i)[0]; self.i += 4   # StringTable array
        for _ in range(max(n, 0)):
            self.string()
        self.node_id(); self.skip(1)                           # additionalHeader ExtensionObject (null)
        return service_result


# ─────────────────────────── request builders ───────────────────────────
def _hello(endpoint_url: bytes) -> bytes:
    body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + _ua_str(endpoint_url)
    return _message(b"HEL", body)


def _open_channel() -> bytes:
    asym = _ua_str(_SECURITY_POLICY_NONE) + _ua_str(None) + _ua_str(None)
    seq = struct.pack("<II", 1, 1)
    body = (_node_id(446) + _request_header(1)
            + struct.pack("<I", 0)        # clientProtocolVersion
            + struct.pack("<I", 0)        # requestType: ISSUE
            + struct.pack("<I", 1)        # securityMode: NONE
            + _ua_str(None)               # clientNonce
            + struct.pack("<I", 3600000))  # requestedLifetime
    return _message(b"OPN", struct.pack("<I", 0) + asym + seq + body)


def _get_endpoints(channel_id: int, token_id: int, endpoint_url: bytes) -> bytes:
    seq = struct.pack("<II", 2, 2)
    body = (_node_id(428) + _request_header(2) + _ua_str(endpoint_url)
            + struct.pack("<i", -1)       # localeIds: null array
            + struct.pack("<i", -1))      # profileUris: null array
    return _message(b"MSG", struct.pack("<II", channel_id, token_id) + seq + body)


# ─────────────────────────── probe ───────────────────────────
def _recv_message(s: socket.socket, timeout: float) -> Optional[bytes]:
    """Read one OPC UA message (8-byte header carries the total size). Returns the whole message."""
    s.settimeout(timeout)
    hdr = b""
    while len(hdr) < 8:
        chunk = s.recv(8 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    size = struct.unpack_from("<I", hdr, 4)[0]
    if size < 8 or size > 1 << 20:
        return None
    body = b""
    while len(body) < size - 8:
        chunk = s.recv(size - 8 - len(body))
        if not chunk:
            return None
        body += chunk
    return hdr + body


def _parse_open_response(msg: bytes):
    """Return (channel_id, token_id) from an OPN response, or None."""
    if msg[:3] != b"OPN":
        return None
    r = _R(msg, 8)
    channel_id = r.u32()
    r.string(); r.string(); r.string()        # asym header: policy, senderCert, thumbprint
    r.skip(8)                                 # sequence header
    r.node_id()                               # response TypeId
    if r.response_header() != 0:
        return None
    r.skip(4)                                 # serverProtocolVersion
    r.skip(4)                                 # SecurityToken.channelId
    token_id = r.u32()                        # SecurityToken.tokenId
    return channel_id, token_id


def _parse_endpoints_identity(msg: bytes):
    """Pull the first endpoint's ApplicationDescription out of a GetEndpoints response."""
    if msg[:3] != b"MSG":
        return None
    r = _R(msg, 8)
    r.skip(4 + 4 + 8)                         # channelId + tokenId + sequence header
    r.node_id()                              # response TypeId
    if r.response_header() != 0:
        return None
    count = struct.unpack_from("<i", r.b, r.i)[0]; r.i += 4   # Endpoints array count
    if count <= 0:
        return {}
    endpoint_url = r.string()                 # EndpointDescription.endpointUrl
    app_uri = r.string()                      # ApplicationDescription.applicationUri
    product_uri = r.string()                  # ApplicationDescription.productUri
    app_name = r.localized_text()             # ApplicationDescription.applicationName
    app_type = r.u32()                        # ApplicationDescription.applicationType
    return {"endpoint_url": endpoint_url, "application_uri": app_uri, "product_uri": product_uri,
            "application_name": app_name, "application_type": _APP_TYPE.get(app_type, app_type)}


def probe_opcua_identity(host: str, port: int = OPCUA_PORT, timeout: float = 4.0):
    """Active OPC UA identity probe (HEL/ACK -> OpenSecureChannel#None -> GetEndpoints). Read-only:
    never touches a node. Returns a FingerprintResult with the server's ApplicationDescription, or
    OPC UA presence if only the Hello/Acknowledge handshake completed, or confidence 'none'."""
    from core.fingerprint import FingerprintResult
    none = FingerprintResult(vendor="unknown", confidence="none", method="opcua_get_endpoints")
    endpoint_url = f"opc.tcp://{host}:{port}".encode()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(_hello(endpoint_url))
            ack = _recv_message(s, timeout)
            if not ack or ack[:3] != b"ACK":
                return none
            # presence established; now try the fuller identity exchange
            try:
                s.sendall(_open_channel())
                opn = _recv_message(s, timeout)
                ids = _parse_open_response(opn) if opn else None
                if ids is not None:
                    channel_id, token_id = ids
                    s.sendall(_get_endpoints(channel_id, token_id, endpoint_url))
                    ge = _recv_message(s, timeout)
                    ident = _parse_endpoints_identity(ge) if ge else None
                    if ident:
                        name = ident.get("application_name") or ident.get("application_uri")
                        return FingerprintResult(
                            vendor=_vendor_from(ident), model=name or "OPC UA server",
                            confidence="high", method="opcua_get_endpoints",
                            extra={"protocol": "opcua", **{k: v for k, v in ident.items() if v is not None}})
            except (OSError, struct.error, ValueError, IndexError):
                pass
    except (OSError, socket.timeout):
        return none
    # Hello/Acknowledge only -> presence
    return FingerprintResult(vendor="unknown", model="OPC UA server", confidence="low",
                             method="opcua_hello", extra={"protocol": "opcua"})


def _vendor_from(ident: dict) -> str:
    """Best-effort vendor from the productUri/applicationUri host or path (e.g. 'opcfoundation.org',
    'siemens.com')."""
    for key in ("product_uri", "application_uri"):
        uri = ident.get(key) or ""
        for sep in ("://", ":"):
            if sep in uri:
                uri = uri.split(sep, 1)[1]
                break
        host = uri.lstrip("/").split("/", 1)[0].split(":", 1)[0]
        parts = [p for p in host.split(".") if p not in ("www", "com", "org", "net", "io", "de")]
        if parts:
            return parts[-1] if len(parts[-1]) > 2 else parts[0]
    return "unknown"
