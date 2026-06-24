"""Core data models for proxy nodes and configuration."""

from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional


class ProxyType(Enum):
    Unknown = auto()
    Shadowsocks = auto()
    ShadowsocksR = auto()
    VMess = auto()
    Trojan = auto()
    Snell = auto()
    HTTP = auto()
    HTTPS = auto()
    SOCKS5 = auto()
    WireGuard = auto()
    VLESS = auto()
    Hysteria = auto()
    Hysteria2 = auto()
    TUIC = auto()
    AnyTLS = auto()
    Mieru = auto()

    def __str__(self):
        names = {
            ProxyType.Shadowsocks: "SS",
            ProxyType.ShadowsocksR: "SSR",
            ProxyType.VMess: "VMess",
            ProxyType.Trojan: "Trojan",
            ProxyType.Snell: "Snell",
            ProxyType.HTTP: "HTTP",
            ProxyType.HTTPS: "HTTPS",
            ProxyType.SOCKS5: "SOCKS5",
            ProxyType.WireGuard: "WireGuard",
            ProxyType.VLESS: "Vless",
            ProxyType.Hysteria: "Hysteria",
            ProxyType.Hysteria2: "Hysteria2",
            ProxyType.TUIC: "Tuic",
            ProxyType.AnyTLS: "AnyTLS",
            ProxyType.Mieru: "Mieru",
        }
        return names.get(self, "Unknown")


@dataclass
class Proxy:
    """Represents a single proxy node."""
    Type: ProxyType = ProxyType.Unknown
    Id: int = 0
    GroupId: int = 0
    Group: str = ""
    Remark: str = ""
    Hostname: str = ""
    Port: int = 0

    # Authentication
    Username: str = ""
    Password: str = ""

    # SS/SSR specific
    EncryptMethod: str = ""
    Plugin: str = ""
    PluginOption: str = ""
    Protocol: str = ""
    ProtocolParam: str = ""
    OBFS: str = ""
    OBFSParam: str = ""

    # VMess/VLESS specific
    UserId: str = ""
    AlterId: int = 0
    TransferProtocol: str = "tcp"
    FakeType: str = ""
    Host: str = ""
    Path: str = ""
    Edge: str = ""
    TLSStr: str = ""
    TLSSecure: bool = False
    QUICSecure: str = ""
    QUICSecret: str = ""
    ServerName: str = ""  # SNI
    Flow: str = ""
    Encryption: str = ""
    FlowShow: bool = False
    Fingerprint: str = ""
    AlpnList: list = field(default_factory=list)
    PacketEncoding: str = ""

    # Hysteria/Hysteria2
    AuthStr: str = ""
    Alpn: str = ""
    UpMbps: str = ""
    DownMbps: str = ""
    Insecure: str = ""
    OBFSPassword: str = ""
    GRPCServiceName: str = ""
    GRPCMode: str = ""
    ShortId: str = ""
    Ports: str = ""
    Auth: str = ""

    # TUIC
    CongestionControl: str = ""
    UdpRelayMode: str = "native"
    ReduceRtt: bool = False
    DisableSni: bool = False
    RequestTimeout: int = 15000
    token: str = ""

    # WireGuard
    SelfIP: str = ""
    SelfIPv6: str = ""
    PublicKey: str = ""
    PrivateKey: str = ""
    PreSharedKey: str = ""
    DnsServers: list = field(default_factory=list)
    Mtu: int = 0
    AllowedIPs: str = "0.0.0.0/0, ::/0"
    KeepAlive: int = 0
    TestUrl: str = ""
    ClientId: str = ""

    # General flags
    UDP: Optional[bool] = None
    XUDP: Optional[bool] = None
    TCPFastOpen: Optional[bool] = None
    AllowInsecure: Optional[bool] = None
    TLS13: Optional[bool] = None
    SnellVersion: int = 0

    # Mieru
    Multiplexing: str = ""
    V2rayHttpUpgrade: Optional[bool] = None
    XHTTPOptions: dict = field(default_factory=dict)
    SNI: str = ""
    UnderlyingProxy: str = ""


# Default group names for different proxy types
DEFAULT_GROUPS = {
    ProxyType.Shadowsocks: "SSProvider",
    ProxyType.ShadowsocksR: "SSRProvider",
    ProxyType.VMess: "V2RayProvider",
    ProxyType.Trojan: "TrojanProvider",
    ProxyType.Snell: "SnellProvider",
    ProxyType.HTTP: "HTTPProvider",
    ProxyType.HTTPS: "HTTPProvider",
    ProxyType.SOCKS5: "SocksProvider",
    ProxyType.WireGuard: "WireGuardProvider",
    ProxyType.VLESS: "XRayProvider",
    ProxyType.Hysteria: "HysteriaProvider",
    ProxyType.Hysteria2: "Hysteria2Provider",
    ProxyType.TUIC: "TuicProvider",
    ProxyType.AnyTLS: "AnyTLSProvider",
    ProxyType.Mieru: "MieruProvider",
}
