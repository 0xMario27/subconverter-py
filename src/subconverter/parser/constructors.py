"""Proxy node constructors - set fields on a Proxy object."""

from typing import List

from ..config.models import Proxy, ProxyType, DEFAULT_GROUPS
from .common import common_construct


def ss_construct(node: Proxy, group: str, remarks: str, server: str,
                 port: str, password: str, method: str,
                 plugin: str = "", plugin_opts: str = "",
                 udp=None, tfo=None, scv=None, tls13=None,
                 underlying_proxy=""):
    common_construct(node, ProxyType.Shadowsocks, group, remarks, server, port,
                     udp, tfo, scv, tls13, underlying_proxy)
    node.EncryptMethod = method
    node.Password = password
    node.Plugin = plugin
    node.PluginOption = plugin_opts


def ssr_construct(node: Proxy, group: str, remarks: str, server: str,
                  port: str, protocol: str, method: str, obfs: str,
                  password: str, obfs_param: str = "", proto_param: str = "",
                  udp=None, tfo=None, scv=None, underlying_proxy=""):
    common_construct(node, ProxyType.ShadowsocksR, group, remarks, server, port,
                     udp, tfo, scv, None, underlying_proxy)
    node.EncryptMethod = method
    node.Password = password
    node.Protocol = protocol
    node.ProtocolParam = proto_param
    node.OBFS = obfs
    node.OBFSParam = obfs_param


def vmess_construct(node: Proxy, group: str, remarks: str, add: str,
                    port: str, _type: str, uid: str, aid: str,
                    net: str, cipher: str, path: str, host: str,
                    edge: str, tls: str, sni: str,
                    alpn_list: List[str], udp=None, tfo=None,
                    scv=None, tls13=None, underlying_proxy=""):
    common_construct(node, ProxyType.VMess, group, remarks, add, port,
                     udp, tfo, scv, tls13, underlying_proxy)
    node.UserId = uid or "00000000-0000-0000-0000-000000000000"
    node.AlterId = int(aid) if aid else 0
    node.EncryptMethod = cipher
    node.TransferProtocol = net if net else "tcp"
    node.Edge = edge
    node.ServerName = sni
    node.AlpnList = alpn_list
    node.Path = path
    node.Host = host
    node.TLSStr = tls
    node.TLSSecure = (tls == "tls")


def vless_construct(node: Proxy, group: str, remarks: str, add: str,
                    port: str, _type: str, uid: str, aid: str,
                    net: str, cipher: str, flow: str, mode: str,
                    path: str, host: str, edge: str, tls: str,
                    pkd: str, sid: str, fp: str, sni: str,
                    alpn_list: List[str], packet_encoding: str,
                    encryption: str, udp=None, tfo=None,
                    scv=None, tls13=None, underlying_proxy="",
                    v2ray_http_upgrade=None):
    common_construct(node, ProxyType.VLESS, group, remarks, add, port,
                     udp, tfo, scv, tls13, underlying_proxy)
    node.UserId = uid or "00000000-0000-0000-0000-000000000000"
    node.EncryptMethod = encryption if encryption else cipher
    node.TransferProtocol = net if net else "tcp"
    node.Edge = edge
    node.ServerName = sni
    node.AlpnList = alpn_list
    node.Path = path
    node.Host = host
    node.TLSStr = tls
    node.Flow = flow
    node.FlowShow = bool(flow)
    if tls == "reality":
        node.Fingerprint = fp
        node.PublicKey = pkd
        node.ShortId = sid
    node.PacketEncoding = packet_encoding
    node.V2rayHttpUpgrade = v2ray_http_upgrade


def trojan_construct(node: Proxy, group: str, remarks: str, server: str,
                     port: str, password: str, network: str = "",
                     host: str = "", path: str = "", fp: str = "",
                     sni: str = "", alpn_list: List[str] = None,
                     tls_secure: bool = True, udp=None, tfo=None,
                     scv=None, tls13=None, underlying_proxy=""):
    common_construct(node, ProxyType.Trojan, group, remarks, server, port,
                     udp, tfo, scv, tls13, underlying_proxy)
    node.Password = password
    node.Host = host
    node.Path = path
    node.ServerName = sni or host
    node.AlpnList = alpn_list or []
    node.Fingerprint = fp
    node.TLSSecure = tls_secure
    if network:
        node.TransferProtocol = network


def socks_construct(node: Proxy, group: str, remarks: str, server: str,
                    port: str, username: str = "", password: str = "",
                    udp=None, tfo=None, scv=None, underlying_proxy=""):
    common_construct(node, ProxyType.SOCKS5, group, remarks, server, port,
                     udp, tfo, scv, None, underlying_proxy)
    node.Username = username
    node.Password = password


def http_construct(node: Proxy, group: str, remarks: str, server: str,
                   port: str, username: str = "", password: str = "",
                   tls: bool = False, tfo=None, scv=None, tls13=None,
                   underlying_proxy=""):
    ptype = ProxyType.HTTPS if tls else ProxyType.HTTP
    common_construct(node, ptype, group, remarks, server, port,
                     None, tfo, scv, tls13, underlying_proxy)
    node.Username = username
    node.Password = password
    node.TLSSecure = tls


def hysteria_construct(node: Proxy, group: str, remarks: str, add: str,
                       port: str, _type: str, auth: str, auth_str: str,
                       host: str, up: str, down: str, alpn: str,
                       obfs_param: str, insecure: str, ports: str,
                       sni: str, udp=None, tfo=None, scv=None,
                       tls13=None, underlying_proxy=""):
    common_construct(node, ProxyType.Hysteria, group, remarks, add, port,
                     udp, tfo, scv, tls13, underlying_proxy)
    node.AuthStr = auth_str
    node.Host = host
    node.UpMbps = up
    node.DownMbps = down
    node.Alpn = alpn
    node.OBFSParam = obfs_param
    node.Insecure = insecure
    node.Ports = ports
    node.ServerName = sni or add


def hysteria2_construct(node: Proxy, group: str, remarks: str, add: str,
                        port: str, password: str, host: str = "",
                        up: str = "", down: str = "", alpn: str = "",
                        obfs_param: str = "", obfs_password: str = "",
                        sni: str = "", public_key: str = "",
                        ports: str = "", udp=None, tfo=None,
                        scv=None, underlying_proxy=""):
    common_construct(node, ProxyType.Hysteria2, group, remarks, add, port,
                     udp, tfo, scv, None, underlying_proxy)
    node.Password = password
    node.Host = host
    node.UpMbps = up
    node.DownMbps = down
    node.Alpn = alpn
    node.OBFSParam = obfs_param
    node.OBFSPassword = obfs_password
    node.ServerName = sni or add
    node.Auth = public_key
    node.Ports = ports


def tuic_construct(node: Proxy, group: str, remarks: str, add: str,
                   port: str, password: str, congestion_control: str = "",
                   alpn: str = "", sni: str = "", uuid: str = "",
                   udp_relay_mode: str = "native", token: str = "",
                   udp=None, tfo=None, scv=None, reduce_rtt=None,
                   disable_sni=None, request_timeout: int = 15000,
                   underlying_proxy=""):
    common_construct(node, ProxyType.TUIC, group, remarks, add, port,
                     udp, tfo, scv, None, underlying_proxy)
    node.Password = password
    node.CongestionControl = congestion_control
    node.Alpn = alpn
    node.ServerName = sni or add
    node.UdpRelayMode = udp_relay_mode
    node.token = token
    node.ReduceRtt = reduce_rtt
    node.DisableSni = disable_sni
    node.RequestTimeout = request_timeout
