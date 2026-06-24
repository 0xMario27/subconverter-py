"""Proxy link parser - ported from parser/subparser.cpp.

Handles parsing of various proxy formats:
- SS (Shadowsocks): ss://
- SSR (ShadowsocksR): ssr://
- VMess: vmess://
- Trojan: trojan://
- VLESS: vless://
- Hysteria / Hysteria2: hysteria://, hysteria2://
- TUIC: tuic://
- HTTP/SOCKS: http://, socks5://, https://
- Snell: snell://
- AnyTLS: anytls://
- Mieru: mieru://
- Clash subscriptions (base64 encoded)
- Surge/Quantumult configs
- SSD links
- Telegram-style links
"""

import re
import json
from typing import List, Optional, Tuple, Dict
from urllib.parse import parse_qs, urlparse, unquote

from ..config.models import Proxy, ProxyType, DEFAULT_GROUPS
from ..utils.base64_util import base64_decode, url_safe_base64_decode
from ..utils.url_util import url_decode, get_url_arg
from ..utils.string_util import (
    split, starts_with, ends_with, trim, remove_brackets,
    replace_all, str_find, is_link, file_exist, file_get
)
from ..utils.network import web_get
from ..utils.logger import write_log, LOG_LEVEL_INFO, LOG_LEVEL_WARNING, LOG_LEVEL_ERROR

# Cipher lists
SS_CIPHERS = [
    "rc4-md5", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
    "bf-cfb", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "salsa20", "chacha20", "chacha20-ietf",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "2022-blake3-chacha12-poly1305",
    "2022-blake3-chacha8-poly1305"
]

SSR_CIPHERS = SS_CIPHERS + [
    "none", "table", "rc4", "cast5-cfb", "des-cfb",
    "idea-cfb", "rc2-cfb", "seed-cfb"
]


def _common_construct(node: Proxy, ptype: ProxyType, group: str, remarks: str,
                      server: str, port: str, udp=None, tfo=None, scv=None,
                      tls13=None, underlying_proxy=""):
    """Common proxy node construction."""
    node.Type = ptype
    node.Group = group
    node.Remark = remarks
    node.Hostname = remove_brackets(server)
    node.Port = int(port) if port else 0
    node.UDP = udp
    node.TCPFastOpen = tfo
    node.AllowInsecure = scv
    node.TLS13 = tls13
    node.UnderlyingProxy = underlying_proxy


def _parse_url_alpn_list(addition: str) -> List[str]:
    """Parse ALPN list from URL params."""
    alpn_str = get_url_arg(addition, "alpn")
    if not alpn_str:
        return []
    return [trim(a) for a in split(alpn_str, ",") if trim(a)]


# ==================== Proxy Constructors ====================

def ss_construct(node: Proxy, group: str, remarks: str, server: str,
                 port: str, password: str, method: str,
                 plugin: str = "", plugin_opts: str = "",
                 udp=None, tfo=None, scv=None, tls13=None,
                 underlying_proxy=""):
    """Construct a Shadowsocks node."""
    _common_construct(node, ProxyType.Shadowsocks, group, remarks, server, port,
                      udp, tfo, scv, tls13, underlying_proxy)
    node.EncryptMethod = method
    node.Password = password
    node.Plugin = plugin
    node.PluginOption = plugin_opts


def ssr_construct(node: Proxy, group: str, remarks: str, server: str,
                  port: str, protocol: str, method: str, obfs: str,
                  password: str, obfs_param: str = "", proto_param: str = "",
                  udp=None, tfo=None, scv=None, underlying_proxy=""):
    """Construct a ShadowsocksR node."""
    _common_construct(node, ProxyType.ShadowsocksR, group, remarks, server, port,
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
    """Construct a VMess node."""
    _common_construct(node, ProxyType.VMess, group, remarks, add, port,
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
    """Construct a VLESS node."""
    _common_construct(node, ProxyType.VLESS, group, remarks, add, port,
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
    """Construct a Trojan node."""
    _common_construct(node, ProxyType.Trojan, group, remarks, server, port,
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
    """Construct a SOCKS5 node."""
    _common_construct(node, ProxyType.SOCKS5, group, remarks, server, port,
                      udp, tfo, scv, None, underlying_proxy)
    node.Username = username
    node.Password = password


def http_construct(node: Proxy, group: str, remarks: str, server: str,
                   port: str, username: str = "", password: str = "",
                   tls: bool = False, tfo=None, scv=None, tls13=None,
                   underlying_proxy=""):
    """Construct an HTTP/HTTPS node."""
    ptype = ProxyType.HTTPS if tls else ProxyType.HTTP
    _common_construct(node, ptype, group, remarks, server, port,
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
    """Construct a Hysteria node."""
    _common_construct(node, ProxyType.Hysteria, group, remarks, add, port,
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
    """Construct a Hysteria2 node."""
    _common_construct(node, ProxyType.Hysteria2, group, remarks, add, port,
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
    """Construct a TUIC node."""
    _common_construct(node, ProxyType.TUIC, group, remarks, add, port,
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


# ==================== Link Exploders ====================

def _extract_remark_from_link(link: str) -> Tuple[str, str]:
    """Extract #remark from link. Returns (link_without_remark, remark)."""
    remark = ""
    # Check for # at end
    pos = link.rfind("#")
    if pos != -1:
        remark = url_decode(link[pos + 1:])
        link = link[:pos]

    # Also check for # elsewhere (some clients put it before params)
    pos = link.find("#")
    if pos != -1:
        link = link[:pos]

    return link, remark


def explode_ss(ss: str, node: Proxy):
    """Parse Shadowsocks links: ss://method:password@server:port#remark and SIP002 URIs."""
    if starts_with(ss, "ss://"):
        ss = ss[5:]

    link, remark = _extract_remark_from_link(ss)

    if link.endswith("/") and not link.endswith("//"):
        link = link[:-1]

    # SIP002 / base64-encoded format detection:
    # - If no '@' anywhere: fully base64 encoded (old format)
    # - If '?' present: SIP002 with query params (base64 before @)
    # - If '@' present and no '?': could be SIP002 (base64 userinfo) or plain text
    at_pos = link.rfind('@')

    if at_pos == -1 or '?' in link:
        # Fully base64 encoded or SIP002 with params
        # Try base64 decode of the whole thing or the part before ?
        b64_part = link
        extra = ""
        qpos = link.find('?')
        if qpos != -1:
            b64_part = link[:qpos]
            extra = link[qpos:]

        decoded = base64_decode(b64_part)
        if not decoded:
            decoded = url_safe_base64_decode(b64_part)
        if not decoded:
            return

        # Parse method:password@server:port
        at_pos2 = decoded.rfind('@')
        if at_pos2 == -1:
            return

        userinfo = decoded[:at_pos2]
        hostport = decoded[at_pos2 + 1:]

        colon_pos = userinfo.find(':')
        if colon_pos == -1:
            return
        method = userinfo[:colon_pos]
        password = userinfo[colon_pos + 1:]

        # Parse hostport
        colon_pos2 = hostport.rfind(':')
        if colon_pos2 != -1:
            server = hostport[:colon_pos2]
            if server.endswith(']'):
                server = server[1:-1]
            port = hostport[colon_pos2 + 1:]
        else:
            server = hostport
            port = "8388"

        # Parse extra params
        plugin = ""
        plugin_opts = ""
        if extra:
            plugin_params = urllib.parse.parse_qs(extra)
            plugin_val = plugin_params.get('plugin', [''])[0]
            if plugin_val:
                plugin_parts = plugin_val.split(';')
                if plugin_parts:
                    plugin = trim(plugin_parts[0])
                    if len(plugin_parts) > 1:
                        plugin_opts = trim(plugin_parts[1])

        ss_construct(node, DEFAULT_GROUPS[ProxyType.Shadowsocks], remark or server,
                     server, port, password, method, plugin, plugin_opts)
        return

    # Has '@' and no '?' - try base64 decoding the userinfo part
    userinfo_b64 = link[:at_pos]
    hostport = link[at_pos + 1:]

    # Try base64 decode
    decoded_userinfo = base64_decode(userinfo_b64)
    if not decoded_userinfo:
        decoded_userinfo = url_safe_base64_decode(userinfo_b64)

    if decoded_userinfo and ':' in decoded_userinfo:
        # SIP002 style with base64-encoded userinfo
        colon_pos = decoded_userinfo.find(':')
        method = decoded_userinfo[:colon_pos]
        password = decoded_userinfo[colon_pos + 1:]
    else:
        # Plain text: method:password@server:port
        colon_pos = userinfo_b64.find(':')
        if colon_pos == -1:
            return
        method = userinfo_b64[:colon_pos]
        password = userinfo_b64[colon_pos + 1:]

    colon_pos2 = hostport.rfind(':')
    if colon_pos2 != -1:
        server = hostport[:colon_pos2]
        port = hostport[colon_pos2 + 1:]
    else:
        server = hostport
        port = "8388"

    ss_construct(node, DEFAULT_GROUPS[ProxyType.Shadowsocks], remark or server,
                 server, port, password, method)


def explode_ssr(ssr: str, node: Proxy):
    """Parse ShadowsocksR links: ssr://base64(server:port:protocol:method:obfs:base64password/?params)"""
    if starts_with(ssr, "ssr://"):
        ssr = ssr[5:]

    link, remark = _extract_remark_from_link(ssr)

    # Base64 decode
    decoded = base64_decode(link)
    if not decoded:
        decoded = url_safe_base64_decode(link)
    if not decoded:
        return

    # Format: server:port:protocol:method:obfs:password_base64/?params...
    params_pos = decoded.find('/')
    params = ""
    main_part = decoded
    if params_pos != -1:
        main_part = decoded[:params_pos]
        params = decoded[params_pos + 1:]

    parts = main_part.split(':')
    if len(parts) < 6:
        return

    server = parts[0]
    port = parts[1]
    protocol = parts[2]
    method = parts[3]
    obfs = parts[4]
    password_b64 = parts[5]
    password = base64_decode(password_b64) or url_safe_base64_decode(password_b64) or password_b64

    # Parse params
    obfs_param = ""
    proto_param = ""
    group = DEFAULT_GROUPS[ProxyType.ShadowsocksR]

    if params:
        pairs = params.split('&')
        for pair in pairs:
            if '=' in pair:
                k, v = pair.split('=', 1)
                v = url_decode(v)
                if k == 'obfsparam':
                    obfs_param = base64_decode(v) or url_safe_base64_decode(v) or v
                elif k == 'protoparam':
                    proto_param = base64_decode(v) or url_safe_base64_decode(v) or v
                elif k == 'group':
                    group = base64_decode(v) or url_safe_base64_decode(v) or v

    ssr_construct(node, group, remark or server, server, port,
                  protocol, method, obfs, password, obfs_param, proto_param)


def explode_vmess_str(vmess: str, node: Proxy):
    """
    Parse VMess (v2rayN) links: vmess://base64(json)
    The JSON has keys: v, ps, add, port, type, id, aid, net, path, host, tls, sni, alpn, etc.
    """
    if starts_with(vmess, "vmess://"):
        vmess = vmess[8:]

    link, remark = _extract_remark_from_link(vmess)

    decoded = base64_decode(link)
    if not decoded:
        decoded = url_safe_base64_decode(link)

    if not decoded:
        return

    # Parse JSON
    try:
        data = json.loads(decoded)
    except json.JSONDecodeError:
        try:
            # Try parsing manually
            data = _manual_vmess_parse(decoded)
        except Exception:
            return

    if not isinstance(data, dict):
        return

    ps = data.get('ps', data.get('remarks', remark))
    add = data.get('add', '')
    port = str(data.get('port', '0'))
    _type = data.get('type', 'none')
    uid = data.get('id', '')
    aid = str(data.get('aid', '0'))
    net = data.get('net', 'tcp')
    cipher = data.get('cipher', data.get('scy', 'auto'))
    path = data.get('path', '')
    host = data.get('host', '')
    edge = data.get('edge', '')
    tls = data.get('tls', '')
    sni = data.get('sni', '')
    alpn_str = data.get('alpn', '')
    alpn_list = [trim(a) for a in split(alpn_str, ",") if trim(a)]
    fp = data.get('fp', '')

    vmess_construct(node, DEFAULT_GROUPS[ProxyType.VMess], ps or remark, add,
                    port, _type, uid, aid, net, cipher, path, host,
                    edge, tls, sni, alpn_list,
                    tls13=(fp == 'tls13' or None))


def _manual_vmess_parse(s: str) -> dict:
    """Fallback parser for malformed VMess JSON strings."""
    result = {}
    pattern = r'"([^"]+)"\s*:\s*"([^"]*)"'
    matches = re.findall(pattern, s)
    for k, v in matches:
        result[k] = v
    return result


def explode_trojan(trojan: str, node: Proxy):
    """Parse Trojan links: trojan://password@server:port?params#remark"""
    if starts_with(trojan, "trojan://"):
        trojan = trojan[9:]

    link, remark = _extract_remark_from_link(trojan)

    # Find password and server:port
    at_pos = link.rfind('@')
    if at_pos == -1:
        return

    password = url_decode(link[:at_pos])
    hostport = link[at_pos + 1:]

    params_pos = hostport.find('?')
    params = ""
    if params_pos != -1:
        params = hostport[params_pos + 1:]
        hostport = hostport[:params_pos]

    colon_pos = hostport.rfind(':')
    if colon_pos != -1:
        server = hostport[:colon_pos]
        port = hostport[colon_pos + 1:]
    else:
        server = hostport
        port = "443"

    # Parse params
    sni = get_url_arg(params, "sni") or server
    alpn = get_url_arg(params, "alpn")
    fp = get_url_arg(params, "fp") or get_url_arg(params, "fingerprint")
    _type = get_url_arg(params, "type")
    host = get_url_arg(params, "host")
    path = get_url_arg(params, "path")
    security = get_url_arg(params, "security") or "tls"
    allow_insecure = get_url_arg(params, "allowInsecure")

    alpn_list = [trim(a) for a in split(alpn, ",") if trim(a)]

    scv = (allow_insecure == "1") if allow_insecure else None
    trojan_construct(node, DEFAULT_GROUPS[ProxyType.Trojan], remark or server,
                     server, port, password, network=_type, host=host,
                     path=path, fp=fp, sni=sni, alpn_list=alpn_list,
                     tls_secure=(security != "none"), scv=scv)


def explode_vless(vless: str, node: Proxy):
    """Parse VLESS links: vless://uuid@server:port?params#remark"""
    if starts_with(vless, "vless://"):
        vless = vless[8:]

    link, remark = _extract_remark_from_link(vless)

    at_pos = link.rfind('@')
    if at_pos == -1:
        return

    uid = link[:at_pos]
    hostport = link[at_pos + 1:]

    params_pos = hostport.find('?')
    params = ""
    if params_pos != -1:
        params = hostport[params_pos + 1:]
        hostport = hostport[:params_pos]

    colon_pos = hostport.rfind(':')
    if colon_pos != -1:
        server = hostport[:colon_pos]
        port = hostport[colon_pos + 1:]
    else:
        server = hostport
        port = "443"

    # Parse VLESS params
    _type = get_url_arg(params, "type") or "tcp"
    security = get_url_arg(params, "security") or "none"
    encryption = get_url_arg(params, "encryption") or "none"
    path = get_url_arg(params, "path") or "/"
    host = get_url_arg(params, "host") or ""
    sni = get_url_arg(params, "sni") or host or server
    fp = get_url_arg(params, "fp") or get_url_arg(params, "fingerprint") or ""
    flow = get_url_arg(params, "flow") or ""
    alpn = get_url_arg(params, "alpn")
    alpn_list = [trim(a) for a in split(alpn, ",") if trim(a)]
    pbk = get_url_arg(params, "pbk") or ""
    sid = get_url_arg(params, "sid") or ""
    spx = get_url_arg(params, "spx") or ""
    mode = get_url_arg(params, "mode") or ""

    vless_construct(node, DEFAULT_GROUPS[ProxyType.VLESS], remark or server,
                    server, port, _type, uid, "0", _type, "", flow, mode,
                    path, host, "", security, pbk, sid, fp, sni,
                    alpn_list, spx, encryption)


def explode_hysteria(hysteria: str, node: Proxy):
    """Parse Hysteria links: hysteria://host:port?params#remark"""
    if starts_with(hysteria, "hysteria://"):
        hysteria = hysteria[11:]

    link, remark = _extract_remark_from_link(hysteria)

    hostport = link
    params_pos = hostport.find('?')
    params = ""
    if params_pos != -1:
        params = hostport[params_pos + 1:]
        hostport = hostport[:params_pos]

    colon_pos = hostport.rfind(':')
    if colon_pos != -1:
        server = hostport[:colon_pos]
        port = hostport[colon_pos + 1:]
    else:
        server = hostport
        port = "443"

    # Parse params
    protocol = get_url_arg(params, "protocol") or "udp"
    auth = get_url_arg(params, "auth")
    peer = get_url_arg(params, "peer") or server
    up = get_url_arg(params, "upmbps") or get_url_arg(params, "up")
    down = get_url_arg(params, "downmbps") or get_url_arg(params, "down")
    alpn = get_url_arg(params, "alpn") or ""
    obfs_param = get_url_arg(params, "obfsParam") or get_url_arg(params, "obfs")
    insecure = get_url_arg(params, "insecure")

    scv = (insecure == "1") if insecure else None
    hysteria_construct(node, DEFAULT_GROUPS[ProxyType.Hysteria], remark or server,
                       server, port, protocol, auth, auth, peer,
                       up, down, alpn, obfs_param, insecure, "",
                       peer, scv=scv)


def explode_hysteria2(hysteria2: str, node: Proxy):
    """Parse Hysteria2 links: hysteria2://password@host:port?params#remark"""
    if starts_with(hysteria2, "hysteria2://"):
        hysteria2 = hysteria2[12:]

    link, remark = _extract_remark_from_link(hysteria2)

    at_pos = link.rfind('@')
    password = ""
    hostport = link

    if at_pos != -1:
        password = url_decode(link[:at_pos])
        hostport = link[at_pos + 1:]

    params_pos = hostport.find('?')
    params = ""
    if params_pos != -1:
        params = hostport[params_pos + 1:]
        hostport = hostport[:params_pos]

    colon_pos = hostport.rfind(':')
    if colon_pos != -1:
        server = hostport[:colon_pos]
        port = hostport[colon_pos + 1:]
    else:
        server = hostport
        port = "443"

    sni = get_url_arg(params, "sni") or server
    alpn_str = get_url_arg(params, "alpn") or ""
    obfs_param = get_url_arg(params, "obfs") or ""
    obfs_password = get_url_arg(params, "obfs-password") or ""
    insecure = get_url_arg(params, "insecure")

    scv = (insecure == "1") if insecure else None
    hysteria2_construct(node, DEFAULT_GROUPS[ProxyType.Hysteria2],
                        remark or server, server, port, password,
                        sni, "", "", alpn_str, obfs_param,
                        obfs_password, sni, "", "", scv=scv)


def explode_tuic(tuic: str, node: Proxy):
    """Parse TUIC links: tuic://uuid:password@host:port?params#remark"""
    if starts_with(tuic, "tuic://"):
        tuic = tuic[7:]

    link, remark = _extract_remark_from_link(tuic)

    at_pos = link.rfind('@')
    if at_pos == -1:
        return

    userinfo = link[:at_pos]
    hostport = link[at_pos + 1:]

    # Parse uuid:password
    colon_pos = userinfo.find(':')
    uuid = userinfo[:colon_pos] if colon_pos != -1 else userinfo
    password = userinfo[colon_pos + 1:] if colon_pos != -1 else ""

    params_pos = hostport.find('?')
    params = ""
    if params_pos != -1:
        params = hostport[params_pos + 1:]
        hostport = hostport[:params_pos]

    colon_pos2 = hostport.rfind(':')
    if colon_pos2 != -1:
        server = hostport[:colon_pos2]
        port = hostport[colon_pos2 + 1:]
    else:
        server = hostport
        port = "443"

    cc = get_url_arg(params, "congestion_control") or "cubic"
    alpn = get_url_arg(params, "alpn") or ""
    sni = get_url_arg(params, "sni") or server

    tuic_construct(node, DEFAULT_GROUPS[ProxyType.TUIC], remark or server,
                   server, port, password, cc, alpn, sni, uuid)


def explode_socks(socks: str, node: Proxy):
    """Parse SOCKS5 links: socks5://user:pass@server:port#remark"""
    for prefix, tls in [("socks5://", False), ("socks://", False)]:
        if starts_with(socks, prefix):
            real = socks[len(prefix):]
            break
    else:
        return

    link, remark = _extract_remark_from_link(real)

    at_pos = link.rfind('@')
    username = ""
    password = ""
    hostport = link

    if at_pos != -1:
        userinfo = link[:at_pos]
        hostport = link[at_pos + 1:]
        colon_pos = userinfo.find(':')
        if colon_pos != -1:
            username = url_decode(userinfo[:colon_pos])
            password = url_decode(userinfo[colon_pos + 1:])
        else:
            username = url_decode(userinfo)

    colon_pos = hostport.rfind(':')
    if colon_pos != -1:
        server = hostport[:colon_pos]
        port = hostport[colon_pos + 1:]
    else:
        server = hostport
        port = "1080"

    socks_construct(node, DEFAULT_GROUPS[ProxyType.SOCKS5], remark or server,
                    server, port, username, password)


def explode_http_link(http: str, node: Proxy):
    """Parse HTTP/HTTPS proxy links."""
    tls = False
    if starts_with(http, "https://"):
        real = http[8:]
        tls = True
    elif starts_with(http, "http://"):
        real = http[7:]
    else:
        return

    link, remark = _extract_remark_from_link(real)

    at_pos = link.rfind('@')
    username = ""
    password = ""
    hostport = link

    if at_pos != -1:
        userinfo = link[:at_pos]
        hostport = link[at_pos + 1:]
        colon_pos = userinfo.find(':')
        if colon_pos != -1:
            username = url_decode(userinfo[:colon_pos])
            password = url_decode(userinfo[colon_pos + 1:])
        else:
            username = url_decode(userinfo)

    colon_pos = hostport.rfind(':')
    if colon_pos != -1:
        server = hostport[:colon_pos]
        port = hostport[colon_pos + 1:]
    else:
        server = hostport
        port = "8080"

    group = DEFAULT_GROUPS[ProxyType.HTTPS if tls else ProxyType.HTTP]
    http_construct(node, group, remark or server, server, port,
                   username, password, tls)


def explode_snell(snell: str, node: Proxy):
    """Parse Snell links: snell://password@server:port?params#remark"""
    if starts_with(snell, "snell://"):
        snell = snell[8:]

    link, remark = _extract_remark_from_link(snell)

    at_pos = link.rfind('@')
    if at_pos == -1:
        return

    password = url_decode(link[:at_pos])
    hostport = link[at_pos + 1:]

    params_pos = hostport.find('?')
    params = ""
    if params_pos != -1:
        params = hostport[params_pos + 1:]
        hostport = hostport[:params_pos]

    colon_pos = hostport.rfind(':')
    if colon_pos != -1:
        server = hostport[:colon_pos]
        port = hostport[colon_pos + 1:]
    else:
        server = hostport
        port = "8388"

    obfs = get_url_arg(params, "obfs") or ""
    host = get_url_arg(params, "host") or ""
    version = get_url_arg(params, "version") or "0"

    # Construct as Snell
    _common_construct(node, ProxyType.Snell, DEFAULT_GROUPS[ProxyType.Snell],
                      remark or server, server, port)
    node.Password = password
    node.OBFS = obfs
    node.Host = host
    node.SnellVersion = int(version) if version.isdigit() else 0


def explode_wireguard(wg: str, node: Proxy):
    """Parse WireGuard links: wireguard://..."""
    if starts_with(wg, "wireguard://"):
        wg = wg[12:]

    link, remark = _extract_remark_from_link(wg)

    params_pos = link.find('?')
    params = ""
    endpoint_part = link
    if params_pos != -1:
        params = link[params_pos + 1:]
        endpoint_part = link[:params_pos]

    # Parse params
    private_key = get_url_arg(params, "privateKey") or ""
    public_key = get_url_arg(params, "publicKey") or ""
    psk = get_url_arg(params, "presharedKey") or ""
    dns = get_url_arg(params, "dns") or ""
    mtu = get_url_arg(params, "mtu") or "0"
    address = get_url_arg(params, "address") or ""

    node.Type = ProxyType.WireGuard
    node.Group = DEFAULT_GROUPS[ProxyType.WireGuard]
    node.Remark = remark
    node.PrivateKey = private_key
    node.PublicKey = public_key
    node.PrivateKey = private_key
    node.PreSharedKey = psk
    node.DnsServers = [trim(d) for d in split(dns, ",") if trim(d)]
    node.Mtu = int(mtu) if mtu.isdigit() else 0
    self_ips = [trim(a) for a in split(address, ",") if trim(a)]
    if self_ips:
        node.SelfIP = self_ips[0]
        if len(self_ips) > 1:
            node.SelfIPv6 = self_ips[1]

    # Parse endpoint from endpoint_part
    colon_pos = endpoint_part.rfind(':')
    if colon_pos != -1:
        node.Hostname = endpoint_part[:colon_pos]
        node.Port = int(endpoint_part[colon_pos + 1:]) if endpoint_part[colon_pos + 1:].isdigit() else 51820


def explode_tg(tg: str, node: Proxy):
    """Parse Telegram-style links: tg://http?server=... or tg://socks?server=..."""
    tg_lower = tg.lower()
    for prefix in ['tg://http?', 'tg://socks?']:
        if starts_with(tg_lower, prefix):
            params = tg[len(prefix):]
            break
    else:
        return

    server = get_url_arg(params, "server")
    port = get_url_arg(params, "port")
    user = get_url_arg(params, "user")
    _pass = get_url_arg(params, "pass")
    remark = get_url_arg(params, "remark")

    if not server or not port:
        return

    if tg_lower.startswith("tg://socks?"):
        socks_construct(node, remark or server, remark or server,
                        server, port, user, _pass)
    else:
        http_construct(node, remark or server, remark or server,
                       server, port, user, _pass)


# ==================== Main Exploder ====================

def explode(link: str, node: Proxy) -> bool:
    """
    Parse a single proxy link and populate the node.
    Returns True if successful.
    """
    link_lower = link.lower()

    if link_lower.startswith("ss://"):
        explode_ss(link, node)
    elif link_lower.startswith("ssr://"):
        explode_ssr(link, node)
    elif link_lower.startswith("vmess://"):
        explode_vmess_str(link, node)
    elif link_lower.startswith("trojan://"):
        explode_trojan(link, node)
    elif link_lower.startswith("vless://"):
        explode_vless(link, node)
    elif link_lower.startswith("hysteria://"):
        explode_hysteria(link, node)
    elif link_lower.startswith("hysteria2://"):
        explode_hysteria2(link, node)
    elif link_lower.startswith("tuic://"):
        explode_tuic(link, node)
    elif link_lower.startswith("snell://"):
        explode_snell(link, node)
    elif link_lower.startswith("wireguard://"):
        explode_wireguard(link, node)
    elif link_lower.startswith("socks5://") or link_lower.startswith("socks://"):
        explode_socks(link, node)
    elif link_lower.startswith("https://") or link_lower.startswith("http://"):
        explode_http_link(link, node)
    elif link_lower.startswith("tg://"):
        explode_tg(link, node)
    elif link_lower.startswith("anytls://"):
        # AnyTLS - simple handler (fully parse if needed)
        _common_construct(node, ProxyType.AnyTLS, DEFAULT_GROUPS[ProxyType.AnyTLS],
                          "", "", "0")
    elif link_lower.startswith("mieru://"):
        _common_construct(node, ProxyType.Mieru, DEFAULT_GROUPS[ProxyType.Mieru],
                          "", "", "0")
    else:
        return False

    return node.Type != ProxyType.Unknown


def explode_sub(content: str, nodes: List[Proxy], default_group: str = "") -> int:
    """
    Parse subscription content (base64-encoded list of links).
    Returns number of nodes parsed.
    """
    # Try to decode as base64
    decoded = base64_decode(content)
    if not decoded:
        return 0

    links = decoded.strip().split('\n')
    count = 0

    for line in links:
        line = trim(line)
        if not line or line.startswith(';') or line.startswith('#') or line.startswith('//'):
            continue

        # Skip HTML tags
        if line.startswith('<') and line.endswith('>'):
            continue

        node = Proxy()
        if line.startswith("ssd://"):
            # SSD (ShadowsocksD) - batch of SS links
            nodes_from_ssd = _explode_ssd(line, default_group)
            nodes.extend(nodes_from_ssd)
            count += len(nodes_from_ssd)
        elif explode(line, node):
            if default_group:
                node.Group = default_group
            nodes.append(node)
            count += 1

    return count


def _explode_ssd(ssd_link: str, default_group: str = "") -> List[Proxy]:
    """Parse SSD links: ssd://base64..."""
    if starts_with(ssd_link, "ssd://"):
        ssd_link = ssd_link[6:]

    decoded = base64_decode(ssd_link)
    if not decoded:
        return []

    # Parse SSD: the format is server:port:method:password per line
    nodes = []
    lines = decoded.strip().split('\n')
    for line in lines:
        line = trim(line)
        if not line:
            continue
        parts = line.split(':')
        if len(parts) >= 4:
            node = Proxy()
            ss_construct(node, default_group or DEFAULT_GROUPS[ProxyType.Shadowsocks],
                         parts[0], parts[0], parts[1], parts[3], parts[2])
            nodes.append(node)

    return nodes


def explode_clash_sub(content: str, nodes: List[Proxy], default_group: str = "") -> int:
    """
    Parse a Clash YAML subscription content and extract proxies.
    Returns number of nodes parsed.
    """
    import yaml
    try:
        config = yaml.safe_load(content)
        if not config or not isinstance(config, dict):
            return 0
    except yaml.YAMLError:
        return 0

    count = 0
    proxies = config.get('proxies', config.get('Proxy', []))
    if not proxies:
        return 0

    for proxy_item in proxies:
        if not isinstance(proxy_item, dict):
            continue
        node = _parse_clash_proxy(proxy_item, default_group)
        if node:
            nodes.append(node)
            count += 1

    return count


def _parse_clash_proxy(proxy: dict, default_group: str = "") -> Optional[Proxy]:
    """Parse a single Clash proxy object into a Proxy node."""
    ptype = proxy.get('type', '').lower()
    name = proxy.get('name', '')
    server = proxy.get('server', '')
    port = str(proxy.get('port', '0'))
    group = default_group or proxy.get('group', '')

    node = Proxy()
    node.Remark = name
    node.Hostname = server
    node.Port = int(port) if port else 0
    node.Group = group

    if ptype == 'ss':
        node.Type = ProxyType.Shadowsocks
        node.EncryptMethod = proxy.get('cipher', '')
        node.Password = proxy.get('password', '')
        node.Plugin = proxy.get('plugin', '')
        node.PluginOption = proxy.get('plugin-opts', '') if proxy.get('plugin-opts') else ''
        node.UDP = proxy.get('udp', None)
    elif ptype == 'ssr':
        node.Type = ProxyType.ShadowsocksR
        node.EncryptMethod = proxy.get('cipher', '')
        node.Password = proxy.get('password', '')
        node.Protocol = proxy.get('protocol', '')
        node.ProtocolParam = proxy.get('protocol-param', '')
        node.OBFS = proxy.get('obfs', '')
        node.OBFSParam = proxy.get('obfs-param', '')
    elif ptype == 'vmess':
        node.Type = ProxyType.VMess
        node.UserId = proxy.get('uuid', '')
        node.AlterId = proxy.get('alterId', 0)
        node.EncryptMethod = proxy.get('cipher', 'auto')
        node.TransferProtocol = proxy.get('network', 'tcp')
        node.Path = proxy.get('ws-path', '') or proxy.get('path', '')
        node.Host = proxy.get('ws-headers', {}).get('Host', '') if isinstance(proxy.get('ws-headers'), dict) else ''
        node.TLSStr = proxy.get('tls', '') and 'tls' or ''
        node.ServerName = proxy.get('servername', '') or proxy.get('sni', '')
        node.Fingerprint = proxy.get('fp', '')
    elif ptype == 'trojan':
        node.Type = ProxyType.Trojan
        node.Password = proxy.get('password', '')
        node.ServerName = proxy.get('sni', server)
        node.Host = proxy.get('sni', '')
        node.Path = proxy.get('ws-path', '')
    elif ptype == 'vless':
        node.Type = ProxyType.VLESS
        node.UserId = proxy.get('uuid', '')
        node.TransferProtocol = proxy.get('network', 'tcp')
    elif ptype == 'hysteria':
        node.Type = ProxyType.Hysteria
        node.AuthStr = proxy.get('auth_str', '') or proxy.get('auth', '')
        node.ServerName = proxy.get('sni', server)
    elif ptype == 'hysteria2':
        node.Type = ProxyType.Hysteria2
        node.Password = proxy.get('password', '')
        node.ServerName = proxy.get('sni', server)
    elif ptype == 'http':
        node.Type = ProxyType.HTTP
        node.Username = proxy.get('username', '')
        node.Password = proxy.get('password', '')
    elif ptype == 'socks5':
        node.Type = ProxyType.SOCKS5
        node.Username = proxy.get('username', '')
        node.Password = proxy.get('password', '')
    elif ptype == 'anytls':
        node.Type = ProxyType.AnyTLS
        node.Password = proxy.get('password', '')
        node.ServerName = proxy.get('servername', '') or proxy.get('sni', server)
        node.TransferProtocol = proxy.get('network', 'tcp')
    elif ptype == 'tuic':
        node.Type = ProxyType.TUIC
        node.UserId = proxy.get('uuid', '')
        node.Password = proxy.get('password', '')
        node.ServerName = proxy.get('sni', server) or proxy.get('servername', '')
        node.CongestionControl = proxy.get('congestion-controller', '')
    elif ptype == 'snell':
        node.Type = ProxyType.Snell
        node.Password = proxy.get('password', '')
        node.Host = proxy.get('sni', '') or proxy.get('host', '')
        node.OBFS = proxy.get('obfs', '')
    elif ptype == 'mieru':
        node.Type = ProxyType.Mieru
        node.Password = proxy.get('password', '')
        node.Username = proxy.get('username', '')
    else:
        # Unknown type - still create a basic node so it can pass through
        # Some targets can handle unknown types if we just carry the data
        node.Type = ProxyType.Unknown
        # Store generic fields for passthrough
        if proxy.get('password'):
            node.Password = str(proxy.get('password', ''))
        if proxy.get('username'):
            node.Username = str(proxy.get('username', ''))
        if proxy.get('uuid'):
            node.UserId = str(proxy.get('uuid', ''))

    return node if node.Type != ProxyType.Unknown else None


# ==================== Subscription Parsing ====================

def add_nodes(link: str, all_nodes: List[Proxy], group_id: int,
              proxy: str = "", exclude_remarks: List[str] = None,
              include_remarks: List[str] = None,
              sub_info: Dict = None) -> int:
    """
    Fetch and parse a subscription URL or local file.
    Returns count of nodes added, or -1 on failure.
    """
    import re as re_module

    link = replace_all(link, '"', '')

    if not link:
        return 0

    # Determine type and fetch content
    content = ""
    link_type = "url"

    if is_link(link):
        write_log(0, f"Fetching subscription from URL: {link}", LOG_LEVEL_INFO)
        content = web_get(link, proxy or _get_proxy_subscription(), cache_ttl=3600)
    elif file_exist(link):
        write_log(0, f"Reading subscription from file: {link}", LOG_LEVEL_INFO)
        content = file_get(link)
    else:
        # Check if it's a direct proxy link
        node = Proxy()
        if explode(link, node):
            node.GroupId = group_id
            all_nodes.append(node)
            return 1

        # Try as base64-decoded subscription
        if starts_with(link, "https://") or starts_with(link, "http://"):
            content = web_get(link, proxy or _get_proxy_subscription(), cache_ttl=3600)
        else:
            write_log(0, f"Invalid link or file: {link}", LOG_LEVEL_WARNING)
            return -1

    if not content:
        write_log(0, f"Empty content from: {link}", LOG_LEVEL_WARNING)
        return -1

    # Check if it's a Clash subscription (YAML)
    if content.strip().startswith(('proxies:', 'Proxy:', '{')):
        header = content.strip()[:50].lower()
        if 'proxies' in header or 'proxy' in header:
            n = explode_clash_sub(content, all_nodes, str(group_id))
            for node in all_nodes[-n:]:
                node.GroupId = group_id
            return n if n > 0 else -1

    # Check for subscription info header
    if 'subscription-userinfo' in content.lower()[:200]:
        lines = content.split('\n')
        for line in lines:
            if 'subscription-userinfo' in line.lower():
                info = line.split(':', 1)[1].strip() if ':' in line else ''
                if sub_info is not None:
                    sub_info['info'] = info
        # Try to find actual proxy links after headers
        proxy_content = []
        for line in lines:
            line = trim(line)
            if line and not line.startswith('#') and not line.startswith('//'):
                if any(line.lower().startswith(p) for p in
                       ['ss://', 'ssr://', 'vmess://', 'trojan://', 'vless://',
                        'hysteria', 'tuic://', 'snell://', 'socks', 'http://',
                        'https://', 'ssd://']):
                    proxy_content.append(line)
        if proxy_content:
            content = '\n'.join(proxy_content)

    # Parse as subscription
    n = explode_sub(content, all_nodes, str(group_id))
    for node in all_nodes[-n:]:
        node.GroupId = group_id

    # Apply filters
    if exclude_remarks:
        all_nodes[:] = [n for n in all_nodes if
                        not any(re_module.search(pat, n.Remark)
                               for pat in exclude_remarks if pat)]
    if include_remarks:
        all_nodes[:] = [n for n in all_nodes if
                        not include_remarks or
                        any(re_module.search(pat, n.Remark)
                            for pat in include_remarks if pat)]

    return n if n > 0 else -1


def _get_proxy_subscription() -> str:
    """Get proxy for subscription fetching."""
    from ..config.settings import global_settings as gs
    if gs.proxy_subscription:
        return gs.proxy_subscription
    return ""
