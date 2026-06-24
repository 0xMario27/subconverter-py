"""Proxy link type parsers: SS, SSR, VMess, Trojan, VLESS, Hysteria, TUIC, etc."""

import re
import json
from typing import List, Optional, Tuple
from urllib.parse import parse_qs

from ..config.models import Proxy, ProxyType, DEFAULT_GROUPS
from ..utils.base64_util import base64_decode, url_safe_base64_decode
from ..utils.url_util import url_decode, get_url_arg
from ..utils.string_util import split, starts_with, trim
from .common import extract_remark, common_construct
from .constructors import (
    ss_construct, ssr_construct, vmess_construct, vless_construct,
    trojan_construct, socks_construct, http_construct,
    hysteria_construct, hysteria2_construct, tuic_construct
)


# ==================== SS (Shadowsocks) ====================

def explode_ss(ss: str, node: Proxy):
    """Parse SS links: ss://method:password@server:port#remark and SIP002 URIs."""
    if starts_with(ss, "ss://"):
        ss = ss[5:]

    link, remark = extract_remark(ss)

    if link.endswith("/") and not link.endswith("//"):
        link = link[:-1]

    at_pos = link.rfind('@')

    if at_pos == -1 or '?' in link:
        # Fully base64 encoded or SIP002 with params
        b64_part = link
        extra = ""
        qpos = link.find('?')
        if qpos != -1:
            b64_part = link[:qpos]
            extra = link[qpos:]

        decoded = base64_decode(b64_part) or url_safe_base64_decode(b64_part)
        if not decoded:
            return

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

        colon_pos2 = hostport.rfind(':')
        if colon_pos2 != -1:
            server = hostport[:colon_pos2]
            if server.endswith(']'):
                server = server[1:-1]
            port = hostport[colon_pos2 + 1:]
        else:
            server = hostport
            port = "8388"

        plugin = ""
        plugin_opts = ""
        if extra:
            import urllib.parse
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

    # Has '@' and no '?' - try base64 decoding userinfo
    userinfo_b64 = link[:at_pos]
    hostport = link[at_pos + 1:]

    decoded_userinfo = base64_decode(userinfo_b64) or url_safe_base64_decode(userinfo_b64)

    if decoded_userinfo and ':' in decoded_userinfo:
        colon_pos = decoded_userinfo.find(':')
        method = decoded_userinfo[:colon_pos]
        password = decoded_userinfo[colon_pos + 1:]
    else:
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


# ==================== SSR (ShadowsocksR) ====================

def explode_ssr(ssr: str, node: Proxy):
    """Parse SSR links: ssr://base64(server:port:protocol:method:obfs:password/?params)"""
    if starts_with(ssr, "ssr://"):
        ssr = ssr[5:]

    link, remark = extract_remark(ssr)
    decoded = base64_decode(link) or url_safe_base64_decode(link)
    if not decoded:
        return

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


# ==================== VMess ====================

def explode_vmess(vmess: str, node: Proxy):
    """Parse VMess links: vmess://base64(json)"""
    if starts_with(vmess, "vmess://"):
        vmess = vmess[8:]

    link, remark = extract_remark(vmess)
    decoded = base64_decode(link) or url_safe_base64_decode(link)
    if not decoded:
        return

    try:
        data = json.loads(decoded)
    except json.JSONDecodeError:
        data = _manual_vmess_parse(decoded)
        if not data:
            return

    ps = data.get('ps', data.get('remarks', remark))
    add = data.get('add', '')
    port = str(data.get('port', '0'))
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
                    port, 'none', uid, aid, net, cipher, path, host,
                    edge, tls, sni, alpn_list,
                    tls13=(fp == 'tls13' or None))


def _manual_vmess_parse(s: str) -> Optional[dict]:
    """Fallback parser for malformed VMess JSON strings."""
    result = {}
    pattern = r'"([^"]+)"\s*:\s*"([^"]*)"'
    matches = re.findall(pattern, s)
    for k, v in matches:
        result[k] = v
    return result if result else None


# ==================== Trojan ====================

def explode_trojan(trojan: str, node: Proxy):
    """Parse Trojan links: trojan://password@server:port?params#remark"""
    if starts_with(trojan, "trojan://"):
        trojan = trojan[9:]

    link, remark = extract_remark(trojan)

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


# ==================== VLESS ====================

def explode_vless(vless: str, node: Proxy):
    """Parse VLESS links: vless://uuid@server:port?params#remark"""
    if starts_with(vless, "vless://"):
        vless = vless[8:]

    link, remark = extract_remark(vless)

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

    _type = get_url_arg(params, "type") or "tcp"
    security = get_url_arg(params, "security") or "none"
    encryption = get_url_arg(params, "encryption") or "none"
    path = get_url_arg(params, "path") or "/"
    host = get_url_arg(params, "host") or ""
    sni = get_url_arg(params, "sni") or host or server
    fp = get_url_arg(params, "fp") or ""
    flow = get_url_arg(params, "flow") or ""
    alpn = get_url_arg(params, "alpn")
    alpn_list = [trim(a) for a in split(alpn, ",") if trim(a)]
    pbk = get_url_arg(params, "pbk") or ""
    sid = get_url_arg(params, "sid") or ""
    spx = get_url_arg(params, "spx") or ""

    vless_construct(node, DEFAULT_GROUPS[ProxyType.VLESS], remark or server,
                    server, port, _type, uid, "0", _type, "", flow, "",
                    path, host, "", security, pbk, sid, fp, sni,
                    alpn_list, spx, encryption)


# ==================== Hysteria / Hysteria2 ====================

def explode_hysteria(hysteria: str, node: Proxy):
    """Parse Hysteria links: hysteria://host:port?params#remark"""
    if starts_with(hysteria, "hysteria://"):
        hysteria = hysteria[11:]

    link, remark = extract_remark(hysteria)
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

    protocol = get_url_arg(params, "protocol") or "udp"
    auth = get_url_arg(params, "auth") or ""
    peer = get_url_arg(params, "peer") or server
    up = get_url_arg(params, "upmbps") or get_url_arg(params, "up") or ""
    down = get_url_arg(params, "downmbps") or get_url_arg(params, "down") or ""
    alpn = get_url_arg(params, "alpn") or ""
    obfs_param = get_url_arg(params, "obfsParam") or get_url_arg(params, "obfs") or ""
    insecure = get_url_arg(params, "insecure") or ""

    scv = (insecure == "1") if insecure else None
    hysteria_construct(node, DEFAULT_GROUPS[ProxyType.Hysteria], remark or server,
                       server, port, protocol, auth, auth, peer,
                       up, down, alpn, obfs_param, insecure, "",
                       peer, scv=scv)


def explode_hysteria2(hysteria2: str, node: Proxy):
    """Parse Hysteria2 links: hysteria2://password@host:port?params#remark"""
    if starts_with(hysteria2, "hysteria2://"):
        hysteria2 = hysteria2[12:]

    link, remark = extract_remark(hysteria2)

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
    insecure = get_url_arg(params, "insecure") or ""

    scv = (insecure == "1") if insecure else None
    hysteria2_construct(node, DEFAULT_GROUPS[ProxyType.Hysteria2],
                        remark or server, server, port, password,
                        sni, "", "", alpn_str, obfs_param,
                        obfs_password, sni, "", "", scv=scv)


# ==================== TUIC ====================

def explode_tuic(tuic: str, node: Proxy):
    """Parse TUIC links: tuic://uuid:password@host:port?params#remark"""
    if starts_with(tuic, "tuic://"):
        tuic = tuic[7:]

    link, remark = extract_remark(tuic)

    at_pos = link.rfind('@')
    if at_pos == -1:
        return

    userinfo = link[:at_pos]
    hostport = link[at_pos + 1:]

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


# ==================== SOCKS / HTTP / Snell / WireGuard / AnyTLS / Mieru / TG ====================

def explode_socks(socks: str, node: Proxy):
    """Parse SOCKS5 links: socks5://user:pass@server:port#remark"""
    for prefix, tls in [("socks5://", False), ("socks://", False)]:
        if starts_with(socks, prefix):
            real = socks[len(prefix):]
            break
    else:
        return

    link, remark = extract_remark(real)

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

    link, remark = extract_remark(real)

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

    link, remark = extract_remark(snell)

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

    common_construct(node, ProxyType.Snell, DEFAULT_GROUPS[ProxyType.Snell],
                     remark or server, server, port)
    node.Password = password
    node.OBFS = obfs
    node.Host = host
    node.SnellVersion = int(version) if version.isdigit() else 0


def explode_wireguard(wg: str, node: Proxy):
    """Parse WireGuard links: wireguard://..."""
    if starts_with(wg, "wireguard://"):
        wg = wg[12:]

    link, remark = extract_remark(wg)

    params_pos = link.find('?')
    params = ""
    endpoint_part = link
    if params_pos != -1:
        params = link[params_pos + 1:]
        endpoint_part = link[:params_pos]

    node.Type = ProxyType.WireGuard
    node.Group = DEFAULT_GROUPS[ProxyType.WireGuard]
    node.Remark = remark
    node.PrivateKey = get_url_arg(params, "privateKey") or ""
    node.PublicKey = get_url_arg(params, "publicKey") or ""
    node.PreSharedKey = get_url_arg(params, "presharedKey") or ""

    dns = get_url_arg(params, "dns") or ""
    node.DnsServers = [trim(d) for d in split(dns, ",") if trim(d)]
    mtu = get_url_arg(params, "mtu") or "0"
    node.Mtu = int(mtu) if mtu.isdigit() else 0

    address = get_url_arg(params, "address") or ""
    self_ips = [trim(a) for a in split(address, ",") if trim(a)]
    if self_ips:
        node.SelfIP = self_ips[0]
        if len(self_ips) > 1:
            node.SelfIPv6 = self_ips[1]

    colon_pos = endpoint_part.rfind(':')
    if colon_pos != -1:
        node.Hostname = endpoint_part[:colon_pos]
        node.Port = int(endpoint_part[colon_pos + 1:]) if endpoint_part[colon_pos + 1:].isdigit() else 51820


def explode_anytls(anytls: str, node: Proxy):
    """Parse AnyTLS links: anytls://password@server:port?params#remark"""
    if starts_with(anytls, "anytls://"):
        anytls = anytls[9:]

    link, remark = extract_remark(anytls)

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

    if hostport.endswith('/'):
        hostport = hostport[:-1]

    colon_pos = hostport.rfind(':')
    if colon_pos != -1:
        server = hostport[:colon_pos]
        port = hostport[colon_pos + 1:]
    else:
        server = hostport
        port = "443"

    sni = get_url_arg(params, "sni") or server
    fp = get_url_arg(params, "fp") or ""
    insecure = get_url_arg(params, "insecure") or ""
    scv = (insecure == "1") if insecure else None

    common_construct(node, ProxyType.AnyTLS, DEFAULT_GROUPS[ProxyType.AnyTLS],
                     remark or server, server, port, scv=scv)
    node.Password = password
    node.SNI = sni
    node.ServerName = sni
    node.Fingerprint = fp


def explode_mieru(mieru: str, node: Proxy):
    """Parse Mieru links: mieru://password@server:port?params#remark"""
    if starts_with(mieru, "mieru://"):
        mieru = mieru[8:]

    link, remark = extract_remark(mieru)

    at_pos = link.rfind('@')
    password = ""
    hostport = link
    if at_pos != -1:
        password = url_decode(link[:at_pos])
        hostport = link[at_pos + 1:]

    params_pos = hostport.find('?')
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
    username = get_url_arg(params, "username") or ""

    common_construct(node, ProxyType.Mieru, DEFAULT_GROUPS[ProxyType.Mieru],
                     remark or server, server, port)
    node.Password = password
    node.Username = username
    node.SNI = sni
    node.ServerName = sni


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
