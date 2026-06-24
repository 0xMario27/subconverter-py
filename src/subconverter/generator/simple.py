"""Simple subscription generators (SS/SSR/V2Ray/Trojan/Mixed/SSD/SS-Sub/Mellow)."""

import base64 as b64
import json
from typing import List

from ..config.models import Proxy, ProxyType
from ..utils.base64_util import base64_encode
from ..utils.url_util import url_encode
from .common import ExtraSettings


def proxy_to_single(nodes: List[Proxy], types: int, settings: ExtraSettings) -> str:
    """Generate simple subscription. types bitmask: 1=SS,2=SSR,4=VMess,8=Trojan,16=VLESS,32=Hysteria,63=Mixed."""
    result_lines = []
    builders = {
        (ProxyType.Shadowsocks, 1): _build_ss_link,
        (ProxyType.ShadowsocksR, 2): _build_ssr_link,
        (ProxyType.VMess, 4): _build_vmess_link,
        (ProxyType.Trojan, 8): _build_trojan_link,
        (ProxyType.VLESS, 16): _build_vless_link,
        (ProxyType.Hysteria, 32): _build_hysteria_link,
        (ProxyType.Hysteria2, 32): _build_hysteria_link,
        (ProxyType.AnyTLS, 8): _build_trojan_link,
    }
    for node in nodes:
        found = False
        for (ptype, mask), builder in builders.items():
            if node.Type == ptype and (types & mask):
                link = builder(node)
                if link: result_lines.append(link)
                found = True
                break
        if not found and types == 63:
            link = _build_any_link(node)
            if link: result_lines.append(link)

    return b64.b64encode('\n'.join(result_lines).encode()).decode()


def _build_ss_link(node: Proxy) -> str:
    userinfo = f"{node.EncryptMethod}:{node.Password}"
    encoded = base64_encode(userinfo)
    link = f"ss://{encoded}@{node.Hostname}:{node.Port}"
    params = []
    if node.Plugin: params.append(f"plugin={url_encode(node.Plugin)}")
    if params: link += '?' + '&'.join(params)
    if node.Remark: link += f"#{url_encode(node.Remark)}"
    return link


def _build_ssr_link(node: Proxy) -> str:
    password_b64 = base64_encode(node.Password).rstrip('=')
    main = f"{node.Hostname}:{node.Port}:{node.Protocol}:{node.EncryptMethod}:{node.OBFS}:{password_b64}"
    params = []
    if node.OBFSParam: params.append(f"obfsparam={url_encode(base64_encode(node.OBFSParam))}")
    if node.ProtocolParam: params.append(f"protoparam={url_encode(base64_encode(node.ProtocolParam))}")
    if node.Remark and node.Remark != node.Hostname:
        params.append(f"remarks={url_encode(base64_encode(node.Remark))}")
    if node.Group: params.append(f"group={url_encode(base64_encode(node.Group))}")
    if params: main += '/?' + '&'.join(params)
    return f"ssr://{base64_encode(main)}"


def _build_vmess_link(node: Proxy) -> str:
    data = {'v': '2', 'ps': node.Remark or node.Hostname, 'add': node.Hostname,
            'port': str(node.Port), 'id': node.UserId, 'aid': str(node.AlterId),
            'net': node.TransferProtocol or 'tcp', 'type': 'none',
            'host': node.Host or '', 'path': node.Path or '', 'tls': node.TLSStr or ''}
    if node.ServerName: data['sni'] = node.ServerName
    return f"vmess://{base64_encode(json.dumps(data))}"


def _build_trojan_link(node: Proxy) -> str:
    link = f"trojan://{url_encode(node.Password)}@{node.Hostname}:{node.Port}"
    params = []
    sni = node.ServerName or node.Hostname
    if sni and sni != node.Hostname: params.append(f"sni={url_encode(sni)}")
    elif node.Hostname: params.append(f"sni={url_encode(node.Hostname)}")
    if node.TransferProtocol and node.TransferProtocol != 'tcp': params.append(f"type={node.TransferProtocol}")
    if node.Host: params.append(f"host={url_encode(node.Host)}")
    if node.Path: params.append(f"path={url_encode(node.Path)}")
    if node.AllowInsecure is not None: params.append(f"allowInsecure={'1' if node.AllowInsecure else '0'}")
    if params: link += '?' + '&'.join(params)
    if node.Remark and node.Remark != node.Hostname: link += f"#{url_encode(node.Remark)}"
    return link


def _build_vless_link(node: Proxy) -> str:
    link = f"vless://{node.UserId}@{node.Hostname}:{node.Port}"
    params = []
    if node.TransferProtocol and node.TransferProtocol != 'tcp': params.append(f"type={node.TransferProtocol}")
    if node.TLSStr: params.append(f"security={node.TLSStr}")
    if node.ServerName: params.append(f"sni={url_encode(node.ServerName)}")
    if node.Fingerprint: params.append(f"fp={node.Fingerprint}")
    if node.Flow: params.append(f"flow={node.Flow}")
    if params: link += '?' + '&'.join(params)
    if node.Remark and node.Remark != node.Hostname: link += f"#{url_encode(node.Remark)}"
    return link


def _build_hysteria_link(node: Proxy) -> str:
    if node.Type == ProxyType.Hysteria2:
        link = f"hysteria2://{url_encode(node.Password)}@{node.Hostname}:{node.Port}"
    else:
        link = f"hysteria://{node.Hostname}:{node.Port}"
    params = []
    if node.ServerName and node.ServerName != node.Hostname: params.append(f"sni={url_encode(node.ServerName)}")
    if node.Alpn: params.append(f"alpn={node.Alpn}")
    if node.OBFSParam: params.append(f"obfs={node.OBFSParam}")
    if params: link += '?' + '&'.join(params)
    if node.Remark and node.Remark != node.Hostname: link += f"#{url_encode(node.Remark)}"
    return link


def _build_any_link(node: Proxy) -> str:
    builders = {
        ProxyType.Shadowsocks: _build_ss_link, ProxyType.ShadowsocksR: _build_ssr_link,
        ProxyType.VMess: _build_vmess_link, ProxyType.Trojan: _build_trojan_link,
        ProxyType.VLESS: _build_vless_link,
        ProxyType.Hysteria: _build_hysteria_link, ProxyType.Hysteria2: _build_hysteria_link,
        ProxyType.AnyTLS: _build_trojan_link,
    }
    builder = builders.get(node.Type)
    return builder(node) if builder else None


def proxy_to_ssd(nodes: List[Proxy], group: str, userinfo: str, settings: ExtraSettings) -> str:
    ss_nodes = [n for n in nodes if n.Type == ProxyType.Shadowsocks]
    lines = [f"{n.Hostname}:{n.Port}:{n.EncryptMethod}:{n.Password}" for n in ss_nodes]
    sep = '\n'
    return f"ssd://{base64_encode(sep.join(lines))}"


def proxy_to_ss_sub(base_conf: str, nodes: List[Proxy], settings: ExtraSettings) -> str:
    ss_nodes = [n for n in nodes if n.Type == ProxyType.Shadowsocks]
    links = [_build_ss_link(n) for n in ss_nodes if _build_ss_link(n)]
    return b64.b64encode('\n'.join(links).encode()).decode()


def proxy_to_mellow(nodes: List[Proxy], base_conf: str, ruleset_content: List,
                    extra_groups: List, settings: ExtraSettings) -> str:
    result = [base_conf] if base_conf else []
    for node in nodes:
        if node.Type == ProxyType.VMess:
            link = _build_vmess_link(node)
            if link: result.append(link)
    return '\n'.join(result) + '\n'
