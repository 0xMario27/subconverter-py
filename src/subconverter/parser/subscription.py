"""Subscription parsing: base64-encoded lists, Clash YAML, SSD."""

from typing import List, Optional, Dict

import yaml

from ..config.models import Proxy, ProxyType, DEFAULT_GROUPS
from ..utils.base64_util import base64_decode
from ..utils.string_util import split, starts_with, trim, is_link, file_exist, file_get, replace_all
from ..utils.network import web_get
from ..utils.logger import write_log, LOG_LEVEL_INFO, LOG_LEVEL_WARNING
from ..utils.url_util import url_decode
from .common import extract_remark
from .constructors import ss_construct
from .proxy_types import (
    explode_ss, explode_ssr, explode_vmess, explode_trojan, explode_vless,
    explode_hysteria, explode_hysteria2, explode_tuic,
    explode_socks, explode_http_link, explode_snell, explode_wireguard,
    explode_anytls, explode_mieru, explode_tg,
)
from .dispatcher import explode


def explode_sub(content: str, nodes: List[Proxy], default_group: str = "") -> int:
    """Parse subscription content (base64-encoded list of links). Returns count."""
    decoded = base64_decode(content)
    if not decoded:
        return 0

    links = decoded.strip().split('\n')
    count = 0

    for line in links:
        line = trim(line)
        if not line or line.startswith(';') or line.startswith('#') or line.startswith('//'):
            continue
        if line.startswith('<') and line.endswith('>'):
            continue

        node = Proxy()
        if line.startswith("ssd://"):
            from ._ssd import explode_ssd
            nodes_from_ssd = explode_ssd(line, default_group)
            nodes.extend(nodes_from_ssd)
            count += len(nodes_from_ssd)
        elif explode(line, node):
            if default_group:
                node.Group = default_group
            nodes.append(node)
            count += 1

    return count


def explode_clash_sub(content: str, nodes: List[Proxy], default_group: str = "") -> int:
    """Parse a Clash YAML subscription content. Returns count."""
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

    node = Proxy()
    node.Remark = name
    node.Hostname = server
    node.Port = int(port) if port else 0
    node.Group = default_group or proxy.get('group', '')

    handlers = {
        'ss': _clash_ss,
        'ssr': _clash_ssr,
        'vmess': _clash_vmess,
        'trojan': _clash_trojan,
        'vless': _clash_vless,
        'hysteria': _clash_hysteria,
        'hysteria2': _clash_hysteria2,
        'http': _clash_http,
        'socks5': _clash_socks5,
        'anytls': _clash_anytls,
        'tuic': _clash_tuic,
        'snell': _clash_snell,
        'mieru': _clash_mieru,
    }

    handler = handlers.get(ptype)
    if handler:
        handler(node, proxy, server, port)
        return node

    # Unknown type - store generically for passthrough
    node.Type = ProxyType.Unknown
    if proxy.get('password'):
        node.Password = str(proxy.get('password', ''))
    if proxy.get('username'):
        node.Username = str(proxy.get('username', ''))
    if proxy.get('uuid'):
        node.UserId = str(proxy.get('uuid', ''))
    return node


def _clash_ss(node, proxy, server, port):
    node.Type = ProxyType.Shadowsocks
    node.EncryptMethod = proxy.get('cipher', '')
    node.Password = proxy.get('password', '')
    node.Plugin = proxy.get('plugin', '')
    node.PluginOption = proxy.get('plugin-opts', '') if proxy.get('plugin-opts') else ''
    node.UDP = proxy.get('udp', None)

def _clash_ssr(node, proxy, server, port):
    node.Type = ProxyType.ShadowsocksR
    node.EncryptMethod = proxy.get('cipher', '')
    node.Password = proxy.get('password', '')
    node.Protocol = proxy.get('protocol', '')
    node.ProtocolParam = proxy.get('protocol-param', '')
    node.OBFS = proxy.get('obfs', '')
    node.OBFSParam = proxy.get('obfs-param', '')

def _clash_vmess(node, proxy, server, port):
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

def _clash_trojan(node, proxy, server, port):
    node.Type = ProxyType.Trojan
    node.Password = proxy.get('password', '')
    node.ServerName = proxy.get('sni', server)
    node.Host = proxy.get('sni', '')
    node.Path = proxy.get('ws-path', '')

def _clash_vless(node, proxy, server, port):
    node.Type = ProxyType.VLESS
    node.UserId = proxy.get('uuid', '')
    node.TransferProtocol = proxy.get('network', 'tcp')

def _clash_hysteria(node, proxy, server, port):
    node.Type = ProxyType.Hysteria
    node.AuthStr = proxy.get('auth_str', '') or proxy.get('auth', '')
    node.ServerName = proxy.get('sni', server)

def _clash_hysteria2(node, proxy, server, port):
    node.Type = ProxyType.Hysteria2
    node.Password = proxy.get('password', '')
    node.ServerName = proxy.get('sni', server)

def _clash_http(node, proxy, server, port):
    node.Type = ProxyType.HTTP
    node.Username = proxy.get('username', '')
    node.Password = proxy.get('password', '')

def _clash_socks5(node, proxy, server, port):
    node.Type = ProxyType.SOCKS5
    node.Username = proxy.get('username', '')
    node.Password = proxy.get('password', '')

def _clash_anytls(node, proxy, server, port):
    node.Type = ProxyType.AnyTLS
    node.Password = proxy.get('password', '')
    node.ServerName = proxy.get('servername', '') or proxy.get('sni', server)
    node.TransferProtocol = proxy.get('network', 'tcp')

def _clash_tuic(node, proxy, server, port):
    node.Type = ProxyType.TUIC
    node.UserId = proxy.get('uuid', '')
    node.Password = proxy.get('password', '')
    node.ServerName = proxy.get('sni', server) or proxy.get('servername', '')
    node.CongestionControl = proxy.get('congestion-controller', '')

def _clash_snell(node, proxy, server, port):
    node.Type = ProxyType.Snell
    node.Password = proxy.get('password', '')
    node.Host = proxy.get('sni', '') or proxy.get('host', '')
    node.OBFS = proxy.get('obfs', '')

def _clash_mieru(node, proxy, server, port):
    node.Type = ProxyType.Mieru
    node.Password = proxy.get('password', '')
    node.Username = proxy.get('username', '')


# ==================== add_nodes (fetch + parse subscription) ====================

def _get_proxy_subscription() -> str:
    from ..config.settings import global_settings as gs
    return gs.proxy_subscription or ""


def add_nodes(link: str, all_nodes: List[Proxy], group_id: int,
              proxy: str = "", exclude_remarks: List[str] = None,
              include_remarks: List[str] = None,
              sub_info: Dict = None) -> int:
    """Fetch and parse a subscription URL or local file. Returns count or -1."""
    import re as re_module

    link = replace_all(link, '"', '')

    if not link:
        return 0

    content = ""

    if is_link(link):
        write_log(0, f"Fetching subscription from URL: {link}", LOG_LEVEL_INFO)
        content = web_get(link, proxy or _get_proxy_subscription(), cache_ttl=3600)
    elif file_exist(link):
        write_log(0, f"Reading subscription from file: {link}", LOG_LEVEL_INFO)
        content = file_get(link)
    else:
        node = Proxy()
        if explode(link, node):
            node.GroupId = group_id
            all_nodes.append(node)
            return 1
        if is_link(link):
            content = web_get(link, proxy or _get_proxy_subscription(), cache_ttl=3600)
        else:
            write_log(0, f"Invalid link or file: {link}", LOG_LEVEL_WARNING)
            return -1

    if not content:
        write_log(0, f"Empty content from: {link}", LOG_LEVEL_WARNING)
        return -1

    # Check for Clash YAML subscription
    stripped = content.strip()
    if stripped.startswith(('proxies:', 'Proxy:')) or (
            stripped.startswith('{') and '"proxies"' in stripped[:200].lower()):
        n = explode_clash_sub(content, all_nodes, str(group_id))
        for node in all_nodes[-n:]:
            node.GroupId = group_id
        return n if n > 0 else -1

    # Check for subscription-userinfo header
    if 'subscription-userinfo' in content.lower()[:200]:
        lines = content.split('\n')
        for line in lines:
            if 'subscription-userinfo' in line.lower():
                info = line.split(':', 1)[1].strip() if ':' in line else ''
                if sub_info is not None:
                    sub_info['info'] = info
        proxy_content = []
        for line in lines:
            line = trim(line)
            if line and not line.startswith('#') and not line.startswith('//'):
                if any(line.lower().startswith(p) for p in
                       ['ss://', 'ssr://', 'vmess://', 'trojan://', 'vless://',
                        'hysteria', 'tuic://', 'snell://', 'socks', 'http://',
                        'https://', 'ssd://', 'anytls://', 'mieru://']):
                    proxy_content.append(line)
        if proxy_content:
            content = '\n'.join(proxy_content)

    n = explode_sub(content, all_nodes, str(group_id))
    for node in all_nodes[-n:]:
        node.GroupId = group_id

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
