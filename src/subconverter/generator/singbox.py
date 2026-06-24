"""Sing-box configuration generator."""

import json
from typing import List, Optional, Dict

from ..config.models import Proxy, ProxyType
from ..config.settings import ProxyGroupConfig
from .common import ExtraSettings


def proxy_to_singbox(nodes: List[Proxy], base_conf: str,
                     ruleset_content: List,
                     extra_groups: List[ProxyGroupConfig],
                     settings: ExtraSettings) -> str:
    config = {}
    if base_conf:
        try: config = json.loads(base_conf)
        except json.JSONDecodeError: pass

    outbounds = [_singbox_proxy(n) for n in nodes if _singbox_proxy(n)]
    if outbounds:
        selector = {"type": "selector", "tag": "proxy", "outbounds": [o['tag'] for o in outbounds if 'tag' in o]}
        all_obs = config.get('outbounds', [])
        all_obs.insert(0, selector)
        outbounds = all_obs + [o for o in outbounds if o not in all_obs]
    config['outbounds'] = outbounds or config.get('outbounds', [])

    return json.dumps(config, indent=2, ensure_ascii=False)


def _singbox_proxy(node: Proxy) -> Optional[Dict]:
    tag = node.Remark or f"{node.Hostname}:{node.Port}"
    out = {'tag': tag, 'server': node.Hostname, 'server_port': node.Port}

    if node.Type == ProxyType.Shadowsocks:
        out.update(type='shadowsocks', method=node.EncryptMethod, password=node.Password)
        if node.Plugin: out['plugin'] = node.Plugin
    elif node.Type == ProxyType.VMess:
        out.update(type='vmess', uuid=node.UserId, security=node.EncryptMethod or 'auto')
        if node.TransferProtocol == 'ws':
            out['transport'] = {'type': 'ws', 'path': node.Path or '/', 'headers': {'Host': node.Host or node.Hostname}}
        if node.TLSStr: out['tls'] = {'enabled': True, 'server_name': node.ServerName or node.Hostname}
    elif node.Type == ProxyType.Trojan:
        out.update(type='trojan', password=node.Password)
        if node.ServerName: out['tls'] = {'enabled': True, 'server_name': node.ServerName}
    elif node.Type == ProxyType.Hysteria:
        out['type'] = 'hysteria'; out['auth_str'] = node.AuthStr
        out['up_mbps'] = int(node.UpMbps) if node.UpMbps and node.UpMbps.isdigit() else 50
        out['down_mbps'] = int(node.DownMbps) if node.DownMbps and node.DownMbps.isdigit() else 100
        if node.ServerName: out['tls'] = {'enabled': True, 'server_name': node.ServerName}
    elif node.Type == ProxyType.Hysteria2:
        out.update(type='hysteria2', password=node.Password)
        if node.ServerName: out['tls'] = {'enabled': True, 'server_name': node.ServerName}
    elif node.Type == ProxyType.TUIC:
        out.update(type='tuic', uuid=node.UserId, password=node.Password)
        if node.ServerName: out['tls'] = {'enabled': True, 'server_name': node.ServerName}
    elif node.Type == ProxyType.AnyTLS:
        out.update(type='anytls', password=node.Password)
        if node.ServerName: out['tls'] = {'enabled': True, 'server_name': node.ServerName}
    else:
        return None
    return out
