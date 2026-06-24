"""Quantumult X generator."""

from typing import List

from ..config.models import Proxy, ProxyType
from ..config.settings import ProxyGroupConfig
from ..utils.string_util import trim
from .common import ExtraSettings
from .ruleconvert import convert_ruleset, RULESET_SURGE


def proxy_to_quanx(nodes: List[Proxy], base_conf: str,
                   ruleset_content: List,
                   extra_groups: List[ProxyGroupConfig],
                   settings: ExtraSettings) -> str:
    result = []
    if base_conf:
        result.append(base_conf)

    result.append("[server_local]")
    for node in nodes:
        line = _quanx_proxy(node)
        if line: result.append(line)

    result.append("[policy]")
    for g in extra_groups:
        proxies_str = ', '.join(g.Proxies)
        gtype = 'static' if g.Type.value == 1 else 'available'
        result.append(f"{gtype}={g.Name}, {proxies_str}")

    if ruleset_content:
        result.append("[filter_local]")
        for rc in ruleset_content:
            content = rc.rule_content or ""
            if not content: continue
            converted = convert_ruleset(content, rc.rule_type or RULESET_SURGE)
            for line in converted.strip().split('\n'):
                line = trim(line)
                if not line or line[0] in (';', '#') or line.startswith('//'):
                    continue
                result.append(f"{line},{rc.rule_group}")

    return '\n'.join(result) + '\n'


def _quanx_proxy(node: Proxy):
    name = node.Remark or f"{node.Hostname}:{node.Port}"
    if node.Type == ProxyType.Shadowsocks:
        return f"shadowsocks={node.Hostname}:{node.Port}, method={node.EncryptMethod}, password={node.Password}, fast-open=false, udp-relay=false, tag={name}"
    elif node.Type == ProxyType.VMess:
        ws = (node.TransferProtocol == 'ws')
        tls = node.TLSStr == 'tls'
        opts = f", obfs={'wss' if ws and tls else 'ws' if ws else 'over-tls' if tls else 'none'}"
        if node.Path: opts += f", obfs-host={node.Host}, obfs-uri={node.Path}"
        if node.TLSStr: opts += f", tls13={node.TLS13 or False}"
        return f"vmess={node.Hostname}:{node.Port}, method={node.EncryptMethod}, password={node.UserId}{opts}, tag={name}"
    elif node.Type == ProxyType.Trojan:
        return f"trojan={node.Hostname}:{node.Port}, password={node.Password}, over-tls={'true' if node.TLSStr else 'false'}, tls-host={node.ServerName or node.Hostname}, fast-open=false, udp-relay=false, tag={name}"
    elif node.Type == ProxyType.AnyTLS:
        return f"anytls={node.Hostname}:{node.Port}, password={node.Password}, sni={node.ServerName or node.Hostname}, fast-open=false, udp-relay=false, tag={name}"
    return None
